"""
agent.py — DetectionForge core single agent.

A SINGLE agent (one reasoning loop) with a toolbelt. It ingests cyber threat
intel and produces a validated, ATT&CK-mapped detection rule (Sigma + SPL +
Elastic), self-correcting when validation fails.

Capabilities demonstrated:
  - Function calling / tool use   (AGENT_TOOLS, automatic function calling)
  - Agentic loop                  (validate -> self-correct -> retry, x3)
  - Structured output             (Pydantic RuleVerdict schema)
  - RAG / embeddings              (map_attack over the ATT&CK corpus)
  - Memory / context engineering  (RuleMemory: dedup + style grounding)
  - Security feature              (sanitise_cti guards against prompt injection
                                   hidden in fetched intel)

Design note — two-phase pipeline:
  The Gemini API does not allow function-calling tools and a JSON
  response_schema in the SAME request, so the agent runs in two phases:
    Phase 1 (agentic): free reasoning with the toolbelt (map_attack,
             validate_sigma, convert_rule, fetch_cti) via automatic
             function calling.
    Phase 2 (structuring): the phase-1 result is compiled into the strict
             Pydantic RuleVerdict schema.
    Phase 3 (zero-trust backstop): validation/conversion are re-run
             deterministically in code; if the rule is invalid the agent
             enters a self-correction loop (read errors -> fix -> re-validate,
             up to MAX_FIX_ATTEMPTS).

Porting to ADK: the same `AGENT_TOOLS` functions can be handed to
`google.adk.agents.Agent(tools=AGENT_TOOLS, ...)`. This module uses the
google-genai SDK directly so it runs out-of-the-box; see README.
"""
from __future__ import annotations

import os
import re
import time

from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from .schemas import RuleVerdict
from .tools import AGENT_TOOLS, validate_sigma, convert_rule
from .memory import RuleMemory

load_dotenv()  # picks up GEMINI_API_KEY / GEMINI_MODEL from .env if present

MAX_FIX_ATTEMPTS = 3


def generate_with_backoff(client, max_retries: int = 12, **kwargs):
    """Call generate_content, waiting out free-tier rate limits (HTTP 429).

    The AI Studio free tier allows only a handful of requests per minute;
    instead of crashing, we sleep and retry so long runs (e.g. the eval
    harness) complete unattended.
    """
    for attempt in range(1, max_retries + 1):
        try:
            return client.models.generate_content(**kwargs)
        except Exception as e:
            msg = str(e)
            if "429" in msg or "RESOURCE_EXHAUSTED" in msg:
                wait = min(40 + 10 * (attempt - 1), 90)
                print(f"  [rate limit] free-tier quota hit — waiting {wait}s "
                      f"(retry {attempt}/{max_retries})", flush=True)
                time.sleep(wait)
            elif "503" in msg or "UNAVAILABLE" in msg or "500" in msg:
                wait = 15 * attempt
                print(f"  [server busy] Gemini overloaded — waiting {wait}s "
                      f"(retry {attempt}/{max_retries})", flush=True)
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("Gemini rate/availability limit persisted after all retries")


SYSTEM_INSTRUCTION = """You are DetectionForge, an autonomous detection-engineering agent.
Given cyber threat intelligence, you:
  1. Extract a short threat summary, IOCs, and adversary behaviours (TTPs).
  2. Map each behaviour to MITRE ATT&CK using the map_attack tool.
  3. Author a Sigma detection rule in YAML. It must include: title, id (uuid4),
     status, description, logsource (category/product), detection with a
     condition, falsepositives, and level.
  4. Validate it with validate_sigma. If invalid, READ the errors and fix the
     rule, then re-validate. Retry up to 3 times.
  5. Convert the validated rule with convert_rule.
  6. State your log-source assumptions honestly (what fields/log source the rule
     needs, and the false-positive risk). Do NOT overclaim detection coverage.

Be precise. A specific rule that matches the malicious behaviour but not benign
activity is worth more than a broad rule that fires on everything.
"""

# A conservative guard against prompt-injection smuggled inside fetched CTI text.
_INJECTION_PATTERNS = [
    r"ignore\s+(?:(?:all|any|the|previous|above|prior|earlier)\s+)*instructions",
    r"disregard .{0,20}(system|prompt|rules)",
    r"you are now",
    r"new instructions:",
]


def sanitise_cti(text: str) -> str:
    """Security feature: neutralise obvious instruction-injection in untrusted
    intel before it reaches the model. Flags rather than silently dropping."""
    flagged = text
    for pat in _INJECTION_PATTERNS:
        flagged = re.sub(pat, "[REDACTED-POSSIBLE-INJECTION]", flagged, flags=re.IGNORECASE)
    return flagged


class _FixedRule(BaseModel):
    """Structured output for the self-correction loop."""
    sigma_yaml: str = Field(description="The corrected, complete Sigma rule in YAML")


class DetectionForgeAgent:
    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.client = genai.Client(api_key=api_key or os.environ["GEMINI_API_KEY"])
        self.model = model or os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        self.memory = RuleMemory()

    # ------------------------------------------------------------------ #
    def run(self, cti_text: str) -> RuleVerdict:
        """Run the full triage->detection pipeline on a piece of threat intel."""
        cti_text = sanitise_cti(cti_text)
        style = self.memory.style_examples()
        style_block = ("\n\nHouse style — match the structure of these prior rules:\n"
                       + "\n---\n".join(style)) if style else ""

        # ---- Phase 1: agentic generation with automatic function calling.
        # The SDK runs the tool-use loop (model calls map_attack /
        # validate_sigma / convert_rule until it is satisfied).
        analysis = generate_with_backoff(
            self.client,
            model=self.model,
            contents=(
                "Threat intelligence to analyse:\n\n"
                f"{cti_text}\n{style_block}\n\n"
                "Work through your full process using the tools. Finish with: "
                "the threat summary, IOCs, TTPs, ATT&CK mappings (with tool "
                "scores), the final Sigma rule YAML, and your log-source "
                "assumptions."
            ),
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                tools=AGENT_TOOLS,                  # function calling
                temperature=0.2,
            ),
        )

        # ---- Phase 2: compile the analysis into the strict output schema.
        # One retry if the structured parse comes back empty (e.g. truncation).
        verdict = None
        for _ in range(2):
            structured = generate_with_backoff(
                self.client,
                model=self.model,
                contents=(
                    "Convert this detection-engineering analysis into the required "
                    "schema. Copy the Sigma YAML verbatim into rule.sigma_yaml.\n\n"
                    f"{analysis.text}"
                ),
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=RuleVerdict,        # structured output
                    temperature=0.0,
                ),
            )
            verdict = structured.parsed
            if verdict is None:
                try:
                    verdict = RuleVerdict.model_validate_json(structured.text)
                except Exception:
                    verdict = None
            if verdict is not None:
                break
        if verdict is None:
            raise RuntimeError("Structured output failed twice; raw response: "
                               f"{getattr(structured, 'text', '')[:500]}")

        # ---- Phase 3: deterministic zero-trust backstop + self-correction.
        # We re-run validation in code rather than trusting the model's claim,
        # and loop error->fix->re-validate up to MAX_FIX_ATTEMPTS.
        v = validate_sigma(verdict.rule.sigma_yaml)
        attempts = 0
        while not v["valid"] and attempts < MAX_FIX_ATTEMPTS:
            attempts += 1
            fix = generate_with_backoff(
                self.client,
                model=self.model,
                contents=(
                    "This Sigma rule failed pySigma validation.\n\n"
                    f"RULE:\n{verdict.rule.sigma_yaml}\n\n"
                    f"ERRORS:\n{v['errors']}\n\n"
                    "Fix the rule. Keep the detection logic; correct only what "
                    "the errors require. Return the complete corrected YAML."
                ),
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=_FixedRule,
                    temperature=0.0,
                ),
            )
            if fix.parsed is not None:
                verdict.rule.sigma_yaml = fix.parsed.sigma_yaml
            v = validate_sigma(verdict.rule.sigma_yaml)

        verdict.rule.validation_passed = v["valid"]
        verdict.rule.validation_errors = v["errors"]

        if v["valid"]:
            conv = convert_rule(verdict.rule.sigma_yaml)
            verdict.rule.splunk_spl = conv["splunk_spl"]
            verdict.rule.elastic_query = conv["elastic_query"]
            if not self.memory.is_duplicate(verdict.rule.title):
                self.memory.add(verdict.rule.title, verdict.rule.sigma_yaml)

        return verdict


if __name__ == "__main__":
    sample = ("An adversary sent a phishing email with a malicious Office "
              "attachment. On open, a macro launched powershell.exe with a "
              "base64-encoded command that downloaded a second-stage payload "
              "and created a Registry Run key for persistence.")
    agent = DetectionForgeAgent()
    result = agent.run(sample)
    print(result.model_dump_json(indent=2))
