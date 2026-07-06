"""
schemas.py — Structured-output contracts for DetectionForge.

Demonstrates the *structured output* capability: every artifact the agent
produces is validated against a strict Pydantic schema, so downstream code
(and the eval harness) can trust the shape of the data instead of parsing
free-form LLM text.
"""
from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


class IOC(BaseModel):
    """A single indicator of compromise extracted from threat intel."""
    type: Literal["ip", "domain", "url", "hash", "filename", "registry", "process", "command"]
    value: str
    context: str = Field(description="Why this IOC matters / where it appeared")


class TTP(BaseModel):
    """An observed adversary behaviour, pre-ATT&CK-mapping."""
    behaviour: str = Field(description="Plain-language description of the technique observed")
    evidence: str = Field(description="The sentence/phrase from the CTI that supports it")


class AttackMapping(BaseModel):
    """A behaviour mapped to a MITRE ATT&CK technique."""
    technique_id: str = Field(description="e.g. T1059.001")
    technique_name: str
    tactic: str = Field(description="e.g. Execution")
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str


class ExtractionResult(BaseModel):
    """Output of the parse + extract stage."""
    summary: str = Field(description="2-3 sentence summary of the threat")
    iocs: list[IOC]
    ttps: list[TTP]


class DetectionRule(BaseModel):
    """The final reviewer-ready detection artifact."""
    title: str
    sigma_yaml: str = Field(description="Valid Sigma rule in YAML")
    attack_mappings: list[AttackMapping]
    splunk_spl: str | None = None
    elastic_query: str | None = None
    validation_passed: bool = False
    validation_errors: list[str] = Field(default_factory=list)
    log_source_assumptions: str = Field(
        description="Explicit statement of what log source / field schema this rule assumes — "
                    "honesty about false-positive risk is a scoring and credibility win."
    )


class RuleVerdict(BaseModel):
    """A complete DetectionForge run: intel in, validated detection PR out."""
    extraction: ExtractionResult
    rule: DetectionRule
    self_eval_score: float = Field(ge=0.0, le=1.0, default=0.0)
