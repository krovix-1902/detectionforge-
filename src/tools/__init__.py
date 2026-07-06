"""
tools — DetectionForge's toolbelt.

Each function here is a *tool* the agent can call (the function-calling /
tool-use capability). They are plain Python functions on purpose: that keeps
them portable — the same functions can be registered with the Gemini SDK's
automatic function calling OR wrapped in Google ADK's FunctionTool. See the
README "Porting to ADK" note.

The ATT&CK index is persisted to disk (data/attack_index.*) by
build_attack_index(), so you build it once and every later process reuses it.
If the index has not been built, map_attack falls back to a small built-in
technique map covering the most common behaviours, so the agent and eval
harness still run end-to-end out of the box.
"""
from __future__ import annotations

import json
import os
import re

import requests
from bs4 import BeautifulSoup

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
_INDEX_VECS = os.path.join(_DATA_DIR, "attack_index.npy")
_INDEX_META = os.path.join(_DATA_DIR, "attack_index.json")


# ---------------------------------------------------------------------------
# Tool 1: fetch_cti — pull and clean a threat-intel article
# ---------------------------------------------------------------------------
def fetch_cti(url: str) -> str:
    """Fetch a cyber threat intelligence article and return its cleaned text.

    Args:
        url: A public URL to a threat-intel blog post or report.
    Returns:
        The article's main text, stripped of nav/scripts, truncated to a safe
        length for the model context.
    """
    resp = requests.get(url, timeout=20, headers={"User-Agent": "DetectionForge/0.1"})
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    text = " ".join(soup.get_text(separator=" ").split())
    return text[:20000]


# ---------------------------------------------------------------------------
# Tool 2: validate_sigma — syntactic validation via pySigma
# ---------------------------------------------------------------------------
def validate_sigma(sigma_yaml: str) -> dict:
    """Validate a Sigma rule's YAML structure with pySigma.

    This is the agent's *self-correction* signal: on failure the agent reads the
    error and regenerates the rule (the agentic loop).

    Args:
        sigma_yaml: The candidate Sigma rule as a YAML string.
    Returns:
        {"valid": bool, "errors": list[str]}
    """
    try:
        from sigma.collection import SigmaCollection
        SigmaCollection.from_yaml(sigma_yaml)
        return {"valid": True, "errors": []}
    except Exception as e:
        return {"valid": False, "errors": [f"{type(e).__name__}: {e}"]}


# ---------------------------------------------------------------------------
# Tool 3: convert_rule — Sigma -> SPL / Elastic via pySigma backends
# ---------------------------------------------------------------------------
def convert_rule(sigma_yaml: str) -> dict:
    """Convert a validated Sigma rule into Splunk SPL and an Elastic query.

    Args:
        sigma_yaml: A *validated* Sigma rule.
    Returns:
        {"splunk_spl": str|None, "elastic_query": str|None, "errors": list[str]}
    """
    out = {"splunk_spl": None, "elastic_query": None, "errors": []}
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.splunk import SplunkBackend
        out["splunk_spl"] = SplunkBackend().convert(SigmaCollection.from_yaml(sigma_yaml))[0]
    except Exception as e:
        out["errors"].append(f"splunk: {type(e).__name__}: {e}")
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.elasticsearch import LuceneBackend
        out["elastic_query"] = LuceneBackend().convert(SigmaCollection.from_yaml(sigma_yaml))[0]
    except Exception as e:
        out["errors"].append(f"elastic: {type(e).__name__}: {e}")
    return out


# ---------------------------------------------------------------------------
# Tool 4: map_attack — RAG over a local MITRE ATT&CK corpus
# ---------------------------------------------------------------------------
_ATTACK_INDEX = None  # loaded lazily from disk

# Built-in fallback map so the agent runs before the full index is built.
_MINI = [
    {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution",
     "text": "powershell encoded command script execution base64"},
    {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment",
     "tactic": "Initial Access",
     "text": "phishing spearphishing email malicious attachment word office macro vba"},
    {"technique_id": "T1547.001", "technique_name": "Registry Run Keys / Startup Folder",
     "tactic": "Persistence", "text": "registry run key persistence autostart startup"},
    {"technique_id": "T1003.001", "technique_name": "LSASS Memory", "tactic": "Credential Access",
     "text": "lsass memory credential dump dumping harvest hashes mimikatz ntlm plaintext"},
    {"technique_id": "T1053.005", "technique_name": "Scheduled Task", "tactic": "Persistence",
     "text": "scheduled task schtasks persistence hourly temp payload"},
    {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "Command and Control",
     "text": "download second stage payload transfer tool remote file"},
    {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information",
     "tactic": "Defense Evasion", "text": "obfuscated encoded base64 packed encrypted payload"},
]


def _try_load_index():
    """Load the persisted semantic index if it exists and deps are installed."""
    global _ATTACK_INDEX
    if _ATTACK_INDEX is not None:
        return _ATTACK_INDEX
    if not (os.path.exists(_INDEX_VECS) and os.path.exists(_INDEX_META)):
        return None
    try:
        import numpy as np
        from sentence_transformers import SentenceTransformer

        vecs = np.load(_INDEX_VECS)
        with open(_INDEX_META) as f:
            techniques = json.load(f)
        model = SentenceTransformer("all-MiniLM-L6-v2")

        class _Index:
            def search(self, q: str, top_k: int = 3):
                qv = model.encode([q], normalize_embeddings=True)[0]
                sims = vecs @ qv
                idx = np.argsort(-sims)[:top_k]
                return [{k: techniques[i][k]
                         for k in ("technique_id", "technique_name", "tactic")}
                        | {"score": round(float(sims[i]), 3)} for i in idx]

        _ATTACK_INDEX = _Index()
        return _ATTACK_INDEX
    except Exception:
        return None


def map_attack(behaviour: str) -> list[dict]:
    """Map an observed adversary behaviour to the most likely MITRE ATT&CK
    technique(s) using semantic search over a local ATT&CK corpus.

    Args:
        behaviour: Plain-language description of an adversary behaviour.
    Returns:
        Up to 3 candidate techniques:
        [{"technique_id","technique_name","tactic","score"}]
    """
    index = _try_load_index()
    if index is not None:
        return index.search(behaviour, top_k=3)

    # Fallback: keyword scoring over the built-in mini corpus.
    words = set(re.findall(r"[a-z0-9.]+", behaviour.lower()))
    scored = []
    for t in _MINI:
        overlap = len(words & set(t["text"].split()))
        if overlap:
            scored.append((overlap, t))
    scored.sort(key=lambda x: -x[0])
    return [{k: t[k] for k in ("technique_id", "technique_name", "tactic")}
            | {"score": round(min(1.0, n / 4), 2)} for n, t in scored[:3]]


def build_attack_index(stix_path: str):
    """Build and PERSIST the semantic ATT&CK index from a MITRE STIX bundle.

    Run once at setup; later processes load it automatically from data/.

    Download enterprise-attack.json from:
    https://github.com/mitre-attack/attack-stix-data
    """
    import numpy as np
    from sentence_transformers import SentenceTransformer

    with open(stix_path) as f:
        bundle = json.load(f)

    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern" and not obj.get("revoked") \
                and not obj.get("x_mitre_deprecated"):
            ext = next((r for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if not ext:
                continue
            techniques.append({
                "technique_id": ext["external_id"],
                "technique_name": obj.get("name", ""),
                "tactic": ", ".join(p["phase_name"]
                                    for p in obj.get("kill_chain_phases", [])),
                "text": f"{obj.get('name', '')}. {obj.get('description', '')[:1000]}",
            })

    model = SentenceTransformer("all-MiniLM-L6-v2")
    vecs = model.encode([t["text"] for t in techniques], normalize_embeddings=True)

    os.makedirs(_DATA_DIR, exist_ok=True)
    np.save(_INDEX_VECS, vecs)
    with open(_INDEX_META, "w") as f:
        json.dump(techniques, f)

    global _ATTACK_INDEX
    _ATTACK_INDEX = None          # force reload from the fresh files
    print(f"Indexed {len(techniques)} ATT&CK techniques -> {_DATA_DIR}")
    return _try_load_index()


# The set of tools exposed to the agent's function-calling loop.
AGENT_TOOLS = [fetch_cti, map_attack, validate_sigma, convert_rule]
