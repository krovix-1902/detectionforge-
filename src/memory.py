"""
memory.py — long-term rule memory.

Demonstrates the *memory / context engineering* capability. The agent keeps a
store of previously authored, validated rules so it can (a) avoid generating a
near-duplicate detection, and (b) ground new rules in the house Sigma style.

Kept deliberately simple (JSON-backed) — the point is to show the pattern, not
to ship a vector DB. Swap in a persistent store if you deploy.
"""
from __future__ import annotations

import json
import os
from difflib import SequenceMatcher


class RuleMemory:
    def __init__(self, path: str = "rule_memory.json"):
        self.path = path
        self.rules: list[dict] = []
        if os.path.exists(path):
            with open(path) as f:
                self.rules = json.load(f)

    def is_duplicate(self, title: str, threshold: float = 0.8) -> bool:
        """True if a very similar rule title already exists (cheap dedup)."""
        return any(
            SequenceMatcher(None, title.lower(), r["title"].lower()).ratio() >= threshold
            for r in self.rules
        )

    def style_examples(self, k: int = 2) -> list[str]:
        """Return a few prior rules as few-shot style anchors for the prompt."""
        return [r["sigma_yaml"] for r in self.rules[-k:]]

    def add(self, title: str, sigma_yaml: str) -> None:
        self.rules.append({"title": title, "sigma_yaml": sigma_yaml})
        with open(self.path, "w") as f:
            json.dump(self.rules, f, indent=2)
