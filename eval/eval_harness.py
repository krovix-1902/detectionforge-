"""
eval_harness.py — DetectionForge evaluation harness.

This is the project's single biggest scoring lever. Most capstone submissions
skip evaluation entirely; the course dedicates a whole day to it. We score every
generated rule on four axes against a small hand-labelled ground-truth set:

  1. syntax_valid       — does pySigma parse it? (automated, binary)
  2. attack_accuracy    — did we map the correct ATT&CK technique IDs? (recall)
  3. convertible        — does it compile to SPL/Elastic? (deployability proxy)
  4. specificity_judge  — LLM-as-judge: does it match the malicious sample but
                          NOT the benign baseline? (false-positive control)

Run:  python -m eval.eval_harness
Outputs a per-case table + an aggregate score, and saves eval_results.png.
"""
from __future__ import annotations

import json
import os

import pandas as pd
from dotenv import load_dotenv

load_dotenv()

from src.agent import DetectionForgeAgent, generate_with_backoff
from src.tools import validate_sigma, convert_rule


GT_PATH = os.path.join(os.path.dirname(__file__), "ground_truth", "samples.json")


def attack_recall(predicted_ids: list[str], expected_ids: list[str]) -> float:
    if not expected_ids:
        return 1.0
    hit = sum(1 for e in expected_ids if e in predicted_ids)
    return hit / len(expected_ids)


def specificity_judge(agent: DetectionForgeAgent, sigma_yaml: str,
                      should_match: list[str], should_not_match: list[str]) -> float:
    """LLM-as-judge: would this rule fire on the malicious case but not the benign one?"""
    from google.genai import types
    prompt = (
        "You are a strict detection-engineering reviewer. Given this Sigma rule:\n\n"
        f"{sigma_yaml}\n\n"
        f"It SHOULD fire on: {should_match}\n"
        f"It SHOULD NOT fire on: {should_not_match}\n\n"
        "Score 1.0 if it cleanly distinguishes malicious from benign, 0.5 if partial, "
        "0.0 if it would miss the malicious case or fire on the benign one. "
        "Respond with ONLY the number."
    )
    resp = generate_with_backoff(
        agent.client,
        model=agent.model, contents=prompt,
        config=types.GenerateContentConfig(temperature=0.0),
    )
    try:
        return max(0.0, min(1.0, float(resp.text.strip().split()[0])))
    except Exception:
        return 0.0


def run_eval() -> pd.DataFrame:
    with open(GT_PATH) as f:
        cases = json.load(f)

    agent = DetectionForgeAgent()
    rows = []
    for case in cases:
        verdict = agent.run(case["cti_text"])
        rule = verdict.rule

        syntax = 1.0 if rule.validation_passed else 0.0
        predicted = [m.technique_id for m in rule.attack_mappings]
        recall = attack_recall(predicted, case["expected_techniques"])
        convertible = 1.0 if (rule.splunk_spl or rule.elastic_query) else 0.0
        specificity = specificity_judge(
            agent, rule.sigma_yaml, case["should_match"], case["should_not_match"]
        ) if rule.validation_passed else 0.0

        overall = round(0.25 * syntax + 0.25 * recall + 0.20 * convertible + 0.30 * specificity, 3)
        rows.append({
            "case": case["id"], "syntax": syntax, "attack_recall": round(recall, 2),
            "convertible": convertible, "specificity": specificity, "overall": overall,
        })

    df = pd.DataFrame(rows)
    return df


def main():
    df = run_eval()
    print(df.to_string(index=False))
    print(f"\nAGGREGATE SCORE: {df['overall'].mean():.3f}")

    # Save a simple chart for the writeup / video.
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        ax = df.set_index("case")[["syntax", "attack_recall", "convertible", "specificity"]].plot(
            kind="bar", figsize=(9, 5))
        ax.set_title("DetectionForge — evaluation by case")
        ax.set_ylabel("score (0-1)")
        plt.tight_layout()
        plt.savefig("eval_results.png", dpi=140)
        print("Saved eval_results.png")
    except Exception as e:
        print(f"(chart skipped: {e})")


if __name__ == "__main__":
    main()
