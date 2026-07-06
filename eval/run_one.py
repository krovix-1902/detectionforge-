"""Checkpointed eval runner: evaluates ONE ground-truth case per invocation.

Usage: python -m eval.run_one <case_index>
Appends the row to eval/partial_results.json; eval_harness-style report can be
built once all cases are done. Lets the eval run in short, resumable steps.
"""
import json
import os
import sys

from dotenv import load_dotenv

load_dotenv()

from src.agent import DetectionForgeAgent
from eval.eval_harness import attack_recall, specificity_judge, GT_PATH

OUT = os.path.join(os.path.dirname(__file__), "partial_results.json")


def main(i: int):
    with open(GT_PATH) as f:
        cases = json.load(f)
    case = cases[i]

    agent = DetectionForgeAgent()
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

    row = {"case": case["id"], "syntax": syntax, "attack_recall": round(recall, 2),
           "convertible": convertible, "specificity": specificity, "overall": overall}

    rows = []
    if os.path.exists(OUT):
        with open(OUT) as f:
            rows = json.load(f)
    rows = [r for r in rows if r["case"] != row["case"]] + [row]
    with open(OUT, "w") as f:
        json.dump(rows, f, indent=2)
    print(json.dumps(row))


if __name__ == "__main__":
    main(int(sys.argv[1]))
