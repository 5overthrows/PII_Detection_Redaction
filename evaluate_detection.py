"""Evaluate detector span precision/recall against samples/pii_benchmark.jsonl.

This small reviewed seed set is a regression aid, not evidence of production
or population-wide 100% recall. Expand it with independently reviewed cases.
"""
import json
from pathlib import Path

from detector.pii_engine import PIIEngine


def main():
    corpus = Path(__file__).parent / "samples" / "pii_benchmark.jsonl"
    tp = fp = fn = 0
    errors = []
    for line in corpus.read_text(encoding="utf-8").splitlines():
        case = json.loads(line)
        expected = {(e["value"], e["entity_type"]) for e in case["expected"]}
        predicted_entities = PIIEngine.detect_in_text(case["text"])
        predicted = {(e.value, e.entity_type) for e in predicted_entities}
        case_tp = expected & predicted
        case_fp = predicted - expected
        case_fn = expected - predicted
        tp += len(case_tp)
        fp += len(case_fp)
        fn += len(case_fn)
        if case_fp or case_fn:
            errors.append({"id": case["id"], "false_positives": sorted(case_fp), "missed": sorted(case_fn)})

    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    print(json.dumps({"cases": sum(1 for _ in corpus.open(encoding="utf-8")), "tp": tp, "fp": fp, "fn": fn,
                      "precision": round(precision, 4), "recall": round(recall, 4), "errors": errors,
                      "scope_note": "Seed benchmark only; does not establish 100% detection."}, indent=2))


if __name__ == "__main__":
    main()
