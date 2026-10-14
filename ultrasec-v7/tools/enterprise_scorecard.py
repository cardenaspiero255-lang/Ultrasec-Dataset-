#!/usr/bin/env python3
"""Owner-hosted blind binary-detection scorecard. Does not certify private data.

Keep hidden ground truth and model predictions off public CI. Output only
aggregate confusion counts and buyer-selected threshold results.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path
import re
import sys
from typing import Iterable

# Owner-only, shared strict reader and one-shot sealed reporting.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sealed_evidence import read_jsonl, write_private, public_receipt

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
GOLD_FIELDS = frozenset({"record_id", "split", "expected_vulnerable"})
PRED_FIELDS = frozenset({"record_id", "predicted_vulnerable"})


def _report() -> dict:
    return {
        "schema": "ultrasec.blind-detection-scorecard.v1",
        "scope": "OWNER_HOSTED_BLIND_HOLDOUT_ONLY",
        "certification": "NOT_CERTIFIED",
        "external_audit": "NOT_VERIFIED",
        "buyer_thresholds_pass": False,
        "confusion_matrix": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
        "metrics": {},
        "failures": {},
    }


def _valid_row(row: object, fields: frozenset[str], truth_name: str) -> bool:
    return (
        isinstance(row, dict)
        and set(row) == fields
        and isinstance(row["record_id"], str)
        and bool(IDENTIFIER.fullmatch(row["record_id"]))
        and type(row[truth_name]) is bool
        and (fields != GOLD_FIELDS or row["split"] in ("train", "validation", "test"))
    )


def evaluate_scorecard(gold_rows: Iterable[object], prediction_rows: Iterable[object],
                       min_recall: float, max_fpr: float) -> dict:
    """No raw records or identifiers are returned, even on invalid input."""
    if not (isinstance(min_recall, (int, float)) and not isinstance(min_recall, bool)
            and math.isfinite(min_recall) and 0 <= min_recall <= 1
            and isinstance(max_fpr, (int, float)) and not isinstance(max_fpr, bool)
            and math.isfinite(max_fpr) and 0 <= max_fpr <= 1):
        raise ValueError("Buyer thresholds must be finite ratios between zero and one")

    failures: Counter[str] = Counter()
    gold: dict[str, bool] = {}
    pred: dict[str, bool] = {}

    for row in gold_rows:
        if not _valid_row(row, GOLD_FIELDS, "expected_vulnerable"):
            failures["invalid_gold_schema"] += 1
            continue
        rid = row["record_id"]
        if rid in gold:
            failures["duplicate_gold"] += 1
        else:
            gold[rid] = row["expected_vulnerable"]
        if row["split"] != "test":
            failures["unsealed_split"] += 1

    for row in prediction_rows:
        if not _valid_row(row, PRED_FIELDS, "predicted_vulnerable"):
            failures["invalid_prediction_schema"] += 1
            continue
        rid = row["record_id"]
        if rid in pred:
            failures["duplicate_prediction"] += 1
        else:
            pred[rid] = row["predicted_vulnerable"]

    if not gold:
        failures["empty_holdout"] += 1
    if gold and (not any(gold.values()) or all(gold.values())):
        failures["single_class_holdout"] += 1
    missing = len(gold.keys() - pred.keys())
    unknown = len(pred.keys() - gold.keys())
    if missing:
        failures["missing_prediction"] += missing
    if unknown:
        failures["unknown_prediction"] += unknown

    report = _report()
    report["buyer_thresholds"] = {"min_recall": min_recall, "max_fpr": max_fpr}
    report["threshold_comparison"] = "raw_rates_inclusive"
    if failures:
        report["failures"] = dict(sorted((key, n) for key, n in failures.items() if n))
        return report

    counts = Counter()
    for rid, truth in gold.items():
        guess = pred[rid]
        if truth:
            counts["tp" if guess else "fn"] += 1
        else:
            counts["fp" if guess else "tn"] += 1

    tp, fp, tn, fn = (counts[key] for key in ("tp", "fp", "tn", "fn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn)
    specificity = tn / (tn + fp)
    fpr = fp / (tn + fp)
    f1 = (2 * precision * recall / (precision + recall)
          if precision + recall else 0.0)

    report["confusion_matrix"] = {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
    report["metrics"] = {
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "specificity": round(specificity, 6),
        "false_positive_rate": round(fpr, 6),
        "false_negative_rate": round(1 - recall, 6),
        "balanced_accuracy": round((recall + specificity) / 2, 6),
    }
    if recall < min_recall:
        failures["recall_below_target"] += 1
    if fpr > max_fpr:
        failures["false_positive_rate_above_target"] += 1
    report["failures"] = dict(sorted(failures.items()))
    report["buyer_thresholds_pass"] = not bool(failures)
    return report


def _rows(path: Path):
    yield from read_jsonl(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local blind holdout scorer (never uploads data)")
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--min-recall", type=float, required=True)
    parser.add_argument("--max-fpr", type=float, required=True)
    parser.add_argument("--sealed-report", type=Path, required=True)
    parser.add_argument("--session-lock", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = evaluate_scorecard(_rows(args.gold), _rows(args.predictions),
                                    args.min_recall, args.max_fpr)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError):
        report = _report()
        report["failures"] = {"input_parse_error": 1}
        report["buyer_thresholds"] = {"min_recall": args.min_recall, "max_fpr": args.max_fpr}
        report["threshold_comparison"] = "raw_rates_inclusive"
    try:
        write_private(args.sealed_report, args.session_lock, report)
    except (ValueError, OSError, UnicodeError):
        print('{"status":"RECORDING_FAILED"}')
        return 2
    print(public_receipt())
    return 0


if __name__ == "__main__":
    sys.exit(main())
