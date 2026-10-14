#!/usr/bin/env python3
"""Owner-hosted candidate-vs-baseline AppSec benchmark on identical blind gold.

Neither this tool nor its tests access a private corpus. Inputs are private,
results are aggregate-only; comparative gains are NOT commercial valuations.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
from pathlib import Path
import sys
from typing import Iterable

# Owner-only, shared strict reader and one-shot sealed reporting.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sealed_evidence import read_jsonl, write_private, public_receipt, safe_ratio

SCORECARD = Path(__file__).resolve().with_name("enterprise_scorecard.py")
spec = importlib.util.spec_from_file_location("ultrasec_scorecard_for_comparison", SCORECARD)
scorecard = importlib.util.module_from_spec(spec)
assert spec is not None and spec.loader is not None
spec.loader.exec_module(scorecard)


def _empty() -> dict:
    return {
        "schema": "ultrasec.enterprise-comparison.v1",
        "scope": "OWNER_HOSTED_BLIND_HOLDOUT_ONLY",
        "certification": "NOT_CERTIFIED",
        "buyer_valuation": "NOT_VERIFIED",
        "comparison_pass": False,
        "criteria": {},
        "candidate": {},
        "baseline": {},
        "delta": {},
        "failures": {},
    }


def compare_to_baseline(
    gold_rows: Iterable[object],
    candidate_rows: Iterable[object],
    baseline_rows: Iterable[object],
    min_recall: float,
    max_fpr: float,
    min_recall_gain: float,
    max_fpr_increase: float,
) -> dict:
    """Compare on one identical, sealed set; return neither rows nor identifiers.

    Difference in FPR/recall alone is insufficient evidence of statistical
    significance or of out-of-distribution generalization. Independent human
    review, holdout custody and uncertainty estimates remain separate gates.
    """
    for value in (min_recall, max_fpr, min_recall_gain, max_fpr_increase):
        if (not isinstance(value, (float, int))
                or isinstance(value, bool) or not math.isfinite(value)
                or value < -1 or value > 1):
            raise ValueError("Comparison criteria must be finite ratios from -1 to 1")
    if not (0 <= min_recall <= 1 and 0 <= max_fpr <= 1):
        raise ValueError("Absolute thresholds must be in [0, 1]")
    if min_recall_gain < 0:
        raise ValueError("Required recall gain must be nonnegative")

    report = _empty()
    report["criteria"] = {
        "min_recall": min_recall,
        "max_fpr": max_fpr,
        "min_recall_gain": min_recall_gain,
        "max_fpr_increase": max_fpr_increase,
        "comparisons": "raw_confusion_counts_not_rounded_metrics",
    }
    # Materialize gold once. Both systems MUST evaluate exactly these same
    # records; missing/extra predictions always block comparison.
    gold = list(gold_rows)
    candidate = scorecard.evaluate_scorecard(
        gold, candidate_rows, min_recall=min_recall, max_fpr=max_fpr)
    baseline = scorecard.evaluate_scorecard(
        gold, baseline_rows, min_recall=min_recall, max_fpr=max_fpr)
    report["candidate"] = candidate
    report["baseline"] = baseline
    failures = {}
    if candidate["failures"] and any(k not in {
        "recall_below_target", "false_positive_rate_above_target"
    } for k in candidate["failures"]):
        failures["candidate_input_invalid"] = 1
    if baseline["failures"] and any(k not in {
        "recall_below_target", "false_positive_rate_above_target"
    } for k in baseline["failures"]):
        failures["baseline_input_invalid"] = 1
    if failures:
        report["failures"] = failures
        return report

    a = candidate["confusion_matrix"]
    b = baseline["confusion_matrix"]
    positive = a["tp"] + a["fn"]
    negative = a["tn"] + a["fp"]
    # Both scorecards compared against the same gold; denominators match.
    recall_gain = (a["tp"] - b["tp"]) / positive
    fpr_increase = (a["fp"] - b["fp"]) / negative
    report["delta"] = {
        "recall": round(recall_gain, 6),
        "false_positive_rate": round(fpr_increase, 6),
        "true_positives": a["tp"] - b["tp"],
        "false_positives": a["fp"] - b["fp"],
    }
    if recall_gain < min_recall_gain:
        failures["insufficient_recall_gain"] = 1
    if fpr_increase > max_fpr_increase:
        failures["excessive_fpr_increase"] = 1
    if not candidate["buyer_thresholds_pass"]:
        failures["candidate_buyer_targets_failed"] = 1
    report["failures"] = failures
    report["comparison_pass"] = not bool(failures)
    return report


def _rows(path: Path):
    yield from read_jsonl(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local aggregate-only AppSec baseline comparison")
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--min-recall", type=float, required=True)
    parser.add_argument("--max-fpr", type=float, required=True)
    parser.add_argument("--min-recall-gain", type=float, required=True)
    parser.add_argument("--max-fpr-increase", type=float, required=True)
    parser.add_argument("--sealed-report", type=Path, required=True)
    parser.add_argument("--session-lock", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = compare_to_baseline(
            _rows(args.gold), _rows(args.candidate), _rows(args.baseline),
            args.min_recall, args.max_fpr, args.min_recall_gain, args.max_fpr_increase)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError):
        result = _empty()
        result["failures"] = {"input_parse_error": 1}
        result["criteria"] = {
            "min_recall": safe_ratio(args.min_recall), "max_fpr": safe_ratio(args.max_fpr),
            "min_recall_gain": safe_ratio(args.min_recall_gain),
            "max_fpr_increase": safe_ratio(args.max_fpr_increase),
            "comparisons": "raw_confusion_counts_not_rounded_metrics",
        }
    try:
        write_private(args.sealed_report, args.session_lock, result)
    except (ValueError, OSError, UnicodeError):
        print('{"status":"RECORDING_FAILED"}')
        return 2
    print(public_receipt())
    return 0


if __name__ == "__main__":
    sys.exit(main())
