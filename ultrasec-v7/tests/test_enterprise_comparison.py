"""Buyer-vendor comparison tests use fabricated cases and never export case identifiers."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ultrasec-v7" / "tools" / "enterprise_comparison.py"
spec = importlib.util.spec_from_file_location("enterprise_comparison", SCRIPT)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.gold = [
            {"record_id": "v1", "split": "test", "expected_vulnerable": True},
            {"record_id": "v2", "split": "test", "expected_vulnerable": True},
            {"record_id": "n1", "split": "test", "expected_vulnerable": False},
            {"record_id": "n2", "split": "test", "expected_vulnerable": False},
        ]
        self.candidate = [
            {"record_id": "v1", "predicted_vulnerable": True},
            {"record_id": "v2", "predicted_vulnerable": True},
            {"record_id": "n1", "predicted_vulnerable": False},
            {"record_id": "n2", "predicted_vulnerable": False},
        ]
        self.baseline = [
            {"record_id": "v1", "predicted_vulnerable": True},
            {"record_id": "v2", "predicted_vulnerable": False},
            {"record_id": "n1", "predicted_vulnerable": True},
            {"record_id": "n2", "predicted_vulnerable": False},
        ]

    def compare(self, baseline=None, candidate=None):
        return checker.compare_to_baseline(
            self.gold, candidate if candidate is not None else self.candidate,
            baseline if baseline is not None else self.baseline,
            min_recall=0.75, max_fpr=0.25, min_recall_gain=0.1,
            max_fpr_increase=0.0)

    def test_improvement_is_measured_on_identical_holdout(self):
        report = self.compare()
        self.assertTrue(report["comparison_pass"])
        self.assertEqual(report["candidate"]["confusion_matrix"], {"tp": 2, "fp": 0, "tn": 2, "fn": 0})
        self.assertEqual(report["baseline"]["confusion_matrix"], {"tp": 1, "fp": 1, "tn": 1, "fn": 1})
        self.assertEqual(report["delta"]["recall"], 0.5)
        self.assertEqual(report["delta"]["false_positive_rate"], -0.5)
        self.assertEqual(report["delta"]["true_positives"], 1)
        self.assertEqual(report["delta"]["false_positives"], -1)
        self.assertEqual(report["criteria"]["min_recall_gain"], 0.1)
        self.assertEqual(report["certification"], "NOT_CERTIFIED")

    def test_failing_baseline_is_comparable(self):
        report = self.compare()
        self.assertFalse(report["baseline"]["buyer_thresholds_pass"])
        self.assertTrue(report["comparison_pass"])

    def test_missing_candidate_prediction_blocks_comparison(self):
        report = self.compare(candidate=self.candidate[:-1])
        self.assertFalse(report["comparison_pass"])
        self.assertIn("candidate_input_invalid", report["failures"])
        self.assertEqual(report["delta"], {})

    def test_missing_baseline_prediction_blocks_comparison(self):
        report = self.compare(baseline=self.baseline[:-1])
        self.assertFalse(report["comparison_pass"])
        self.assertIn("baseline_input_invalid", report["failures"])

    def test_no_statistical_or_valuation_claims(self):
        output = json.dumps(self.compare())
        self.assertNotIn("record_id", output)
        self.assertNotIn('"v1"', output)
        self.assertNotIn("150000", output)
        self.assertEqual(self.compare()["certification"], "NOT_CERTIFIED")

    def test_deterioration_cannot_pass(self):
        report = self.compare(baseline=self.candidate, candidate=self.baseline)
        self.assertFalse(report["comparison_pass"])
        self.assertIn("insufficient_recall_gain", report["failures"])
        self.assertIn("excessive_fpr_increase", report["failures"])

    def test_equal_performance_fails_positive_gain_target(self):
        report = self.compare(baseline=self.candidate)
        self.assertFalse(report["comparison_pass"])
        self.assertIn("insufficient_recall_gain", report["failures"])

    def test_reject_invalid_economic_or_statistical_criteria(self):
        with self.assertRaises(ValueError):
            checker.compare_to_baseline(self.gold, self.candidate, self.baseline,
                                       0.8, 0.1, float("nan"), 0.0)

    def test_negative_recall_gain_cannot_certify_regression(self):
        with self.assertRaises(ValueError):
            checker.compare_to_baseline(
                self.gold, self.baseline, self.candidate,
                min_recall=0.5, max_fpr=0.5, min_recall_gain=-0.2,
                max_fpr_increase=0.0)

    def test_cli_is_local_and_fails_closed_on_corrupt_prediction(self):
        with tempfile.TemporaryDirectory() as d:
            paths = [Path(d) / name for name in ("gold.jsonl", "candidate.jsonl", "baseline.jsonl")]
            for path, records in zip(paths, (self.gold, self.candidate, self.baseline)):
                path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
            paths[1].write_text("invalid-local-data\n", encoding="utf-8")
            proc = subprocess.run([
                sys.executable, str(SCRIPT), "--gold", str(paths[0]),
                "--candidate", str(paths[1]), "--baseline", str(paths[2]),
                "--min-recall", "0.75", "--max-fpr", "0.25",
                "--min-recall-gain", "0.1", "--max-fpr-increase", "0",
                "--sealed-report", str(Path(d) / "evidence.json"),
                "--session-lock", str(Path(d) / "session.lock")],
                text=True, capture_output=True, check=False)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout), {"status": "SEALED"})
            self.assertNotIn("invalid-local-data", proc.stdout + proc.stderr)
            self.assertIn("input_parse_error", json.loads((Path(d) / "evidence.json").read_text())["failures"])


if __name__ == "__main__":
    unittest.main()
