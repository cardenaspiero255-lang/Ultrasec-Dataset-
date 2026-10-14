"""Synthetic regression cases for blinded binary-detection scorecards."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ultrasec-v7/tools/enterprise_scorecard.py"
spec = importlib.util.spec_from_file_location("enterprise_scorecard", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EnterpriseScorecardTests(unittest.TestCase):
    def setUp(self):
        self.gold = [
            {"record_id": "p1", "split": "test", "expected_vulnerable": True},
            {"record_id": "n1", "split": "test", "expected_vulnerable": False},
            {"record_id": "p2", "split": "test", "expected_vulnerable": True},
            {"record_id": "n2", "split": "test", "expected_vulnerable": False},
        ]
        self.pred = [
            {"record_id": "p1", "predicted_vulnerable": True},
            {"record_id": "n1", "predicted_vulnerable": True},
            {"record_id": "p2", "predicted_vulnerable": False},
            {"record_id": "n2", "predicted_vulnerable": False},
        ]

    def failed(self, gold, preds, code):
        report = module.evaluate_scorecard(gold, preds, min_recall=0.5, max_fpr=0.5)
        self.assertFalse(report["buyer_thresholds_pass"])
        self.assertIn(code, report["failures"])
        self.assertEqual(report["certification"], "NOT_CERTIFIED")
        return report

    def test_confusion_metrics_from_blind_holdout(self):
        report = module.evaluate_scorecard(self.gold, self.pred, min_recall=0.5, max_fpr=0.5)
        self.assertTrue(report["buyer_thresholds_pass"])
        self.assertEqual(report["confusion_matrix"], {"tp": 1, "fp": 1, "tn": 1, "fn": 1})
        self.assertEqual(report["metrics"]["precision"], 0.5)
        self.assertEqual(report["metrics"]["recall"], 0.5)
        self.assertEqual(report["metrics"]["f1"], 0.5)
        self.assertEqual(report["metrics"]["false_positive_rate"], 0.5)
        self.assertEqual(report["certification"], "NOT_CERTIFIED")

    def test_thresholds_are_enforced(self):
        report = module.evaluate_scorecard(self.gold, self.pred, min_recall=0.9, max_fpr=0.1)
        self.assertFalse(report["buyer_thresholds_pass"])
        self.assertIn("recall_below_target", report["failures"])
        self.assertIn("false_positive_rate_above_target", report["failures"])

    def test_unexpected_predictions_are_rejected(self):
        self.failed(self.gold, self.pred + [{"record_id": "extra", "predicted_vulnerable": True}], "unknown_prediction")

    def test_missing_prediction_is_rejected(self):
        self.failed(self.gold, self.pred[:-1], "missing_prediction")

    def test_duplicate_prediction_is_rejected(self):
        self.failed(self.gold, self.pred + [dict(self.pred[0])], "duplicate_prediction")

    def test_duplicate_gold_is_rejected(self):
        self.failed(self.gold + [dict(self.gold[0])], self.pred, "duplicate_gold")

    def test_non_test_partition_is_rejected(self):
        rows = [dict(row) for row in self.gold]
        rows[0]["split"] = "train"
        self.failed(rows, self.pred, "unsealed_split")

    def test_missing_positive_or_negative_class_is_rejected(self):
        rows = [dict(row, expected_vulnerable=True) for row in self.gold]
        self.failed(rows, self.pred, "single_class_holdout")

    def test_extra_fields_are_rejected(self):
        preds = [dict(row) for row in self.pred]
        preds[0]["comment"] = "sample"
        self.failed(self.gold, preds, "invalid_prediction_schema")

    def test_aggregate_score_has_no_case_identifiers(self):
        report = module.evaluate_scorecard(self.gold, self.pred, 0.4, 0.7)
        output = json.dumps(report)
        self.assertNotIn("record_id", output)
        self.assertNotIn("p1", output)

    def test_cli_is_fail_closed_for_corrupt_local_gold(self):
        with tempfile.TemporaryDirectory() as d:
            goldfile, predfile = Path(d) / "gold.jsonl", Path(d) / "pred.jsonl"
            goldfile.write_text("invalid json", encoding="utf-8")
            predfile.write_text("".join(json.dumps(row) + "\n" for row in self.pred), encoding="utf-8")
            proc = subprocess.run([sys.executable, str(SCRIPT), "--gold", str(goldfile),
                "--predictions", str(predfile), "--min-recall", "0.5", "--max-fpr", "0.5"],
                capture_output=True, text=True, check=False)
            self.assertNotEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout)["certification"], "NOT_CERTIFIED")
            self.assertIn("input_parse_error", json.loads(proc.stdout)["failures"])


if __name__ == "__main__":
    unittest.main()
