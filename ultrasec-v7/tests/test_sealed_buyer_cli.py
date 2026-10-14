"""A sealed buyer holdout must never become an adaptive label oracle."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "ultrasec-v7" / "tools"


class SealedCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.gold = self._jsonl("gold", [
            {"record_id": "case-pos", "split": "test", "expected_vulnerable": True},
            {"record_id": "case-neg", "split": "test", "expected_vulnerable": False},
        ])
        self.candidate = self._jsonl("candidate", [
            {"record_id": "case-pos", "predicted_vulnerable": True},
            {"record_id": "case-neg", "predicted_vulnerable": False},
        ])
        self.baseline = self._jsonl("baseline", [
            {"record_id": "case-pos", "predicted_vulnerable": False},
            {"record_id": "case-neg", "predicted_vulnerable": False},
        ])
        self.metadata = self._jsonl("metadata", [
            {"schema_version": 1, "record_id": str(i), "pair_id": "one",
             "variant": variant, "cwe_id": "CWE-89", "language": "python",
             "mechanism_id": "m1", "project_id": "p1", "split": "test",
             "content_sha256": format(i+1, "064x"), "rights_status": "cleared"}
            for i, variant in enumerate(("vulnerable", "fixed"))
        ])

    def _jsonl(self, name, rows):
        path = self.root / (name + ".jsonl")
        path.write_text("".join(json.dumps(item) + "\n" for item in rows), encoding="utf-8")
        return path

    def _run(self, command, extra=()):
        return subprocess.run([sys.executable, str(TOOLS / command), *extra],
                              text=True, capture_output=True, check=False)

    def _sealed(self, name, arglist, lock=None, report=None):
        lock = lock or self.root / (name + ".lock")
        report = report or self.root / (name + ".report.json")
        proc = self._run(name, [*arglist, "--sealed-report", str(report),
                                "--session-lock", str(lock)])
        return proc, report, lock

    def test_scorecard_keeps_confusion_matrix_off_stdout(self):
        proc, path, lock = self._sealed("enterprise_scorecard.py",
            ["--gold", str(self.gold), "--predictions", str(self.candidate),
             "--min-recall", "0.8", "--max-fpr", "0.25"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), {"status": "SEALED"})
        self.assertNotIn("confusion_matrix", proc.stdout)
        self.assertEqual(json.loads(path.read_text())["confusion_matrix"]["tp"], 1)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

    def test_comparison_keeps_scores_and_criteria_off_stdout(self):
        proc, path, _ = self._sealed("enterprise_comparison.py",
            ["--gold", str(self.gold), "--candidate", str(self.candidate),
             "--baseline", str(self.baseline), "--min-recall", "0.8",
             "--max-fpr", "0.25", "--min-recall-gain", "0.0", "--max-fpr-increase", "0"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), {"status": "SEALED"})
        report = json.loads(path.read_text())
        self.assertEqual(report["delta"]["recall"], 1.0)
        self.assertNotIn("candidate", proc.stdout)

    def test_failed_score_is_indistinguishable_to_candidate(self):
        proc, path, _ = self._sealed("enterprise_scorecard.py",
            ["--gold", str(self.gold), "--predictions", str(self.candidate),
             "--min-recall", "1", "--max-fpr", "0"])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout), {"status": "SEALED"})
        self.assertTrue(path.is_file())

    def test_invalid_json_does_not_echo_and_retains_thresholds_in_sealed_report(self):
        self.gold.write_text("invalid-private-record", encoding="utf-8")
        proc, path, _ = self._sealed("enterprise_scorecard.py",
            ["--gold", str(self.gold), "--predictions", str(self.candidate),
             "--min-recall", ".75", "--max-fpr", ".25"])
        self.assertEqual(json.loads(proc.stdout), {"status": "SEALED"})
        report = json.loads(path.read_text())
        self.assertEqual(report["buyer_thresholds"], {"min_recall": 0.75, "max_fpr": 0.25})
        self.assertEqual(report["threshold_comparison"], "raw_rates_inclusive")
        self.assertIn("input_parse_error", report["failures"])
        self.assertNotIn("invalid-private-record", proc.stdout + proc.stderr)

    def test_comparison_parse_failure_retains_all_criteria(self):
        self.candidate.write_text("invalid-private-record", encoding="utf-8")
        proc, path, _ = self._sealed("enterprise_comparison.py",
            ["--gold", str(self.gold), "--candidate", str(self.candidate),
             "--baseline", str(self.baseline), "--min-recall", ".75",
             "--max-fpr", ".25", "--min-recall-gain", ".1",
             "--max-fpr-increase", "0"])
        self.assertEqual(json.loads(proc.stdout), {"status": "SEALED"})
        report = json.loads(path.read_text())
        self.assertEqual(report["criteria"]["min_recall_gain"], .1)
        self.assertIn("input_parse_error", report["failures"])

    def test_duplicate_json_property_fails_closed_in_all_readers(self):
        bad = '{"record_id":"fake","record_id":"case-pos","split":"test","expected_vulnerable":true}\n'
        self.gold.write_text(bad, encoding="utf-8")
        for command, args in [
            ("enterprise_scorecard.py", ["--gold", str(self.gold),
             "--predictions", str(self.candidate), "--min-recall", ".8", "--max-fpr", ".25"]),
            ("enterprise_comparison.py", ["--gold", str(self.gold), "--candidate", str(self.candidate),
             "--baseline", str(self.baseline), "--min-recall", ".8", "--max-fpr", ".25",
             "--min-recall-gain", ".1", "--max-fpr-increase", "0"]),
        ]:
            proc, path, _ = self._sealed(command, args)
            self.assertEqual(json.loads(proc.stdout), {"status": "SEALED"})
            self.assertIn("input_parse_error", json.loads(path.read_text())["failures"])

        self.metadata.write_text('{"record_id":"a","record_id":"b"}\n', encoding="utf-8")
        proc, path, _ = self._sealed("enterprise_metadata.py",
            ["--input", str(self.metadata), "--minimum-records", "2", "--minimum-mechanisms", "1"])
        self.assertEqual(json.loads(proc.stdout), {"status": "SEALED"})
        self.assertIn("input_parse_error", json.loads(path.read_text())["failures"])

    def test_session_lock_prevents_adaptive_replay(self):
        args = ["--gold", str(self.gold), "--predictions", str(self.candidate),
                "--min-recall", "0", "--max-fpr", "1"]
        proc, path, lock = self._sealed("enterprise_scorecard.py", args)
        self.assertEqual(proc.returncode, 0)
        previous = path.read_bytes()
        again, _, _ = self._sealed("enterprise_scorecard.py", args, lock=lock, report=path)
        self.assertNotEqual(again.returncode, 0)
        self.assertNotIn("confusion_matrix", again.stdout + again.stderr)
        self.assertEqual(path.read_bytes(), previous)

    def test_unsealed_run_is_rejected(self):
        proc = self._run("enterprise_scorecard.py", [
            "--gold", str(self.gold), "--predictions", str(self.candidate),
            "--min-recall", "0", "--max-fpr", "1"])
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("confusion_matrix", proc.stdout + proc.stderr)

    def test_reports_cannot_be_overwritten(self):
        args = ["--gold", str(self.gold), "--predictions", str(self.candidate),
                "--min-recall", "0", "--max-fpr", "1"]
        report = self.root / "preexisting.json"
        report.write_text("KEEP", encoding="utf-8")
        proc, _, _ = self._sealed("enterprise_scorecard.py", args, report=report)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(report.read_text(), "KEEP")

    def test_negative_required_gain_is_rejected(self):
        proc, path, _ = self._sealed("enterprise_comparison.py", [
            "--gold", str(self.gold), "--candidate", str(self.candidate),
            "--baseline", str(self.baseline), "--min-recall", ".5",
            "--max-fpr", ".5", "--min-recall-gain", "-.2", "--max-fpr-increase", "0"])
        self.assertEqual(json.loads(proc.stdout), {"status": "SEALED"})
        self.assertIn("input_parse_error", json.loads(path.read_text())["failures"])


if __name__ == "__main__":
    unittest.main()
