"""Regression tests for the enterprise metadata-only QA tool (synthetic inputs)."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ultrasec-v7/tools/enterprise_metadata.py"
spec = importlib.util.spec_from_file_location("enterprise_metadata", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def pair(name, split="train", project=None, mechanism=None):
    return [{
        "schema_version": 1,
        "record_id": name + "-" + variant,
        "pair_id": name,
        "variant": variant,
        "cwe_id": "CWE-89",
        "language": "python",
        "mechanism_id": mechanism or "mechanism-" + name,
        "project_id": project or "project-" + name,
        "split": split,
        "content_sha256": hashlib.sha256((name + variant).encode()).hexdigest(),
        "rights_status": "cleared",
    } for variant in ("vulnerable", "fixed")]


class EnterpriseMetadataTests(unittest.TestCase):
    def setUp(self):
        self.rows = pair("alpha") + pair("beta", split="test")

    def check_issue(self, rows, code, records=4, mechanisms=2):
        report = module.evaluate_records(rows, records, mechanisms)
        self.assertFalse(report["metadata_screening_pass"])
        self.assertIn(code, report["failures"])
        self.assertEqual(report["certification"], "NOT_CERTIFIED")
        return report

    def test_valid_metadata_is_not_a_certification(self):
        report = module.evaluate_records(self.rows, 4, 2)
        self.assertTrue(report["metadata_screening_pass"])
        self.assertEqual(report["certification"], "NOT_CERTIFIED")
        self.assertEqual(report["metrics"]["complete_pairs"], 2)
        self.assertEqual(report["metrics"]["mechanisms"], 2)

    def test_duplicate_id_is_rejected(self):
        self.check_issue(self.rows + [dict(self.rows[0])], "duplicate_record_id")

    def test_duplicate_sha256_is_rejected(self):
        rows = [dict(row) for row in self.rows]
        rows[2]["content_sha256"] = rows[0]["content_sha256"]
        self.check_issue(rows, "duplicate_content_hash")

    def test_missing_mitigation_is_rejected(self):
        self.check_issue(self.rows[:-1], "incomplete_pair")

    def test_pair_metadata_mismatch_is_rejected(self):
        rows = [dict(row) for row in self.rows]
        rows[1]["cwe_id"] = "CWE-78"
        self.check_issue(rows, "pair_metadata_mismatch")

    def test_project_split_leakage_is_rejected(self):
        rows = pair("alpha", project="shared") + pair("beta", split="test", project="shared")
        self.check_issue(rows, "project_split_leakage")

    def test_mechanism_split_leakage_is_rejected(self):
        rows = pair("alpha", mechanism="shared") + pair("beta", split="test", mechanism="shared")
        self.check_issue(rows, "mechanism_split_leakage")

    def test_unknown_metadata_fields_are_rejected(self):
        rows = [dict(row) for row in self.rows]
        rows[0]["extra_content"] = "sample"
        self.check_issue(rows, "invalid_schema")

    def test_malformed_hash_is_rejected(self):
        rows = [dict(row) for row in self.rows]
        rows[0]["content_sha256"] = "invalid"
        self.check_issue(rows, "invalid_field")

    def test_uncleared_rights_fail(self):
        rows = [dict(row) for row in self.rows]
        rows[0]["rights_status"] = "pending"
        self.check_issue(rows, "rights_not_cleared")

    def test_empty_input_fails_closed(self):
        self.check_issue([], "empty_input")

    def test_commercial_targets_are_not_automatically_claimed(self):
        report = self.check_issue(self.rows, "insufficient_records", records=1000000, mechanisms=500)
        self.assertIn("insufficient_mechanisms", report["failures"])

    def test_report_has_aggregates_not_record_ids(self):
        report = module.evaluate_records(pair("example") + pair("second", split="test"), 4, 2)
        output = json.dumps(report)
        self.assertNotIn("example-", output)
        self.assertNotIn("project-example", output)
        self.assertNotIn("content_sha256", output)

    def test_cli_rejects_bad_input_without_echoing_lines(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "input.jsonl"
            path.write_text("unexpected input row", encoding="utf-8")
            proc = subprocess.run([sys.executable, str(SCRIPT), "--input", str(path),
                "--minimum-records", "4", "--minimum-mechanisms", "2",
                "--sealed-report", str(Path(d) / "evidence.json"),
                "--session-lock", str(Path(d) / "session.lock")],
                text=True, capture_output=True, check=False)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout), {"status": "SEALED"})
            report = json.loads((Path(d) / "evidence.json").read_text())
            self.assertEqual(report["certification"], "NOT_CERTIFIED")
            self.assertIn("input_parse_error", report["failures"])
            self.assertNotIn("unexpected input row", proc.stdout + proc.stderr)

    def test_cli_accepts_local_synthetic_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "input.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in self.rows), encoding="utf-8")
            proc = subprocess.run([sys.executable, str(SCRIPT), "--input", str(path),
                "--minimum-records", "4", "--minimum-mechanisms", "2",
                "--sealed-report", str(Path(d) / "evidence.json"),
                "--session-lock", str(Path(d) / "session.lock")],
                text=True, capture_output=True, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout), {"status": "SEALED"})
            self.assertTrue(json.loads((Path(d) / "evidence.json").read_text())["metadata_screening_pass"])


if __name__ == "__main__":
    unittest.main()
