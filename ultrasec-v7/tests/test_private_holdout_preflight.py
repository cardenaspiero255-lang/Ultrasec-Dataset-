"""Unit tests for a PRIVATE, metadata-only benchmark preflight. Never certify labels."""
from __future__ import annotations
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "private_holdout_preflight.py"
spec = importlib.util.spec_from_file_location("private_holdout_preflight", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

CWES = ("CWE-79","CWE-89","CWE-352","CWE-862","CWE-787","CWE-22",
        "CWE-416","CWE-125","CWE-78","CWE-94","CWE-120","CWE-434")


def fixture():
    rows = []
    for i in range(48):
        rows.append({
            "case_id": f"case-{i:03}",
            "cve_id": f"CVE-2025-{10000+i}",
            "project_fingerprint": hashlib.sha256(f"project-{i}".encode()).hexdigest(),
            "mechanism_fingerprint": hashlib.sha256(f"mechanism-{i}".encode()).hexdigest(),
            "source_commit": hashlib.sha1(f"before-{i}".encode()).hexdigest(),
            "fix_commit": hashlib.sha1(f"after-{i}".encode()).hexdigest(),
            "source_sha256": hashlib.sha256(f"before-content-{i}".encode()).hexdigest(),
            "fix_sha256": hashlib.sha256(f"after-content-{i}".encode()).hexdigest(),
            "cwe_id": CWES[i//4],
            "vulnerable": i % 2 == 0,
            "split": "test" if i % 4 >= 2 else "train",
            "oracle_type": "ORIGINAL_RED_GREEN_TEST",
            "oracle_run_sha256": hashlib.sha256(f"log-{i}".encode()).hexdigest(),
            "rule_pre_registered": True,
            "scanner_output_sha256": hashlib.sha256(f"scanner-{i}".encode()).hexdigest(),
        })
    return rows


class PrivateHoldoutPreflightTests(unittest.TestCase):
    def test_valid_metadata_is_not_gold_or_certification(self):
        report = module.preflight(fixture(), minimum_cases=48, minimum_cwes=12)
        self.assertTrue(report["metadata_preflight_pass"])
        self.assertEqual(report["certification"], "NOT_CERTIFIED")
        self.assertEqual(report["gold_independently_verified"], False)
        self.assertEqual(report["real_scanner_execution_verified"], False)
        self.assertNotIn("case-000", str(report))
        self.assertEqual(report["metrics"]["test"], 24)

    def test_missing_negative_control_for_cwe_is_rejected(self):
        rows = fixture()
        rows[3]["vulnerable"] = True
        self.assertIn("cwe_without_both_classes", module.preflight(rows,48,12)["failures"])

    def test_cross_split_project_alias_hash_is_rejected(self):
        rows = fixture()
        rows[2]["project_fingerprint"] = rows[0]["project_fingerprint"]
        self.assertIn("project_split_leakage", module.preflight(rows,48,12)["failures"])

    def test_cross_split_same_cve_with_different_project_is_rejected(self):
        rows = fixture()
        rows[2]["cve_id"] = rows[0]["cve_id"]
        self.assertIn("cve_split_leakage", module.preflight(rows,48,12)["failures"])

    def test_cross_split_content_reuse_is_rejected(self):
        rows = fixture()
        rows[2]["source_sha256"] = rows[0]["fix_sha256"]
        self.assertIn("source_content_split_leakage", module.preflight(rows,48,12)["failures"])

    def test_reused_origin_inside_test_is_not_independent(self):
        rows = fixture()
        rows[6]["project_fingerprint"] = rows[2]["project_fingerprint"]
        self.assertIn("duplicate_test_origin", module.preflight(rows,48,12)["failures"])

    def test_same_original_commit_cannot_reappear_in_test_as_new_case(self):
        rows = fixture()
        rows[6]["source_commit"] = rows[2]["fix_commit"]
        self.assertIn("duplicate_test_source_commit", module.preflight(rows,48,12)["failures"])

    def test_posthoc_rule_cannot_enter_blind_benchmark(self):
        rows = fixture()
        rows[0]["rule_pre_registered"] = False
        self.assertIn("posthoc_or_unknown_rule", module.preflight(rows,48,12)["failures"])

    def test_missing_original_test_witness_is_rejected(self):
        rows = fixture()
        rows[1]["oracle_type"] = "AI_GUESSED_LABEL"
        self.assertIn("unverified_oracle_kind", module.preflight(rows,48,12)["failures"])

    def test_unassigned_split_blocks_preflight(self):
        rows = fixture()
        rows[3]["split"] = "UNASSIGNED"
        self.assertIn("unassigned_or_invalid_split", module.preflight(rows,48,12)["failures"])

    def test_no_real_data_blocks_preflight(self):
        r = module.preflight([],48,12)
        self.assertFalse(r["metadata_preflight_pass"])
        self.assertEqual(r["metrics"]["cases"],0)
        self.assertIn("insufficient_cases",r["failures"])

    def test_bogus_digest_blocks_preflight(self):
        rows = fixture()
        rows[2]["oracle_run_sha256"] = "0"*16
        self.assertIn("invalid_record", module.preflight(rows,48,12)["failures"])


if __name__ == "__main__":
    unittest.main()
