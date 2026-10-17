"""Public test fixtures only; do not create real review mapping in a Git checkout."""
import copy
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / "tools"))
from prepare_blind_cohort import prepare_review_packets


def fixture():
    return json.loads((BASE / "verification" / "research" /
                       "COHORT_5_PRE_ADMISSION_PUBLIC.json").read_text("utf-8"))


class TestBlindReviewIntake(unittest.TestCase):
    def test_disjoint_reviewer_tokens_and_zero_leak(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "private_blind_review"
            outcome = prepare_review_packets(fixture(), "q" * 48, folder)
            self.assertEqual(outcome["status"], "PREPARED_NOT_SIGNED")
            self.assertEqual(outcome["confirmed_reviewers"], 0)
            left = json.loads((folder / "reviewer_A.json").read_text())
            right = json.loads((folder / "reviewer_B.json").read_text())
            ids_l = {case["blind_id"] for case in left["cases"]}
            ids_r = {case["blind_id"] for case in right["cases"]}
            self.assertEqual(len(ids_l), 5)
            self.assertEqual(len(ids_r), 5)
            self.assertFalse(ids_l & ids_r)
            rendered = json.dumps(left) + json.dumps(right)
            for case in fixture()["candidates"]:
                for secret_field in ("cve_id", "cwe_id", "source_commit", "source_url",
                                     "fix_commit", "native_evidence_url"):
                    value = case.get(secret_field)
                    if value:
                        self.assertNotIn(value, rendered)
            for fragment in ("CVE-", "CWE-", "github.com"):
                self.assertNotIn(fragment, rendered)
            self.assertTrue(all(x["independent_reviewer_signature"] is None
                                for x in left["cases"]))
            private_map = folder / "PRIVATE_DO_NOT_COMMIT_case_mapping.json"
            self.assertEqual(len(json.loads(private_map.read_text())["case_ids"]), 10)
            self.assertEqual(stat.S_IMODE(private_map.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)

    def test_weak_secret_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                prepare_review_packets(fixture(), "short", Path(td) / "private_review")

    def test_premature_gold_review_or_split_rejected(self):
        changes = [
            ("gold_status", "ADMITTED"), ("commercial_rights", "CLEARED"),
            ("independent_review", "HUMAN_PASSED"), ("split", "HOLDOUT"),
            ("training_import", "YES")
        ]
        for field, value in changes:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as td:
                record = copy.deepcopy(fixture())
                record["candidates"][0][field] = value
                with self.assertRaises(ValueError):
                    prepare_review_packets(record, "q" * 48, Path(td) / "private_review")

    def test_refuse_public_output_folder(self):
        with self.assertRaises(ValueError):
            prepare_review_packets(fixture(), "q" * 48, Path("/tmp/public"))

    def test_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "private_review"
            prepare_review_packets(fixture(), "q" * 48, folder)
            with self.assertRaises(ValueError):
                prepare_review_packets(fixture(), "q" * 48, folder)

    def test_missing_or_duplicate_candidates_rejected(self):
        for kind in ("missing", "duplicate"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as td:
                record = copy.deepcopy(fixture())
                if kind == "missing":
                    record["candidates"] = []
                else:
                    record["candidates"][4]["cve_id"] = record["candidates"][0]["cve_id"]
                with self.assertRaises(ValueError):
                    prepare_review_packets(record, "q" * 48, Path(td) / "private_review")


if __name__ == "__main__":
    unittest.main()
