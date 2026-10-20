"""TDD regression: repeated source/fix pairs are not independent, even within a split.

Only deterministic synthetic metadata. Does not claim private GOLD verification.
"""
from __future__ import annotations

from copy import deepcopy
import unittest
from test_private_holdout_preflight import fixture, module


class HoldoutDuplicatePairsTests(unittest.TestCase):
    def test_same_source_fix_commits_under_two_train_ids_fail(self):
        rows = fixture()
        rows[1]["source_commit"] = rows[0]["source_commit"]
        rows[1]["fix_commit"] = rows[0]["fix_commit"]
        self.assertIn("duplicate_source_pair", module.preflight(rows, 48, 12)["failures"])

    def test_same_source_fix_contents_under_two_train_ids_fail(self):
        rows = fixture()
        rows[1]["source_sha256"] = rows[0]["source_sha256"]
        rows[1]["fix_sha256"] = rows[0]["fix_sha256"]
        self.assertIn("duplicate_content_pair", module.preflight(rows, 48, 12)["failures"])

    def test_same_pair_inside_validation_is_not_independent(self):
        rows = fixture()
        rows[0]["split"] = rows[1]["split"] = "validation"
        for field in ("source_commit", "fix_commit", "source_sha256", "fix_sha256"):
            rows[1][field] = rows[0][field]
        report = module.preflight(rows, 48, 12)
        self.assertIn("duplicate_source_pair", report["failures"])
        self.assertIn("duplicate_content_pair", report["failures"])

    def test_same_project_different_pairs_are_allowed_inside_train(self):
        rows = fixture()
        rows[1]["project_fingerprint"] = rows[0]["project_fingerprint"]
        self.assertTrue(module.preflight(rows, 48, 12)["metadata_preflight_pass"])

    def test_unchanged_synthetic_fixture_still_passes(self):
        self.assertTrue(module.preflight(fixture(), 48, 12)["metadata_preflight_pass"])


if __name__ == "__main__":
    unittest.main()
