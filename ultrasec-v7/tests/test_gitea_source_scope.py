"""Fail-closed, public-only checks for source-file provenance and license scope."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from gitea_source_scope import check_scope

FILE=ROOT/"verification/research/GITEA_ORIGINAL_FILE_RIGHTS_SCOPE.json"

def fixture():
    return json.loads(FILE.read_text(encoding="utf-8"))

class GiteaOriginalScopeTest(unittest.TestCase):
    def test_six_original_changed_files_and_three_runtime_documents(self):
        result=check_scope(fixture())
        self.assertEqual(result["errors"],[])
        self.assertEqual(result["changed_files"],6)
        self.assertEqual(result["runtime_files"],3)
        self.assertEqual(result["verified_git_blob_ids"],18)
        self.assertEqual(result["reproducible_pair_gold"],0)
        self.assertEqual(result["commercial_distribution_authorized"],False)
        self.assertEqual(result["certification"],"NOT_CERTIFIED")

    def test_upstream_sha_is_immutable_and_correct(self):
        data=fixture()
        data["parent_commit"]="0"*40
        self.assertIn("unexpected_original_commit",check_scope(data)["errors"])

    def test_changed_file_blob_cannot_match_before_and_after(self):
        data=fixture()
        data["changed_files"][0]["fixed_git_blob"]=data["changed_files"][0]["vulnerable_git_blob"]
        self.assertIn("unchanged_in_fix",check_scope(data)["errors"])

    def test_missing_file_or_extra_file_is_rejected(self):
        data=fixture()
        data["changed_files"].pop()
        self.assertIn("changed_file_list_mismatch",check_scope(data)["errors"])

    def test_disguised_license_claim_is_rejected(self):
        data=fixture()
        data["changed_files"][4]["file_level_rights_cleared"]=True
        self.assertIn("unsupported_license_clearance",check_scope(data)["errors"])

    def test_commercial_rights_cannot_be_claimed_from_mit_header(self):
        data=fixture()
        data["commercial_distribution_authorized"]=True
        self.assertIn("unsupported_license_clearance",check_scope(data)["errors"])

    def test_no_bundle_can_include_original_source_yet(self):
        data=fixture()
        data["packaged_source_paths"]=["services/release/release.go"]
        self.assertIn("premature_source_packaging",check_scope(data)["errors"])

    def test_go_module_and_license_blobs_must_match_before_after(self):
        data=fixture()
        data["runtime_files"][1]["fixed_git_blob"]="0"*40
        self.assertIn("unexpected_runtime_blob",check_scope(data)["errors"])

    def test_template_not_falsely_spdx_verified(self):
        data=fixture()
        data["changed_files"][4]["observed_spdx"]="MIT"
        self.assertIn("file_header_unverified",check_scope(data)["errors"])

    def test_test_provenance_is_not_cleared_as_independent_holdout(self):
        data=fixture()
        data["test_source_derived_from_fix"]=False
        self.assertIn("witness_provenance_mismatch",check_scope(data)["errors"])

if __name__=="__main__":
    unittest.main()
