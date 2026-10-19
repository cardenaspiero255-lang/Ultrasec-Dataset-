"""TDD contracts: an exact public-metadata delivery proposal is not commercial clearance."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("delivery_scope_manifest",ROOT/"tools"/"delivery_scope_manifest.py")
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
MANIFEST=ROOT/"verification"/"research"/"DELIVERY_SCOPE_PUBLIC_METADATA_DRAFT.json"


class DeliveryScopeTests(unittest.TestCase):
    def setUp(self):
        self.doc=json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_exact_files_and_blobs_in_original_repository(self):
        result=mod.inspect(self.doc, ROOT)
        self.assertTrue(result["metadata_inventory_integrity_pass"])
        self.assertEqual(result["manifested_files"],5)
        self.assertEqual(result["rights_verified"],0)
        self.assertFalse(result["commercial_release_ready"])
        self.assertEqual(result["commercial_rights"],"NOT_VERIFIED")
        self.assertEqual(result["source_distribution_allowed"],False)
        self.assertEqual(len(result["files"]),5)
        self.assertTrue(all(len(f["sha256"])==64 for f in result["files"]))

    def test_sha256_checks_exact_disk_bytes_independent_of_git_object_id(self):
        report=mod.inspect(self.doc,ROOT)
        for entry in report["files"]:
            payload=(ROOT/entry["path"]).read_bytes()
            self.assertEqual(entry["sha256"],hashlib.sha256(payload).hexdigest())

    def test_changes_to_listed_file_fail_integrity(self):
        wrong=deepcopy(self.doc)
        wrong["files"][0]["git_blob_sha1"]="0"*40
        result=mod.inspect(wrong,ROOT)
        self.assertFalse(result["metadata_inventory_integrity_pass"])
        self.assertIn("source_blob_mismatch",result["failures"])

    def test_unlisted_source_file_fails_safe(self):
        wrong=deepcopy(self.doc)
        wrong["files"].append({"path":"tools/adversarial_sast.py","git_blob_sha1":"0"*40,"rights_status":"NOT_VERIFIED","contains_upstream_source":False})
        result=mod.inspect(wrong,ROOT)
        self.assertIn("invalid_distribution_file_path",result["failures"])
        self.assertFalse(result["commercial_release_ready"])

    def test_false_legal_clearance_is_rejected(self):
        wrong=deepcopy(self.doc)
        wrong["files"][0]["rights_status"]="CLEARED"
        result=mod.inspect(wrong,ROOT)
        self.assertIn("unsupported_commercial_rights_claim",result["failures"])

    def test_traversal_and_absolute_path_rejected(self):
        for name in ["../../outside.txt","/tmp/secret.json","verification/research/../../LICENSE-PROPRIETARY.txt"]:
            wrong=deepcopy(self.doc)
            wrong["files"][0]["path"]=name
            with self.subTest(name=name):
                self.assertIn("invalid_distribution_file_path",mod.inspect(wrong,ROOT)["failures"])

    def test_duplicate_path_or_blob_not_accepted(self):
        wrong=deepcopy(self.doc)
        wrong["files"][1]=dict(wrong["files"][0])
        self.assertIn("duplicate_distribution_file",mod.inspect(wrong,ROOT)["failures"])

    def test_adding_synthetic_gold_or_a_private_holdout_disables_readiness(self):
        wrong=deepcopy(self.doc)
        wrong["includes_gold_or_holdout"]=True
        self.assertIn("invalid_private_corpus_claim",mod.inspect(wrong,ROOT)["failures"])

    def test_distribution_other_than_metadata_is_not_implicitly_covered(self):
        wrong=deepcopy(self.doc)
        wrong["delivery_mode"]="full_source_pairs"
        result=mod.inspect(wrong,ROOT)
        self.assertFalse(result["metadata_inventory_integrity_pass"])
        self.assertIn("unsupported_distribution_mode",result["failures"])


if __name__=="__main__":
    unittest.main()
