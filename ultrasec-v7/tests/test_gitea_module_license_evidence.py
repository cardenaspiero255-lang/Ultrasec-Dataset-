"""Unit tests for observed license files, not an automatic legal opinion."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"tools"))
from gitea_module_license_evidence import collect_license_evidence


class GiteaModuleLicenseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache = Path(self.temp.name) / "pkg" / "mod"
        self.cache.mkdir(parents=True)
        self.module = self.cache / "example.org" / "original@v1.0.0"
        self.module.mkdir(parents=True)
        self.closure = {"external_modules":[{"path":"example.org/original","version":"v1.0.0"}]}
        self.pkgs = [{
            "ImportPath":"example.org/original/part",
            "Module":{"Path":"example.org/original","Version":"v1.0.0","Dir":str(self.module)}
        }]

    def test_original_license_file_receipt_is_not_legal_clearance(self):
        license_data=b"Copyright Original Authors\nMIT License\n"
        (self.module/"LICENSE").write_bytes(license_data)
        r = collect_license_evidence(self.pkgs, self.closure, self.cache)
        self.assertEqual(r["external_modules_examined"],1)
        self.assertEqual(r["modules_with_license_files"],1)
        self.assertEqual(r["modules_without_root_license_files"],0)
        self.assertEqual(r["license_files_observed"],1)
        item=r["modules"][0]
        self.assertEqual(item["license_files"][0]["sha256"],hashlib.sha256(license_data).hexdigest())
        self.assertEqual(item["license_files"][0]["name"],"LICENSE")
        self.assertEqual(item["license_status"],"LICENSE_FILE_PRESENT_CLASSIFICATION_PENDING")
        self.assertEqual(r["commercial_licenses_cleared"],0)
        self.assertFalse(r["ready_to_distribute"])
        self.assertEqual(r["certification"],"NOT_CERTIFIED")
        self.assertNotIn(str(self.cache),json.dumps(r))

    def test_missing_license_is_explicit_and_not_cleared(self):
        r=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertEqual(r["modules_without_root_license_files"],1)
        self.assertEqual(r["modules"][0]["license_status"],"MISSING_LICENSE_AT_MODULE_ROOT")

    def test_notice_is_recorded_separately(self):
        (self.module/"NOTICE.txt").write_bytes(b"Third-party credit")
        r=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertEqual(r["modules_with_license_files"],0)
        self.assertEqual(r["modules"][0]["notice_files"][0]["name"],"NOTICE.txt")

    def test_symlink_outside_module_is_never_read(self):
        outside=Path(self.temp.name)/"secret"
        outside.write_text("DO NOT READ")
        (self.module/"LICENSE").symlink_to(outside)
        r=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertEqual(r["modules"][0]["license_status"],"UNSAFE_OR_UNREADABLE_LICENSE_PATH")
        self.assertNotIn("DO NOT READ",json.dumps(r))

    def test_empty_license_not_counted_as_present(self):
        (self.module/"LICENSE").write_bytes(b"")
        r=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertEqual(r["modules"][0]["license_status"],"EMPTY_LICENSE_FILE")

    def test_missing_dir_is_unresolved_not_success(self):
        del self.pkgs[0]["Module"]["Dir"]
        r=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertEqual(r["modules"][0]["license_status"],"MODULE_DIRECTORY_MISSING")

    def test_untrusted_module_dir_outside_cache_rejected(self):
        self.pkgs[0]["Module"]["Dir"]=self.temp.name
        with self.assertRaises(ValueError):
            collect_license_evidence(self.pkgs,self.closure,self.cache)

    def test_closure_mismatch_or_duplicate_version_rejected(self):
        self.closure["external_modules"][0]["version"]="v3.0.0"
        with self.assertRaises(ValueError):
            collect_license_evidence(self.pkgs,self.closure,self.cache)

    def test_unlisted_module_rejected(self):
        self.pkgs.append({"ImportPath":"other.net/new","Module":{"Path":"other.net/new","Version":"v2.0.0","Dir":str(self.module)}})
        with self.assertRaises(ValueError):
            collect_license_evidence(self.pkgs,self.closure,self.cache)

    def test_replacement_license_hash_is_preserved_but_rights_blocked(self):
        self.pkgs[0]["Module"]["Replace"]={"Path":"other.net/fork","Version":"v1.0.0","Dir":str(self.module)}
        (self.module/"LICENSE").write_bytes(b"Copyright Third Party\n")
        r=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertEqual(r["modules_with_license_files"],1)
        self.assertEqual(r["modules_without_root_license_files"],0)
        self.assertEqual(r["modules"][0]["license_status"],"MODULE_REPLACEMENT_REQUIRES_REVIEW")
        self.assertEqual(r["modules"][0]["replacement_path"],"other.net/fork")
        self.assertEqual(r["modules"][0]["license_files"][0]["name"],"LICENSE")
        self.assertEqual(r["commercial_licenses_cleared"],0)

    def test_replacement_outside_cache_never_exposes_source(self):
        outside=Path(self.temp.name)/"outside"
        outside.mkdir()
        (outside/"LICENSE").write_bytes(b"DO NOT READ")
        self.pkgs[0]["Module"]["Dir"]=str(outside)
        self.pkgs[0]["Module"]["Replace"]={"Path":"other.net/fork","Version":"v1.0.0"}
        r=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertEqual(r["modules"][0]["license_status"],"REPLACEMENT_SOURCE_OUTSIDE_CACHE")
        self.assertNotIn("DO NOT READ",json.dumps(r))

    def test_unresolved_replacement_requires_manual_scope_review(self):
        self.pkgs[0]["Module"]["Replace"]={"Path":"other.net/fork","Version":"v1.0.0","Dir":str(self.module)}
        r=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertEqual(r["modules"][0]["license_status"],"MODULE_REPLACEMENT_REQUIRES_REVIEW")


if __name__ == "__main__":
    unittest.main()
