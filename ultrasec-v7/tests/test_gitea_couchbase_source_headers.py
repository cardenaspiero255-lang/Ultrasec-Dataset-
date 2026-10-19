"""Audit actual ORIGINAL compiled Go source headers for Couchbase goutils; never infer resale rights."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from gitea_couchbase_source_headers import scan_goutils_imported_files

MODULE="github.com/couchbase/goutils"

class GoutilsActualSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache=Path(self.temp.name)/"pkg/mod"
        self.module=self.cache/"github.com/couchbase/goutils@v0.3.0"
        self.part=self.module/"logging"
        self.part.mkdir(parents=True)
        self.text=(b"// Copyright 2016-Present Couchbase, Inc.\n"
            b"// Use of this software is governed by the Business Source License included\n"
            b"// in the file licenses/BSL-Couchbase.txt. As of the Change Date specified\n"
            b"// in that file, use is governed by the Apache License, Version 2.0.\n"
            b"package logging\n")
        (self.part/"logger.go").write_bytes(self.text)
        (self.module/"LICENSE.txt").write_text(
            "Source code in this repository is licensed under various licenses.\n"
            "Each file indicates which applies; see licenses/\n")
        folder=self.module/"licenses"
        folder.mkdir()
        (folder/"BSL-Couchbase.txt").write_text(
            "Business Source License 1.1\nLicensed Work: Couchbase Server Version 8.0\n"
            "Change Date:  March 1, 2029\nChange License: Apache License, Version 2.0\n")
        (folder/"APL2.txt").write_text("Apache License Version 2.0")
        self.pkgs=[{"ImportPath":MODULE+"/logging",
            "Dir":str(self.part),"GoFiles":["logger.go"],
            "Module":{"Path":MODULE,"Version":"v0.3.0","Dir":str(self.module)}}]

    def test_original_compiled_headers_and_referenced_license_hashes(self):
        r=scan_goutils_imported_files(self.pkgs,self.cache)
        self.assertEqual(r["imported_packages"],1)
        self.assertEqual(r["inspected_source_files"],1)
        f=r["files"][0]
        self.assertEqual(f["path"],"logging/logger.go")
        self.assertEqual(f["sha256"],hashlib.sha256(self.text).hexdigest())
        self.assertEqual(f["source_header_license_indicators"],["BSL-1.1-REFERENCE"])
        self.assertEqual(r["linked_license_documents"],2)
        self.assertEqual(r["licensed_work_observed"],"Couchbase Server Version 8.0")
        self.assertEqual(r["change_date_observed"],"March 1, 2029")
        self.assertEqual(r["license_applicability"],"REQUIRES_FILE_AND_LICENSE_SCOPE_REVIEW")
        self.assertFalse(r["commercial_distribution_cleared"])
        self.assertEqual(r["certification"],"NOT_CERTIFIED")
        self.assertNotIn(str(self.cache),json.dumps(r))
        self.assertNotIn("package logging",json.dumps(r))

    def test_unreferenced_package_not_counted_as_imported(self):
        (self.module/"tls").mkdir()
        (self.module/"tls/tls.go").write_bytes(self.text)
        r=scan_goutils_imported_files(self.pkgs,self.cache)
        self.assertEqual(r["inspected_source_files"],1)

    def test_absent_file_fails_closed(self):
        self.pkgs[0]["GoFiles"]=["missing.go"]
        with self.assertRaises(ValueError):
            scan_goutils_imported_files(self.pkgs,self.cache)

    def test_no_source_metadata_is_not_independently_verified(self):
        self.pkgs[0]["GoFiles"]=[]
        with self.assertRaises(ValueError):
            scan_goutils_imported_files(self.pkgs,self.cache)

    def test_path_traversal_rejected(self):
        self.pkgs[0]["GoFiles"]=["../LICENSE.txt"]
        with self.assertRaises(ValueError):
            scan_goutils_imported_files(self.pkgs,self.cache)

    def test_external_symlink_rejected(self):
        outside=Path(self.temp.name)/"outside.go"
        outside.write_bytes(b"secret marker")
        (self.part/"logger.go").unlink()
        (self.part/"logger.go").symlink_to(outside)
        with self.assertRaises(ValueError):
            scan_goutils_imported_files(self.pkgs,self.cache)

    def test_claimed_package_path_must_match_real_module(self):
        self.pkgs[0]["Module"]["Path"]="github.com/other/company"
        with self.assertRaises(ValueError):
            scan_goutils_imported_files(self.pkgs,self.cache)

    def test_unlicensed_source_is_rejected_for_clearance_not_silently_inferred(self):
        (self.part/"logger.go").write_bytes(b"package logging\n")
        r=scan_goutils_imported_files(self.pkgs,self.cache)
        self.assertEqual(r["files"][0]["source_header_license_indicators"],[])
        self.assertFalse(r["commercial_distribution_cleared"])
        self.assertTrue(r["files_requiring_manual_adjudication"])

    def test_document_missing_fails_closed(self):
        (self.module/"licenses/BSL-Couchbase.txt").unlink()
        with self.assertRaises(ValueError):
            scan_goutils_imported_files(self.pkgs,self.cache)

if __name__=="__main__":
    unittest.main()
