"""Unit tests for observed license files, not an automatic legal opinion."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"tools"))
from gitea_module_license_evidence import collect_license_evidence, classify_original_license_text


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

    def test_mpl_2_recognizes_three_original_variants(self):
        variants=(
            b"Mozilla Public License, version 2.0\n1. Definitions\nCovered Software",
            b"Mozilla Public License Version 2.0\n1. Definitions\nCovered Software",
            b"Copyright IBM Corp.\nMozilla Public License, version 2.0\nCovered Software",
        )
        for raw in variants:
            with self.subTest(raw=raw):
                self.assertEqual(classify_original_license_text(raw),["MPL-2.0"])

    def test_bsd_two_clause_not_mistaken_for_bsd_three(self):
        raw=(b"Copyright 2015 Example\n"
             b"Redistribution and use in source and binary forms, with or without\n"
             b"modification, are permitted provided that the following conditions are met:\n"
             b"Redistributions of source code must retain the above copyright notice\n"
             b"Redistributions in binary form must reproduce the above copyright notice\n"
             b'THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"\n')
        self.assertEqual(classify_original_license_text(raw),["BSD-2-Clause"])

    def test_bsd_three_clause_without_exact_neither_wording_still_recognized(self):
        raw=(b"Redistribution and use in source and binary forms\n"
             b"Redistributions of source code must retain\n"
             b"Redistributions in binary form must reproduce\n"
             b"My name, Example Author, may not be used to endorse or promote products\n"
             b'THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS"')
        self.assertEqual(classify_original_license_text(raw),["BSD-3-Clause"])

    def test_bsl_per_file_root_gets_risk_not_apache_approval(self):
        root_license=(b"Source code in this repository is licensed under various licenses.\n"
                      b"The Business Source License 1.1 (BSL) is one such license.\n"
                      b"Each file indicates in a section at the beginning of the file\n"
                      b"All licenses used in this repository are in the top-level licenses directory.\n")
        (self.module/"LICENSE.txt").write_bytes(root_license)
        self.assertEqual(classify_original_license_text(root_license),["PER_FILE_LICENSE_MAPPING_REQUIRED"])
        r=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertIn("PER_FILE_LICENSE_REVIEW",r["modules"][0]["license_status"])
        self.assertTrue(r["modules"][0]["restricted_or_per_file_review"])
        self.assertFalse(r["ready_to_distribute"])

    def test_mpl_bsl_unknown_remain_undistributable_even_with_found_license(self):
        for raw in (
            b"Mozilla Public License, version 2.0\nCovered Software\n",
            b"Business Source License 1.1\nLicensed Work: Example\nChange Date: March 1, 2029",
        ):
            with self.subTest(raw=raw):
                (self.module/"LICENSE").write_bytes(raw)
                r=collect_license_evidence(self.pkgs,self.closure,self.cache)
                self.assertEqual(r["commercial_licenses_cleared"],0)
                self.assertFalse(r["ready_to_distribute"])

    def test_wrapped_mit_original_notice_is_recognized(self):
        raw=(b"Copyright 2012 Person\n"
             b"Permission is hereby granted, free of charge, to any person obtaining\n"
             b"a copy of this software and associated documentation files\n"
             b"The above copyright notice and this permission notice shall be\n"
             b"included in all copies or substantial portions of the Software.\n")
        self.assertEqual(classify_original_license_text(raw),["MIT"])

    def test_xi2_explicit_public_domain_statement_not_commercial_clearance(self):
        raw=(b"Licensing of github.com/xi2/xz\n"
             b"All these files have been put\n into the public domain.\n"
             b"You can do whatever you want with these files.\n"
             b'This software is provided "as is"\n')
        self.assertEqual(classify_original_license_text(raw),
                         ["PUBLIC_DOMAIN_CLAIM_UNSTANDARDIZED"])
        (self.module/"LICENSE").write_bytes(raw)
        report=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertEqual(report["modules"][0]["license_status"],
                         "PUBLIC_DOMAIN_PROVENANCE_REVIEW_REQUIRED")
        self.assertTrue(report["modules"][0]["restricted_or_per_file_review"])
        self.assertEqual(report["commercial_licenses_cleared"],0)

    def test_classify_mit_with_original_permission_and_notice(self):
        raw=(b"MIT License\nPermission is hereby granted, free of charge, "
             b"to any person obtaining a copy\n"
             b"The above copyright notice and this permission notice shall be included\n"
             b'THE SOFTWARE IS PROVIDED "AS IS"\n')
        self.assertEqual(classify_original_license_text(raw),["MIT"])
        (self.module/"LICENSE").write_bytes(raw)
        r=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertEqual(r["modules"][0]["license_files"][0]["observed_license_families"],["MIT"])
        self.assertEqual(r["modules"][0]["obligation_hints"],["MIT_RETAIN_COPYRIGHT_AND_PERMISSION_NOTICE"])
        self.assertEqual(r["commercial_licenses_cleared"],0)

    def test_classify_bsd_three_clause_and_notice(self):
        raw=(b"Redistribution and use in source and binary forms, with or without "
             b"modification, are permitted\nNeither the name of the copyright "
             b"holder nor the names of its contributors may be used to endorse\n"
             b"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n")
        self.assertEqual(classify_original_license_text(raw),["BSD-3-Clause"])

    def test_classify_apache_two_and_conditions_without_legal_approval(self):
        raw=(b"Apache License\nVersion 2.0, January 2004\n"
             b"http://www.apache.org/licenses/\nTERMS AND CONDITIONS FOR USE\n")
        self.assertEqual(classify_original_license_text(raw),["Apache-2.0"])

    def test_dual_license_preserves_both_possible_families(self):
        raw=(b"Apache License Version 2.0, January 2004\n"
             b"TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION\n"
             b"Permission is hereby granted, free of charge\n"
             b"the above copyright notice and this permission notice shall be included\n"
             b'the software is provided "as is"\n')
        self.assertEqual(classify_original_license_text(raw),["Apache-2.0","MIT"])

    def test_unknown_or_spoofed_license_is_not_classified(self):
        self.assertEqual(classify_original_license_text(b"SPDX-License-Identifier: MIT\n"),[])
        self.assertEqual(classify_original_license_text(b"redistribute this source at will"),[])

    def test_replacement_tracks_effective_version_not_requested_version(self):
        self.pkgs[0]["Module"]["Replace"]={"Path":"example.org/fork","Version":"v0.8.0","Dir":str(self.module)}
        (self.module/"LICENSE").write_bytes(b"unknown license terms")
        r=collect_license_evidence(self.pkgs,self.closure,self.cache)
        self.assertEqual(r["modules"][0]["replacement_version"],"v0.8.0")
        self.assertEqual(r["modules"][0]["effective_module_version"],"v0.8.0")
        self.assertEqual(r["modules"][0]["license_status"],"MODULE_REPLACEMENT_REQUIRES_REVIEW")

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
