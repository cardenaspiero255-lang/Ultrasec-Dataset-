"""A Gitea SOURCE OVERLAY, not standalone software or commercial permission."""
from __future__ import annotations
from pathlib import Path
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from gitea_source_overlay import build_checked_overlay

PATCH=("services/release/release.go","services/release/release_test.go",
 "routers/web/repo/release.go","routers/web/repo/release_test.go",
 "templates/repo/release/new.tmpl","tests/integration/release_test.go")
REQUIRED=PATCH+("LICENSE","go.mod","go.sum")


def git_blob_id(payload:bytes)->str:
    return subprocess.run(["git","hash-object","--stdin"],input=payload,check=True,capture_output=True).stdout.decode().strip()


class GiteaSourceOverlayTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out=Path(self.tmp.name)/"gitea-pair.zip"
        self.payloads={k:(f"// SPDX-License-Identifier: MIT\\n// {k}\\n").encode() for k in PATCH}
        self.payloads["LICENSE"]=(b"Copyright (c) 2016 The Gitea Authors\n"
             b"Permission is hereby granted, free of charge\n"
             b"The above copyright notice and this permission notice shall be included\n")
        self.payloads["go.mod"]=b"module gitea.dev\n\ngo 1.26.4\n"
        self.payloads["go.sum"]=b"example.org/module v1.0.0 h1:fiction\n"
        self.declared={k:git_blob_id(v) for k,v in self.payloads.items()}

    def test_overlay_includes_exact_original_files_and_mit_notice(self):
        receipt=build_checked_overlay(self.payloads,self.declared,self.out,phase="fixed")
        self.assertEqual(receipt["source_files"],9)
        self.assertTrue(receipt["original_license_text_included"])
        self.assertFalse(receipt["standalone_build_verified"])
        self.assertFalse(receipt["commercial_rights_verified"])
        self.assertEqual(receipt["certification"],"NOT_CERTIFIED")
        self.assertEqual(len(receipt["overlay_sha256"]),64)
        with ZipFile(self.out) as z:
            self.assertEqual(sorted(z.namelist()),sorted("gitea/"+n for n in REQUIRED))
            for n,b in self.payloads.items():
                self.assertEqual(z.read("gitea/"+n),b)
        self.assertNotIn("sample source",json.dumps(receipt))

    def test_missing_license_fails(self):
        self.payloads.pop("LICENSE")
        with self.assertRaises(ValueError):
            build_checked_overlay(self.payloads,self.declared,self.out,phase="vulnerable")

    def test_extra_source_or_path_traversal_fails(self):
        self.payloads["../escape.go"]=b"oops"
        self.declared["../escape.go"]=git_blob_id(b"oops")
        with self.assertRaises(ValueError):
            build_checked_overlay(self.payloads,self.declared,self.out,phase="fixed")

    def test_git_blob_mismatch_blocks_overlay(self):
        self.declared["LICENSE"]="0"*40
        with self.assertRaises(ValueError):
            build_checked_overlay(self.payloads,self.declared,self.out,phase="fixed")

    def test_wrong_mode_fails(self):
        with self.assertRaises(ValueError):
            build_checked_overlay(self.payloads,self.declared,self.out,phase="commercial_release")

    def test_mit_notice_must_be_preserved(self):
        self.payloads["LICENSE"]=b"MIT License\n"
        self.declared["LICENSE"]=git_blob_id(self.payloads["LICENSE"])
        with self.assertRaises(ValueError):
            build_checked_overlay(self.payloads,self.declared,self.out,phase="fixed")


if __name__=="__main__":
    unittest.main()
