"""Public fake Go package metadata tests; no private corpus and no inferred license grants."""
import json
import sys
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from gitea_go_dependency_closure import build_closure

ORIGINAL="7fdfb8d642201b388014f29889ef28e35b8c1872"
FIXED="e4ef995f2a162e3aca3f3a0b536afae067975d71"


def fixture():
    return [
       {"ImportPath":"fmt","Standard":True},
       {"ImportPath":"gitea.dev/services/release","Module":{"Path":"gitea.dev","Main":True},"Imports":["fmt","github.com/example/lib"]},
       {"ImportPath":"github.com/example/lib","Module":{"Path":"github.com/example/lib","Version":"v1.2.3"},"Imports":["fmt"]},
    ]


class GiteaClosureTests(unittest.TestCase):
    def test_closure_counts_are_public_metadata_and_no_license_approval(self):
        x=build_closure(fixture(),ORIGINAL,"a"*64,"b"*64,"c"*64)
        self.assertEqual(x["package_count"],3)
        self.assertEqual(x["stdlib_package_count"],1)
        self.assertEqual(x["local_gitea_package_count"],1)
        self.assertEqual(x["external_module_count"],1)
        self.assertEqual(x["external_modules"][0]["path"],"github.com/example/lib")
        self.assertEqual(x["commercial_distribution_cleared_modules"],0)
        self.assertFalse(x["third_party_licenses_audited"])
        self.assertEqual(x["status"],"MODULE_CLOSURE_ONLY_NOT_LICENSE_CLEARANCE")
        self.assertEqual(x["gold_admitted"],0)

    def test_package_errors_fail_without_faking_sbom(self):
        bad=fixture()
        bad[2]["Error"]={"Err":"missing module"}
        with self.assertRaises(ValueError):
            build_closure(bad,ORIGINAL,"a"*64,"b"*64,"c"*64)

    def test_no_go_package_fails_closed(self):
        with self.assertRaises(ValueError):
            build_closure([],ORIGINAL,"a"*64,"b"*64,"c"*64)

    def test_another_commit_fails_closed(self):
        with self.assertRaises(ValueError):
            build_closure(fixture(),"0"*40,"a"*64,"b"*64,"c"*64)

    def test_same_path_with_incompatible_versions_fails(self):
        f=fixture()+[{"ImportPath":"github.com/example/lib/v2","Module":{"Path":"github.com/example/lib","Version":"v9.9.9"}}]
        with self.assertRaises(ValueError):
            build_closure(f,ORIGINAL,"a"*64,"b"*64,"c"*64)

    def test_dependency_with_missing_version_fails(self):
        f=fixture()
        del f[2]["Module"]["Version"]
        with self.assertRaises(ValueError):
            build_closure(f,FIXED,"a"*64,"b"*64,"c"*64)

    def test_no_unverified_modules_promoted_to_licensed(self):
        x=build_closure(fixture(),FIXED,"a"*64,"b"*64,"c"*64)
        self.assertTrue(all(m["file_level_license_status"]=="NOT_AUDITED" for m in x["external_modules"]))
        self.assertFalse(x["ready_for_relicensed_binary_distribution"])


if __name__=="__main__":
    unittest.main()
