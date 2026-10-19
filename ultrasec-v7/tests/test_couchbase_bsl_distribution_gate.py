"""RED first: future commercial packages must not bypass original Couchbase BSL risk."""
import copy
import importlib.util
from pathlib import Path
import unittest

SRC=Path(__file__).resolve().parents[1]/"tools"/"couchbase_bsl_distribution_gate.py"
spec=importlib.util.spec_from_file_location("couchbase_bsl_gate",SRC)
assert spec and spec.loader
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

FILES={
 "logging/logger.go":"49077aba6fbe5241fa6a93f7d00d94df4add65b1ec7d247995391e0034cba270",
 "logging/logger_golog.go":"d32725e23d15ec9af4cffb8d8a299eb76cbf50ba2cb51b9c47fd69a2dec8ac27",
 "scramsha/scramsha.go":"8a43d5236b3212b1e6bfb63cbce3faf9f6e16d2bf4583d046e5edf7ec64ec00f",
 "scramsha/scramsha_http.go":"20bdfdf5ef281fcafb79fe528823ec627d90afd7fba06b3636053dccee67c684",
}
DOCS={
 "LICENSE.txt":"584aa21e4e3c29356e5064b3d58cad614fc6c8a3265d96327de658a20b370f42",
 "licenses/BSL-Couchbase.txt":"3c22e5817c43fb602a003fd713cafc4db0cf46d9ec0473dd324eab22ad3eb4e1",
 "licenses/APL2.txt":"a6cba85bc92e0cff7a450b1d873c0eaa2e9fc96bf472df0247a26bec77bf3ff9",
}

def fixture():
    return {"schema":"ultrasec.gitea-couchbase-compiled-source-risk.v1",
      "module":"github.com/couchbase/goutils","module_version":"v0.3.0",
      "imported_packages":2,"inspected_source_files":4,
      "files":[{"path":p,"sha256":h,"source_header_license_indicators":[
        "APACHE-2.0-FUTURE-CHANGE-REFERENCE","BSL-1.1-REFERENCE"],
        "per_file_license_verified":False} for p,h in FILES.items()],
      "license_documents":[{"path":p,"sha256":h} for p,h in DOCS.items()],
      "change_date_observed":"March 1, 2029",
      "licensed_work_observed":"Couchbase Server Version 8.0",
      "license_applicability":"REQUIRES_FILE_AND_LICENSE_SCOPE_REVIEW",
      "commercial_distribution_cleared":False,
      "gold_admitted":0,"certification":"NOT_CERTIFIED"}

class CouchbaseOriginalRightsTest(unittest.TestCase):
    def test_four_compiled_original_files_block_commercial_packaging(self):
        result=gate.evaluate(fixture(),"fixed")
        self.assertEqual(result["actual_original_source_files"],4)
        self.assertEqual(result["source_header_bsl_references"],4)
        self.assertFalse(result["commercial_distribution_allowed"])
        self.assertFalse(result["file_level_rights_verified"])
        self.assertEqual(result["legal_question"],"LICENSED_WORK_SCOPE_AMBIGUOUS")
        self.assertEqual(result["certification"],"NOT_CERTIFIED")

    def test_missing_original_file_fails_closed(self):
        j=fixture();j["files"].pop()
        with self.assertRaises(ValueError):gate.evaluate(j,"fixed")

    def test_unknown_sha_fails_closed(self):
        j=fixture();j["files"][0]["sha256"]="a"*64
        with self.assertRaises(ValueError):gate.evaluate(j,"fixed")

    def test_changed_licensing_text_fails_closed(self):
        j=fixture();j["license_documents"][1]["sha256"]="0"*64
        with self.assertRaises(ValueError):gate.evaluate(j,"fixed")

    def test_apache_future_change_not_current_clearance(self):
        j=fixture();j["commercial_distribution_cleared"]=True
        with self.assertRaises(ValueError):gate.evaluate(j,"fixed")
        j=fixture();j["change_date_observed"]="March 1, 2024"
        with self.assertRaises(ValueError):gate.evaluate(j,"fixed")

    def test_license_scope_ambiguity_cannot_be_silently_removed(self):
        j=fixture();j["licensed_work_observed"]="github.com/couchbase/goutils"
        with self.assertRaises(ValueError):gate.evaluate(j,"fixed")

    def test_original_pre_patch_absence_is_not_commercial_clearance(self):
        j=fixture();j.update({"files":[],"module_version":None,
           "imported_packages":0,"inspected_source_files":0,
           "license_documents":[],"change_date_observed":None,
           "licensed_work_observed":None,
           "license_applicability":"NOT_WITHIN_THIS_ORIGINAL_GO_SERVICE_IMPORT_CLOSURE"})
        result=gate.evaluate(j,"vulnerable")
        self.assertFalse(result["commercial_distribution_allowed"])
        self.assertEqual(result["source_header_bsl_references"],0)
        self.assertEqual(result["scope_status"],"MODULE_ABSENT_FROM_SERVICE_IMPORT_CLOSURE")

if __name__=="__main__":unittest.main()
