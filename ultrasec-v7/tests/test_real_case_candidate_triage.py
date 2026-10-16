"""Synthetic screening-contract tests: never certified real vulnerabilities."""
import importlib.util
from pathlib import Path
import unittest

TOOL=Path(__file__).resolve().parents[1]/"tools"/"real_case_candidate_triage.py"
CWES=("CWE-79","CWE-89","CWE-352","CWE-862","CWE-787","CWE-22",
      "CWE-416","CWE-125","CWE-78","CWE-94","CWE-120","CWE-434")

def load():
    spec=importlib.util.spec_from_file_location("real_case_candidate_triage",TOOL)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def rows(count=100):
    return [{
        "cve_id":f"CVE-2024-{i+10000}",
        "cwe_id":CWES[i%12],
        "repo_url":f"https://github.com/owner-{i}/project-{i}",
        "source_commit":f"{i+1:040x}",
        "fix_commit":f"{i+1001:040x}",
        "source_dataset":"MoreFixes v4",
        "score":80,
        "rights_clearance":"cleared",  # intentionally untrusted input
        "independent_label_status":"expert_adjudicated",
    } for i in range(count)]

class CandidateTriage(unittest.TestCase):
    def test_100_metadata_candidates_still_zero_verified(self):
        r=load().screen_candidates(rows())
        self.assertTrue(r["candidate_target_met"])
        self.assertEqual(r["candidate_count"],100)
        self.assertEqual(r["distinct_cwes"],12)
        self.assertEqual(r["externally_verified_cases"],0)
        self.assertEqual(r["commercial_rights"],"NOT_VERIFIED")
        self.assertEqual(r["independent_gold"],"NOT_VERIFIED")
        self.assertEqual(r["real_sast"],"NOT_RUN")
        self.assertEqual(r["certification"],"NOT_CERTIFIED")

    def test_duplicate_repos_are_excluded_not_held_out_as_independent(self):
        data=rows()
        data[1]["repo_url"]=data[0]["repo_url"]
        report=load().screen_candidates(data)
        self.assertFalse(report["candidate_target_met"])
        self.assertEqual(report["candidate_count"],99)

    def test_insufficient_family_coverage_is_not_accepted(self):
        data=rows()
        for entry in data:
            entry["cwe_id"]="CWE-79"
        result=load().screen_candidates(data)
        self.assertFalse(result["candidate_target_met"])
        self.assertEqual(result["distinct_cwes"],1)

    def test_malformed_commit_or_untrusted_host_is_excluded(self):
        data=rows()
        data[0]["fix_commit"]="abc"
        data[1]["repo_url"]="https://github.com.evil.example/u/r"
        result=load().screen_candidates(data)
        self.assertEqual(result["candidate_count"],98)
        self.assertFalse(result["candidate_target_met"])

    def test_low_quality_morefixes_score_excluded(self):
        data=rows()
        data[0]["score"]=60
        result=load().screen_candidates(data)
        self.assertEqual(result["candidate_count"],99)

    def test_no_user_supplied_license_claim_can_certify_cases(self):
        data=rows()
        for item in data:
            item["rights_clearance"]="cleared"
            item["independent_label_status"]="expert_adjudicated"
            item["vulnerable_reproduced"]=True
            item["fix_verified"]=True
        result=load().screen_candidates(data)
        self.assertEqual(result["externally_verified_cases"],0)
        self.assertNotIn("cleared",str(result))
        self.assertEqual(result["commercial_rights"],"NOT_VERIFIED")

if __name__=="__main__":
    unittest.main()
