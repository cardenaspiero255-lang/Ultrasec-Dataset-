"""TDD contract: enterprise admission, blind reviewer agreement, causal gate, SAST reporting.

All examples here are FABRICATED. They are not part of a real-world gold set.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / "tools"


def load(name):
    path = TOOLS / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gates = load("premium_evidence")
blind = load("blind_appsec")
sast = load("adversarial_sast")


def case(i, family=None, kind="real_world", split="test"):
    return {
        "case_id": "c"+str(i), "family_id": family or "F"+str(i%12),
        "cwe_id": "CWE-89", "language": "python", "split": split,
        "source_kind": kind,
        "source_url": "https://example.org/repo/commit/"+("a"*40),
        "source_commit": "a"*40, "fix_commit": "b"*40,
        "provenance_reviewed": True, "rights_clearance": "cleared",
        "independent_label_status": "expert_adjudicated",
        "vulnerable_reproduced": True, "fix_verified": True,
        "vulnerable_code": "query = input()\ndb.execute('SELECT ' + query)",
        "fixed_code": "query = input()\ndb.execute('SELECT ?', (query,))",
    }


class PremiumEvidenceTDD(unittest.TestCase):
    def test_admits_100_real_world_cases_12_families(self):
        data = [case(i) for i in range(100)]
        report = gates.admission_report(data, required_cases=100, required_families=12)
        self.assertTrue(report["admission_pass"])
        self.assertEqual(report["metrics"]["families"], 12)
        self.assertEqual(report["certification"], "NOT_CERTIFIED")

    def test_rejects_synthetic_corpus_even_with_provenance_claims(self):
        data = [case(i, kind="synthetic") for i in range(100)]
        r = gates.admission_report(data, 100, 12)
        self.assertFalse(r["admission_pass"])
        self.assertIn("not_real_world", r["failures"])

    def test_rejects_unverified_label_or_rights(self):
        data = [case(i) for i in range(100)]
        data[0]["independent_label_status"] = "generator_intent_unverified"
        data[1]["rights_clearance"] = "pending"
        r = gates.admission_report(data, 100, 12)
        self.assertIn("unverified_independent_label", r["failures"])
        self.assertIn("rights_not_cleared", r["failures"])

    def test_duplicate_case_and_project_overlap_fail_closed(self):
        data = [case(i) for i in range(100)]
        data[1]["case_id"] = data[0]["case_id"]
        r = gates.admission_report(data, 100, 12)
        self.assertIn("duplicate_case_id", r["failures"])

    def test_trivial_variable_rename_is_rejected(self):
        r = gates.causal_patch_gate("x = 1\nprint(x)", "y = 1\nprint(y)",
                                    {"vulnerable_reproduced":True, "fix_verified":True})
        self.assertFalse(r["causal_gate_pass"])
        self.assertIn("trivial_identifier_only_change", r["failures"])

    def test_add_only_if_without_a_verified_witness_fails(self):
        r = gates.causal_patch_gate("run(x)", "if allowed(x):\n    run(x)", {})
        self.assertFalse(r["causal_gate_pass"])
        self.assertIn("missing_executable_witness", r["failures"])

    def test_patch_with_material_flow_change_and_witness_can_pass_screen(self):
        r = gates.causal_patch_gate("db.execute('Q'+user)",
                                    "db.execute('Q?', (user,))",
                                    {"vulnerable_reproduced":True, "fix_verified":True})
        self.assertTrue(r["causal_gate_pass"])
        self.assertEqual(r["external_certification"], "NOT_VERIFIED")

    def test_report_never_exposes_corpus_code(self):
        data = [case(i) for i in range(100)]
        data[0]["vulnerable_code"] = "OWNER-SECRET-NOT-FOR-REPORT"
        report = json.dumps(gates.admission_report(data, 100, 12))
        self.assertNotIn("OWNER-SECRET", report)
        self.assertNotIn("https://example.org", report)


class BlindEvaluationTDD(unittest.TestCase):
    def test_all_100_have_separate_reviewer_and_owner_artifacts(self):
        data = [case(i) for i in range(100)]
        with tempfile.TemporaryDirectory() as d:
            out = blind.create_reviewer_package(data, Path(d), secret=b"owner-only-blinding-secret")
            self.assertEqual(out["count"], 100)
            self.assertNotEqual(out["reviewers_path"], out["owner_key_path"])
            import zipfile
            with zipfile.ZipFile(out["reviewers_path"]) as z:
                reviewer = z.read("cases.jsonl").decode()
                self.assertNotIn("source_commit", reviewer)
                self.assertNotIn("vulnerable_code", reviewer)
                self.assertNotIn("vulnerable_side", reviewer)
                self.assertEqual(len(reviewer.splitlines()), 100)
            with zipfile.ZipFile(out["owner_key_path"]) as z:
                key = z.read("owner_key.jsonl").decode()
                self.assertEqual(len(key.splitlines()), 100)
                self.assertIn("vulnerable_side", key)
            self.assertEqual(Path(out["owner_key_path"]).stat().st_mode & 0o777, 0o600)

    def test_package_fails_for_unverified_synthetic(self):
        data = [case(i, kind="synthetic") for i in range(100)]
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                blind.create_reviewer_package(data, Path(d), secret=b"secret")

    def test_80_percent_agreement_is_not_strictly_greater(self):
        a = {str(i):"A" for i in range(100)}
        b = {str(i):("A" if i<80 else "B") for i in range(100)}
        r = blind.agreement_report(a,b,required_cases=100,min_agreement=0.80)
        self.assertFalse(r["agreement_gate_pass"])
        self.assertEqual(r["observed_agreement"],0.8)
        self.assertEqual(r["external_certification"],"NOT_VERIFIED")

    def test_90_percent_agreement_reports_adjudication_queue(self):
        a = {str(i):("A" if i%2 else "B") for i in range(100)}
        b = dict(a)
        for i in range(10):b[str(i)] = "B" if a[str(i)]=="A" else "A"
        r = blind.agreement_report(a,b,100,0.8)
        self.assertTrue(r["agreement_gate_pass"])
        self.assertEqual(r["adjudication_required"],10)
        self.assertGreater(r["cohens_kappa"],0.7)
        self.assertEqual(r["certification"],"NOT_CERTIFIED")

    def test_missing_or_invalid_review_fails(self):
        a={"c1":"A","c2":"B"}
        b={"c1":"A"}
        r=blind.agreement_report(a,b,2,.8)
        self.assertFalse(r["agreement_gate_pass"])
        self.assertIn("incomplete_review",r["failures"])


class AdversarialSASTTDD(unittest.TestCase):
    def test_tool_scoring_by_cwe(self):
        gold=[{"case_id":"v1","cwe_id":"CWE-89","language":"python","vulnerable":True},
              {"case_id":"s1","cwe_id":"CWE-89","language":"python","vulnerable":False}]
        records=[{"case_id":"v1","tool":"semgrep","detected":True,"coverage":"rule_applied"},
                 {"case_id":"s1","tool":"semgrep","detected":False,"coverage":"rule_applied"}]
        report=sast.summarize_sast(gold,records)
        c=report["by_tool_cwe"]["semgrep"]["CWE-89"]
        self.assertEqual(c["tp"],1)
        self.assertEqual(c["tn"],1)
        self.assertEqual(c["precision"],1)
        self.assertEqual(c["recall"],1)
        self.assertEqual(report["certification"],"NOT_CERTIFIED")

    def test_rule_absence_is_not_a_successful_miss(self):
        gold=[{"case_id":"v1","cwe_id":"CWE-89","language":"python","vulnerable":True}]
        records=[{"case_id":"v1","tool":"semgrep","detected":False,"coverage":"no_rule"}]
        report=sast.summarize_sast(gold,records)
        self.assertIn("no_rule",report["limitations"])
        self.assertFalse(report["benchmark_pass"])
        self.assertIn("low_recall",report["failures"])

    def test_slither_must_not_claim_python_support(self):
        gold=[{"case_id":"v1","cwe_id":"CWE-89","language":"python","vulnerable":True}]
        records=[{"case_id":"v1","tool":"slither","detected":False,"coverage":"not_applicable"}]
        r=sast.summarize_sast(gold,records)
        self.assertFalse(r["benchmark_pass"])
        self.assertIn("not_applicable",r["limitations"])

    def test_scorecard_rejects_partial_tool_results(self):
        gold=[{"case_id":"v1","cwe_id":"CWE-89","language":"python","vulnerable":True}]
        r=sast.summarize_sast(gold,[])
        self.assertFalse(r["benchmark_pass"])
        self.assertIn("missing_tool_results",r["failures"])

    def test_unaudited_real_results_are_not_fabricated(self):
        r=sast.summarize_sast([],[])
        self.assertEqual(r["execution_status"],"NO_REAL_EXECUTION")
        self.assertFalse(r["benchmark_pass"])


if __name__=="__main__":
    unittest.main()
