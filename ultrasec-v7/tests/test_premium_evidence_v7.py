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
mutations = load("semantic_mutations")


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


class SemanticMutationTDD(unittest.TestCase):
    def test_mutations_cover_four_semantic_axes_but_remain_unvalidated(self):
        fixture = {
            "control_flow": "sink(user)",
            "data_flow": "sink(user)",
            "sanitization_order": "sink(sanitize(decode(user)))",
            "boundary_conditions": "if len(user) < 10:\n    sink(user)",
        }
        for operator, source in fixture.items():
            with self.subTest(operator=operator):
                result = mutations.propose_mutation(source, operator, family_id="CWE-89")
                self.assertNotEqual(result["source"], source)
                self.assertEqual(result["operator"], operator)
                self.assertEqual(result["validation_status"], "UNVALIDATED_CANDIDATE")
                self.assertIn("executable_witness",result["required_before_admission"])

    def test_unsupported_operator_fails_and_does_not_output_claim(self):
        with self.assertRaises(ValueError):
            mutations.propose_mutation("print('ok')","magic_increase_count",family_id="CWE-89")

    def test_mutator_never_promotes_without_provenance_and_oracle(self):
        changed=mutations.propose_mutation("sink(x)","control_flow",family_id="CWE-89")
        r=mutations.mutation_admission(changed,{"vulnerable_reproduced":False,"fix_verified":True})
        self.assertFalse(r["admitted"])
        self.assertIn("missing_executable_witness",r["failures"])


class BlindEvaluationTDD(unittest.TestCase):
    def test_all_100_have_separate_reviewer_and_owner_artifacts(self):
        data = [case(i) for i in range(100)]
        with tempfile.TemporaryDirectory() as d:
            out = blind.create_reviewer_package(data, Path(d))
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
                blind.create_reviewer_package(data, Path(d))

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


class PrivateCLIRegressionTDD(unittest.TestCase):
    def test_signed_human_rating_jsonl_can_be_scored_only_locally(self):
        import subprocess
        import sys
        script=TOOLS/"premium_eval_cli.py"
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            ratings_a=root/"a.jsonl";ratings_b=root/"b.jsonl"
            a=[{"case_id":str(i),"vulnerable_side":"A"} for i in range(100)]
            b=[{"case_id":str(i),"vulnerable_side":"A" if i<90 else "B"} for i in range(100)]
            ratings_a.write_text("".join(json.dumps(x)+"\\n" for x in a).replace("\\n","\n"),encoding="utf-8")
            ratings_b.write_text("".join(json.dumps(x)+"\\n" for x in b).replace("\\n","\n"),encoding="utf-8")
            out=root/"report.json"
            proc=subprocess.run([sys.executable,str(script),"agreement",
                "--reviewer-a",str(ratings_a),"--reviewer-b",str(ratings_b),
                "--sealed-report",str(out),"--session-lock",str(root/"run.lock")],
                capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(json.loads(proc.stdout),{"status":"SEALED"})
            result=json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(result["observed_agreement"],0.9)
            self.assertEqual(result["certification"],"NOT_CERTIFIED")
            self.assertEqual(out.stat().st_mode & 0o777,0o600)

    def test_duplicate_rating_ids_are_rejected_without_releasing_answers(self):
        import subprocess
        import sys
        script=TOOLS/"premium_eval_cli.py"
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"a.jsonl").write_text('{"case_id":"x","vulnerable_side":"A"}\\n{"case_id":"x","vulnerable_side":"B"}\\n'.replace("\\n","\n"))
            (root/"b.jsonl").write_text('{"case_id":"x","vulnerable_side":"A"}\\n'.replace("\\n","\n"))
            out=root/"report.json"
            proc=subprocess.run([sys.executable,str(script),"agreement",
                "--reviewer-a",str(root/"a.jsonl"),"--reviewer-b",str(root/"b.jsonl"),
                "--sealed-report",str(out),"--session-lock",str(root/"lock")],
                capture_output=True,text=True)
            self.assertEqual(json.loads(proc.stdout),{"status":"SEALED"})
            self.assertIn("input_parse_error",json.loads(out.read_text())["failures"])
            self.assertNotIn('"vulnerable_side"',proc.stdout)


class AdversarialSASTTDD(unittest.TestCase):
    def test_tool_scoring_by_cwe(self):
        gold=[{"case_id":"v1","cwe_id":"CWE-89","language":"python","vulnerable":True},
              {"case_id":"s1","cwe_id":"CWE-89","language":"python","vulnerable":False}]
        records=[{"case_id":"v1","tool":"semgrep","detected":True,"coverage":"rule_applied","rule_id":"test-sql","rule_cwe_id":"CWE-89"},
                 {"case_id":"s1","tool":"semgrep","detected":False,"coverage":"rule_applied","rule_id":"test-sql","rule_cwe_id":"CWE-89"}]
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

    def test_sast_one_class_cannot_pass_even_if_every_case_is_negative(self):
        gold=[{"case_id":"n1","cwe_id":"CWE-89","language":"python","vulnerable":False}]
        records=[{"case_id":"n1","tool":"semgrep","detected":False,"coverage":"rule_applied"}]
        r=sast.summarize_sast(gold,records)
        self.assertFalse(r["benchmark_pass"])
        self.assertIn("unmeasurable_cwe_class_balance",r["failures"])

    def test_sast_no_safe_controls_cannot_claim_low_false_positive_rate(self):
        gold=[{"case_id":"v1","cwe_id":"CWE-89","language":"python","vulnerable":True}]
        records=[{"case_id":"v1","tool":"semgrep","detected":True,"coverage":"rule_applied"}]
        r=sast.summarize_sast(gold,records)
        self.assertFalse(r["benchmark_pass"])
        self.assertIn("unmeasurable_cwe_class_balance",r["failures"])

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
