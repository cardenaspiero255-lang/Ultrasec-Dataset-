"""P1/P2 adversarial regressions from Codex: never allow misleading enterprise PASS."""
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
import zipfile

TOOLS=Path(__file__).resolve().parents[1]/"tools"
def module(name):
    spec=importlib.util.spec_from_file_location(name,TOOLS/(name+".py"))
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
sast=module("adversarial_sast")
blind=module("blind_appsec")
mut=module("semantic_mutations")
release=module("premium_release_gate")


class PremiumSecurityRegressions(unittest.TestCase):
    def test_two_perfect_scanner_predictions_cannot_pass_100_case_gate(self):
        gold=[{"case_id":"v","cwe_id":"CWE-89","language":"python","vulnerable":True},
              {"case_id":"n","cwe_id":"CWE-89","language":"python","vulnerable":False}]
        rows=[{"case_id":case["case_id"],"tool":tool,
               "detected":case["vulnerable"],"coverage":"rule_applied",
               "rule_id":"example-rule","rule_cwe_id":"CWE-89"}
              for case in gold for tool in ("semgrep","codeql")]
        result=sast.summarize_sast(gold,rows)
        self.assertFalse(result["benchmark_pass"])
        self.assertIn("wrong_holdout_size",result["failures"])
        self.assertEqual(result["metrics"]["submitted_cases"],2)
        self.assertEqual(result["criteria"]["required_cases"],100)

    def test_codeql_missing_when_only_semgrep_reported_is_a_blocker(self):
        gold=[{"case_id":"v1","cwe_id":"CWE-89","language":"python","vulnerable":True},
              {"case_id":"n1","cwe_id":"CWE-89","language":"python","vulnerable":False}]
        rows=[{"case_id":x["case_id"],"tool":"semgrep","detected":x["vulnerable"],
               "coverage":"rule_applied","rule_id":"p/sql","rule_cwe_id":"CWE-89"} for x in gold]
        report=sast.summarize_sast(gold,rows)
        self.assertFalse(report["benchmark_pass"])
        self.assertIn("missing_tool_results",report["failures"])

    def test_invalid_gold_types_and_prediction_ids_fail_closed(self):
        gold=[{"case_id":"ok","cwe_id":"CWE-89","language":"python","vulnerable":True},
              {"case_id":"bad","cwe_id":"CWE-89","language":None,"vulnerable":False},
              {"case_id":[],"cwe_id":"CWE-89","language":"python","vulnerable":True},
              {"case_id":"bad2","cwe_id":[],"language":"python","vulnerable":False}]
        predictions=[{"case_id":[],"tool":"semgrep","detected":False,"coverage":"no_rule"}]
        result=sast.summarize_sast(gold,predictions)
        self.assertFalse(result["benchmark_pass"])
        self.assertIn("invalid_gold",result["failures"])
        self.assertIn("invalid_tool_record",result["failures"])

    def test_irrelevant_rule_cwe_must_not_turn_into_tp(self):
        gold=[{"case_id":"v1","cwe_id":"CWE-89","language":"python","vulnerable":True}]
        rows=[{"case_id":"v1","tool":tool,"detected":True,"coverage":"rule_applied",
               "rule_id":"wrong-xss","rule_cwe_id":"CWE-79"} for tool in ("semgrep","codeql")]
        report=sast.summarize_sast(gold,rows)
        self.assertFalse(report["benchmark_pass"])
        self.assertIn("mismatched_rule_cwe",report["failures"])
        for tool in ("semgrep","codeql"):
            self.assertEqual(report["by_tool_cwe"][tool]["CWE-89"]["tp"],0)

    def test_unanimous_uncertain_answers_are_not_independent_validation(self):
        a={str(i):"uncertain" for i in range(100)}
        result=blind.agreement_report(a,dict(a),100,.8)
        self.assertFalse(result["agreement_gate_pass"])
        self.assertIn("degenerate_review_distribution",result["failures"])
        self.assertIsNone(result["cohens_kappa"])

    def test_pending_adjudication_blocks_technical_readiness(self):
        evidence={"corpus":{"records":1000000,"exact_sha256_unique":1000000,
            "split_leaks":0,"lexical_patterns":200001},
            "independent":{"confirmed_real_world_cases":100,
                "qualified_independent_reviewers":2,"reviewer_agreement":0.9,
                "adjudication_unresolved":10,"adjudication_complete_signed":False},
            "benchmark":{"baseline_real_executions":True,"low_recall_cwes":0},
            "legal":{"redistribution_rights_verified":True},
            "ci":{"total":17,"passed":17,"unresolved_codex":0}}
        r=release.evaluate_readiness(evidence)
        self.assertFalse(r["technical_release_ready"])
        self.assertIn("unresolved_adjudication",r["blockers"])

    def test_mutation_admission_requires_bound_artifact_and_hash(self):
        evidence={"vulnerable_reproduced":True,"fix_verified":True,
          "independent_appsec_signed":True,"real_world_provenance_confirmed":True,
          "legal_rights_cleared":True,"holdout_no_leakage":True}
        self.assertFalse(mut.mutation_admission({},evidence)["admitted"])
        candidate=mut.propose_mutation("sink(input_data)","control_flow","CWE-89")
        self.assertEqual(len(candidate["source_sha256"]),64)
        self.assertFalse(mut.mutation_admission(candidate,evidence)["admitted"])
        evidence["artifact_sha256"]=candidate["source_sha256"]
        self.assertFalse(mut.mutation_admission(candidate,evidence)["admitted"])
        evidence["original_sha256"]=candidate["original_sha256"]
        evidence["proposal_identity_sha256"]=candidate["proposal_identity_sha256"]
        self.assertTrue(mut.mutation_admission(candidate,evidence)["admitted"])
        candidate["source"]+="\n# tampered"
        self.assertFalse(mut.mutation_admission(candidate,evidence)["admitted"])

    def test_mutation_origin_must_be_reproducible_not_just_self_hashed(self):
        src = "print('unrelated text')"
        proposal = {"source": src, "source_sha256": hashlib.sha256(src.encode()).hexdigest(),
            "operator": "control_flow", "family_id": "CWE-89",
            "validation_status": "UNVALIDATED_CANDIDATE"}
        evidence = {"artifact_sha256": proposal["source_sha256"],
            "vulnerable_reproduced": True, "fix_verified": True,
            "independent_appsec_signed": True, "real_world_provenance_confirmed": True,
            "legal_rights_cleared": True, "holdout_no_leakage": True}
        result = mut.mutation_admission(proposal, evidence)
        self.assertFalse(result["admitted"])
        self.assertIn("unverifiable_mutation_origin", result["failures"])

    def test_case_family_is_part_of_mutation_attestation(self):
        proposal=mut.propose_mutation("sink(user)","control_flow","CWE-89")
        original_identity=proposal["proposal_identity_sha256"]
        proposal["family_id"]="CWE-79"
        evidence={"original_sha256":proposal["original_sha256"],
          "artifact_sha256":proposal["source_sha256"],
          "proposal_identity_sha256":original_identity,"vulnerable_reproduced":True,
          "fix_verified":True,"independent_appsec_signed":True,
          "real_world_provenance_confirmed":True,"legal_rights_cleared":True,
          "holdout_no_leakage":True}
        result=mut.mutation_admission(proposal,evidence)
        self.assertFalse(result["admitted"])
        self.assertIn("unverifiable_mutation_origin",result["failures"])

    def test_blind_pack_rejects_low_entropy_hmac_secret(self):
        with self.assertRaises(ValueError):
            blind.create_reviewer_package([],Path("."),b"secret")
        with self.assertRaises(ValueError):
            blind.create_reviewer_package([],Path("."),b"x"*32)
        with self.assertRaises(ValueError):
            blind.create_reviewer_package([],Path("."),b"01234567"*4)

    def test_unsupported_review_evidence_never_unlocks_agreement_gate(self):
        cases=[{"case_id":str(i),"vulnerable_side":("A" if i%2 else "B"),
                "vulnerability_evidence":"insufficient",
                "fix_evidence":"insufficient","reproduction":"not_run"} for i in range(100)]
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for suffix,name in (("a","expert-A"),("b","expert-B")):
                (root/(suffix+".jsonl")).write_text("".join(
                    json.dumps({**row,"reviewer_id":name})+"\\n" for row in cases).replace("\\n","\n"))
            report=root/"report.json"
            proc=subprocess.run([sys.executable,str(TOOLS/"premium_eval_cli.py"),"agreement",
                "--reviewer-a",str(root/"a.jsonl"),"--reviewer-b",str(root/"b.jsonl"),
                "--sealed-report",str(report),"--session-lock",str(root/"lock")],
                capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            result=json.loads(report.read_text())
            self.assertFalse(result["agreement_gate_pass"])
            self.assertIn("review_evidence_inadequate",result["failures"])

    def test_one_reviewer_identity_is_required_per_rating_file(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for suffix in ("a","b"):
                rows=[{"case_id":str(i),"vulnerable_side":("A" if i%2 else "B"),
                     "vulnerability_evidence":"supported","fix_evidence":"supported",
                     "reproduction":"pass","reviewer_id":("A-"+str(i) if suffix=="a" else "B")} for i in range(100)]
                (root/(suffix+".jsonl")).write_text("".join(json.dumps(row)+"\\n" for row in rows).replace("\\n","\n"))
            report=root/"report.json"
            run=subprocess.run([sys.executable,str(TOOLS/"premium_eval_cli.py"),"agreement",
                "--reviewer-a",str(root/"a.jsonl"),"--reviewer-b",str(root/"b.jsonl"),
                "--sealed-report",str(report),"--session-lock",str(root/"lock")],capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)
            result=json.loads(report.read_text())
            self.assertFalse(result["agreement_gate_pass"])
            self.assertIn("reviewer_identity_not_independent",result["failures"])

    def test_reviewer_documentation_matches_accepted_six_field_schema(self):
        guide=(TOOLS.parent/"verification"/"EXTERNAL_BLIND_100_ES.md").read_text()
        self.assertIn("fix_evidence",guide)
        self.assertNotIn("mitigation_evidence=",guide)
        self.assertIn("reproduction",guide)
        self.assertIn("reviewer_id",guide)
        self.assertIn("evidencia firmada separada",guide.lower())

    def test_local_cli_accepts_full_reviewer_form_without_echoing_evidence(self):
        cases=[{"case_id":str(i),"vulnerable_side":side,
           "vulnerability_evidence":"supported",
           "fix_evidence":"supported",
           "reproduction":"pass",
           "reviewer_id":"reviewer-A" if side=="A" else "reviewer-B"} for i,side in enumerate(["A"]*100)]
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);a=root/"a.jsonl";b=root/"b.jsonl";out=root/"report.json"
            for path in (a,b):
                path.write_text("".join(json.dumps(x)+"\n" for x in cases))
            proc=subprocess.run([sys.executable,str(TOOLS/"premium_eval_cli.py"),
                "agreement","--reviewer-a",str(a),"--reviewer-b",str(b),
                "--sealed-report",str(out),"--session-lock",str(root/"lock")],
                capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(json.loads(proc.stdout),{"status":"SEALED"})
            report=json.loads(out.read_text())
            self.assertEqual(report["evidence_records"]["reviewer_a"],100)
            self.assertFalse(report["agreement_gate_pass"])  # one-class agreement must fail


if __name__=="__main__":
    unittest.main()
