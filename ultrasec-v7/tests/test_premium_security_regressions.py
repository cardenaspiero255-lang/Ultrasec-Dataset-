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
    def test_codeql_missing_when_only_semgrep_reported_is_a_blocker(self):
        gold=[{"case_id":"v1","cwe_id":"CWE-89","language":"python","vulnerable":True},
              {"case_id":"n1","cwe_id":"CWE-89","language":"python","vulnerable":False}]
        rows=[{"case_id":x["case_id"],"tool":"semgrep","detected":x["vulnerable"],
               "coverage":"rule_applied","rule_id":"p/sql","rule_cwe_id":"CWE-89"} for x in gold]
        report=sast.summarize_sast(gold,rows)
        self.assertFalse(report["benchmark_pass"])
        self.assertIn("missing_tool_results",report["failures"])

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
        self.assertTrue(mut.mutation_admission(candidate,evidence)["admitted"])
        candidate["source"]+="\n# tampered"
        self.assertFalse(mut.mutation_admission(candidate,evidence)["admitted"])

    def test_blind_pack_rejects_low_entropy_hmac_secret(self):
        with self.assertRaises(ValueError):
            blind.create_reviewer_package([],Path("."),b"secret")
        with self.assertRaises(ValueError):
            blind.create_reviewer_package([],Path("."),b"x"*32)

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
