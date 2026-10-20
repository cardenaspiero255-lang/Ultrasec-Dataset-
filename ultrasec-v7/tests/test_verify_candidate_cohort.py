"""Fail-closed security invariants of public pre-admission metadata (stdlib only)."""
from __future__ import annotations
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from verify_candidate_cohort import validate, report

REGISTRY = ROOT / "verification" / "research" / "COHORT_5_PRE_ADMISSION_PUBLIC.json"


def fixture():
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


class ResearchCohortContract(unittest.TestCase):
    def test_registry_has_five_cases_and_two_native_witnesses_without_gold(self):
        doc = fixture()
        self.assertEqual(validate(doc), [])
        result = report(doc)
        self.assertEqual(result["candidate_count"], 5)
        self.assertEqual(result["native_red_green_count"], 5)
        self.assertEqual(result["confirmed_gold_count"], 0)
        self.assertEqual(result["certification"], "NOT_CERTIFIED")

    def test_missing_registry_rejected(self):
        self.assertTrue(validate({}))

    def test_ci_is_not_independent_external_security_adjudication(self):
        doc = fixture()
        self.assertEqual(doc["candidates"][0]["native_evidence"], "RED_GREEN_REPRODUCED")
        self.assertEqual(report(doc)["confirmed_gold_count"], 0)

    def test_red_green_run_urls_must_be_canonical_and_belong_to_ultrasec(self):
        bad = [
            "https://github.com/outsider/other/actions/runs/39073712740",
            "https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/not-an-id",
            "https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39073712740/extra",
        ]
        for url in bad:
            with self.subTest(url=url):
                doc = copy.deepcopy(fixture())
                doc["candidates"][0]["native_evidence_url"] = url
                self.assertIn("invalid_red_green_run_reference", validate(doc))

    def test_automation_phase_is_distinct_from_external_certification(self):
        result = report(fixture())
        self.assertEqual(result["automated_phase"], "METADATA_CONSISTENCY_ONLY")
        self.assertEqual(result["human_review_phase"], "DEFERRED")
        self.assertEqual(result["certification"], "NOT_CERTIFIED")
        self.assertEqual(result["confirmed_gold_count"], 0)

    def test_repeated_release_pair_is_rejected(self):
        doc = copy.deepcopy(fixture())
        source = doc["candidates"][1]
        other = doc["candidates"][4]
        other["source_commit"] = None
        other["fix_commit"] = None
        other["source_release_sha256"] = source["source_release_sha256"]
        other["fix_release_sha256"] = source["fix_release_sha256"]
        self.assertIn("duplicate_source_patch_pair", validate(doc))

    def test_duplicated_upstream_project_is_not_independent(self):
        doc = copy.deepcopy(fixture())
        doc["candidates"][4]["source_url"] = doc["candidates"][0]["source_url"]
        self.assertIn("nonindependent_upstream_project", validate(doc))

    def test_reused_native_witness_run_is_rejected(self):
        doc = copy.deepcopy(fixture())
        doc["candidates"][4]["native_evidence_url"] = doc["candidates"][0]["native_evidence_url"]
        self.assertIn("duplicate_native_witness", validate(doc))

    def test_public_disjointness_does_not_claim_independent_holdout(self):
        result = report(fixture())
        self.assertEqual(result["distinct_upstream_projects"], 5)
        self.assertEqual(result["distinct_native_witnesses"], 5)
        self.assertEqual(result["private_holdout_independence"], "NOT_VERIFIED")

    def test_repeated_original_patch_pair_is_rejected(self):
        doc = fixture()
        doc["candidates"][4]["source_commit"] = doc["candidates"][0]["source_commit"]
        doc["candidates"][4]["fix_commit"] = doc["candidates"][0]["fix_commit"]
        self.assertIn("duplicate_source_patch_pair", validate(doc))


NEGATIVE_CASES = {
    "self_certified_gold": lambda d: d["candidates"][0].update(gold_status="ADMITTED"),
    "fabricated_expert": lambda d: d["candidates"][0].update(independent_review="EXPERT_ADJUDICATED"),
    "fabricated_rights": lambda d: d["candidates"][0].update(commercial_rights="CLEARED"),
    "holdout_leak": lambda d: d["candidates"][0].update(split="TEST"),
    "private_source": lambda d: d["candidates"][0].update(provenance="PRIVATE_SOURCE"),
    "fake_certification": lambda d: d.update(certification="CERTIFIED"),
    "duplicate_cve": lambda d: d["candidates"][1].update(cve_id=d["candidates"][0]["cve_id"]),
    "unknown_cwe": lambda d: d["candidates"][1].update(cwe_id="CWE-9999"),
    "short_sha": lambda d: d["candidates"][0].update(source_commit="deadbeef"),
    "fake_pass_native": lambda d: d["candidates"][0].update(native_evidence="PASS"),
    "missing_candidate": lambda d: d["candidates"].pop(),
    "training_import": lambda d: d["candidates"][0].update(training_import="YES"),
    "faked_witness": lambda d: d["candidates"][0].update(vulnerable_reproduced="YES"),
    "http_evidence": lambda d: d["candidates"][0].update(source_url="http://example.invalid"),
}


def make_negative_test(tamper):
    def test(self):
        doc = copy.deepcopy(fixture())
        tamper(doc)
        self.assertTrue(validate(doc), "Unsafe metadata was accepted")
    return test


for name, tamper in NEGATIVE_CASES.items():
    setattr(ResearchCohortContract, "test_reject_" + name, make_negative_test(tamper))
