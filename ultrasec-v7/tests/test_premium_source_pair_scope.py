"""Fail-closed scope for highest-potential-value UltraSec product; no licensed source shipped."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from premium_source_pair_scope import screen_product_scope

FILE=ROOT/"verification/research/PREMIUM_SOURCE_PAIR_PRODUCT_DRAFT.json"
COHORT=ROOT/"verification/research/COHORT_5_PRE_ADMISSION_PUBLIC.json"


def data():
    return json.loads(FILE.read_text(encoding="utf-8")),json.loads(COHORT.read_text(encoding="utf-8"))


class PremiumProductScopeTests(unittest.TestCase):
    def test_premium_product_is_defined_without_pretending_cases_can_ship(self):
        product,cohort=data()
        result=screen_product_scope(product,cohort)
        self.assertEqual(result["errors"],[])
        self.assertEqual(result["proposed_delivery_mode"],"minimal_reproducible_source_pairs")
        self.assertEqual(result["candidate_origins"],5)
        self.assertEqual(result["admitted_reproducible_pairs"],0)
        self.assertEqual(result["commercially_releaseable_pairs"],0)
        self.assertFalse(result["ready_to_sell"])
        self.assertEqual(result["certification"],"NOT_CERTIFIED")

    def test_no_sale_if_obligations_marked_cleared_without_evidence(self):
        product,cohort=data()
        product["candidates"][0]["distribution_rights"]="CLEARED"
        result=screen_product_scope(product,cohort)
        self.assertIn("unsupported_rights_claim",result["errors"])
        self.assertFalse(result["ready_to_sell"])

    def test_no_unverified_gold_promotion(self):
        product,cohort=data()
        product["candidates"][0]["gold_status"]="ADMITTED"
        self.assertIn("unsupported_gold_claim",screen_product_scope(product,cohort)["errors"])

    def test_source_pair_must_not_ship_original_code_in_public_manifest(self):
        product,cohort=data()
        product["candidates"][0]["packaged_source_files"]=["src/upstream-private-file.c"]
        self.assertIn("source_files_must_remain_unshipped",screen_product_scope(product,cohort)["errors"])

    def test_unknown_origin_not_accepted(self):
        product,cohort=data()
        product["candidates"][0]["cve_id"]="CVE-2025-999999"
        self.assertIn("cohort_mismatch",screen_product_scope(product,cohort)["errors"])

    def test_duplicate_origin_not_accepted(self):
        product,cohort=data()
        product["candidates"][1]=copy.deepcopy(product["candidates"][0])
        self.assertIn("duplicate_candidate_origin",screen_product_scope(product,cohort)["errors"])

    def test_no_unreviewed_private_holdout_is_admitted(self):
        product,cohort=data()
        product["candidates"][0]["split"]="test"
        self.assertIn("holdout_not_sealed",screen_product_scope(product,cohort)["errors"])

    def test_wrong_product_mode_not_accepted(self):
        product,cohort=data()
        product["proposed_delivery_mode"]="dump_every_upstream_repository"
        self.assertIn("unsupported_product_mode",screen_product_scope(product,cohort)["errors"])

    def test_source_rights_and_chain_of_custody_are_gates_not_assumptions(self):
        product,cohort=data()
        result=screen_product_scope(product,cohort)
        required=result["release_requirements"]
        self.assertIn("reproduced_original_before_after_witness",required)
        self.assertIn("per_file_spdx_copyright_and_dependency_obligations",required)
        self.assertIn("commercial_license_conditions_for_actual_customer_package",required)
        self.assertIn("sealed_project_and_mechanism_disjoint_holdout",required)
        self.assertIn("scanner_baseline_on_unseen_original_cases",required)


if __name__=="__main__":
    unittest.main()
