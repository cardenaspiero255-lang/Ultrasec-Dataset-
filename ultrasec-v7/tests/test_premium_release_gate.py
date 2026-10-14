"""False-positive-resistant enterprise readiness evaluation with synthetic fixtures."""
import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]/"tools"/"premium_release_gate.py"
spec=importlib.util.spec_from_file_location("premium_release_gate",ROOT)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PremiumReleaseGates(unittest.TestCase):
    def test_historical_million_is_not_150k_commercially_ready(self):
        report=module.evaluate_readiness({
          "corpus":{"records":1000000,"exact_sha256_unique":1000000,
                    "split_leaks":0,"lexical_patterns":11280},
          "independent":{"confirmed_real_world_cases":0,
                         "qualified_independent_reviewers":0,"reviewer_agreement":None},
          "benchmark":{"baseline_real_executions":False,"low_recall_cwes":12},
          "legal":{"redistribution_rights_verified":False},
          "ci":{"total":17,"passed":17,"unresolved_codex":0},
          "buyer":{"signed_150k_offer":False},
        })
        self.assertFalse(report["technical_release_ready"])
        self.assertIn("lexical_diversity_not_proven",report["blockers"])
        self.assertIn("independent_review_missing",report["blockers"])
        self.assertEqual(report["commercial_value_usd_150k"],"NOT_VERIFIED")

    def test_even_all_technical_targets_do_not_constitute_a_sale(self):
        r=module.evaluate_readiness({
          "corpus":{"records":1000000,"exact_sha256_unique":1000000,
                    "split_leaks":0,"lexical_patterns":250000},
          "independent":{"confirmed_real_world_cases":100,
                         "qualified_independent_reviewers":2,"reviewer_agreement":0.86,
                         "adjudication_unresolved":0,"adjudication_complete_signed":True},
          "benchmark":{"baseline_real_executions":True,"low_recall_cwes":0},
          "legal":{"redistribution_rights_verified":True},
          "ci":{"total":17,"passed":17,"unresolved_codex":0},
          "buyer":{"signed_150k_offer":False},
        })
        self.assertTrue(r["technical_release_ready"])
        self.assertEqual(r["commercial_value_usd_150k"],"NOT_VERIFIED")
        self.assertIn("buyer_offer_missing",r["commercial_blockers"])

    def test_exactly_eighty_percent_is_not_more_than_eighty(self):
        r=module.evaluate_readiness({"independent":{"confirmed_real_world_cases":100,
                     "qualified_independent_reviewers":2,"reviewer_agreement":0.8}})
        self.assertIn("reviewer_agreement_below_target",r["blockers"])

    def test_cannot_misrepresent_missing_data_as_pass(self):
        r=module.evaluate_readiness({})
        self.assertFalse(r["technical_release_ready"])
        self.assertEqual(r["certification"],"NOT_CERTIFIED")
        self.assertTrue(r["blockers"])


if __name__=="__main__":
    unittest.main()
