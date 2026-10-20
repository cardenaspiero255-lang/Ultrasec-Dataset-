"""TDD: preregister 11 additional CWE-scoped exploratory Semgrep rule files.

These patterns are triage indicators, NOT original CVE detector validation.
Positive/negative *synthetic* fixtures are deliberately not GOLD.
"""
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from premium_evidence import _PINNED_MITRE_CWES
from sast_target_coverage import audit


class TwelveCweExploratoryRulepackTest(unittest.TestCase):
    def plan(self):
        return json.loads((ROOT/'verification/research/FUTURE_UNSEEN_SAST_BYTE_FREEZE_PLAN_V3.json').read_text())

    def test_all_twelve_distinct_cwe_rules_have_pinned_bytes_not_multilabel_one_rule(self):
        plan=self.plan()
        evidence=audit(plan,ROOT)
        self.assertEqual(evidence['target_cwe_count'],12)
        self.assertEqual(evidence['declared_target_cwe_count'],12)
        self.assertEqual(evidence['verified_rule_files'],12)
        self.assertEqual(evidence['missing_target_cwe_count'],0)
        self.assertTrue(evidence['all_researched_public_cves_excluded'])
        self.assertTrue(evidence['complete_declared_byte_scope'])
        self.assertFalse(evidence['scanner_semantics_verified'])
        self.assertFalse(evidence['blind_benchmark_ready'])
        self.assertEqual(evidence['gold_admitted'],0)

    def test_every_new_rule_has_one_synthetic_positive_and_negative_fixture(self):
        plan=self.plan()
        self.assertEqual({e['cwes'][0] for e in plan['entries']},_PINNED_MITRE_CWES)
        ids=set()
        for entry in plan['entries']:
            key=entry['cwes'][0].lower().replace('-','')
            if key=='cwe94':
                continue
            self.assertNotIn(key,ids)
            ids.add(key)
            for suffix in ('positive','negative'):
                matching=list((ROOT/'verification/fixtures/future-sast').glob(f'{key}_{suffix}.*'))
                self.assertEqual(len(matching),1,(key,suffix))
                self.assertGreater(matching[0].stat().st_size,10)
            self.assertTrue(entry['path'].startswith('verification/rules/future-unseen-'))
        self.assertEqual(len(ids),11)

    def test_plan_has_only_one_target_cwe_per_file_and_does_not_claim_gold(self):
        plan=self.plan()
        self.assertEqual(plan['gold_count'],0)
        self.assertEqual(plan['holdout_status'],'UNASSIGNED')
        self.assertIs(plan['scoring_enabled'],False)
        for entry in plan['entries']:
            self.assertEqual(len(entry['cwes']),1)


if __name__=='__main__':
    unittest.main()
