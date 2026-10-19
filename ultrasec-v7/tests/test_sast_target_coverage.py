"""Research-only scope accounting for all 12 MITRE target CWE.

Never represents scanner recall, original holdout quality or commercial rights.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from premium_evidence import _PINNED_MITRE_CWES
from sast_target_coverage import audit
from test_sast_ruleset_freeze import fixture


class FullSastScopePreRegistrationTest(unittest.TestCase):
    def test_current_real_ruleset_has_11_missing_cwe_and_55_unexcluded_public_cve(self):
        plan=json.loads((ROOT/'verification/research/FUTURE_UNSEEN_SAST_BYTE_FREEZE_PLAN.json').read_text())
        report=audit(plan,ROOT)
        self.assertEqual(report['target_cwe_count'],12)
        self.assertEqual(report['declared_target_cwe_count'],1)
        self.assertEqual(report['missing_target_cwe_count'],11)
        self.assertEqual(report['researched_public_cves'],63)
        self.assertFalse(report['all_researched_public_cves_excluded'])
        self.assertFalse(report['complete_declared_byte_scope'])
        self.assertFalse(report['blind_benchmark_ready'])
        self.assertEqual(report['gold_admitted'],0)

    def test_v2_exclusions_include_every_public_studied_cve_and_other_known_case(self):
        p=ROOT/'verification/research/FUTURE_UNSEEN_SAST_BYTE_FREEZE_PLAN_V2.json'
        plan=json.loads(p.read_text())
        receipt=audit(plan,ROOT)
        self.assertTrue(receipt['all_researched_public_cves_excluded'])
        self.assertEqual(receipt['excluded_researched_public_cves'],63)
        self.assertGreaterEqual(len(plan['known_case_exclusions']),70)
        self.assertEqual(receipt['missing_target_cwe_count'],11)
        self.assertFalse(receipt['blind_benchmark_ready'])

    def test_single_rule_cannot_falsely_cover_all_twelve_cwe_by_claim(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            plan=fixture(root)
            plan['entries'][0]['cwes']=sorted(_PINNED_MITRE_CWES)
            with self.assertRaisesRegex(ValueError,'ambiguous_multi_cwe_rule_claim'):
                audit(plan,root)

    def test_distinct_twelve_rule_bytes_still_not_a_gold_benchmark(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            plan=fixture(root)
            entries=[]
            for idx,cwe in enumerate(sorted(_PINNED_MITRE_CWES)):
                name=f'rules/rule-{idx}.yml'
                payload=f'# synthetic {cwe}\nrules:\n  - id: test-{idx}\n    languages: [python]\n    severity: WARNING\n    message: test\n    pattern: exec($X)\n'.encode()
                (root/name).write_bytes(payload)
                entries.append({'tool':'semgrep','version':'1.180.0','path':name,
                                'sha256':hashlib.sha256(payload).hexdigest(),'cwes':[cwe]})
            plan['entries']=entries
            # Even all declarations do NOT verify rule behavior, pin all public
            # excluded identifiers, or establish holdout chronology.
            report=audit(plan,root)
            self.assertEqual(report['missing_target_cwe_count'],0)
            self.assertTrue(report['complete_declared_byte_scope'])
            self.assertFalse(report['all_researched_public_cves_excluded'])
            self.assertFalse(report['scanner_semantics_verified'])
            self.assertFalse(report['blind_benchmark_ready'])

    def test_actual_rule_byte_tampering_still_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            plan=fixture(root)
            (root/'rules/rule.yml').write_text('rules: []')
            with self.assertRaisesRegex(ValueError,'digest_mismatch'):
                audit(plan,root)


if __name__=='__main__':
    unittest.main()
