"""Synthetic TDD for keeping owner-only historical 37 CVEs out of future holdout.

Does NOT upload or embed the real owner library file. This is a fail-closed
metadata screening contract, not independent gold or scanner accreditation.
"""
import hashlib
import unittest
from test_private_training_disjointness import healthy, module


def history():
    rows=[]
    for i in range(37):
        rows.append({
            'schema':'ultrasec.public-cve-candidate.v1',
            'admission_status':'NOT_ADMITTED',
            'commercial_rights':'NOT_VERIFIED',
            'cve_id':f'CVE-2026-{60000+i}',
            'repo_url':f'https://github.com/history/private-reference-{i}',
            'fix_commit':hashlib.sha1(f'fixed-{i}'.encode()).hexdigest(),
        })
    return rows


class PrivatePriorResearchDisjointnessTest(unittest.TestCase):
    def screen(self, prior):
        train,test=healthy()
        return module.audit_with_history(train,test,prior,
                minimum_train=2,minimum_test=2,minimum_cwes=1,minimum_history=37)

    def test_original_private_cve_seen_in_test_cannot_be_reused(self):
        h=history()
        h[0]['cve_id']='CVE-2025-30003'
        r=self.screen(h)
        self.assertIn('private_history_cve_overlap',r['failures'])
        self.assertFalse(r['metadata_separation_pass'])

    def test_same_old_project_alias_is_rejected_even_with_new_cve(self):
        h=history()
        h[0]['repo_url']='https://GITHUB.COM/example/testone.git/'
        r=self.screen(h)
        self.assertIn('private_history_project_overlap',r['failures'])

    def test_complete_37_record_private_history_is_checked_without_gold_claim(self):
        r=self.screen(history())
        self.assertTrue(r['metadata_separation_pass'])
        self.assertEqual(r['private_prior_research_rows_checked'],37)
        self.assertGreaterEqual(r['known_research_cves_excluded'],100)
        self.assertFalse(r['causal_independence_certified'])
        self.assertFalse(r['blind_benchmark_ready'])
        self.assertEqual(r['gold_admitted'],0)
        self.assertNotIn('private-reference-',str(r))

    def test_short_or_duplicate_history_is_rejected(self):
        h=history()
        self.assertIn('insufficient_private_history',self.screen(h[:-1])['failures'])
        h[1]['cve_id']=h[0]['cve_id']
        self.assertIn('duplicate_private_history_cve',self.screen(h)['failures'])

    def test_not_admitted_provenance_cannot_be_turned_into_gold(self):
        h=history()
        h[0]['admission_status']='GOLD_ADMITTED'
        self.assertIn('invalid_private_history_record',self.screen(h)['failures'])

    def test_unsafe_original_project_url_is_blocked(self):
        h=history()
        h[0]['repo_url']='http://example.invalid/training'
        self.assertIn('invalid_private_history_record',self.screen(h)['failures'])


if __name__=='__main__':
    unittest.main()
