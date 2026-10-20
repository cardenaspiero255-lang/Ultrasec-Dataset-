"""Synthetic-only exposure tests; never publish real holdout rows."""
import hashlib
import importlib.util
import unittest
from pathlib import Path

SRC=Path(__file__).resolve().parents[1]/'tools'/'future_holdout_exposure.py'
spec=importlib.util.spec_from_file_location('future_holdout_exposure',SRC)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def row(i,url):
    h=lambda x:hashlib.sha256(x.encode()).hexdigest()
    return {'case_id':f'opaque-{i}', 'cve_id':f'CVE-2026-{11000+i}',
            'project_fingerprint':module.project_fingerprint(url),
            'mechanism_fingerprint':h('mechanism-'+str(i)),
            'source_commit':hashlib.sha1(f'before-{i}'.encode()).hexdigest(),
            'fix_commit':hashlib.sha1(f'after-{i}'.encode()).hexdigest(),
            'source_sha256':h('before-'+str(i)), 'fix_sha256':h('after-'+str(i))}


class FutureHoldoutExposureTest(unittest.TestCase):
    def test_known_gitea_project_alias_is_excluded_even_when_cve_changes(self):
        rows=[row(1,'https://GITHUB.COM/GO-GITEA/GITEA.git/')]
        r=module.screen(rows)
        self.assertIn('previously_studied_project',r['failures'])
        self.assertFalse(r['candidate_metadata_screen_pass'])

    def test_known_bulgarisation_cve_is_excluded_despite_other_project(self):
        rows=[row(2,'https://github.com/example/unknown-demo')]
        rows[0]['cve_id']='CVE-2024-2395'
        r=module.screen(rows)
        self.assertIn('previously_studied_cve',r['failures'])

    def test_future_candidate_is_only_prepared_not_independently_admitted(self):
        r=module.screen([row(3,'https://github.com/example/never-studied')])
        self.assertTrue(r['candidate_metadata_screen_pass'])
        self.assertFalse(r['independence_verified'])
        self.assertFalse(r['holdout_assigned'])
        self.assertEqual(r['gold_admitted'],0)
        self.assertNotIn('opaque-3',str(r))

    def test_same_project_under_two_cves_must_be_grouped(self):
        r=module.screen([row(4,'https://github.com/example/independent'),
                         row(5,'https://github.com/example/independent')])
        self.assertIn('reused_project_requires_grouping',r['failures'])

    def test_same_mechanism_across_distinct_projects_requires_grouping(self):
        a=row(6,'https://github.com/example/new1')
        b=row(7,'https://github.com/example/new2')
        b['mechanism_fingerprint']=a['mechanism_fingerprint']
        self.assertIn('reused_mechanism_requires_grouping',module.screen([a,b])['failures'])

    def test_duplicate_original_pair_is_not_two_distinct_examples(self):
        a=row(8,'https://github.com/example/new3')
        b=row(9,'https://github.com/example/new4')
        b['source_commit']=a['source_commit']; b['fix_commit']=a['fix_commit']
        self.assertIn('duplicate_original_pair',module.screen([a,b])['failures'])

    def test_empty_rows_never_yield_benchmark_ready(self):
        r=module.screen([])
        self.assertFalse(r['candidate_metadata_screen_pass'])
        self.assertIn('no_candidate_metadata',r['failures'])

    def test_source_urls_are_not_leaked_from_reporting(self):
        r=module.screen([row(10,'https://github.com/example/new5')])
        self.assertNotIn('example/new5',str(r))


if __name__=='__main__':unittest.main()
