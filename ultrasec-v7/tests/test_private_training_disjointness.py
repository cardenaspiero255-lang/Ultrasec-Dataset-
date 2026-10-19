"""Training-vs-holdout metadata separation regressions: no private code/labels."""
import hashlib
import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]/'tools'
SCRIPT=ROOT/'private_training_disjointness.py'
spec=importlib.util.spec_from_file_location('training_holdout_disjointness',SCRIPT)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def sample(i,project,split,vulnerable=False,cwe='CWE-22'):
    from future_holdout_exposure import project_fingerprint
    h=lambda s: hashlib.sha256(s.encode()).hexdigest()
    hs=lambda s: hashlib.sha1(s.encode()).hexdigest()
    return {
      'case_id':f'synthetic-{i}', 'project_url':project,
      'project_fingerprint':project_fingerprint(project), 'cve_id':f'CVE-2025-{30000+i}',
      'cwe_id':cwe, 'mechanism_fingerprint':h(f'mechanism-{i}'),
      'source_commit':hs(f'src-{i}'),'fix_commit':hs(f'fix-{i}'),
      'source_sha256':h(f'src-bytes-{i}'),'fix_sha256':h(f'fix-bytes-{i}'),
      'oracle_type':'ORIGINAL_RED_GREEN_TEST','oracle_run_sha256':h(f'log-{i}'),
      'split':split,'vulnerable':vulnerable,
    }


def healthy():
    train=[sample(1,'https://github.com/example/trainone','train'),
           sample(2,'https://github.com/example/traintwo','train',True)]
    test=[sample(3,'https://github.com/example/testone','test'),
          sample(4,'https://github.com/example/testtwo','test',True)]
    return train,test


class PrivateTrainingDisjointnessTest(unittest.TestCase):
    def run_screen(self,train,test):
        return module.audit(train,test,minimum_train=2,minimum_test=2,minimum_cwes=1)

    def test_disjoint_inputs_only_pass_metadata_not_gold(self):
        train,test=healthy()
        r=self.run_screen(train,test)
        self.assertTrue(r['metadata_separation_pass'])
        self.assertFalse(r['causal_independence_certified'])
        self.assertFalse(r['blind_benchmark_ready'])
        self.assertFalse(r['scanner_execution_verified'])
        self.assertEqual(r['gold_admitted'],0)
        self.assertEqual(r['certification'],'NOT_CERTIFIED')

    def test_project_alias_reused_across_splits_is_rejected(self):
        train,test=healthy()
        test[0]['project_url']='https://GITHUB.COM/example/trainone.git/'
        from future_holdout_exposure import project_fingerprint
        test[0]['project_fingerprint']=project_fingerprint(test[0]['project_url'])
        self.assertIn('project_overlap',self.run_screen(train,test)['failures'])

    def test_same_mechanism_across_projects_is_rejected(self):
        train,test=healthy();test[0]['mechanism_fingerprint']=train[0]['mechanism_fingerprint']
        self.assertIn('mechanism_overlap',self.run_screen(train,test)['failures'])

    def test_same_content_crosses_splits_even_if_new_commit(self):
        train,test=healthy();test[0]['source_sha256']=train[0]['fix_sha256']
        self.assertIn('content_overlap',self.run_screen(train,test)['failures'])

    def test_reused_fix_commit_is_rejected_even_if_new_cve(self):
        train,test=healthy();test[0]['source_commit']=train[1]['fix_commit']
        self.assertIn('commit_overlap',self.run_screen(train,test)['failures'])

    def test_cve_alias_known_gladys_is_excluded(self):
        train,test=healthy();test[0]['cve_id']='CVE-2023-43256'
        self.assertIn('known_research_cve',self.run_screen(train,test)['failures'])

    def test_known_misp_project_is_excluded_even_under_new_cve(self):
        train,test=healthy();test[0]['project_url']='https://github.com/MISP/cti-transmute'
        from future_holdout_exposure import project_fingerprint
        test[0]['project_fingerprint']=project_fingerprint(test[0]['project_url'])
        self.assertIn('known_research_project',self.run_screen(train,test)['failures'])

    def test_forged_project_hash_is_rejected(self):
        train,test=healthy();test[0]['project_fingerprint']='a'*64
        self.assertIn('project_fingerprint_mismatch',self.run_screen(train,test)['failures'])

    def test_missing_oracle_is_rejected(self):
        train,test=healthy();test[0]['oracle_run_sha256']='bad'
        self.assertIn('invalid_record',self.run_screen(train,test)['failures'])

    def test_no_actual_cases_fail_closed(self):
        r=module.audit([],[],minimum_train=2,minimum_test=2,minimum_cwes=1)
        self.assertFalse(r['metadata_separation_pass'])
        self.assertIn('insufficient_train',r['failures'])
        self.assertIn('insufficient_test',r['failures'])

    def test_study_case_id_not_emitted(self):
        train,test=healthy()
        self.assertNotIn('synthetic-3',str(self.run_screen(train,test)))
        self.assertNotIn('example/testone',str(self.run_screen(train,test)))


if __name__=='__main__':unittest.main()
