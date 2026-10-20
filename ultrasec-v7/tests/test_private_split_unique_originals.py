"""TDD: 100 TRAIN and 100 TEST must not be inflated by repeated original pairs.

These fixtures are synthetic. No private originals, CVEs or holdout labels.
"""
import unittest
from test_private_training_disjointness import healthy, module


class OriginalPairUniquenessTest(unittest.TestCase):
    def screen(self, train, test):
        return module.audit(train, test, minimum_train=2, minimum_test=2,
                            minimum_cwes=1)

    def test_reused_training_case_id_cannot_count_twice(self):
        train, test = healthy()
        train[1]['case_id'] = train[0]['case_id']
        report = self.screen(train, test)
        self.assertIn('duplicate_train_case_id', report['failures'])
        self.assertFalse(report['metadata_separation_pass'])

    def test_training_pair_reused_under_new_case_and_project_is_not_independent(self):
        train, test = healthy()
        train[1]['source_commit'] = train[0]['source_commit']
        train[1]['fix_commit'] = train[0]['fix_commit']
        report = self.screen(train, test)
        self.assertIn('duplicate_train_original_pair', report['failures'])
        self.assertFalse(report['metadata_separation_pass'])

    def test_training_original_content_reused_under_another_cve_is_not_independent(self):
        train, test = healthy()
        train[1]['source_sha256'] = train[0]['source_sha256']
        train[1]['fix_sha256'] = train[0]['fix_sha256']
        report = self.screen(train, test)
        self.assertIn('duplicate_train_content_pair', report['failures'])

    def test_test_original_content_pair_reused_across_different_projects(self):
        train, test = healthy()
        test[1]['source_sha256'] = test[0]['source_sha256']
        test[1]['fix_sha256'] = test[0]['fix_sha256']
        report = self.screen(train, test)
        self.assertIn('duplicate_test_content_pair', report['failures'])

    def test_source_content_used_as_other_fix_requires_holdout_grouping(self):
        train, test = healthy()
        test[1]['source_sha256'] = test[0]['fix_sha256']
        report = self.screen(train, test)
        self.assertIn('shared_test_content_requires_grouping', report['failures'])

    def test_valid_distinct_originals_still_pass_metadata_only(self):
        train, test = healthy()
        report = self.screen(train, test)
        self.assertTrue(report['metadata_separation_pass'])
        self.assertFalse(report['causal_independence_certified'])
        self.assertFalse(report['blind_benchmark_ready'])


if __name__ == '__main__':
    unittest.main()
