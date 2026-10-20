"""Synthetic TDD for the fixed twelve-CWE private TRAIN/TEST admission threshold.

Twenty-four synthetic TEST records across twelve pinned CWE, each with one
positive and one negative. These are not genuine labels or source oracles.
"""
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from premium_evidence import _PINNED_MITRE_CWES
from test_private_training_disjointness import module, sample


def cohort():
    targets=sorted(_PINNED_MITRE_CWES)
    train=[sample(700,'https://github.com/owner/train-first','train'),
           sample(701,'https://github.com/owner/train-second','train',True)]
    test=[]
    for idx,cwe in enumerate(targets):
        for positive in (False,True):
            n=1000+2*idx+int(positive)
            test.append(sample(n,f'https://github.com/owner/original-{n}',
                               'test',positive,cwe))
    return train,test


class PinnedPrivateCweAdmissionTest(unittest.TestCase):
    def audit(self,train,test):
        return module.audit(train,test,minimum_train=2,minimum_test=24,minimum_cwes=12)

    def test_all_pinned_twelve_with_two_classes_pass_metadata_only(self):
        train,test=cohort()
        report=self.audit(train,test)
        self.assertTrue(report['metadata_separation_pass'])
        self.assertEqual(report['test_cwes_checked'],12)
        self.assertFalse(report['causal_independence_certified'])

    def test_twelve_other_cwes_must_not_substitute_one_required_family(self):
        train,test=cohort()
        missing=sorted(_PINNED_MITRE_CWES)[0]
        for item in test:
            if item['cwe_id']==missing:
                item['cwe_id']='CWE-200'
        report=self.audit(train,test)
        self.assertEqual(report['test_cwes_checked'],12)
        self.assertIn('missing_pinned_test_cwe',report['failures'])
        self.assertFalse(report['metadata_separation_pass'])

    def test_non_balanced_target_cwe_is_rejected(self):
        train,test=cohort()
        missing=sorted(_PINNED_MITRE_CWES)[0]
        for item in test:
            if item['cwe_id']==missing:
                item['vulnerable']=True
        report=self.audit(train,test)
        self.assertIn('test_cwe_without_both_classes',report['failures'])


if __name__=='__main__':
    unittest.main()
