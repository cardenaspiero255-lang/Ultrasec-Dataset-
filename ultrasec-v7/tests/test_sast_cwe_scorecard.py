"""Synthetic-only tests for SAST confusion metrics per CWE.

No real private holdout or scored benchmark is processed here.
"""
import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sast_cwe_scorecard import calculate_diagnostic
from premium_evidence import _PINNED_MITRE_CWES
TARGET_CWES=sorted(_PINNED_MITRE_CWES)


def balanced_fixture():
    gold = []
    for i in range(120):
        gold.append({
          'record_id':f'synth-{i:03d}', 'split':'test',
          'cwe_id':TARGET_CWES[i % 12],
          'expected_vulnerable':bool((i//12)%2)
        })
    preds=[{'record_id':r['record_id'],
            'predicted_vulnerable':r['expected_vulnerable']} for r in gold]
    return gold,preds


class DiagnosticPerCweScorerTests(unittest.TestCase):
    def test_12_cwes_positive_and_negative_can_be_scored_only_as_diagnostic(self):
        gold,preds=balanced_fixture()
        report=calculate_diagnostic(gold,preds)
        self.assertTrue(report['arithmetic_valid'])
        self.assertEqual(report['tested_rows'],120)
        self.assertEqual(report['evaluated_cwes'],12)
        self.assertEqual(report['overall']['tp']+report['overall']['tn'],120)
        self.assertEqual(report['overall']['fp'],0)
        self.assertEqual(report['overall']['fn'],0)
        self.assertEqual(report['micro_metrics']['f1'],1)
        self.assertEqual(report['macro_metrics']['f1'],1)
        self.assertFalse(report['blind_benchmark_accredited'])
        self.assertFalse(report['publishable_result'])
        self.assertEqual(report['certification'],'NOT_CERTIFIED')

    def test_corrupted_predictions_produce_distinct_fp_fn_per_cwe(self):
        gold,preds=balanced_fixture()
        positive=next(r for r in gold if r['expected_vulnerable'])
        negative=next(r for r in gold if not r['expected_vulnerable'])
        for p in preds:
            if p['record_id']==positive['record_id']:
                p['predicted_vulnerable']=False
            elif p['record_id']==negative['record_id']:
                p['predicted_vulnerable']=True
        report=calculate_diagnostic(gold,preds)
        self.assertEqual(report['overall']['fn'],1)
        self.assertEqual(report['overall']['fp'],1)
        self.assertEqual(sum(row['fn'] for row in report['by_cwe']),1)
        self.assertEqual(sum(row['fp'] for row in report['by_cwe']),1)

    def test_too_few_rows_are_not_scored(self):
        gold,preds=balanced_fixture()
        result=calculate_diagnostic(gold[:96],preds[:96])
        self.assertFalse(result['arithmetic_valid'])
        self.assertIn('insufficient_test_rows',result['failures'])
        self.assertEqual(result['by_cwe'],[])

    def test_less_than_12_cwes_are_not_scored(self):
        gold,preds=balanced_fixture()
        for g in gold:
            if g['cwe_id']==TARGET_CWES[-1]:g['cwe_id']=TARGET_CWES[0]
        result=calculate_diagnostic(gold,preds)
        self.assertIn('insufficient_cwes',result['failures'])
        self.assertEqual(result['by_cwe'],[])

    def test_twelve_arbitrary_easy_cwes_cannot_replace_pinned_target_families(self):
        gold,preds=balanced_fixture()
        for i,g in enumerate(gold):
            g['cwe_id']=f'CWE-{100+(i%12)}'
        result=calculate_diagnostic(gold,preds)
        self.assertIn('missing_pinned_cwe_family',result['failures'])
        self.assertFalse(result['arithmetic_valid'])

    def test_single_class_in_any_cwe_is_not_scored(self):
        gold,preds=balanced_fixture()
        for g in gold:
            if g['cwe_id']==TARGET_CWES[0]:g['expected_vulnerable']=True
        result=calculate_diagnostic(gold,preds)
        self.assertIn('cwe_without_both_classes',result['failures'])

    def test_duplicate_missing_and_extra_prediction_ids_block(self):
        gold,preds=balanced_fixture()
        duplicate=calculate_diagnostic(gold,preds+[dict(preds[0])])
        self.assertIn('duplicate_prediction',duplicate['failures'])
        missing=calculate_diagnostic(gold,preds[:-1])
        self.assertIn('missing_prediction',missing['failures'])
        unknown=calculate_diagnostic(gold,preds+[{'record_id':'unknown','predicted_vulnerable':False}])
        self.assertIn('unknown_prediction',unknown['failures'])

    def test_record_identifiers_never_leave_aggregate_report(self):
        gold,preds=balanced_fixture()
        report=calculate_diagnostic(gold,preds)
        self.assertNotIn('synth-001',str(report))
        self.assertNotIn('record_id',str(report))

if __name__=='__main__':
    unittest.main()
