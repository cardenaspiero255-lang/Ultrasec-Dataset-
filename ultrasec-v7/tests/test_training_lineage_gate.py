"""Synthetic TDD for fully enumerating training samples from checkpoint lineage.

A pass means structural equality with claimed run receipts. It does NOT
authenticate owner run receipts or prove completeness against undocumented runs.
No owner-private train, cases, case IDs or checkpoints are included.
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from test_private_training_disjointness import sample
from training_lineage_gate import inspect, fingerprint


def rows():
    return [
        sample(901,'https://github.com/example/source-genesis','train'),
        sample(902,'https://github.com/example/source-append','train',True)
    ]


def lineage(entries):
    sha=lambda s: hashlib.sha256(s.encode()).hexdigest()
    return {
      'schema':'ultrasec.owner-training-lineage.v1',
      'scope':'OWNER_PRIVATE_RUN_RECEIPTS_ONLY',
      'final_checkpoint_sha256':'c'*64,
      'independent_authenticity_verified':False,
      'runs':[
        {'run_id':'synthetic-genesis','parent_checkpoint_sha256':None,
         'checkpoint_sha256':'b'*64,
         'trainer_source_sha256':sha('trainer1'),'run_log_sha256':sha('log1'),
         'completed_at_utc':'2026-10-01T12:00:00Z',
         'consumed_case_fingerprints':[fingerprint(entries[0])]},
        {'run_id':'synthetic-continuation','parent_checkpoint_sha256':'b'*64,
         'checkpoint_sha256':'c'*64,
         'trainer_source_sha256':sha('trainer2'),'run_log_sha256':sha('log2'),
         'completed_at_utc':'2026-10-02T12:00:00Z',
         'consumed_case_fingerprints':[fingerprint(entries[1])]}
      ]
    }


class TrainingLineageGateTests(unittest.TestCase):
    def test_exactly_reconciled_two_ancestor_runs_only_yield_structural_status(self):
        train=rows()
        r=inspect(train,lineage(train),minimum_train=2)
        self.assertTrue(r['training_samples_match_declared_run_receipts'])
        self.assertTrue(r['training_checkpoint_chain_closed'])
        self.assertEqual(r['unique_training_records'],2)
        self.assertEqual(r['training_run_count'],2)
        self.assertFalse(r['complete_training_history_externally_attested'])
        self.assertFalse(r['holdout_admission_allowed'])
        self.assertEqual(r['gold_admitted'],0)

    def test_missing_first_training_run_is_rejected_even_when_final_checkpoint_matches(self):
        train=rows();proof=lineage(train)
        proof['runs'].pop(0)
        r=inspect(train,proof,minimum_train=2)
        self.assertFalse(r['training_checkpoint_chain_closed'])
        self.assertIn('missing_genesis_or_parent_checkpoint',r['failures'])

    def test_omitted_training_record_from_export_is_rejected(self):
        train=rows()
        r=inspect(train[:1],lineage(train),minimum_train=1)
        self.assertFalse(r['training_samples_match_declared_run_receipts'])
        self.assertIn('missing_exported_training_case',r['failures'])

    def test_extra_training_record_without_run_receipt_is_rejected(self):
        train=rows();receipt=lineage(train[:])
        train.append(sample(903,'https://github.com/example/unaccounted','train'))
        r=inspect(train,receipt,minimum_train=2)
        self.assertIn('training_record_without_run_receipt',r['failures'])

    def test_unauthenticated_claim_of_external_verification_is_rejected(self):
        train=rows();proof=lineage(train)
        proof['independent_authenticity_verified']=True
        r=inspect(train,proof,minimum_train=2)
        self.assertIn('unsupported_external_authenticity_claim',r['failures'])
        self.assertFalse(r['holdout_admission_allowed'])

    def test_forged_checkpoint_ancestry_is_blocked(self):
        train=rows();proof=lineage(train)
        proof['runs'][1]['parent_checkpoint_sha256']='f'*64
        r=inspect(train,proof,minimum_train=2)
        self.assertIn('broken_checkpoint_chain',r['failures'])

    def test_under_threshold_cannot_claim_real_train(self):
        train=rows()
        r=inspect(train,lineage(train))
        self.assertIn('insufficient_train',r['failures'])

    def test_duplicate_train_identity_is_rejected_even_across_run_receipts(self):
        train=rows();train[1]['case_id']=train[0]['case_id']
        r=inspect(train,lineage(train),minimum_train=2)
        self.assertIn('duplicate_train_case_id',r['failures'])

    def test_aggregate_receipt_cannot_disclose_case_identifier(self):
        train=rows();r=inspect(train,lineage(train),minimum_train=2)
        self.assertNotIn('synthetic-901',str(r))
        self.assertNotIn('synthetic-genesis',str(r))
        self.assertNotIn('example/source-',str(r))


if __name__=='__main__':
    unittest.main()
