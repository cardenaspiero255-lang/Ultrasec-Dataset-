"""Synthetic TDD: actual training bytes, logs, and checkpoints must exist.

Synthetic files are deliberately not an actual model or authentic training
receipt. No privately owned TRAIN sample is included in this test.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from training_original_artifact_bytes import inspect_original_bytes


def fixture(root):
    sha=lambda v:hashlib.sha256(v).hexdigest()
    (root/'evidence').mkdir()
    src=b'print("synthetic trainer")\n'
    checkpoint=b'synthetic non-model checkpoint'
    consumed=[sha(b'synthetic-case-a'),sha(b'synthetic-case-b')]
    (root/'evidence/trainer.py').write_bytes(src)
    (root/'evidence/model.bin').write_bytes(checkpoint)
    event={'schema':'ultrasec.training-consumption-event.v1','run_id':'synthetic-run',
           'checkpoint_sha256':sha(checkpoint),'parent_checkpoint_sha256':None,
           'consumed_case_fingerprints':consumed}
    log=root/'evidence/run.jsonl'
    log.write_text(json.dumps(event)+'\n')
    return {'schema':'ultrasec.owner-training-lineage.v1',
      'scope':'OWNER_PRIVATE_RUN_RECEIPTS_ONLY','independent_authenticity_verified':False,
      'final_checkpoint_sha256':sha(checkpoint),
      'runs':[{'run_id':'synthetic-run','parent_checkpoint_sha256':None,
        'checkpoint_sha256':sha(checkpoint),'trainer_source_sha256':sha(src),
        'run_log_sha256':sha(log.read_bytes()),'consumed_case_fingerprints':consumed,
        'trainer_source_file':'evidence/trainer.py','run_log_file':'evidence/run.jsonl',
        'checkpoint_file':'evidence/model.bin'}]}


class OriginalTrainingBytesTest(unittest.TestCase):
    def test_synthetic_file_bytes_are_consistent_but_never_certified(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);proof=fixture(root);r=inspect_original_bytes(proof,root)
            self.assertTrue(r['original_byte_digests_match'])
            self.assertTrue(r['original_log_consumption_matches'])
            self.assertEqual(r['run_artifact_files_verified'],3)
            self.assertEqual(r['logged_distinct_training_fingerprints'],2)
            self.assertFalse(r['proof_of_actual_model_input_consumption'])
            self.assertFalse(r['holdout_admission_allowed'])
            self.assertEqual(r['gold_admitted'],0)
            self.assertNotIn('synthetic-run',str(r))

    def test_missing_checkpoint_fails_even_with_a_declared_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);proof=fixture(root)
            (root/'evidence/model.bin').unlink()
            with self.assertRaisesRegex(ValueError,'missing_original_artifact'):
                inspect_original_bytes(proof,root)

    def test_changed_checkpoint_is_not_original_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);proof=fixture(root)
            (root/'evidence/model.bin').write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError,'artifact_digest_mismatch'):
                inspect_original_bytes(proof,root)

    def test_unstructured_log_does_not_prove_consumed_inputs(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);proof=fixture(root)
            log=root/'evidence/run.jsonl';log.write_text('Training completed!\n')
            proof['runs'][0]['run_log_sha256']=hashlib.sha256(log.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError,'missing_machine_readable_consumption_event'):
                inspect_original_bytes(proof,root)

    def test_claimed_extra_training_sample_not_in_original_log_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);proof=fixture(root)
            proof['runs'][0]['consumed_case_fingerprints'].append('f'*64)
            with self.assertRaisesRegex(ValueError,'consumption_log_mismatch'):
                inspect_original_bytes(proof,root)

    def test_forged_log_checkpoint_cannot_be_accepted_even_if_hash_is_updated(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);proof=fixture(root)
            log=root/'evidence/run.jsonl'
            obj=json.loads(log.read_text());obj['checkpoint_sha256']='f'*64
            log.write_text(json.dumps(obj)+'\n')
            proof['runs'][0]['run_log_sha256']=hashlib.sha256(log.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError,'consumption_log_mismatch'):
                inspect_original_bytes(proof,root)

    def test_symlink_and_path_traversal_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);proof=fixture(root)
            proof['runs'][0]['checkpoint_file']='../external.bin'
            with self.assertRaisesRegex(ValueError,'unsafe_original_artifact_path'):
                inspect_original_bytes(proof,root)
            proof['runs'][0]['checkpoint_file']='evidence/model.bin'
            (root/'evidence/model.bin').unlink()
            (root/'evidence/model.bin').symlink_to(root/'evidence/trainer.py')
            with self.assertRaisesRegex(ValueError,'unsafe_original_artifact_path'):
                inspect_original_bytes(proof,root)

    def test_missing_checkpoint_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);proof=fixture(root)
            proof['runs'][0].pop('checkpoint_file')
            with self.assertRaisesRegex(ValueError,'unsafe_original_artifact_path'):
                inspect_original_bytes(proof,root)


if __name__=='__main__':
    unittest.main()
