"""Original Gitea nine-file overlay rights inventory: fail closed, never license grants.

Only public Git blob identifiers and pre-existing MIT/NOTICE observations occur
here. No original Go source is copied into this repository.
"""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from gitea_file_rights_gate import validate


def fixture():
    return json.loads((ROOT/'verification/research/GITEA_NINE_FILE_SOURCE_RIGHTS_MANIFEST_20261019.json').read_text())


class GiteaFileRightsGateTest(unittest.TestCase):
    def test_complete_original_overlay_has_nine_exact_rows_but_stays_blocked(self):
        receipt=validate(fixture())
        self.assertEqual(receipt['original_file_rows_inspected'],9)
        self.assertEqual(receipt['upstream_patch_files'],6)
        self.assertEqual(receipt['source_files_per_file_spdx_observed'],5)
        self.assertEqual(receipt['files_commercially_cleared'],0)
        self.assertEqual(receipt['commercially_releasable_files'],0)
        self.assertEqual(receipt['unresolved_couchbase_compiled_files'],4)
        self.assertFalse(receipt['full_source_distribution_allowed'])
        self.assertFalse(receipt['legal_rights_verified'])
        self.assertEqual(receipt['certification'],'NOT_CERTIFIED')

    def test_any_missing_file_is_not_an_inventoried_package(self):
        doc=fixture()
        doc['files'].pop()
        with self.assertRaisesRegex(ValueError,'missing_original_file'):
            validate(doc)

    def test_forged_original_blob_sha_does_not_pass(self):
        doc=fixture()
        doc['files'][0]['fixed_blob_sha']='0'*40
        with self.assertRaisesRegex(ValueError,'blob_mismatch'):
            validate(doc)

    def test_self_claimed_rights_are_never_automatically_cleared(self):
        doc=fixture()
        doc['files'][0]['commercial_rights']='CLEARED'
        with self.assertRaisesRegex(ValueError,'unsupported_rights_claim'):
            validate(doc)

    def test_root_mit_license_never_overrides_couchbase_dependency_bsl(self):
        doc=fixture()
        doc['couchbase_compiled_files_unresolved']=0
        with self.assertRaisesRegex(ValueError,'unsupported_rights_claim'):
            validate(doc)

    def test_template_without_header_cannot_be_mislabeled_as_per_file_spdx(self):
        doc=fixture()
        next(x for x in doc['files'] if x['path'].endswith('new.tmpl'))['license_evidence']='SPDX_MIT_PER_FILE'
        with self.assertRaisesRegex(ValueError,'original_license_classification_changed'):
            validate(doc)


if __name__=='__main__':
    unittest.main()
