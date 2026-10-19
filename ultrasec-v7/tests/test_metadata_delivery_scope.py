"""TDD for byte-specific metadata-only shipping scope (NO legal clearance).

Checks selected public bytes and lists blockers. Neither test grants rights.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT / 'tools'))
from verify_metadata_delivery_scope import inspect_scope

MANIFEST = ROOT / 'verification/research/DELIVERY_SCOPE_PUBLIC_METADATA_DRAFT.json'


class MetadataDeliveryScopeTests(unittest.TestCase):
    def test_real_pinned_original_research_files_remain_blocked_for_sale(self):
        plan = json.loads(MANIFEST.read_text(encoding='utf-8'))
        report = inspect_scope(plan, ROOT)
        self.assertTrue(report['file_bytes_match_pins'])
        self.assertEqual(report['files_inspected'],5)
        self.assertFalse(report['commercial_distribution_allowed'])
        self.assertFalse(report['source_content_free_verified'])
        self.assertFalse(report['legal_rights_verified'])
        self.assertEqual(report['status'],'METADATA_SCOPE_VERIFIED_RIGHTS_UNRESOLVED')
        self.assertEqual(report['commercial_rights_by_file_unverified'],5)

    def test_tampered_pinned_git_blob_is_rejected(self):
        plan = json.loads(MANIFEST.read_text(encoding='utf-8'))
        plan['files'][0]['git_blob_sha1']='a'*40
        with self.assertRaisesRegex(ValueError,'blob_mismatch'):
            inspect_scope(plan,ROOT)

    def test_path_traversal_and_source_file_extensions_fail_closed(self):
        plan = json.loads(MANIFEST.read_text(encoding='utf-8'))
        plan['files'][0]['path']='../module.go'
        with self.assertRaisesRegex(ValueError,'unsafe_delivery_path'):
            inspect_scope(plan,ROOT)
        plan['files'][0]['path']='verification/research/gitea_original.go'
        with self.assertRaisesRegex(ValueError,'unsafe_delivery_path'):
            inspect_scope(plan,ROOT)

    def test_duplicate_manifest_files_cannot_masquerade_as_full_scope(self):
        plan = json.loads(MANIFEST.read_text(encoding='utf-8'))
        plan['files'][1]=copy.deepcopy(plan['files'][0])
        with self.assertRaisesRegex(ValueError,'duplicate_delivery_path'):
            inspect_scope(plan,ROOT)

    def test_self_declared_rights_are_not_license_evidence(self):
        plan = json.loads(MANIFEST.read_text(encoding='utf-8'))
        plan['files'][0]['rights_status']='AUTHORIZED'
        with self.assertRaisesRegex(ValueError,'unsupported_rights_claim'):
            inspect_scope(plan,ROOT)
        plan = json.loads(MANIFEST.read_text(encoding='utf-8'))
        plan['commercial_rights']='VERIFIED'
        with self.assertRaisesRegex(ValueError,'unsupported_rights_claim'):
            inspect_scope(plan,ROOT)

    def test_pinned_md_file_replaced_by_symlink_is_rejected(self):
        plan = json.loads(MANIFEST.read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'verification/research').mkdir(parents=True)
            (root / plan['files'][0]['path']).symlink_to(MANIFEST)
            with self.assertRaisesRegex(ValueError,'unsafe_delivery_path'):
                inspect_scope({'schema':plan['schema'], **plan},root)


if __name__ == '__main__':
    unittest.main()
