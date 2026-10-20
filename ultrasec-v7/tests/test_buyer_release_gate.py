"""TDD: one buyer product must not bypass a blocked per-file upstream license.

Synthetic tampering only. This validates *existing* source inventory evidence,
not external legal clearance or authorization to commercially resell code.
"""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from buyer_release_gate import evaluate
from test_couchbase_bsl_distribution_gate import fixture as couchbase_fixture

BASE=ROOT/'verification/research'


def inputs():
    source=json.loads((BASE/'GITEA_NINE_FILE_SOURCE_RIGHTS_MANIFEST_20261019.json').read_text())
    product=json.loads((BASE/'PREMIUM_SOURCE_PAIR_PRODUCT_DRAFT.json').read_text())
    cohort=json.loads((BASE/'COHORT_5_PRE_ADMISSION_PUBLIC.json').read_text())
    return source,couchbase_fixture(),product,cohort


class BuyerProductLicensingGateTest(unittest.TestCase):
    def test_five_source_pair_products_and_thirteen_original_file_evidence_still_block_sale(self):
        receipt=evaluate(*inputs())
        self.assertEqual(receipt['candidate_source_origins'],5)
        self.assertEqual(receipt['gitea_research_overlay_files'],9)
        self.assertEqual(receipt['couchbase_compiled_dependency_files_blocked'],4)
        self.assertEqual(receipt['license_status'],'RIGHTS_NOT_VERIFIED')
        self.assertEqual(receipt['commercially_releaseable_pairs'],0)
        self.assertFalse(receipt['ready_to_sell'])
        self.assertEqual(receipt['certification'],'NOT_CERTIFIED')

    def test_adding_unapproved_source_to_a_buyer_payload_fails_closed(self):
        g,c,p,cohort=inputs()
        p['candidates'][0]['packaged_source_files']=['services/release/release.go']
        with self.assertRaisesRegex(ValueError,'product_scope_unverified'):
            evaluate(g,c,p,cohort)

    def test_bsl_self_authorization_cannot_override_per_file_block(self):
        g,c,p,cohort=inputs()
        c['commercial_distribution_cleared']=True
        with self.assertRaisesRegex(ValueError,'dependency_rights_not_verified'):
            evaluate(g,c,p,cohort)

    def test_root_mit_does_not_reclassify_an_unreviewed_template(self):
        g,c,p,cohort=inputs()
        for row in g['files']:
            if row['path']=='templates/repo/release/new.tmpl':
                row['license_evidence']='SPDX_MIT_PER_FILE'
        with self.assertRaisesRegex(ValueError,'original_file_rights_unverified'):
            evaluate(g,c,p,cohort)

    def test_alternate_metadata_sku_cannot_be_misrepresented_as_source_pair_clearance(self):
        g,c,p,cohort=inputs()
        p['proposed_delivery_mode']='metadata_only'
        with self.assertRaisesRegex(ValueError,'product_scope_unverified'):
            evaluate(g,c,p,cohort)


if __name__=='__main__':
    unittest.main()
