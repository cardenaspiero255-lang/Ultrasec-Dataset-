"""TDD: owner-local TRAIN/HOLDOUT gate must reject all 63 published research CVEs.

No private training or evaluation metadata is stored in these synthetic tests.
"""
import unittest
from unittest.mock import patch
from test_private_training_disjointness import healthy, module


class PrivateTrainFullResearchExclusionsTest(unittest.TestCase):
    def test_one_of_63_known_cves_outside_old_hardcoded_list_is_rejected(self):
        train, holdout = healthy()
        holdout[0]['cve_id'] = 'CVE-2022-1519'
        receipt = module.audit(train, holdout, minimum_train=2, minimum_test=2, minimum_cwes=1)
        self.assertIn('known_research_cve', receipt['failures'])
        self.assertFalse(receipt['metadata_separation_pass'])

    def test_all_published_known_identifiers_contribute_to_exclusion_count(self):
        train, holdout = healthy()
        receipt = module.audit(train, holdout, minimum_train=2, minimum_test=2, minimum_cwes=1)
        self.assertGreaterEqual(receipt['known_research_cves_excluded'], 63)

    def test_missing_original_research_inventory_blocks_private_split_validation(self):
        train, holdout = healthy()
        with patch.object(module, '_read_original_public_cves',
                          side_effect=ValueError('known_public_research_inventory_missing')):
            with self.assertRaises(ValueError):
                module.audit(train, holdout, minimum_train=2, minimum_test=2, minimum_cwes=1)


if __name__ == '__main__':
    unittest.main()
