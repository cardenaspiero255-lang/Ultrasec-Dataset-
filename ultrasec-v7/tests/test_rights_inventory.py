"""Source-level license inventory is NOT a commercial rights clearance."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from verify_rights_inventory import validate_inventory, report

LICENSES = ROOT / "verification/research/LICENSE_SCOPE_INVENTORY_5.json"
COHORT = ROOT / "verification/research/COHORT_5_PRE_ADMISSION_PUBLIC.json"


def fixtures():
    return json.loads(LICENSES.read_text()), json.loads(COHORT.read_text())


class RightsInventoryContract(unittest.TestCase):
    def test_all_five_original_candidates_are_inventoried_but_none_cleared(self):
        data, cohort = fixtures()
        self.assertEqual(validate_inventory(data, cohort), [])
        r = report(data, cohort)
        self.assertEqual(r["observed_license_entries"], 5)
        self.assertEqual(r["rights_cleared"], 0)
        self.assertEqual(r["status"], "INVENTORY_ONLY_NOT_COMMERCIAL_CLEARANCE")
        self.assertEqual(r["certification"], "NOT_CERTIFIED")

    def test_missing_original_cve_is_not_accepted(self):
        data, cohort = fixtures()
        data["cases"].pop()
        self.assertIn("missing_or_extra_case", validate_inventory(data, cohort))

    def test_self_declared_commercial_rights_are_rejected(self):
        data, cohort = fixtures()
        data["cases"][0]["commercial_rights"] = "CLEARED"
        self.assertIn("unsupported_rights_claim", validate_inventory(data, cohort))

    def test_unverified_source_or_empty_license_is_not_accepted(self):
        data, cohort = fixtures()
        data["cases"][0]["license_reference"] = ""
        self.assertIn("missing_license_reference", validate_inventory(data, cohort))

    def test_full_content_redistribution_not_silently_authorized(self):
        data, cohort = fixtures()
        data["cases"][0]["distribution_modes"]["full_source_pairs"] = "AUTHORIZED"
        self.assertIn("unsupported_rights_claim", validate_inventory(data, cohort))


if __name__ == "__main__":
    unittest.main()
