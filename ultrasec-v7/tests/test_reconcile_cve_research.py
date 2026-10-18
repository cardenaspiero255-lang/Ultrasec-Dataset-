"""Fail-closed audit of the 63 public discovery CVEs, not independent gold."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from reconcile_cve_research import reconcile, load_sources

SOURCE = ROOT / "verification" / "research"


class CVEResearchReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.raw = load_sources(SOURCE)

    def test_original_sources_are_fully_accounted_for(self):
        report = reconcile(*self.raw)
        m = report["counts"]
        self.assertEqual(m["discovered"], 63)
        self.assertEqual(m["source_commit_inspected"], 7)
        self.assertEqual(m["native_red_green_in_original_63"], 2)
        self.assertEqual(m["previously_reported_missing_source_verification"], 56)
        self.assertEqual(m["not_yet_source_inspected_after_reconciliation"], 54)
        self.assertEqual(m["holdout_ineligible_without_source_pair"], 5)
        self.assertEqual(m["discovery_only_remaining"], 49)
        self.assertEqual(m["gold_admitted"], 0)
        self.assertEqual(m["independently_validated_private_holdout"], 0)
        self.assertEqual(report["certification"], "NOT_CERTIFIED")

    def test_all_rows_unique_and_have_immutable_statuses(self):
        report = reconcile(*self.raw)
        rows = report["cases"]
        self.assertEqual([x["row_number"] for x in rows], list(range(1, 64)))
        self.assertEqual(len({x["cve_id"] for x in rows}), 63)
        self.assertEqual(len({x["ghsa_id"] for x in rows}), 63)
        self.assertEqual(len({x["cwe_id"] for x in rows}), 12)
        for row in rows:
            self.assertEqual(row["gold_status"], "NOT_ADMITTED")
            self.assertEqual(row["commercial_rights"], "NOT_VERIFIED")
            self.assertEqual(row["holdout_split"], "UNASSIGNED")
            self.assertEqual(row["private_holdout_overlap"], "NOT_VERIFIED")

    def test_native_reproduction_is_not_equivalent_to_new_gold(self):
        report = reconcile(*self.raw)
        indexed = {c["cve_id"]: c for c in report["cases"]}
        for cve in ("CVE-2024-2395", "CVE-2025-69015"):
            self.assertEqual(indexed[cve]["stage"], "NATIVE_RED_GREEN_TECHNICAL_NOT_GOLD")
            self.assertIn("actions/runs/", indexed[cve]["technical_evidence_url"])
        self.assertEqual(indexed["CVE-2024-11921"]["stage"], "DISCOVERY_ONLY_NOT_VERIFIED")

    def test_inspected_seven_must_have_precise_source_commit(self):
        report = reconcile(*self.raw)
        old = [x for x in report["cases"] if x["stage"] == "ORIGINAL_COMMIT_INSPECTED_NO_FULL_UPSTREAM_REPRO"]
        self.assertEqual(len(old), 7)
        for c in old:
            self.assertRegex(c["original_fix_commit"], r"^[0-9a-f]{40}$")
            self.assertRegex(c["original_parent_commit"], r"^[0-9a-f]{40}$")

    def test_blocked_candidates_are_not_falsely_marked_verified(self):
        report = reconcile(*self.raw)
        blocked = [x for x in report["cases"] if x["stage"] == "HOLDOUT_INELIGIBLE_NO_SOURCE_PAIR"]
        self.assertEqual(len(blocked), 5)
        self.assertTrue(all(x["technical_evidence_url"] is None for x in blocked))

    def test_duplicate_discovery_row_rejected(self):
        discovery, reviewed, decisions, cohort = self.raw
        first = next(line for line in discovery.splitlines() if line.startswith("| 1 |"))
        altered = discovery.replace("| 2 |", "| 1 |", 1)
        with self.assertRaisesRegex(ValueError, "discovery"):
            reconcile(altered, reviewed, decisions, cohort)

    def test_missing_provenance_rejected_instead_of_fabricated(self):
        discovery, reviewed, decisions, cohort = self.raw
        altered = reviewed.replace("CVE-2026-29035", "CVE-2099-999999")
        with self.assertRaises(ValueError):
            reconcile(discovery, altered, decisions, cohort)

    def test_fabricated_certified_cohort_is_rejected(self):
        discovery, reviewed, decisions, cohort = self.raw
        altered = json.loads(json.dumps(cohort))
        altered["certification"] = "CERTIFIED"
        with self.assertRaises(ValueError):
            reconcile(discovery, reviewed, decisions, altered)


if __name__ == "__main__":
    unittest.main()
