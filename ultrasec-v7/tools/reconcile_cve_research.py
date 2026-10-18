#!/usr/bin/env python3
"""Reconcile PUBLIC discovery evidence. Never validate or promote private gold."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

from verify_candidate_cohort import validate as validate_native_cohort

CVE = re.compile(r"CVE-(?:19|20)[0-9]{2}-[0-9]{4,}\\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\\Z")
GHSA = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\\Z")
CWE = re.compile(r"CWE-[1-9][0-9]{0,5}\\Z")
CVE_LINK = re.compile(r"\\[(CVE-[0-9]{4}-[0-9]{4,})\\]\\((https://nvd\\.nist\\.gov/vuln/detail/CVE-[0-9]{4}-[0-9]{4,})\\)\\Z")
GHSA_LINK = re.compile(r"\\[(GHSA-[a-z0-9-]+)\\]\\((https://github\\.com/advisories/GHSA-[a-z0-9-]+)\\)\\Z")
COMMIT_LINK = re.compile(r"https://github\\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+/commit/([a-f0-9]{40})\\)")


def cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def parse_discovery(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        values = cells(line)
        if len(values) != 5 or not re.fullmatch(r"[0-9]+", values[0]):
            continue
        cve_match = CVE_LINK.fullmatch(values[1])
        ghsa_match = GHSA_LINK.fullmatch(values[3])
        if not cve_match or not ghsa_match:
            raise ValueError("invalid_discovery_source_link")
        n = int(values[0])
        cve, nvd = cve_match.groups()
        ghsa, ghsa_url = ghsa_match.groups()
        if (n != len(rows) + 1
                or nvd.rsplit("/", 1)[-1] != cve
                or ghsa_url.rsplit("/", 1)[-1] != ghsa
                or not CWE.fullmatch(values[2])
                or not CVE.fullmatch(cve)
                or not GHSA.fullmatch(ghsa)):
            raise ValueError("invalid_discovery_sequence_or_reference")
        rows.append({
            "row_number": n, "cve_id": cve, "cwe_id": values[2],
            "ghsa_id": ghsa, "nvd_url": nvd, "ghsa_url": ghsa_url,
            "source_commit_linked_in_ghsa": "Sin commit en el aviso" not in values[4],
        })
    if (len(rows) != 63
            or len({x["cve_id"] for x in rows}) != 63
            or len({x["ghsa_id"] for x in rows}) != 63
            or len({x["cwe_id"] for x in rows}) != 12):
        raise ValueError("discovery_must_be_exactly_63_unique_ids_and_12_cwes")
    return rows


def parse_inspected(text: str) -> dict[str, dict]:
    section = text.split("## Resultados reales")[0]
    inspected = {}
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        x = cells(line)
        if len(x) != 5 or not CVE.fullmatch(x[0]):
            continue
        match = COMMIT_LINK.search(x[2])
        parent = re.search(r"`([0-9a-f]{40})`", x[3])
        if (not match or not parent or match.group(1) == parent.group(1)
                or not CWE.fullmatch(x[1]) or x[0] in inspected):
            raise ValueError("unverified_original_commit_entry")
        inspected[x[0]] = {"fix":match.group(1), "parent":parent.group(1),
                          "cwe":x[1]}
    if len(inspected) != 7:
        raise ValueError("expected_seven_source_commits_in_historical_review")
    return inspected


def parse_ineligible(text: str) -> set[str]:
    marker = "## Candidatos NO elegibles hoy para holdout fuente/fix"
    end = "## Casos con evidencia aislada previa"
    if marker not in text or end not in text:
        raise ValueError("missing_source_eligibility_section")
    section = text.split(marker, 1)[1].split(end, 1)[0]
    ids = []
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        x = cells(line)
        if x and CVE.fullmatch(x[0]):
            if "HOLDOUT_INELIGIBLE_" not in line:
                raise ValueError("missing_ineligible_reason")
            ids.append(x[0])
    if len(ids) != 5 or len(set(ids)) != 5:
        raise ValueError("expected_five_unevaluable_cases")
    return set(ids)


def reconcile(discovery: str, reviewed: str, decisions: str,
              native_cohort: object) -> dict:
    """Evidence accounting only. No two records qualify as independent gold."""
    source_rows = parse_discovery(discovery)
    by_id = {x["cve_id"]:x for x in source_rows}
    inspected = parse_inspected(reviewed)
    ineligible = parse_ineligible(decisions)
    if (set(inspected) - by_id.keys() or ineligible - by_id.keys()
            or set(inspected) & ineligible):
        raise ValueError("historical_evidence_disagrees_with_discovery")

    native_errors = validate_native_cohort(native_cohort)
    if native_errors:
        raise ValueError("native_cohort_not_valid")
    native = {
        x["cve_id"]:x for x in native_cohort["candidates"]
        if x["cve_id"] in by_id and x["native_evidence"] == "RED_GREEN_REPRODUCED"
    }
    if len(native) != 2 or set(native) & set(inspected) or set(native) & ineligible:
        raise ValueError("unexpected_native_overlap_requires_readjudication")

    result = []
    for original in source_rows:
        row = dict(original)
        cid = row["cve_id"]
        row.update({
            "original_fix_commit": None,
            "original_parent_commit": None,
            "technical_evidence_url": None,
            "upstream_cwe_claim": None,
            "cwe_mapping_conflict": False,
            "gold_status": "NOT_ADMITTED",
            "commercial_rights": "NOT_VERIFIED",
            "holdout_split": "UNASSIGNED",
            "private_holdout_overlap": "NOT_VERIFIED",
            "source_license_status": "NOT_CLEARED_FOR_COMMERCIAL_DATASET",
        })
        if cid in native:
            evidence = native[cid]
            row["stage"] = "NATIVE_RED_GREEN_TECHNICAL_NOT_GOLD"
            row["technical_evidence_url"] = evidence["native_evidence_url"]
            row["upstream_cwe_claim"] = evidence["cwe_id"]
            row["cwe_mapping_conflict"] = row["cwe_id"] != evidence["cwe_id"]
        elif cid in inspected:
            evidence = inspected[cid]
            if evidence["cwe"] != row["cwe_id"]:
                raise ValueError("inspected_cwe_disagrees_with_discovery")
            row["stage"] = "ORIGINAL_COMMIT_INSPECTED_NO_FULL_UPSTREAM_REPRO"
            row["original_fix_commit"] = evidence["fix"]
            row["original_parent_commit"] = evidence["parent"]
        elif cid in ineligible:
            row["stage"] = "HOLDOUT_INELIGIBLE_NO_SOURCE_PAIR"
        else:
            row["stage"] = "DISCOVERY_ONLY_NOT_VERIFIED"
        result.append(row)
    statuses = Counter(x["stage"] for x in result)
    return {
        "schema": "ultrasec.cve63-evidence-reconciliation.v1",
        "scope": "PUBLIC_SOURCE_METADATA_ONLY_NO_PRIVATE_HOLDOUT",
        "certification": "NOT_CERTIFIED",
        "source": "GHSA_UNREVIEWED_CANDIDATE_INVENTORY_PLUS_HISTORICAL_RESEARCH",
        "counts": {
            "discovered": 63,
            "source_commit_inspected": statuses["ORIGINAL_COMMIT_INSPECTED_NO_FULL_UPSTREAM_REPRO"],
            "native_red_green_in_original_63": statuses["NATIVE_RED_GREEN_TECHNICAL_NOT_GOLD"],
            "previously_reported_missing_source_verification": 63 - len(inspected),
            "not_yet_source_inspected_after_reconciliation": 63 - len(inspected) - len(native),
            "holdout_ineligible_without_source_pair": statuses["HOLDOUT_INELIGIBLE_NO_SOURCE_PAIR"],
            "discovery_only_remaining": statuses["DISCOVERY_ONLY_NOT_VERIFIED"],
            "unresolved_cwe_mapping_conflicts": sum(x["cwe_mapping_conflict"] for x in result),
            "gold_admitted": 0,
            "independently_validated_private_holdout": 0,
            "resale_rights_verified": 0,
            "qualified_external_reviewers": 0,
        },
        "interpretation": "Source inspection and technical regressions are not independent gold; unreviewed GHSA CWE may conflict with NVD.",
        "cases": result,
    }


def load_sources(base: Path) -> tuple[str, str, str, dict]:
    return (
        (base / "CVE_CANDIDATES_63_PUBLIC_METADATA.md").read_text(encoding="utf-8"),
        (base / "CVE_VERIFICATION_7_OF_63_2026-10-17.md").read_text(encoding="utf-8"),
        (base / "SOURCE_ELIGIBILITY_DECISIONS_20261017_ES.md").read_text(encoding="utf-8"),
        json.loads((base / "COHORT_5_PRE_ADMISSION_PUBLIC.json").read_text(encoding="utf-8")),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Strict 63 CVE public research inventory")
    parser.add_argument("--public-report", type=Path, help="Write only public-source candidate references")
    args = parser.parse_args(argv)
    try:
        base = Path(__file__).resolve().parents[1] / "verification" / "research"
        result = reconcile(*load_sources(base))
        if args.public_report is not None:
            args.public_report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
        print(json.dumps({key:value for key,value in result.items() if key != "cases"}, sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        print("FAIL_CLOSED: source evidence inventory inconsistent", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
