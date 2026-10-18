#!/usr/bin/env python3
"""Fail-closed structural inventory; does not grant, infer, or verify commercial permissions."""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

_SHA40 = re.compile(r"[a-f0-9]{40}\\Z")
MODES = frozenset({"metadata_only", "source_fragments", "full_source_pairs"})
EXPECTED_STATE = "INVENTORY_ONLY_NOT_COMMERCIAL_CLEARANCE"


def validate_inventory(inventory: object, cohort: object) -> list[str]:
    errors = set()
    if not isinstance(inventory, dict) or not isinstance(cohort, dict):
        return ["invalid_inventory"]
    if (inventory.get("schema") != "ultrasec.v7-public-source-license-inventory.v1"
            or inventory.get("status") != EXPECTED_STATE
            or inventory.get("certification") != "NOT_CERTIFIED"):
        errors.add("unsupported_rights_claim")
    known = cohort.get("candidates")
    cases = inventory.get("cases")
    if not isinstance(known, list) or not isinstance(cases, list):
        return sorted(errors | {"invalid_inventory"})
    if (len(cases) != len(known)
            or {c.get("cve_id") for c in cases if isinstance(c, dict)}
               != {c.get("cve_id") for c in known if isinstance(c, dict)}):
        errors.add("missing_or_extra_case")
    known_by_id = {c.get("cve_id"):c for c in known if isinstance(c, dict)}
    seen = set()
    for row in cases:
        if not isinstance(row, dict):
            errors.add("invalid_inventory")
            continue
        cid = row.get("cve_id")
        if cid in seen:
            errors.add("missing_or_extra_case")
        seen.add(cid)
        if (not isinstance(row.get("license_reference"),str)
                or not row["license_reference"].startswith("https://")):
            errors.add("missing_license_reference")
        original = known_by_id.get(cid)
        if original and row.get("license_reference") != original.get("license_evidence_url"):
            errors.add("license_source_mismatch")
        if not isinstance(row.get("license_expression_observed"),str) or not row["license_expression_observed"].strip():
            errors.add("missing_license_reference")
        if not isinstance(row.get("license_path"),str) or not row["license_path"].strip():
            errors.add("missing_license_reference")
        blob = row.get("license_blob_sha")
        if blob is not None and (not isinstance(blob,str) or not _SHA40.fullmatch(blob)):
            errors.add("invalid_license_blob")
        if (row.get("commercial_rights") != "NOT_VERIFIED"
                or row.get("file_level_chain_of_title_verified") is not False
                or row.get("dependencies_complete") is not False
                or row.get("legal_opinion_signed") is not False):
            errors.add("unsupported_rights_claim")
        modes = row.get("distribution_modes")
        if (not isinstance(modes,dict) or set(modes) != MODES
                or any(v != "REQUIRES_SCOPE_REVIEW" for v in modes.values())):
            errors.add("unsupported_rights_claim")
    return sorted(errors)


def report(inventory: dict, cohort: dict) -> dict:
    problems = validate_inventory(inventory,cohort)
    if problems:
        raise ValueError(",".join(problems))
    return {"schema":"ultrasec.v7-license-screen.v1",
            "observed_license_entries":len(inventory["cases"]),
            "rights_cleared":0,
            "status":EXPECTED_STATE,
            "certification":"NOT_CERTIFIED",
            "deliverable_scope_approved":False,
            "independent_legal_opinion":"NOT_RECEIVED"}


def main(argv: list[str]) -> int:
    if len(argv)!=2:
        print("Usage: verify_rights_inventory.py INVENTORY.json COHORT.json",file=sys.stderr)
        return 2
    try:
        a=json.loads(Path(argv[0]).read_text(encoding="utf-8"))
        b=json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        print(json.dumps(report(a,b),sort_keys=True))
        return 0
    except (ValueError,TypeError,OSError) as e:
        print("FAIL_CLOSED: "+str(e),file=sys.stderr)
        return 1


if __name__=="__main__":
    raise SystemExit(main(sys.argv[1:]))
