#!/usr/bin/env python3
"""Fail-closed verification of PUBLIC research metadata. NEVER commercial certification."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
RUN_PATH = re.compile(r"/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/[1-9][0-9]*\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
CWES = frozenset({"CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787", "CWE-22",
                  "CWE-416", "CWE-125", "CWE-78", "CWE-94", "CWE-120", "CWE-434"})
NATIVE = frozenset({"RED_GREEN_REPRODUCED", "DIFF_ONLY", "FIXED_GUARD_ISOLATED_PASS",
                    "UPSTREAM_SUITES_EXECUTED_NO_CVE_REPRO", "PATCH_LOCATED_NO_RUN"})
REQUIRED = frozenset({"cve_id", "cwe_id", "name", "source_url", "source_commit",
    "fix_commit", "source_release_sha256", "fix_release_sha256", "native_evidence",
    "native_evidence_url", "test_provenance", "license_observed",
    "license_evidence_url", "open_questions", "provenance", "commercial_rights",
    "independent_review", "gold_status", "split", "training_import",
    "vulnerable_reproduced"})


def public_url(s: object) -> bool:
    """Disallow credentials and off-origin links in public evidence metadata."""
    if not isinstance(s, str) or len(s) > 600:
        return False
    try:
        u = urlsplit(s)
        return (u.scheme == "https" and
                u.hostname in {"github.com", "wordpress.org", "downloads.wordpress.org"} and
                not u.username and not u.password and not u.query)
    except ValueError:
        return False


def valid_run_reference(value: object) -> bool:
    """Accept only canonical numeric Actions runs in this repository; no status claim."""
    if not public_url(value):
        return False
    u = urlsplit(value)
    return u.hostname == "github.com" and not u.fragment and bool(RUN_PATH.fullmatch(u.path))


def validate(doc: object) -> list[str]:
    """Check internal consistency, NOT that third-party evidence has been adjudicated."""
    errors = []
    if not isinstance(doc, dict):
        return ["invalid_registry"]
    if doc.get("schema_version") != 1:
        errors.append("bad_schema_version")
    if (doc.get("certification") != "NOT_CERTIFIED" or doc.get("gold_count") != 0 or
            doc.get("independent_experts_signed") != 0):
        errors.append("unsupported_certification_claim")
    if doc.get("purpose") != "PUBLIC_METADATA_ONLY_NO_CORPUS_OR_HOLDOUT":
        errors.append("bad_scope")
    xs = doc.get("candidates")
    if not isinstance(xs, list) or len(xs) != 5:
        return errors + ["bad_candidate_count"]
    ids, pairs = set(), set()
    for c in xs:
        if not isinstance(c, dict):
            errors.append("invalid_case")
            continue
        if REQUIRED - c.keys():
            errors.append("missing_field")
        cid = c.get("cve_id")
        if not isinstance(cid, str) or not CVE.fullmatch(cid):
            errors.append("invalid_cve")
        if cid in ids:
            errors.append("duplicate_cve")
        ids.add(cid)
        if c.get("cwe_id") not in CWES:
            errors.append("invalid_cwe")
        if any(not public_url(c.get(k)) for k in (
                "source_url", "native_evidence_url", "license_evidence_url")):
            errors.append("invalid_public_reference")
        if c.get("native_evidence") not in NATIVE:
            errors.append("unsupported_native_evidence")
        for k in ("name", "test_provenance", "license_observed", "open_questions"):
            if not isinstance(c.get(k), str) or not c[k].strip():
                errors.append("missing_text")
        if (c.get("provenance"), c.get("commercial_rights"),
                c.get("independent_review"), c.get("gold_status"),
                c.get("split"), c.get("training_import"), c.get("vulnerable_reproduced")) != (
                "PUBLIC_UPSTREAM", "NOT_VERIFIED", "NOT_DONE", "NOT_ADMITTED",
                "UNASSIGNED", "NO", "NOT_GOLD_VALIDATED"):
            errors.append("premature_gold_claim_or_split_leak")
        source, fix = c.get("source_commit"), c.get("fix_commit")
        if source is None or fix is None:
            a, b = c.get("source_release_sha256"), c.get("fix_release_sha256")
            if (source is not None or fix is not None or not isinstance(a, str) or
                    not SHA256.fullmatch(a) or not isinstance(b, str) or
                    not SHA256.fullmatch(b) or a == b):
                errors.append("invalid_release_pair")
        else:
            if (not all(isinstance(s, str) and SHA40.fullmatch(s) for s in (source, fix))
                    or source == fix):
                errors.append("invalid_commit_pair")
            if c.get("source_release_sha256") is not None or c.get("fix_release_sha256") is not None:
                errors.append("mixed_commit_and_release_pairs")
            pair = (source, fix)
            if pair in pairs:
                errors.append("duplicate_source_patch_pair")
            pairs.add(pair)
        if (c.get("native_evidence") == "RED_GREEN_REPRODUCED" and
                not valid_run_reference(c.get("native_evidence_url"))):
            errors.append("invalid_red_green_run_reference")
    return sorted(set(errors))


def report(doc: dict) -> dict:
    errors = validate(doc)
    if errors:
        raise ValueError(",".join(errors))
    return {
        "schema_version": 1,
        "candidate_count": len(doc["candidates"]),
        "native_red_green_count": sum(c["native_evidence"] == "RED_GREEN_REPRODUCED"
                                      for c in doc["candidates"]),
        "confirmed_gold_count": 0,
        "certification": "NOT_CERTIFIED",
        "rights_verified": 0,
        "independent_experts_signed": 0,
        "scope": "PUBLIC_METADATA_ONLY_NO_CORPUS_OR_HOLDOUT",
        "automated_phase": "METADATA_CONSISTENCY_ONLY",
        "human_review_phase": "DEFERRED",
        "native_run_execution_independently_verified": False,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: verify_candidate_cohort.py registry.json", file=sys.stderr)
        return 2
    try:
        doc = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
        print(json.dumps(report(doc), sort_keys=True, ensure_ascii=False))
    except (OSError, ValueError, TypeError) as e:
        print("FAIL_CLOSED: " + str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
