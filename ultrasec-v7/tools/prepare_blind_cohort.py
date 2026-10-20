#!/usr/bin/env python3
"""Private reviewer intake shells. NOT source delivery, independent review, or certification."""
from __future__ import annotations
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path

SLOTS = ("A", "B")


def _create_private_json(path: Path, payload: dict) -> None:
    """Exclusive create, mode 0600; never overwrite previously signed reviewer material."""
    with os.fdopen(os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                   "w", encoding="utf-8") as output:
        json.dump(payload, output, indent=2, ensure_ascii=False)
        output.write("\n")


def prepare_review_packets(doc: dict, secret: str, private_dir: Path) -> dict:
    """Blind CVE/CWE/source IDs behind keyed, reviewer-specific opaque tokens.

    There is deliberately NO code or security verdict in the reviewer packets.
    A human custodian must furnish lawfully shareable code separately and check
    a reviewer's prior exposure. These packets prove NO human independence.
    """
    if not isinstance(secret, str) or len(secret.encode("utf-8")) < 32:
        raise ValueError("blind_secret_must_have_at_least_32_bytes")
    private_dir = Path(private_dir)
    if not private_dir.name.startswith("private"):
        raise ValueError("use_private_destination_outside_the_repo")
    if not isinstance(doc, dict) or doc.get("certification") != "NOT_CERTIFIED" or doc.get("gold_count") != 0:
        raise ValueError("source_cohort_must_be_uncertified")
    cases = doc.get("candidates")
    if not isinstance(cases, list) or len(cases) != 5:
        raise ValueError("expected_five_unadmitted_cases")
    seen = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("cve_id"), str):
            raise ValueError("bad_case")
        if case["cve_id"] in seen:
            raise ValueError("duplicate_case")
        seen.add(case["cve_id"])
        if any(case.get(k) != value for k, value in (
            ("gold_status", "NOT_ADMITTED"), ("commercial_rights", "NOT_VERIFIED"),
            ("independent_review", "NOT_DONE"), ("split", "UNASSIGNED"),
            ("training_import", "NO")
        )):
            raise ValueError("premature_admission_or_split_leak")
    if private_dir.exists():
        raise ValueError("never_overwrite_existing_reviewer_packets")

    # Do not create this folder inside a Git repository. Private mapping must
    # remain in an access-controlled location managed by the owner.
    private_dir.mkdir(mode=0o700, parents=False)
    mapping = {"scope": "PRIVATE_RECONCILIATION_NOT_SIGNED", "case_ids": {}}
    created = []
    try:
        for slot in SLOTS:
            packets = []
            for case in cases:
                digest = hmac.new(secret.encode("utf-8"),
                    ("v1|slot=" + slot + "|case=" + case["cve_id"]).encode("utf-8"),
                    hashlib.sha256).hexdigest()
                opaque_id = "R" + slot + "-" + digest[:24]
                mapping["case_ids"][opaque_id] = case["cve_id"]
                packets.append({
                    "blind_id": opaque_id, "source_material_delivered_privately": False,
                    "suspected_cwe": None, "vulnerable_behavior_reproduced": None,
                    "fix_addresses_root_cause": None, "prior_exposure_to_public_case": None,
                    "conflict_of_interest": None, "technical_reasoning": None,
                    "independent_reviewer_signature": None
                })
            packets.sort(key=lambda c: c["blind_id"])
            path = private_dir / ("reviewer_" + slot + ".json")
            _create_private_json(path, {
                "slot": slot, "status": "PREPARED_NOT_REVIEWED",
                "instructions": "Human custodian supplies legally sharable anonymized evidence privately; disclose prior exposure; report uncertainty and disagreement; no detector labels.",
                "cases": packets
            })
            created.append(path)
        path = private_dir / "PRIVATE_DO_NOT_COMMIT_case_mapping.json"
        _create_private_json(path, mapping)
        created.append(path)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        private_dir.rmdir()
        raise
    return {"slots": 2, "cases_per_slot": len(cases), "status": "PREPARED_NOT_SIGNED",
            "confirmed_reviewers": 0, "gold_admitted": 0}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    args = parser.parse_args()
    result = prepare_review_packets(
        json.loads(args.registry.read_text(encoding="utf-8")),
        os.environ.get("ULTRASEC_BLIND_KEY", ""), args.private_output
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
