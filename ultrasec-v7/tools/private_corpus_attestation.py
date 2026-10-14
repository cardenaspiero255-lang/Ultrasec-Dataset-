#!/usr/bin/env python3
"""Owner-side structural attestations for compressed, private synthetic corpora.

Nothing private is published, executed, transmitted or printed. A sealable
owner report is NOT a security certification or a legal rights assessment.
"""
from __future__ import annotations

from collections import Counter
import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sealed_evidence import _no_duplicates, public_receipt, write_private

LABELS = frozenset({"vulnerable", "mitigated_example"})
REQUIRED = frozenset({"id", "pair_id", "template_id", "code", "label",
                       "language", "family", "split", "independently_validated",
                       "license_clearance", "verification_tier", "label_provenance",
                       "origin"})
SHA = re.compile(r"[0-9a-f]{64}\Z")


def empty_report() -> dict:
    return {
        "schema": "ultrasec.private-corpus-attestation.v1",
        "scope": "OWNER_CONTROLLED_HISTORICAL_METADATA_AND_CODE",
        "certification": "NOT_CERTIFIED",
        "external_appsec_review": "NOT_VERIFIED",
        "commercial_valuation": "NOT_VERIFIED",
        "owner_integrity_pass": False,
        "integrity": {},
        "metrics": {},
        "errors": {},
    }


def audit_rows(records) -> dict:
    """Structural and exact-hash validation; no claim of semantic uniqueness."""
    errors: Counter[str] = Counter()
    ids: set[str] = set()
    code_hashes: set[bytes] = set()
    templates: dict[str, str] = {}
    pairs: dict[str, dict] = {}
    families: set[str] = set()
    langs: set[str] = set()
    splits: Counter[str] = Counter()
    rows_count = 0
    unverified = 0
    pending_rights = 0
    generator_labels = 0
    for row in records:
        rows_count += 1
        if not isinstance(row, dict) or not REQUIRED.issubset(row):
            errors["invalid_record_schema"] += 1
            continue
        strings = ("id", "pair_id", "template_id", "code", "label",
                   "language", "family", "split", "license_clearance",
                   "verification_tier", "label_provenance", "origin")
        if (not all(isinstance(row.get(k), str) and bool(row[k]) for k in strings)
                or type(row["independently_validated"]) is not bool
                or row["label"] not in LABELS
                or row["split"] not in {"train", "validation", "test"}):
            errors["invalid_record_schema"] += 1
            continue
        rid = row["id"]
        if rid in ids:
            errors["duplicate_record_id"] += 1
            continue
        ids.add(rid)
        digest = hashlib.sha256(row["code"].encode("utf-8")).digest()
        if digest in code_hashes:
            errors["duplicate_code"] += 1
        code_hashes.add(digest)
        if row["independently_validated"] is not True:
            unverified += 1
        if row["license_clearance"] != "cleared":
            pending_rights += 1
        if row["label_provenance"] == "generator_intent_unverified":
            generator_labels += 1
        families.add(row["family"])
        langs.add(row["language"])
        splits[row["split"]] += 1

        split_before = templates.setdefault(row["template_id"], row["split"])
        if split_before != row["split"]:
            errors["template_split_leakage"] += 1
        identity = (row["family"], row["language"], row["template_id"], row["split"])
        bundle = pairs.setdefault(row["pair_id"], {"identity": identity, "labels": set()})
        if identity != bundle["identity"]:
            errors["pair_metadata_mismatch"] += 1
        if row["label"] in bundle["labels"]:
            errors["duplicate_pair_variant"] += 1
        bundle["labels"].add(row["label"])

    incomplete = sum(bundle["labels"] != LABELS for bundle in pairs.values())
    if incomplete:
        errors["incomplete_pair"] += incomplete
    if rows_count == 0:
        errors["empty_input"] += 1

    report = empty_report()
    report["metrics"] = {
        "records": rows_count,
        "unique_record_ids": len(ids),
        "complete_pairs": sum(bundle["labels"] == LABELS for bundle in pairs.values()),
        "unique_pair_ids": len(pairs),
        "template_ids": len(templates),
        "exact_code_hashes": len(code_hashes),
        "family_count": len(families),
        "language_count": len(langs),
        "unverified_records": unverified,
        "rights_pending_records": pending_rights,
        "generator_intent_labels": generator_labels,
        "split_counts": {s: splits[s] for s in ("train", "validation", "test")},
    }
    report["errors"] = dict(sorted((key, n) for key,n in errors.items() if n))
    report["owner_integrity_pass"] = not bool(report["errors"])
    return report


def _archive_records(path: Path, member: str, digester):
    """Stream bounded decompressed bytes without extracting any archive member."""
    if (not member or member.startswith("/") or "\\" in member
            or ".." in PurePosixPath(member).parts or not member.endswith((".jsonl", ".jsonl.gz"))):
        raise ValueError("Unsafe or unsupported archive member")
    with zipfile.ZipFile(path) as archive:
        with archive.open(member) as compressed:
            if member.endswith(".gz"):
                source = gzip.GzipFile(fileobj=compressed)
            else:
                source = compressed
            with source:
                while True:
                    line = source.readline(1_000_001)
                    if not line:
                        break
                    if len(line) > 1_000_000:
                        raise ValueError("Overlong corpus line")
                    digester.update(line)
                    yield json.loads(line.decode("utf-8"),
                                     object_pairs_hook=_no_duplicates,
                                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Owner-local private archive attestation")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--member", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--sealed-report", type=Path, required=True)
    parser.add_argument("--session-lock", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        if not SHA.fullmatch(args.expected_sha256):
            raise ValueError("Malformed SHA-256")
        sha = hashlib.sha256()
        report = audit_rows(_archive_records(args.archive, args.member, sha))
        matches = (sha.hexdigest() == args.expected_sha256)
        report["integrity"] = {"sha256_matches_expected": matches,
                               "digest_algorithm": "SHA-256",
                               "hash_scope": "decompressed_JSONL_bytes"}
        if not matches:
            report["errors"]["sha256_mismatch"] = 1
            report["owner_integrity_pass"] = False
    except (ValueError, OSError, UnicodeError, zipfile.BadZipFile, EOFError, KeyError):
        report = empty_report()
        report["errors"] = {"input_parse_error": 1}
        report["integrity"] = {"sha256_matches_expected": False}
    try:
        write_private(args.sealed_report, args.session_lock, report)
    except (ValueError, OSError, UnicodeError):
        print('{"status":"RECORDING_FAILED"}')
        return 2
    print(public_receipt())
    return 0


if __name__ == "__main__":
    sys.exit(main())
