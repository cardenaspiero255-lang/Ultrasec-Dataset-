#!/usr/bin/env python3
"""Local, metadata-only enterprise quality screen. Not an external certification.

Consumes only a caller-supplied JSONL inventory in their own environment.
The public repository intentionally contains no private inventory or labels.
Output is aggregate JSON; individual identifiers and records are never printed.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys
from typing import Iterable

# Owner-only, shared strict reader and one-shot sealed reporting.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sealed_evidence import read_jsonl, write_private, public_receipt

FIELDS = frozenset({
    "schema_version", "record_id", "pair_id", "variant", "cwe_id",
    "language", "mechanism_id", "project_id", "split",
    "content_sha256", "rights_status",
})
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
CWE = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
LANGUAGE = re.compile(r"[a-z][a-z0-9.+-]{0,31}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
VARIANTS = frozenset({"vulnerable", "fixed"})
SPLITS = frozenset({"train", "validation", "test"})
RIGHTS = frozenset({"cleared", "pending", "restricted"})

# Standardised codes prevent raw customer data being echoed in logs.
def _valid(row: dict) -> bool:
    if set(row) != FIELDS or type(row["schema_version"]) is not int or row["schema_version"] != 1:
        return False
    for field in FIELDS - {"schema_version"}:
        if not isinstance(row[field], str):
            return False
    return (
        all(IDENTIFIER.fullmatch(row[name]) for name in (
            "record_id", "pair_id", "mechanism_id", "project_id"))
        and bool(CWE.fullmatch(row["cwe_id"]))
        and bool(LANGUAGE.fullmatch(row["language"]))
        and bool(SHA256.fullmatch(row["content_sha256"]))
        and row["variant"] in VARIANTS
        and row["split"] in SPLITS
        and row["rights_status"] in RIGHTS
    )


def _base_report() -> dict:
    return {
        "schema": "ultrasec.enterprise-metadata-screening.v1",
        "scope": "PRIVATE_METADATA_LOCAL_ONLY",
        "certification": "NOT_CERTIFIED",
        "external_audit": "NOT_VERIFIED",
        "metadata_screening_pass": False,
        "metrics": {
            "records": 0, "complete_pairs": 0, "mechanisms": 0,
            "projects": 0, "cwe_families": 0, "languages": 0,
            "split_counts": {"train": 0, "validation": 0, "test": 0},
        },
        "failures": {},
    }


def evaluate_records(rows: Iterable[object], minimum_records: int = 1,
                     minimum_mechanisms: int = 1) -> dict:
    """Screen opaque metadata. Complexity O(records) memory and time.

    Input SHA-256 values and rights declarations are *untrusted assertions*.
    A passing report does not prove provenance, semantic novelty, valid fixes,
    blind reviewer agreement, licensing rights, or 500 causal mechanisms.
    """
    if (type(minimum_records) is not int or minimum_records < 1
            or type(minimum_mechanisms) is not int or minimum_mechanisms < 1):
        raise ValueError("Minimum counts must be positive integers")

    errors: Counter[str] = Counter()
    seen_records: set[str] = set()
    seen_hashes: set[str] = set()
    pairs: dict[str, dict] = {}
    projects: dict[str, str] = {}
    mechanisms: dict[str, str] = {}
    cwes: set[str] = set()
    languages: set[str] = set()
    splits: Counter[str] = Counter()
    valid = 0
    encountered = 0

    for row in rows:
        encountered += 1
        if not isinstance(row, dict) or set(row) != FIELDS:
            errors["invalid_schema"] += 1
            continue
        if not _valid(row):
            errors["invalid_field"] += 1
            continue

        rid = row["record_id"]
        digest = row["content_sha256"]
        if rid in seen_records:
            errors["duplicate_record_id"] += 1
            continue
        seen_records.add(rid)
        if digest in seen_hashes:
            errors["duplicate_content_hash"] += 1
            continue
        seen_hashes.add(digest)

        valid += 1
        cwes.add(row["cwe_id"])
        languages.add(row["language"])
        splits[row["split"]] += 1
        if row["rights_status"] != "cleared":
            errors["rights_not_cleared"] += 1

        for field, tracker, code in (
            ("project_id", projects, "project_split_leakage"),
            ("mechanism_id", mechanisms, "mechanism_split_leakage"),
        ):
            key = row[field]
            previous = tracker.setdefault(key, row["split"])
            if previous != row["split"]:
                errors[code] += 1

        identity = (row["cwe_id"], row["language"], row["project_id"],
                    row["mechanism_id"], row["split"])
        current = pairs.setdefault(row["pair_id"],
            {"identity": identity, "variants": set()})
        if current["identity"] != identity:
            errors["pair_metadata_mismatch"] += 1
        if row["variant"] in current["variants"]:
            errors["duplicate_pair_variant"] += 1
        current["variants"].add(row["variant"])

    complete = sum(group["variants"] == VARIANTS for group in pairs.values())
    errors["incomplete_pair"] += sum(group["variants"] != VARIANTS for group in pairs.values())
    if not encountered:
        errors["empty_input"] += 1
    if valid < minimum_records:
        errors["insufficient_records"] += 1
    if len(mechanisms) < minimum_mechanisms:
        errors["insufficient_mechanisms"] += 1

    result = _base_report()
    result["acceptance_thresholds"] = {"minimum_records": minimum_records, "minimum_mechanisms": minimum_mechanisms}
    result["metrics"] = {
        "records": valid,
        "complete_pairs": complete,
        "mechanisms": len(mechanisms),
        "projects": len(projects),
        "cwe_families": len(cwes),
        "languages": len(languages),
        "split_counts": {split: splits[split] for split in ("train", "validation", "test")},
    }
    result["failures"] = dict(sorted((name, count) for name, count in errors.items() if count))
    result["metadata_screening_pass"] = not bool(result["failures"])
    return result


def _iter_jsonl(path: Path):
    yield from read_jsonl(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local enterprise metadata screen; no records leave the host")
    parser.add_argument("--input", required=True, type=Path, help="local metadata-only JSONL inventory")
    parser.add_argument("--minimum-records", type=int, required=True)
    parser.add_argument("--minimum-mechanisms", type=int, required=True)
    parser.add_argument("--sealed-report", type=Path, required=True)
    parser.add_argument("--session-lock", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = evaluate_records(_iter_jsonl(args.input), args.minimum_records,
                                  args.minimum_mechanisms)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError):
        report = _base_report()
        report["failures"] = {"input_parse_error": 1}
        report["acceptance_thresholds"] = {"minimum_records": args.minimum_records, "minimum_mechanisms": args.minimum_mechanisms}
    try:
        write_private(args.sealed_report, args.session_lock, report)
    except (ValueError, OSError, UnicodeError):
        print('{"status":"RECORDING_FAILED"}')
        return 2
    print(public_receipt())
    return 0


if __name__ == "__main__":
    sys.exit(main())
