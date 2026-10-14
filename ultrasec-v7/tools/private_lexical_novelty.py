#!/usr/bin/env python3
"""Owner-only lexical novelty screening; NOT semantic or independent security certification.

The fingerprint intentionally normalizes identifiers, numbers, and whitespace.
Distinct code strings may collapse even when programs have different behavior.
This tool NEVER claims causal independence, correct fixes, or commercial value.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import zipfile
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sealed_evidence import write_private, public_receipt, safe_ratio
from private_corpus_attestation import _archive_records, _LzmaError, _ZstdError

_IDENT = re.compile(r"\b[A-Za-z_][\w]*\b")
_NUMBER = re.compile(r"\b\d+(?:\.\d+)?\b")
_SPACES = re.compile(r"\s+")


def lexical_shape(code: str) -> str:
    """A deliberately coarse, language-agnostic lexical abstraction.

    It is NOT a semantic equivalence algorithm and is not safe to use for
    automatic deletion or to claim independent vulnerabilities.
    """
    if not isinstance(code, str):
        raise TypeError("Code must be text")
    return _SPACES.sub(" ", _NUMBER.sub("NUM", _IDENT.sub("ID", code))).strip()


def _empty() -> dict:
    return {
        "schema": "ultrasec.lexical-novelty-screen.v1",
        "scope": "OWNER_LOCAL_HEURISTIC_ONLY",
        "certification": "NOT_CERTIFIED",
        "semantic_uniqueness": "NOT_VERIFIED",
        "external_appsec_review": "NOT_VERIFIED",
        "commercial_valuation": "NOT_VERIFIED",
        "lexical_screen_pass": False,
        "index_backend": "sqlite-private-temporary",
        "normalization": "identifier->ID; numeric token->NUM; whitespace compacted",
        "criteria": {},
        "integrity": {},
        "metrics": {},
        "failures": {},
    }


def screen_records(records, minimum_lexical_unique_fraction: float,
                   scratch_dir: Path | None = None) -> dict:
    """O(1) Python index memory; SQLite disk indexes contain only SHA-256 digests."""
    if (isinstance(minimum_lexical_unique_fraction, bool)
            or not isinstance(minimum_lexical_unique_fraction, (int, float))
            or not math.isfinite(minimum_lexical_unique_fraction)
            or not 0 <= minimum_lexical_unique_fraction <= 1):
        raise ValueError("Minimum lexical uniqueness fraction must be finite in [0,1]")

    errors: Counter[str] = Counter()
    count = 0
    with tempfile.TemporaryDirectory(prefix="ultrasec-lexical-", dir=scratch_dir) as temp:
        conn = sqlite3.connect(str(Path(temp) / "fingerprints.sqlite3"))
        try:
            conn.execute("PRAGMA temp_store=FILE")
            conn.execute("PRAGMA synchronous=OFF")
            conn.executescript("""
                CREATE TABLE codes (d BLOB PRIMARY KEY);
                CREATE TABLE lexical_forms (d BLOB PRIMARY KEY);
                CREATE TABLE families (d BLOB PRIMARY KEY);
                CREATE TABLE languages (d BLOB PRIMARY KEY);
            """)
            conn.execute("BEGIN")
            for item in records:
                count += 1
                if (not isinstance(item, dict)
                        or not all(isinstance(item.get(k), str) and item.get(k)
                                   for k in ("code", "family", "language"))):
                    errors["invalid_record_schema"] += 1
                    continue
                raw = hashlib.sha256(item["code"].encode("utf-8")).digest()
                shape = hashlib.sha256(lexical_shape(item["code"]).encode("utf-8")).digest()
                family = hashlib.sha256(item["family"].encode("utf-8")).digest()
                language = hashlib.sha256(item["language"].encode("utf-8")).digest()
                conn.execute("INSERT OR IGNORE INTO codes VALUES (?)", (raw,))
                conn.execute("INSERT OR IGNORE INTO lexical_forms VALUES (?)", (shape,))
                conn.execute("INSERT OR IGNORE INTO families VALUES (?)", (family,))
                conn.execute("INSERT OR IGNORE INTO languages VALUES (?)", (language,))
            codes = conn.execute("SELECT COUNT(*) FROM codes").fetchone()[0]
            forms = conn.execute("SELECT COUNT(*) FROM lexical_forms").fetchone()[0]
            families = conn.execute("SELECT COUNT(*) FROM families").fetchone()[0]
            languages = conn.execute("SELECT COUNT(*) FROM languages").fetchone()[0]
        finally:
            conn.close()

    if not count:
        errors["empty_corpus"] += 1
    fraction = forms / count if count else 0.0
    if fraction < minimum_lexical_unique_fraction:
        errors["below_lexical_uniqueness_threshold"] += 1
    report = _empty()
    report["criteria"] = {
        "minimum_lexical_unique_fraction": minimum_lexical_unique_fraction,
        "threshold_comparison": "unrounded_distinct_lexical_forms_over_total_records",
    }
    report["metrics"] = {
        "records": count,
        "exact_unique_code": codes,
        "lexical_patterns": forms,
        "additional_lexical_collisions": count - forms,
        "unique_fraction_display": round(fraction, 6),
        "family_categories": families,
        "language_categories": languages,
    }
    report["failures"] = dict(sorted((k, v) for k, v in errors.items() if v))
    report["lexical_screen_pass"] = not report["failures"]
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Owner-only lexical screen; no private records on stdout")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--member", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--minimum-lexical-unique-fraction", type=float, required=True)
    parser.add_argument("--sealed-report", type=Path, required=True)
    parser.add_argument("--session-lock", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256):
            raise ValueError("Invalid expected SHA-256")
        digest = hashlib.sha256()
        report = screen_records(
            _archive_records(args.archive, args.member, digest),
            args.minimum_lexical_unique_fraction, args.sealed_report.parent)
        matched = digest.hexdigest() == args.expected_sha256
        report["integrity"] = {"sha256_matches_expected": matched,
                                "hash_scope": "decompressed_JSONL_bytes"}
        if not matched:
            report["failures"]["sha256_mismatch"] = 1
            report["lexical_screen_pass"] = False
    except (ValueError, OSError, UnicodeError, EOFError, KeyError, RuntimeError,
            RecursionError, sqlite3.Error, zipfile.BadZipFile, zipfile.LargeZipFile,
            zlib.error, _LzmaError, _ZstdError):
        report = _empty()
        report["criteria"] = {
            "minimum_lexical_unique_fraction": safe_ratio(args.minimum_lexical_unique_fraction),
            "threshold_comparison": "unrounded_distinct_lexical_forms_over_total_records",
        }
        report["failures"] = {"input_parse_error": 1}
    try:
        write_private(args.sealed_report, args.session_lock, report)
    except (ValueError, OSError, UnicodeError):
        print('{"status":"RECORDING_FAILED"}')
        return 2
    print(public_receipt())
    return 0


if __name__ == "__main__":
    sys.exit(main())
