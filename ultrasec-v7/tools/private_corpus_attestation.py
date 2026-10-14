#!/usr/bin/env python3
"""Owner-side structural attestations for compressed, private synthetic corpora.

Nothing private is published, executed, transmitted or printed. A sealable
owner report is NOT a security certification or a legal rights assessment.
"""
from __future__ import annotations

from collections import Counter
import argparse
import gzip
try:
    from lzma import LZMAError as _LzmaError
except ImportError:
    class _LzmaError(Exception):
        """Placeholder when optional _lzma is absent; ZIP_STORED still works."""
        pass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import sqlite3
import tempfile
import zipfile
import zlib

try:
    from compression.zstd import ZstdError as _ZstdError  # Python 3.14+ ZIP_ZSTANDARD
except ImportError:
    class _ZstdError(Exception):
        """Placeholder on interpreters without built-in Zstandard support."""
        pass

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


def audit_rows(records, scratch_dir: Path | None = None) -> dict:
    """Bounded-memory exact uniqueness and pairing through private temporary SQLite.

    A 0700 scratch folder inside owner-owned storage keeps hashed identifiers,
    code hashes and pair masks on disk. No raw code or identifiers are stored.
    Counts reflect *syntactic* uniqueness only, never causal independence.
    """
    errors: Counter[str] = Counter()
    splits: Counter[str] = Counter()
    rows_count = 0
    unverified = 0
    pending_rights = 0
    generator_labels = 0

    def opaque(text: str) -> bytes:
        return hashlib.sha256(text.encode("utf-8")).digest()

    with tempfile.TemporaryDirectory(prefix="ultrasec-private-", dir=scratch_dir) as temporary:
        db_path = Path(temporary) / "indexes.sqlite3"
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("PRAGMA temp_store=FILE")
            conn.execute("PRAGMA synchronous=OFF")
            conn.executescript("""
                CREATE TABLE record_ids (d BLOB PRIMARY KEY);
                CREATE TABLE code_hashes (d BLOB PRIMARY KEY);
                CREATE TABLE families (d BLOB PRIMARY KEY);
                CREATE TABLE languages (d BLOB PRIMARY KEY);
                CREATE TABLE templates (d BLOB PRIMARY KEY, split TEXT NOT NULL);
                CREATE TABLE pairs (d BLOB PRIMARY KEY, identity BLOB NOT NULL,
                                    labels INTEGER NOT NULL);
            """)
            conn.execute("BEGIN")
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

                rid = opaque(row["id"])
                if not conn.execute("INSERT OR IGNORE INTO record_ids VALUES (?)", (rid,)).rowcount:
                    errors["duplicate_record_id"] += 1
                    continue

                digest = opaque(row["code"])
                if not conn.execute("INSERT OR IGNORE INTO code_hashes VALUES (?)", (digest,)).rowcount:
                    errors["duplicate_code"] += 1
                if not row["independently_validated"]:
                    unverified += 1
                if row["license_clearance"] != "cleared":
                    pending_rights += 1
                if row["label_provenance"] == "generator_intent_unverified":
                    generator_labels += 1
                conn.execute("INSERT OR IGNORE INTO families VALUES (?)", (opaque(row["family"]),))
                conn.execute("INSERT OR IGNORE INTO languages VALUES (?)", (opaque(row["language"]),))
                splits[row["split"]] += 1

                template = opaque(row["template_id"])
                previous = conn.execute("SELECT split FROM templates WHERE d=?", (template,)).fetchone()
                if previous is None:
                    conn.execute("INSERT INTO templates VALUES (?,?)", (template, row["split"]))
                elif previous[0] != row["split"]:
                    errors["template_split_leakage"] += 1

                identity = opaque(json.dumps(
                    [row["family"], row["language"], row["template_id"], row["split"]],
                    ensure_ascii=True, separators=(",", ":")))
                pair_id = opaque(row["pair_id"])
                mask = 1 if row["label"] == "vulnerable" else 2
                previous_pair = conn.execute(
                    "SELECT identity, labels FROM pairs WHERE d=?", (pair_id,)).fetchone()
                if previous_pair is None:
                    conn.execute("INSERT INTO pairs VALUES (?,?,?)", (pair_id, identity, mask))
                else:
                    old_identity, labels = previous_pair
                    if old_identity != identity:
                        errors["pair_metadata_mismatch"] += 1
                    if labels & mask:
                        errors["duplicate_pair_variant"] += 1
                    conn.execute("UPDATE pairs SET labels=? WHERE d=?", (labels | mask, pair_id))

            unique_record_ids = conn.execute("SELECT COUNT(*) FROM record_ids").fetchone()[0]
            unique_code_hashes = conn.execute("SELECT COUNT(*) FROM code_hashes").fetchone()[0]
            unique_templates = conn.execute("SELECT COUNT(*) FROM templates").fetchone()[0]
            family_count = conn.execute("SELECT COUNT(*) FROM families").fetchone()[0]
            language_count = conn.execute("SELECT COUNT(*) FROM languages").fetchone()[0]
            unique_pairs = conn.execute("SELECT COUNT(*) FROM pairs").fetchone()[0]
            complete_pairs = conn.execute("SELECT COUNT(*) FROM pairs WHERE labels=3").fetchone()[0]
            incomplete = unique_pairs - complete_pairs
            if incomplete:
                errors["incomplete_pair"] += incomplete
            if rows_count == 0:
                errors["empty_input"] += 1
        finally:
            conn.close()

    report = empty_report()
    report["index_backend"] = "sqlite-private-temporary"
    report["metrics"] = {
        "records": rows_count,
        "unique_record_ids": unique_record_ids,
        "complete_pairs": complete_pairs,
        "unique_pair_ids": unique_pairs,
        "template_ids": unique_templates,
        "exact_code_hashes": unique_code_hashes,
        "family_count": family_count,
        "language_count": language_count,
        "unverified_records": unverified,
        "rights_pending_records": pending_rights,
        "generator_intent_labels": generator_labels,
        "split_counts": {name: splits[name] for name in ("train", "validation", "test")},
    }
    report["errors"] = dict(sorted((key, n) for key, n in errors.items() if n))
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
        report = audit_rows(_archive_records(args.archive, args.member, sha),
                            scratch_dir=args.sealed_report.parent)
        matches = (sha.hexdigest() == args.expected_sha256)
        report["integrity"] = {"sha256_matches_expected": matches,
                               "digest_algorithm": "SHA-256",
                               "hash_scope": "decompressed_JSONL_bytes"}
        if not matches:
            report["errors"]["sha256_mismatch"] = 1
            report["owner_integrity_pass"] = False
    except (ValueError, OSError, UnicodeError, zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, KeyError, RecursionError, RuntimeError, sqlite3.Error, zlib.error, _LzmaError, _ZstdError):
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
