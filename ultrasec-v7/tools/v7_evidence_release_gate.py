#!/usr/bin/env python3
"""Fail-closed public index verifier. It NEVER certifies security, licenses, or data.

A matching SHA-256 proves that a *referenced file* has certain bytes.
It cannot prove the file's assertions, truth of labels, independence,
the validity of a patch or legal permission to redistribute code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

REQUIRED = frozenset({
    "corpus_inventory", "source_reproduction", "causal_labels",
    "split_integrity", "sast_blind", "distribution_rights",
})
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024


def _unique_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate_json_key")
        out[key] = value
    return out


def load_manifest(path: Path) -> object:
    """Strict JSON reader: no duplicate keys or non-standard floating values."""
    with path.open("r", encoding="utf-8") as handle:
        return json.load(
            handle,
            object_pairs_hook=_unique_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("invalid_json_constant")
            ),
        )


def _safe_file(root: Path, raw: str) -> Path | None:
    """Reject traversal, symlinks at *any* component, and non-regular files."""
    if not isinstance(raw, str) or not raw or len(raw) > 240:
        return None
    if "\\" in raw or "\x00" in raw:
        return None
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in ("..", ".") for part in raw.split("/")):
        return None
    if any(not part for part in raw.split("/")):
        return None
    candidate = root
    try:
        for part in path.parts:
            candidate = candidate / part
            mode = candidate.lstat().st_mode
            if stat.S_ISLNK(mode):
                return None
        if not stat.S_ISREG(candidate.stat().st_mode):
            return None
    except (OSError, ValueError):
        return None
    return candidate


def evaluate(manifest: object, root: Path) -> dict:
    """Verify only evidence-index structure, referential integrity, and hashes."""
    failures = set()
    seen = set()
    verified = 0
    passed = 0
    if (not isinstance(manifest, dict)
            or set(manifest) != {"schema_version", "controls"}
            or type(manifest.get("schema_version")) is not int
            or manifest["schema_version"] != 1
            or not isinstance(manifest.get("controls"), list)):
        failures.add("invalid_schema")
        controls = []
    else:
        controls = manifest["controls"]

    for control in controls:
        if not isinstance(control, dict):
            failures.add("invalid_control")
            continue
        key = control.get("id")
        if not isinstance(key, str) or key not in REQUIRED:
            failures.add("unknown_control")
            continue
        if key in seen:
            failures.add("duplicate_control")
            continue
        seen.add(key)
        state = control.get("status")
        if state == "NOT_VERIFIED" and set(control) == {"id", "status"}:
            continue
        if state != "PASS" or set(control) != {
            "id", "status", "source_kind", "evidence_path", "sha256",
        }:
            failures.add("invalid_control")
            continue
        # Source_kind is never allowed to imply outside assurance.
        if control["source_kind"] != "claimed":
            failures.add("invalid_control")
            continue
        digest = control["sha256"]
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            failures.add("invalid_control")
            continue
        filename = _safe_file(root, control["evidence_path"])
        if filename is None:
            failures.add("unsafe_evidence_path")
            continue
        try:
            if filename.stat().st_size > MAX_EVIDENCE_BYTES:
                failures.add("oversize_evidence")
                continue
            sha = hashlib.sha256()
            with filename.open("rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    sha.update(chunk)
            if sha.hexdigest() != digest:
                failures.add("digest_mismatch")
                continue
        except OSError:
            failures.add("evidence_unreadable")
            continue
        verified += 1
        passed += 1
    if seen != REQUIRED:
        failures.add("missing_control")
    complete = not failures and seen == REQUIRED and passed == len(REQUIRED)
    return {
        "schema": "ultrasec.v7.public-evidence-index.v1",
        "evidence_index_complete": complete,
        "verified_evidence_files": verified,
        "required_controls": len(REQUIRED),
        "certification": "NOT_CERTIFIED",
        "commercial_distribution": "NOT_VERIFIED",
        "human_review": "DEFERRED",
        "scope": "PUBLIC_POINTER_AND_DIGEST_CHECK_ONLY",
        "failures": sorted(failures),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--expect-blocked", action="store_true")
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        report = evaluate(manifest, args.root)
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        report = {
            "schema": "ultrasec.v7.public-evidence-index.v1",
            "evidence_index_complete": False,
            "certification": "NOT_CERTIFIED",
            "commercial_distribution": "NOT_VERIFIED",
            "failures": ["invalid_manifest"],
        }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    if report["failures"]:
        return 2
    if args.expect_blocked and report["evidence_index_complete"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
