#!/usr/bin/env python3
"""Offline PRIVATE holdout metadata screening; never verifies labels, scanners or licenses.

No raw identifiers, CVEs, hashes or source code appear in the aggregate output.
A passing metadata preflight is NOT an accepted or independently reviewed gold set.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys

HEX40 = re.compile(r"[a-f0-9]{40}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
CVE = re.compile(r"CVE-(?:19|20)[0-9]{2}-[0-9]{4,}\Z")
CWE = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
ID = re.compile(r"[a-zA-Z0-9_-]{1,128}\Z")
SPLITS = {"train", "validation", "test"}
ORACLES = {"ORIGINAL_RED_GREEN_TEST", "INDEPENDENT_STATIC_CONTRACT"}
FIELDS = frozenset({
    "case_id", "cve_id", "project_fingerprint", "mechanism_fingerprint",
    "source_commit", "fix_commit", "source_sha256", "fix_sha256",
    "cwe_id", "vulnerable", "split", "oracle_type", "oracle_run_sha256",
    "rule_pre_registered", "scanner_output_sha256",
})


def _well_formed(row: object) -> bool:
    if not isinstance(row, dict) or set(row) != FIELDS:
        return False
    if (type(row["vulnerable"]) is not bool or
            type(row["rule_pre_registered"]) is not bool):
        return False
    for key in ("case_id", "cve_id", "cwe_id", "split", "oracle_type"):
        if not isinstance(row[key], str):
            return False
    for key in ("project_fingerprint", "mechanism_fingerprint",
                "source_commit", "fix_commit", "source_sha256", "fix_sha256",
                "oracle_run_sha256", "scanner_output_sha256"):
        if not isinstance(row[key], str):
            return False
    return (
        bool(ID.fullmatch(row["case_id"])) and
        bool(CVE.fullmatch(row["cve_id"])) and
        bool(CWE.fullmatch(row["cwe_id"])) and
        all(HEX64.fullmatch(row[k]) for k in (
            "project_fingerprint", "mechanism_fingerprint", "source_sha256",
            "fix_sha256", "oracle_run_sha256", "scanner_output_sha256")) and
        all(HEX40.fullmatch(row[k]) for k in ("source_commit", "fix_commit")) and
        row["source_commit"] != row["fix_commit"] and
        row["source_sha256"] != row["fix_sha256"]
    )


def preflight(rows: list[dict], minimum_cases: int = 100,
              minimum_cwes: int = 12) -> dict:
    if (type(minimum_cases) is not int or minimum_cases < 1 or
            type(minimum_cwes) is not int or minimum_cwes < 1):
        raise ValueError("minimum_cases and minimum_cwes must be positive integers")
    if not isinstance(rows, list):
        raise ValueError("rows must be a JSONL-derived list")

    errors = Counter()
    seen_case_ids = set()
    seen_by_split = defaultdict(dict)
    all_cwes = set()
    test_cwe_classes = defaultdict(set)
    count_by_split = Counter()
    test_projects = set()
    test_commits = set()
    test_contents = set()
    seen_source_pairs = set()
    seen_content_pairs = set()

    def observe(key: str, value: str, split: str, failure: str) -> None:
        old = seen_by_split[key].setdefault(value, split)
        if old != split:
            errors[failure] += 1

    valid = 0
    for row in rows:
        if not _well_formed(row):
            errors["invalid_record"] += 1
            continue
        valid += 1
        cid = row["case_id"]
        if cid in seen_case_ids:
            errors["duplicate_case_id"] += 1
        seen_case_ids.add(cid)
        cwe = row["cwe_id"]
        split = row["split"]
        all_cwes.add(cwe)

        if split not in SPLITS:
            errors["unassigned_or_invalid_split"] += 1
            continue
        count_by_split[split] += 1
        # Two records that reuse the same complete original before/after pair
        # are ONE piece of evidence, regardless of their case IDs or split.
        # Individual files/projects can legitimately occur in distinct patches.
        source_pair = (row["source_commit"], row["fix_commit"])
        content_pair = (row["source_sha256"], row["fix_sha256"])
        if source_pair in seen_source_pairs:
            errors["duplicate_source_pair"] += 1
        seen_source_pairs.add(source_pair)
        if content_pair in seen_content_pairs:
            errors["duplicate_content_pair"] += 1
        seen_content_pairs.add(content_pair)
        if split == "test":
            test_cwe_classes[cwe].add(row["vulnerable"])
            project = row["project_fingerprint"]
            if project in test_projects:
                errors["duplicate_test_origin"] += 1
            test_projects.add(project)
            for commit in (row["source_commit"], row["fix_commit"]):
                if commit in test_commits:
                    errors["duplicate_test_source_commit"] += 1
                test_commits.add(commit)
            for digest in (row["source_sha256"], row["fix_sha256"]):
                if digest in test_contents:
                    errors["duplicate_test_source_content"] += 1
                test_contents.add(digest)

        if row["oracle_type"] not in ORACLES:
            errors["unverified_oracle_kind"] += 1
        if not row["rule_pre_registered"]:
            errors["posthoc_or_unknown_rule"] += 1

        observe("project", row["project_fingerprint"], split, "project_split_leakage")
        observe("mechanism", row["mechanism_fingerprint"], split, "mechanism_split_leakage")
        observe("cve", row["cve_id"], split, "cve_split_leakage")
        for commit in (row["source_commit"], row["fix_commit"]):
            observe("commit", commit, split, "source_commit_split_leakage")
        for content in (row["source_sha256"], row["fix_sha256"]):
            observe("content", content, split, "source_content_split_leakage")

    if valid < minimum_cases:
        errors["insufficient_cases"] += 1
    if len(all_cwes) < minimum_cwes:
        errors["insufficient_cwe_diversity"] += 1
    if len(test_cwe_classes) < minimum_cwes:
        errors["insufficient_test_cwe_diversity"] += 1
    if any(classes != {True, False} for classes in test_cwe_classes.values()):
        errors["cwe_without_both_classes"] += 1
    if count_by_split["test"] == 0 or count_by_split["train"] == 0:
        errors["missing_train_or_test"] += 1

    return {
        "schema": "ultrasec.private-benchmark-metadata-preflight.v1",
        "scope": "OWNER_LOCAL_ONLY_NO_DATA_EXPORTED",
        "metadata_preflight_pass": not bool(errors),
        "certification": "NOT_CERTIFIED",
        "gold_independently_verified": False,
        "real_scanner_execution_verified": False,
        "resale_rights_verified": False,
        "human_review_phase": "DEFERRED",
        "metrics": {
            "cases": valid, "cwe_families": len(all_cwes),
            "test_cwe_families": len(test_cwe_classes),
            "train": count_by_split["train"],
            "validation": count_by_split["validation"],
            "test": count_by_split["test"],
        },
        "failures": dict(sorted(errors.items())),
        "interpretation": (
            "Checks self-provided metadata consistency only. Hashes and original test"
            " references require external replay; positive preflight is not proof of"
            " truth labels, absence of semantic duplication, or legal reuse rights."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PRIVATE holdout metadata preflight")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--minimum-cases", type=int, default=100)
    parser.add_argument("--minimum-cwes", type=int, default=12)
    args = parser.parse_args(argv)
    try:
        with args.input.open(encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle if line.strip()]
        report = preflight(rows, args.minimum_cases, args.minimum_cwes)
    except (ValueError, TypeError, OSError, UnicodeError, json.JSONDecodeError):
        print('{"status":"INPUT_REJECTED","certification":"NOT_CERTIFIED"}')
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["metadata_preflight_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
