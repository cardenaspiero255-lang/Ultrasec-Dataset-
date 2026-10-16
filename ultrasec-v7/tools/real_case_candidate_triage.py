#!/usr/bin/env python3
"""Offline candidate screening ONLY. Never certifies CVE provenance or rights.

Input JSONL must be owner-supplied, sourced from external CVE mining datasets.
The script does not fetch or execute source code; output contains only safe
aggregate counts and deliberately refuses to claim ground truth or licensing.
"""
from __future__ import annotations

from collections import Counter
import argparse
import json
import math
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from premium_evidence import _PINNED_MITRE_CWES

_CVE=re.compile(r"CVE-(?:19|20)[0-9]{2}-[0-9]{4,}\Z")
_SHA=re.compile(r"[0-9a-f]{40}\Z")
_PATH=re.compile(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?\Z")
_SOURCES=frozenset(("MoreFixes v4","CVEfixes v1.0.8"))


def _eligible(row: dict) -> str | None:
    if not isinstance(row,dict):
        return "invalid_schema"
    if (not isinstance(row.get("cve_id"),str)
            or not _CVE.fullmatch(row["cve_id"])
            or row.get("cwe_id") not in _PINNED_MITRE_CWES
            or row.get("source_dataset") not in _SOURCES):
        return "invalid_public_reference"
    if (not isinstance(row.get("source_commit"),str)
            or not isinstance(row.get("fix_commit"),str)
            or not _SHA.fullmatch(row["source_commit"])
            or not _SHA.fullmatch(row["fix_commit"])
            or row["source_commit"]==row["fix_commit"]):
        return "invalid_commit_reference"
    url=row.get("repo_url")
    if not isinstance(url,str):
        return "invalid_repository_url"
    try:
        u=urlsplit(url)
    except ValueError:
        return "invalid_repository_url"
    if (u.scheme!="https" or u.hostname!="github.com"
            or u.netloc!="github.com"
            or u.query or u.fragment or not _PATH.fullmatch(u.path)):
        return "invalid_repository_url"
    if row["source_dataset"]=="MoreFixes v4":
        score=row.get("score")
        if (type(score) not in (int,float) or not math.isfinite(score)
                or score<65 or score>100):
            return "insufficient_mining_confidence"
    return None


def screen_candidates(rows: list[dict], target:int=100, min_cwes:int=12)->dict:
    """Return a non-certifying, sanitized shortlist count for manual review.

    Unique projects are required for the initial shortlist to reduce shared
    origin bias. The ranking favors representation across CWE classes. Nothing
    in the output validates that the referenced commits or CVEs truly exist.
    """
    if type(target) is not int or target<1 or type(min_cwes) is not int or min_cwes<1:
        raise ValueError("Positive integer screening criteria required")
    if not isinstance(rows,list):
        raise TypeError("Candidate records must be a JSONL-derived list")
    rejected=Counter()
    valid=[]
    for row in rows:
        reason=_eligible(row)
        if reason:
            rejected[reason]+=1
            continue
        valid.append(row)
    # A deterministic candidate order cannot be manipulated by input ordering.
    valid.sort(key=lambda r:(r["cwe_id"],r["repo_url"].lower(),
                             r["cve_id"],r["fix_commit"]))
    seen_repos=set()
    seen_cves=set()
    unique=[]
    for row in valid:
        repo=row["repo_url"].rstrip("/").lower()
        cve=row["cve_id"]
        if repo in seen_repos:
            rejected["duplicate_origin_project"]+=1
            continue
        if cve in seen_cves:
            rejected["duplicate_cve"]+=1
            continue
        unique.append(row)
        seen_repos.add(repo)
        seen_cves.add(cve)
    selected=[]
    selected_ids=set()
    # Coverage-first round: one candidate from each CWE before filling.
    for cwe in sorted({r["cwe_id"] for r in unique}):
        if len(selected)>=target:
            break
        entry=next(r for r in unique if r["cwe_id"]==cwe)
        selected.append(entry)
        selected_ids.add(id(entry))
    for row in unique:
        if len(selected)>=target:
            break
        if id(row) not in selected_ids:
            selected.append(row)
            selected_ids.add(id(row))
    cwes={r["cwe_id"] for r in selected}
    return {
        "schema":"ultrasec.real-case-candidate-screen.v1",
        "scope":"PUBLIC_SOURCE_METADATA_ONLY",
        "candidate_target_met":len(selected)==target and len(cwes)>=min_cwes,
        "candidate_count":len(selected),
        "distinct_cwes":len(cwes),
        "distinct_projects":len(selected),
        "rejected":dict(sorted(rejected.items())),
        "externally_verified_cases":0,
        "independent_gold":"NOT_VERIFIED",
        "commercial_rights":"NOT_VERIFIED",
        "real_sast":"NOT_RUN",
        "certification":"NOT_CERTIFIED",
        "interpretation":"These are UNVERIFIED public metadata candidates, not licensed or reproduced CVEs.",
    }


def main(argv=None)->int:
    parser=argparse.ArgumentParser(description="Private offline CVE candidate metadata screening")
    parser.add_argument("candidates_jsonl",type=Path)
    parser.add_argument("--target",type=int,default=100)
    parser.add_argument("--families",type=int,default=12)
    args=parser.parse_args(argv)
    # No raw rows, source code or secret material is emitted to stdout.
    # A private file supplied by the owner is not published to CI artifacts.
    with args.candidates_jsonl.open(encoding="utf-8") as handle:
        rows=[json.loads(line) for line in handle if line.strip()]
    result=screen_candidates(rows,args.target,args.families)
    print(json.dumps(result,sort_keys=True))
    return 0 if result["candidate_target_met"] else 1


if __name__=="__main__":
    raise SystemExit(main())
