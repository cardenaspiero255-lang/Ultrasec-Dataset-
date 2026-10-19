#!/usr/bin/env python3
"""Inspect exact PUBLIC proposal files for integrity. NOT a legal rights clearance."""
from __future__ import annotations

from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

EXPECTED_SCHEMA="ultrasec.v7-exact-public-metadata-delivery-scope.v1"
SAFE_PATH=re.compile(r"verification/research/[A-Za-z0-9_.-]+\.(?:md|json)\Z")
SHA1=re.compile(r"[0-9a-f]{40}\Z")
EXPECTED_MODE="metadata_only"


def inspect(manifest: object, root: Path) -> dict:
    errors=Counter()
    results=[]
    if not isinstance(manifest,dict):
        return _report(0,[],{"invalid_manifest":1})
    if (manifest.get("schema")!=EXPECTED_SCHEMA
            or manifest.get("status")!="DRAFT_NOT_CERTIFIED_NOT_FOR_COMMERCIAL_DISTRIBUTION"
            or manifest.get("commercial_rights")!="NOT_VERIFIED"
            or manifest.get("legal_opinion")!="NOT_RECEIVED"):
        errors["unsupported_commercial_rights_claim"]+=1
    if manifest.get("delivery_mode")!=EXPECTED_MODE:
        errors["unsupported_distribution_mode"]+=1
    if (manifest.get("includes_gold_or_holdout") is not False
            or manifest.get("source_distribution_allowed") is not False):
        errors["invalid_private_corpus_claim"]+=1
    if (manifest.get("source_fragments_mode")!="OUT_OF_SCOPE_REQUIRES_SEPARATE_MANIFEST"
            or manifest.get("full_source_pairs_mode")!="OUT_OF_SCOPE_REQUIRES_SEPARATE_MANIFEST"):
        errors["unsupported_distribution_mode"]+=1

    inventory=manifest.get("files")
    if not isinstance(inventory,list) or len(inventory)!=5:
        errors["incomplete_proposed_file_inventory"]+=1
        inventory=inventory if isinstance(inventory,list) else []
    seen_paths=set()
    seen_blobs=set()
    for item in inventory:
        if not isinstance(item,dict) or set(item)!={"path","git_blob_sha1","rights_status","contains_upstream_source"}:
            errors["invalid_file_record"]+=1
            continue
        path=item["path"]
        blob=item["git_blob_sha1"]
        if not isinstance(path,str) or not SAFE_PATH.fullmatch(path):
            errors["invalid_distribution_file_path"]+=1
            continue
        if path in seen_paths or blob in seen_blobs:
            errors["duplicate_distribution_file"]+=1
        seen_paths.add(path)
        seen_blobs.add(blob)
        if not isinstance(blob,str) or not SHA1.fullmatch(blob):
            errors["invalid_source_git_blob"]+=1
            continue
        if item["rights_status"]!="NOT_VERIFIED" or item["contains_upstream_source"] is not False:
            errors["unsupported_commercial_rights_claim"]+=1
        source=root/path
        try:
            original=source.read_bytes()
        except (OSError,ValueError):
            errors["missing_proposed_file"]+=1
            continue
        gitblob=hashlib.sha1(f"blob {len(original)}\0".encode("ascii")+original).hexdigest()
        digest=hashlib.sha256(original).hexdigest()
        if blob!=gitblob:
            errors["source_blob_mismatch"]+=1
        results.append({
            "path":path,"git_blob_sha1":gitblob,"sha256":digest,
            "rights_status":"NOT_VERIFIED",
            "mode":"metadata_only",
            "third_party_source_distribution":"NOT_IN_SCOPE"
        })
    return _report(len(inventory),results,errors)


def _report(total:int,files:list,errors:Counter|dict)->dict:
    return {
        "schema":"ultrasec.v7-proposed-delivery-scope-integrity-report.v1",
        "status":"DRAFT_ONLY_NO_RESALE_AUTHORIZATION",
        "metadata_inventory_integrity_pass":not bool(errors),
        "manifested_files":total,
        "files":files,
        "failures":dict(sorted(errors.items())),
        "rights_verified":0,
        "commercial_release_ready":False,
        "commercial_rights":"NOT_VERIFIED",
        "source_distribution_allowed":False,
        "human_review_phase":"DEFERRED",
        "certification":"NOT_CERTIFIED",
        "interpretation":"Identifies five actual public files and content digests, not ownership, resale compliance, or any private holdout."
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Public metadata-only delivery file integrity; no legal clearance")
    parser.add_argument("--manifest",type=Path,default=Path(__file__).resolve().parents[1]/"verification/research/DELIVERY_SCOPE_PUBLIC_METADATA_DRAFT.json")
    parser.add_argument("--report",type=Path)
    args=parser.parse_args(argv)
    try:
        data=json.loads(args.manifest.read_text(encoding="utf-8"))
        report=inspect(data,Path(__file__).resolve().parents[1])
        if args.report is not None:
            args.report.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError):
        print('{"status":"INPUT_REJECTED","certification":"NOT_CERTIFIED"}')
        return 2
    print(json.dumps({k:v for k,v in report.items() if k!="files"},sort_keys=True))
    return 0 if report["metadata_inventory_integrity_pass"] else 1


if __name__=="__main__":
    sys.exit(main())
