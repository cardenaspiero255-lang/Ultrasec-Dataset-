#!/usr/bin/env python3
"""Fail-closed, original-source Couchbase BSL commercial-distribution gate.

Original dependency evidence is from exact SHA-pinned Go import closure, not
licensed rights. No source bytes or private corpus are copied to output.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

FILES = {
    "logging/logger.go": "49077aba6fbe5241fa6a93f7d00d94df4add65b1ec7d247995391e0034cba270",
    "logging/logger_golog.go": "d32725e23d15ec9af4cffb8d8a299eb76cbf50ba2cb51b9c47fd69a2dec8ac27",
    "scramsha/scramsha.go": "8a43d5236b3212b1e6bfb63cbce3faf9f6e16d2bf4583d046e5edf7ec64ec00f",
    "scramsha/scramsha_http.go": "20bdfdf5ef281fcafb79fe528823ec627d90afd7fba06b3636053dccee67c684",
}
LICENSE_DOCS = {
    "LICENSE.txt": "584aa21e4e3c29356e5064b3d58cad614fc6c8a3265d96327de658a20b370f42",
    "licenses/BSL-Couchbase.txt": "3c22e5817c43fb602a003fd713cafc4db0cf46d9ec0473dd324eab22ad3eb4e1",
    "licenses/APL2.txt": "a6cba85bc92e0cff7a450b1d873c0eaa2e9fc96bf472df0247a26bec77bf3ff9",
}

def evaluate(doc: object, phase: str) -> dict:
    """Require all ORIGINAL hashes; fail if evidence or policy state changes."""
    if not isinstance(doc, dict) or doc.get("schema") != "ultrasec.gitea-couchbase-compiled-source-risk.v1":
        raise ValueError("invalid_original_evidence")
    if phase not in {"vulnerable", "fixed"}:
        raise ValueError("invalid_phase")
    if (doc.get("module")!="github.com/couchbase/goutils" or
            doc.get("commercial_distribution_cleared") is not False or
            doc.get("gold_admitted")!=0 or doc.get("certification")!="NOT_CERTIFIED"):
        raise ValueError("unsubstantiated_commercial_claim")
    rows=doc.get("files");docs=doc.get("license_documents")
    if not isinstance(rows,list) or not isinstance(docs,list):
        raise ValueError("invalid_source_scope")
    if phase == "vulnerable":
        if (rows or docs or doc.get("module_version") is not None or
                doc.get("imported_packages")!=0 or doc.get("inspected_source_files")!=0 or
                doc.get("license_applicability")!="NOT_WITHIN_THIS_ORIGINAL_GO_SERVICE_IMPORT_CLOSURE"):
            raise ValueError("unexpected_original_prepatch_closure")
        return {
            "schema":"ultrasec.original-couchbase-commercial-gate.v1",
            "phase":phase,
            "scope_status":"MODULE_ABSENT_FROM_SERVICE_IMPORT_CLOSURE",
            "actual_original_source_files":0,"source_header_bsl_references":0,
            "commercial_distribution_allowed":False,
            "file_level_rights_verified":False,
            "licensed_work_applicability_resolved":False,
            "legal_question":"SCOPE_OF_OTHER_POTENTIAL_BUNDLE_DEPENDENCIES_NOT_REVIEWED",
            "source_only_in_scope":True,
            "certification":"NOT_CERTIFIED",
            "gold_admitted":0,
        }
    if (doc.get("module_version")!="v0.3.0" or
            doc.get("imported_packages")!=2 or doc.get("inspected_source_files")!=4 or
            doc.get("license_applicability")!="REQUIRES_FILE_AND_LICENSE_SCOPE_REVIEW" or
            doc.get("licensed_work_observed")!="Couchbase Server Version 8.0" or
            doc.get("change_date_observed")!="March 1, 2029"):
        raise ValueError("original_bsl_ambiguity_or_scope_changed")
    if len(rows)!=4 or len(docs)!=3:
        raise ValueError("incomplete_original_file_inventory")
    seen={}
    for r in rows:
        if not isinstance(r,dict):
            raise ValueError("invalid_original_file_record")
        path,sha=r.get("path"),r.get("sha256")
        if path in seen or path not in FILES or sha!=FILES[path]:
            raise ValueError("unexpected_original_file_or_hash")
        indicators=r.get("source_header_license_indicators")
        if (not isinstance(indicators,list) or
                not {"BSL-1.1-REFERENCE","APACHE-2.0-FUTURE-CHANGE-REFERENCE"}.issubset(set(indicators)) or
                r.get("per_file_license_verified") is not False):
            raise ValueError("license_header_or_review_misrepresented")
        seen[path]=sha
    if seen!=FILES:
        raise ValueError("missing_original_file")
    observed={}
    for row in docs:
        if not isinstance(row,dict):
            raise ValueError("invalid_original_license_document")
        path,sha=row.get("path"),row.get("sha256")
        if path in observed or path not in LICENSE_DOCS or sha!=LICENSE_DOCS[path]:
            raise ValueError("original_license_document_changed")
        observed[path]=sha
    if observed!=LICENSE_DOCS:
        raise ValueError("missing_license_document")
    return {
        "schema":"ultrasec.original-couchbase-commercial-gate.v1",
        "phase":phase,
        "source_scope":"ORIGINAL_PINNED_GITEA_FIXED_GO_IMPORT_CLOSURE",
        "module":"github.com/couchbase/goutils@v0.3.0",
        "actual_original_source_files":len(rows),
        "source_header_bsl_references":len(rows),
        "original_license_documents_verified_by_sha":len(docs),
        "observed_change_date":"March 1, 2029",
        "observed_licensed_work":"Couchbase Server Version 8.0",
        "legal_question":"LICENSED_WORK_SCOPE_AMBIGUOUS",
        "file_level_rights_verified":False,
        "licensed_work_applicability_resolved":False,
        "commercial_distribution_allowed":False,
        "standalone_compiled_bundle":"BLOCKED",
        "owner_only_ephemeral_reproduction":"RESEARCH_SCOPE_ONLY",
        "buyer_specific_notice_and_rights_review":"PENDING",
        "source_only_in_scope":True,
        "gold_admitted":0,
        "certification":"NOT_CERTIFIED",
    }

def main(argv=None):
    p=argparse.ArgumentParser(description="Conservative commercial rights gate from original file SHA")
    p.add_argument("--scope",type=Path,required=True)
    p.add_argument("--phase",choices=("vulnerable","fixed"),required=True)
    p.add_argument("--receipt",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        doc=json.loads(args.scope.read_text(encoding="utf-8"))
        r=evaluate(doc,args.phase)
        # Output is metadata-only, and the destination is a new file.
        with args.receipt.open("x",encoding="utf-8") as f:
            json.dump(r,f,sort_keys=True,indent=2)
            f.write("\n")
        print(json.dumps(r,sort_keys=True))
    except (ValueError,OSError,TypeError,UnicodeError,KeyError,json.JSONDecodeError):
        print('{"status":"FAIL_CLOSED_RIGHTS_GATE","certification":"NOT_CERTIFIED"}')
        return 1
    return 0

if __name__=="__main__":
    sys.exit(main())
