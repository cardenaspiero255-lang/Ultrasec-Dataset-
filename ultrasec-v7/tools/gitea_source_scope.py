#!/usr/bin/env python3
"""Fail-closed provenance of original Gitea patch and license documents.

GitHub Actions can compare the recorded blobs against Git, and emit a SHA256
only receipt. Never stores source code, private gold, or distribution rights.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

PARENT="7fdfb8d642201b388014f29889ef28e35b8c1872"
FIX="e4ef995f2a162e3aca3f3a0b536afae067975d71"
CHANGED=(
    "services/release/release.go","services/release/release_test.go",
    "routers/web/repo/release.go","routers/web/repo/release_test.go",
    "templates/repo/release/new.tmpl","tests/integration/release_test.go",
)
ENV_FILES=("LICENSE","go.mod","go.sum")
SHA40=re.compile(r"^[0-9a-f]{40}$")
MIT_SPDX_GO_COMMENT=re.compile(rb"^[ \t]*//[ \t]*SPDX-License-Identifier:[ \t]*MIT[ \t]*$")


def has_go_mit_spdx_header(payload:object)->bool:
    """Check actual MIT SPDX Go header comments, not arbitrary source substrings.

    Gitea uses '// SPDX-License-Identifier: MIT'. A bare byte-string membership
    test against splitlines() mistakenly rejects valid commented SPDX headers.
    """
    return isinstance(payload,bytes) and any(
        MIT_SPDX_GO_COMMENT.fullmatch(line) is not None
        for line in payload.splitlines()[:6]
    )

def check_scope(doc:object)->dict:
    errors=set()
    if not isinstance(doc,dict):
        return _summary(errors|{"invalid_manifest"},0,0)
    if (doc.get("schema")!="ultrasec.gitea-source-rights-audit.v1"
        or doc.get("cve_id")!="CVE-2026-58428"
        or doc.get("upstream_url")!="https://github.com/go-gitea/gitea"
        or doc.get("parent_commit")!=PARENT
        or doc.get("fix_commit")!=FIX):
        errors.add("unexpected_original_commit")
    if (doc.get("commercial_distribution_authorized") is not False
        or doc.get("commercial_product_package_ready") is not False
        or doc.get("file_level_chain_of_title_verified") is not False
        or doc.get("third_party_dependency_licenses_verified") is not False
        or doc.get("certification")!="NOT_CERTIFIED"
        or doc.get("private_gold_admitted")!=0):
        errors.add("unsupported_license_clearance")
    if doc.get("packaged_source_paths")!=[]:
        errors.add("premature_source_packaging")
    if doc.get("test_source_derived_from_fix") is not True or doc.get("holdout_blindness")!="NOT_BLIND_PATCH_KNOWN":
        errors.add("witness_provenance_mismatch")
    changed=doc.get("changed_files")
    env=doc.get("runtime_files")
    if not isinstance(changed,list) or not isinstance(env,list):
        return _summary(errors|{"invalid_manifest"},0,0)
    if [r.get("path") for r in changed if isinstance(r,dict)]!=list(CHANGED):
        errors.add("changed_file_list_mismatch")
    if [r.get("path") for r in env if isinstance(r,dict)]!=list(ENV_FILES):
        errors.add("environment_file_list_mismatch")
    allrows=changed+env
    if len(allrows)!=9 or any(not isinstance(r,dict) for r in allrows):
        errors.add("invalid_manifest")
    for row in allrows:
        if not isinstance(row,dict):continue
        a=row.get("vulnerable_git_blob")
        b=row.get("fixed_git_blob")
        if (not isinstance(a,str) or not isinstance(b,str)
            or not SHA40.fullmatch(a) or not SHA40.fullmatch(b)
            or a=="0"*40 or b=="0"*40):
            errors.add("untrusted_blob_id")
    for row in changed:
        if not isinstance(row,dict):continue
        if row.get("vulnerable_git_blob")==row.get("fixed_git_blob"):
            errors.add("unchanged_in_fix")
        spdx=row.get("observed_spdx")
        if row.get("path")=="templates/repo/release/new.tmpl":
            if spdx is not None or row.get("license_evidence")!="ROOT_LICENSE_SCOPE_REQUIRES_REVIEW":
                errors.add("file_header_unverified")
        elif spdx!="MIT" or row.get("license_evidence")!="UPSTREAM_FILE_HEADER":
            errors.add("file_header_unverified")
        if (row.get("file_level_rights_cleared") is not False or
            row.get("commercial_packaging")!="NOT_AUTHORIZED"):
            errors.add("unsupported_license_clearance")
    for row in env:
        if not isinstance(row,dict):continue
        if row.get("vulnerable_git_blob")!=row.get("fixed_git_blob"):
            errors.add("unexpected_runtime_blob")
    return _summary(errors,len(changed),len(env))

def _summary(errors:set,changed:int,env:int)->dict:
    return {
        "schema":"ultrasec.gitea-source-scope-screen.v1",
        "errors":sorted(errors),
        "changed_files":changed,
        "runtime_files":env,
        "recorded_git_blob_ids":(changed+env)*2,
        "reproducible_pair_gold":0,
        "commercial_distribution_authorized":False,
        "third_party_dependency_licenses_verified":False,
        "certification":"NOT_CERTIFIED",
    }

def _git(repo:Path,*args:str)->bytes:
    return subprocess.run(
        ["git","-C",str(repo),*args],check=True,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,
    ).stdout

def verify_original_repository(doc:dict,upstream:Path)->dict:
    """Resolve two original commit trees and exact source bytes. No source exported."""
    shape=check_scope(doc)
    if shape["errors"]:
        return {"errors":shape["errors"],"original_git_verified":False,"files":[]}
    errors=set()
    receipt=[]
    try:
        parents=_git(upstream,"rev-list","--parents","-n","1",FIX).decode().split()
        if parents!=[FIX,PARENT]:
            errors.add("original_parent_mismatch")
        diff=_git(upstream,"diff","--name-only",PARENT,FIX).decode().splitlines()
        if sorted(diff)!=sorted(CHANGED):
            errors.add("original_diff_paths_mismatch")
        for row in doc["changed_files"]+doc["runtime_files"]:
            path=row["path"]
            hashes={}
            for phase,sha,key in (("before",PARENT,"vulnerable_git_blob"),("after",FIX,"fixed_git_blob")):
                blob=_git(upstream,"rev-parse",f"{sha}:{path}").decode().strip()
                payload=_git(upstream,"cat-file","blob",blob)
                if blob!=row[key]:
                    errors.add("original_blob_mismatch")
                hashes[phase]={"git_blob":blob,"sha256":hashlib.sha256(payload).hexdigest(),"bytes":len(payload)}
                if path.endswith(".go") and not has_go_mit_spdx_header(payload):
                    errors.add("go_header_license_mismatch")
                if path=="templates/repo/release/new.tmpl" and b"SPDX-License-Identifier:" in payload.splitlines()[:6]:
                    errors.add("template_license_assumption_mismatch")
                if path=="LICENSE" and (b"Copyright (c) 2016 The Gitea Authors" not in payload
                    or b"this permission notice shall be included" not in payload.lower()):
                    errors.add("original_license_text_mismatch")
                if path=="go.mod" and (b"module gitea.dev\n" not in payload[:200] or b"go 1.26.4" not in payload[:200]):
                    errors.add("go_toolchain_mismatch")
            receipt.append({"path":path,"source_shas":hashes,"file_level_rights":"NOT_VERIFIED"})
    except (OSError,subprocess.SubprocessError,UnicodeError,ValueError):
        errors.add("upstream_git_verification_failed")
    return {
        "schema":"ultrasec.gitea-original-provenance-receipt.v1",
        "original_git_verified":not bool(errors),
        "errors":sorted(errors),
        "source_commit":PARENT,
        "fix_commit":FIX,
        "observed_changed_files":6,
        "go_module_dependency_scope":"LOCKFILES_IDENTIFIED_TRANSITIVE_LICENSES_UNVERIFIED",
        "root_license":"MIT_HEADER_AND_ROOT_OBSERVED_SCOPE_NOT_CLEARED",
        "source_distributed":False,
        "gold_admitted":0,
        "ready_to_sell":False,
        "certification":"NOT_CERTIFIED",
        "files":receipt,
    }

def main(argv=None)->int:
    p=argparse.ArgumentParser()
    p.add_argument("--manifest",type=Path,default=Path(__file__).resolve().parents[1]/"verification/research/GITEA_ORIGINAL_FILE_RIGHTS_SCOPE.json")
    p.add_argument("--original-repo",type=Path)
    p.add_argument("--receipt",type=Path)
    args=p.parse_args(argv)
    try:
        doc=json.loads(args.manifest.read_text(encoding="utf-8"))
        report=verify_original_repository(doc,args.original_repo) if args.original_repo else check_scope(doc)
        if args.receipt is not None:
            args.receipt.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    except (OSError,ValueError,TypeError,json.JSONDecodeError) as exc:
        print('{"errors":["INPUT_REJECTED"],"certification":"NOT_CERTIFIED"}')
        return 2
    print(json.dumps({k:v for k,v in report.items() if k!="files"},sort_keys=True))
    return 0 if not report["errors"] else 1

if __name__=="__main__":
    sys.exit(main())
