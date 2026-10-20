#!/usr/bin/env python3
"""Build and byte-check original Gitea patch-source overlay IN THE CI RUNNER.

Not standalone build, buyer delivery, independent gold or legal clearance.
The ZIP of third-party source is kept runner-local and never uploaded.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from gitea_source_scope import CHANGED, ENV_FILES, PARENT, FIX, check_scope

ALLOWED = tuple(CHANGED)+tuple(ENV_FILES)
MAX_BYTES = 8 * 1024 * 1024


def _object_id(payload: bytes) -> str:
    return subprocess.run(["git","hash-object","--stdin"],
        input=payload,check=True,capture_output=True,timeout=15,
    ).stdout.decode("ascii").strip()


def build_checked_overlay(payloads:dict[str,bytes], expected_blobs:dict[str,str],
                          output:Path,phase:str)->dict:
    """Create minimal byte-identical 6-file patch plus LICENSE and Go lockfiles."""
    if phase not in {"vulnerable","fixed"}:
        raise ValueError("not an upstream source phase")
    if (not isinstance(payloads,dict) or not isinstance(expected_blobs,dict)
            or set(payloads)!=set(ALLOWED) or set(expected_blobs)!=set(ALLOWED)):
        raise ValueError("source/manifest file-list mismatch")
    manifest=[]
    for name in ALLOWED:
        data=payloads[name]
        if not isinstance(data,bytes) or len(data)==0 or len(data)>MAX_BYTES:
            raise ValueError("missing or unusually large original file")
        if _object_id(data)!=expected_blobs[name]:
            raise ValueError("original Git source blob differs from manifest")
        manifest.append({"path":name,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),
                         "original_git_blob":expected_blobs[name]})
    license_text=payloads["LICENSE"]
    if not (b"Copyright (c) 2016 The Gitea Authors" in license_text
            and b"permission is hereby granted, free of charge" in license_text.lower()
            and b"the above copyright notice and this permission notice shall be included" in license_text.lower()):
        raise ValueError("original MIT license and notice may not be dropped")
    output.parent.mkdir(parents=True,exist_ok=True)
    with ZipFile(output,"w",compression=ZIP_DEFLATED,compresslevel=7) as z:
        for path in ALLOWED:
            info=ZipInfo("gitea/"+path,date_time=(1980,1,1,0,0,0))
            info.external_attr=(0o644<<16)
            info.compress_type=ZIP_DEFLATED
            z.writestr(info,payloads[path])
    with ZipFile(output,"r") as z:
        if z.namelist()!=["gitea/"+p for p in ALLOWED]:
            raise ValueError("unexpected overlay archive members")
        for name in ALLOWED:
            if z.read("gitea/"+name)!=payloads[name]:
                raise ValueError("round-trip loss of original source")
    return {
        "schema":"ultrasec.gitea-minimal-source-overlay-receipt.v1",
        "mode":"ORIGINAL_PATCH_FILES_ONLY_RECONSTRUCT_WITH_PUBLIC_UPSTREAM",
        "phase":phase,
        "source_files":len(ALLOWED),
        "file_receipts":manifest,
        "overlay_sha256":hashlib.sha256(output.read_bytes()).hexdigest(),
        "original_license_text_included":True,
        "original_bytes_roundtrip_verified":True,
        "standalone_build_verified":False,
        "reconstruction_requires_full_original_upstream_tree":True,
        "source_overlay_uploaded_as_public_artifact":False,
        "commercial_rights_verified":False,
        "third_party_dependency_rights_verified":False,
        "gold_admitted":0,
        "certification":"NOT_CERTIFIED",
    }


def main(argv=None)->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--upstream",type=Path,required=True)
    parser.add_argument("--manifest",type=Path,default=Path(__file__).resolve().parents[1]/
        "verification/research/GITEA_ORIGINAL_FILE_RIGHTS_SCOPE.json")
    parser.add_argument("--phase",choices=["vulnerable","fixed"],required=True)
    parser.add_argument("--overlay",type=Path,required=True)
    parser.add_argument("--receipt",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        scope=json.loads(args.manifest.read_text(encoding="utf-8"))
        if check_scope(scope)["errors"]:
            raise ValueError("source scope invalid")
        sha=PARENT if args.phase=="vulnerable" else FIX
        head=subprocess.run(["git","-C",str(args.upstream),"rev-parse","HEAD"],
            check=True,capture_output=True,timeout=15).stdout.decode().strip()
        if head!=sha:
            raise ValueError("upstream checkout is not the original exact commit")
        payloads={}
        expected={}
        for row in scope["changed_files"]+scope["runtime_files"]:
            name=row["path"]
            key="vulnerable_git_blob" if args.phase=="vulnerable" else "fixed_git_blob"
            expected[name]=row[key]
            payloads[name]=subprocess.run(["git","-C",str(args.upstream),"show",f"{sha}:{name}"],
                check=True,capture_output=True,timeout=20).stdout
        receipt=build_checked_overlay(payloads,expected,args.overlay,args.phase)
        receipt["upstream_commit"]=sha
        args.receipt.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({k:v for k,v in receipt.items() if k!="file_receipts"},sort_keys=True))
        return 0
    except (ValueError,TypeError,KeyError,OSError,subprocess.SubprocessError,UnicodeError):
        print("FAIL_CLOSED_ORIGINAL_GITEA_SOURCE_OVERLAY",file=sys.stderr)
        return 1


if __name__=="__main__":
    sys.exit(main())
