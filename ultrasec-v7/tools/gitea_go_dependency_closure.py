#!/usr/bin/env python3
"""Offline inspection of genuine go list -deps -json results. Not SPDX or legal clearance."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ORIGINAL="7fdfb8d642201b388014f29889ef28e35b8c1872"
FIXED="e4ef995f2a162e3aca3f3a0b536afae067975d71"
SHA256=re.compile(r"[0-9a-f]{64}\Z")


def read_stream(raw: str) -> list[dict]:
    parser=json.JSONDecoder()
    pos=0
    found=[]
    while True:
        while pos<len(raw) and raw[pos].isspace():
            pos+=1
        if pos==len(raw):
            break
        entry,pos=parser.raw_decode(raw,pos)
        if not isinstance(entry,dict):
            raise ValueError("unexpected Go list item")
        found.append(entry)
    if not found:
        raise ValueError("no Go packages emitted")
    return found


def build_closure(packages:list[dict], commit:str, mod_sha:str, sum_sha:str,license_sha:str)->dict:
    if commit not in {ORIGINAL,FIXED} or any(not SHA256.fullmatch(x) for x in (mod_sha,sum_sha,license_sha)):
        raise ValueError("unexpected source revision or invalid original hash")
    if not packages or any(not isinstance(p,dict) or not isinstance(p.get("ImportPath"),str) for p in packages):
        raise ValueError("missing or malformed Go package")
    all_imports=set()
    stdlib=set()
    local=set()
    external={}
    target_found=False
    for p in packages:
        name=p["ImportPath"]
        if name in all_imports:
            raise ValueError("duplicate Go import path")
        all_imports.add(name)
        if name=="gitea.dev/services/release":
            target_found=True
        if p.get("Error") or p.get("Incomplete") or p.get("DepsErrors"):
            raise ValueError("incomplete Go dependency closure")
        module=p.get("Module")
        if p.get("Standard") is True:
            stdlib.add(name)
        elif isinstance(module,dict) and module.get("Main") is True:
            if module.get("Path")!="gitea.dev":
                raise ValueError("unexpected main module")
            local.add(name)
        elif isinstance(module,dict):
            path=module.get("Path")
            version=module.get("Version")
            if not isinstance(path,str) or not path or not isinstance(version,str) or not version:
                raise ValueError("module path or pinned version missing")
            entry=external.get(path)
            if entry is not None and entry["version"]!=version:
                raise ValueError("conflicting module version in go list")
            external[path]={
                "path":path,"version":version,
                "replacement":"NONE" if not module.get("Replace") else "REQUIRES_LICENSE_REVIEW",
                "file_level_license_status":"NOT_AUDITED",
                "distribution_obligations":"NOT_REVIEWED",
            }
        else:
            raise ValueError("unknown Go package module origin")
    if not target_found:
        raise ValueError("target release service absent")
    refs=[m["path"]+"@"+m["version"] for m in external.values()]
    digest=hashlib.sha256("\n".join(sorted(refs)).encode("utf-8")).hexdigest()
    return {
        "schema":"ultrasec.gitea-go-static-module-closure.v1",
        "upstream":"https://github.com/go-gitea/gitea",
        "commit":commit,
        "target_go_package":"gitea.dev/services/release",
        "build_tags":["sqlite"],
        "go_mod_sha256":mod_sha,
        "go_sum_sha256":sum_sha,
        "license_file_sha256":license_sha,
        "package_count":len(all_imports),
        "stdlib_package_count":len(stdlib),
        "local_gitea_package_count":len(local),
        "external_module_count":len(external),
        "external_modules_sha256":digest,
        "external_modules":sorted(external.values(),key=lambda x:x["path"]),
        "third_party_licenses_audited":False,
        "commercial_distribution_cleared_modules":0,
        "ready_for_relicensed_binary_distribution":False,
        "gold_admitted":0,
        "status":"MODULE_CLOSURE_ONLY_NOT_LICENSE_CLEARANCE",
        "certification":"NOT_CERTIFIED",
        "limitations":"Go source import closure only; excludes runtime dynamic/plugin/assets, JS, test-only deps and vendor licensing. Review SPDX and notices file-by-file before distribution."
    }


def main(argv=None)->int:
    p=argparse.ArgumentParser(description="Fail-closed Gitea public Go dependency metadata")
    p.add_argument("--input",type=Path,required=True)
    p.add_argument("--commit",required=True)
    p.add_argument("--go-mod-sha256",required=True)
    p.add_argument("--go-sum-sha256",required=True)
    p.add_argument("--license-sha256",required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        data=read_stream(args.input.read_text(encoding="utf-8"))
        report=build_closure(data,args.commit,args.go_mod_sha256,args.go_sum_sha256,args.license_sha256)
        args.output.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({k:v for k,v in report.items() if k!="external_modules"},sort_keys=True))
        return 0
    except (ValueError,TypeError,OSError,UnicodeError,json.JSONDecodeError):
        print("FAIL_CLOSED_GITEA_GO_IMPORT_CLOSURE",file=sys.stderr)
        return 1


if __name__=="__main__":
    sys.exit(main())
