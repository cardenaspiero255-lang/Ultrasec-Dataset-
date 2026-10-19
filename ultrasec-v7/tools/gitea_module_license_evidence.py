#!/usr/bin/env python3
"""Record *observed* LICENSE/NOTICE file hashes in original Go module cache.

This scanner does not infer SPDX, legal permission or rights from filenames.
It publishes no source files, contents, private data, filesystem directories,
or user/environment paths. It must be run with original go list input.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

LICENSE_NAME = re.compile(r"^(?:LICENSE|LICENCE|COPYING)(?:[._-][A-Za-z0-9._-]+)?$", re.I)
NOTICE_NAME = re.compile(r"^(?:NOTICE|COPYRIGHT|AUTHORS|PATENTS)(?:[._-][A-Za-z0-9._-]+)?$", re.I)
MAX_FILE_BYTES = 1048576


def _files_at_root(root:Path) -> tuple[list,list,list]:
    licenses, notices, flags = [], [], []
    try:
        entries=sorted(root.iterdir(), key=lambda x:x.name.lower())
    except OSError:
        return [],[],["UNREADABLE_MODULE_DIRECTORY"]
    for entry in entries:
        name=entry.name
        destination=licenses if LICENSE_NAME.fullmatch(name) else (
            notices if NOTICE_NAME.fullmatch(name) else None
        )
        if destination is None:
            continue
        try:
            if entry.is_symlink() or not entry.is_file():
                flags.append("UNSAFE_OR_UNREADABLE_LICENSE_PATH")
                continue
            data=entry.read_bytes()
            if len(data)>MAX_FILE_BYTES:
                flags.append("LICENSE_FILE_TOO_LARGE")
                continue
            if not data.strip():
                flags.append("EMPTY_LICENSE_FILE" if destination is licenses else "EMPTY_NOTICE_FILE")
                continue
            destination.append({"name":name,"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)})
        except OSError:
            flags.append("UNSAFE_OR_UNREADABLE_LICENSE_PATH")
    return licenses,notices,flags


def collect_license_evidence(packages:list[dict],closure:dict,go_cache_root:Path)->dict:
    if not isinstance(packages,list) or not packages or not isinstance(closure,dict):
        raise ValueError("incomplete original Go evidence")
    expected=closure.get("external_modules")
    if not isinstance(expected,list) or not expected:
        raise ValueError("no externally pinned original modules")
    expected_refs={}
    for m in expected:
        if not isinstance(m,dict) or not isinstance(m.get("path"),str) or not isinstance(m.get("version"),str):
            raise ValueError("invalid pinned module")
        if m["path"] in expected_refs:
            raise ValueError("duplicate original module")
        expected_refs[m["path"]]=m["version"]
    observed={}
    for p in packages:
        if not isinstance(p,dict) or not isinstance(p.get("ImportPath"),str):
            raise ValueError("unexpected go list package")
        if p.get("Error") or p.get("DepsErrors") or p.get("Incomplete"):
            raise ValueError("incomplete upstream package")
        m=p.get("Module")
        if p.get("Standard") is True or (isinstance(m,dict) and m.get("Main") is True):
            continue
        if not isinstance(m,dict) or not isinstance(m.get("Path"),str) or not isinstance(m.get("Version"),str):
            raise ValueError("module metadata unavailable")
        path,version=m["Path"],m["Version"]
        if path not in expected_refs or version != expected_refs[path]:
            raise ValueError("module set/version differs from original immutable closure")
        directory=m.get("Dir")
        replacement=bool(m.get("Replace"))
        record=(directory,replacement)
        if path in observed and observed[path]!=record:
            raise ValueError("inconsistent module directories or replacement")
        observed[path]=record
    if set(observed)!=set(expected_refs):
        raise ValueError("original module closure mismatch")

    cache=go_cache_root.resolve(strict=True)
    if not cache.is_dir():
        raise ValueError("no valid original module cache")
    records=[]
    count=Counter()
    for name in sorted(expected_refs):
        dirname,replaced=observed[name]
        licenses,notices,flags=[],[],[]
        if replaced:
            status="MODULE_REPLACEMENT_REQUIRES_REVIEW"
        elif not isinstance(dirname,str) or not dirname:
            status="MODULE_DIRECTORY_MISSING"
        else:
            root=Path(dirname).resolve(strict=False)
            if not root.is_relative_to(cache):
                raise ValueError("external module directory outside explicit original cache")
            if not root.is_dir():
                status="MODULE_DIRECTORY_MISSING"
            else:
                licenses,notices,flags=_files_at_root(root)
                if flags:
                    status=sorted(flags)[0]
                elif licenses:
                    status="LICENSE_FILE_PRESENT_CLASSIFICATION_PENDING"
                else:
                    status="MISSING_LICENSE_AT_MODULE_ROOT"
        if licenses:
            count["modules_with_license_files"]+=1
            count["license_files_observed"]+=len(licenses)
        else:
            count["modules_without_root_license_files"]+=1
        if notices:
            count["modules_with_notice_files"]+=1
        if status not in {"LICENSE_FILE_PRESENT_CLASSIFICATION_PENDING"}:
            count["modules_needing_evidence_remediation"]+=1
        records.append({
            "module":name,"version":expected_refs[name],"license_status":status,
            "license_files":licenses,"notice_files":notices,
            "flags":sorted(set(flags)),"legal_conditions":"NOT_REVIEWED",
        })
    return {
        "schema":"ultrasec.gitea-original-module-license-file-evidence.v1",
        "source":"original_upstream_go_list_module_dir_under_verified_go_cache",
        "external_modules_examined":len(records),
        "modules_with_license_files":count["modules_with_license_files"],
        "modules_without_root_license_files":count["modules_without_root_license_files"],
        "modules_with_notice_files":count["modules_with_notice_files"],
        "license_files_observed":count["license_files_observed"],
        "modules_needing_evidence_remediation":count["modules_needing_evidence_remediation"],
        "modules":records,
        "license_file_presence_only":True,
        "copyright_notice_completeness_verified":False,
        "third_party_file_level_licenses_verified":False,
        "commercial_licenses_cleared":0,
        "ready_to_distribute":False,
        "gold_admitted":0,
        "certification":"NOT_CERTIFIED",
        "limitations":"File presence/hashes at module root only; nested NOTICE, source headers, binaries, transitive rights, license obligations and actual buyer package still need audit.",
    }


def main(argv=None)->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--go-list",type=Path,required=True)
    ap.add_argument("--closure",type=Path,required=True)
    ap.add_argument("--go-mod-cache",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args(argv)
    try:
        from gitea_go_dependency_closure import read_stream
        packages=read_stream(args.go_list.read_text(encoding="utf-8"))
        closure=json.loads(args.closure.read_text(encoding="utf-8"))
        report=collect_license_evidence(packages,closure,args.go_mod_cache)
        args.output.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({k:v for k,v in report.items() if k!="modules"},sort_keys=True))
        return 0
    except (ValueError,TypeError,OSError,UnicodeError,json.JSONDecodeError):
        print("FAIL_CLOSED_GITEA_MODULE_LICENSE_EVIDENCE",file=sys.stderr)
        return 1


if __name__=="__main__":
    sys.exit(main())
