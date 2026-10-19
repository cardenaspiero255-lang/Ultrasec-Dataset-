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

OBSERVED_OBLIGATIONS = {
    "MIT": "MIT_RETAIN_COPYRIGHT_AND_PERMISSION_NOTICE",
    "BSD-3-Clause": "BSD3_RETAIN_COPYRIGHT_CONDITIONS_DISCLAIMER_NO_ENDORSEMENT",
    "Apache-2.0": "APACHE2_PRESERVE_LICENSE_NOTICES_CHANGES_AND_APPLICABLE_NOTICE_FILE",
    "MPL-2.0": "MPL2_COVERED_FILE_SOURCE_AVAILABILITY_AND_NOTICES_REVIEW",
    "BSD-2-Clause": "BSD2_RETAIN_COPYRIGHT_CONDITIONS_AND_DISCLAIMER",
    "BSL-1.1": "BSL1_1_RESTRICTED_USE_CHANGE_DATE_REQUIRES_LEGAL_REVIEW",
    "PER_FILE_LICENSE_MAPPING_REQUIRED": "PER_FILE_LICENSE_SCAN_REQUIRED_DO_NOT_APPLY_ROOT_LICENSE_BLANKET",
}


def classify_original_license_text(payload:bytes)->list[str]:
    """Conservative full-license-text indicators, not legal SPDX clearance.

    Do not infer permissions from filename, repo label, or SPDX-only sentence.
    Multiple matches mean possible multiple terms requiring human interpretation.
    """
    if not isinstance(payload,bytes):
        return []
    text=payload.decode("utf-8",errors="replace").lower()
    observed=[]
    if ("apache license" in text and "version 2.0" in text
            and ("terms and conditions" in text or "http://www.apache.org/licenses" in text)):
        observed.append("Apache-2.0")
    if ("mozilla public license" in text and "version 2.0" in text
            and "covered software" in text):
        observed.append("MPL-2.0")
    # Avoid confusing the restrictive BSL with the separate Apache change license.
    if "business source license" in text and "1.1" in text:
        if "each file indicates" in text or "various licenses" in text:
            observed.append("PER_FILE_LICENSE_MAPPING_REQUIRED")
        elif "licensed work" in text:
            observed.append("BSL-1.1")
        else:
            observed.append("PER_FILE_LICENSE_MAPPING_REQUIRED")
    if "redistribution and use in source and binary forms" in text:
        if ("neither the name" in text or
                ("may not be used to endorse" in text and "name" in text)):
            observed.append("BSD-3-Clause")
        elif ("redistributions of source code must retain" in text
              and "redistributions in binary form must reproduce" in text
              and "as is" in text):
            observed.append("BSD-2-Clause")
    if ("permission is hereby granted, free of charge" in text
            and "the above copyright notice and this permission notice shall be included" in text):
        observed.append("MIT")
    return sorted(observed)


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
            entry={"name":name,"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)}
            if destination is licenses:
                entry["observed_license_families"]=classify_original_license_text(data)
            destination.append(entry)
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
        replace_metadata=m.get("Replace")
        replacement=bool(replace_metadata)
        replace_path=replace_metadata.get("Path") if isinstance(replace_metadata,dict) else None
        replace_version=replace_metadata.get("Version") if isinstance(replace_metadata,dict) else None
        record=(directory,replacement,replace_path,replace_version)
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
        dirname,replaced,replace_path,replace_version=observed[name]
        licenses,notices,flags=[],[],[]
        if not isinstance(dirname,str) or not dirname:
            status="MODULE_DIRECTORY_MISSING"
        else:
            root=Path(dirname).resolve(strict=False)
            if not root.is_relative_to(cache):
                if not replaced:
                    raise ValueError("external module directory outside explicit original cache")
                status="REPLACEMENT_SOURCE_OUTSIDE_CACHE"
            elif not root.is_dir():
                status="MODULE_DIRECTORY_MISSING"
            else:
                licenses,notices,flags=_files_at_root(root)
                if replaced:
                    # Even a found LICENSE does NOT clear a substituted dependency.
                    status="MODULE_REPLACEMENT_REQUIRES_REVIEW"
                elif flags:
                    status=sorted(flags)[0]
                elif licenses and any(
                    ("PER_FILE_LICENSE_MAPPING_REQUIRED" in f["observed_license_families"] or
                     "BSL-1.1" in f["observed_license_families"])
                    for f in licenses
                ):
                    status="PER_FILE_LICENSE_REVIEW_REQUIRED"
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
        observed_families=sorted({family for file in licenses for family in file["observed_license_families"]})
        high_risk=bool(set(observed_families) & {"PER_FILE_LICENSE_MAPPING_REQUIRED", "BSL-1.1"})
        records.append({
            "module":name,"version":expected_refs[name],"license_status":status,
            "replacement_path":replace_path if replaced else None,
            "replacement_version":replace_version if replaced else None,
            "effective_module_version":replace_version if replaced else expected_refs[name],
            "observed_license_families":observed_families,
            "restricted_or_per_file_review":high_risk,
            "obligation_hints":[OBSERVED_OBLIGATIONS[family] for family in observed_families],
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
