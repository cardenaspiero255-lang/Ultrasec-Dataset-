#!/usr/bin/env python3
"""Review actual Go source files imported from Couchbase goutils, not whole repo.

Preserves only paths, hashes, license text scope metadata and risk flags.
Never publishes source or purports to decide BSL applicability/rights.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

MODULE="github.com/couchbase/goutils"
MAX_SOURCE=4_000_000
MAX_LICENSE=150_000
HEADER_BYTES=4096


def _safe_original_file(path:Path,base:Path,limit:int)->bytes:
    try:
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(base):
            raise ValueError("source or license outside original module")
        if not path.is_file() or path.stat().st_size > limit:
            raise ValueError("missing or oversized original file")
        data=path.read_bytes()
    except OSError:
        raise ValueError("missing or unreadable original source/notice") from None
    if not data:
        raise ValueError("empty original file")
    return data


def _metadata_line(text:str,prefix:str)->str|None:
    for line in text.splitlines()[:35]:
        if line.lower().startswith(prefix.lower()+":"):
            return line.split(":",1)[1].strip()
    return None


def scan_goutils_imported_files(packages:list[dict],cache_root:Path)->dict:
    if not isinstance(packages,list) or not packages:
        raise ValueError("no original Go list result")
    cache=cache_root.resolve(strict=True)
    if not cache.is_dir():
        raise ValueError("missing original module cache")
    candidates=[]
    roots=set()
    unresolved_aliases=set()
    module_records_seen=0
    for p in packages:
        if not isinstance(p,dict) or p.get("Error") or p.get("DepsErrors") or p.get("Incomplete"):
            raise ValueError("incomplete Go package")
        name=p.get("ImportPath")
        m=p.get("Module")
        if not isinstance(name,str) or not isinstance(m,dict):
            continue
        is_module=m.get("Path")==MODULE
        is_path=name==MODULE or name.startswith(MODULE+"/")
        if is_module:
            module_records_seen+=1
        if is_module and m.get("Version")!="v0.3.0":
            raise ValueError("unverified Couchbase original module mapping")
        if is_module and not is_path:
            # Go's import graph can refer to a module via another import path.
            # Do not treat this as an absence of licensing obligations.
            unresolved_aliases.add(name)
            continue
        if not is_path:
            continue
        if not is_module:
            raise ValueError("unverified Couchbase original module mapping")
        origin=m.get("Dir")
        pkgdir=p.get("Dir")
        if not isinstance(origin,str) or not isinstance(pkgdir,str):
            raise ValueError("missing module/package directory")
        root=Path(origin).resolve(strict=True)
        directory=Path(pkgdir).resolve(strict=True)
        if not root.is_relative_to(cache) or not directory.is_relative_to(root):
            raise ValueError("source directory outside original Go cache")
        roots.add(root)
        gofiles=p.get("GoFiles",[])+p.get("CgoFiles",[])
        if not isinstance(gofiles,list) or not gofiles:
            raise ValueError("no genuine compiled source files")
        for fn in gofiles:
            if (not isinstance(fn,str) or len(fn)>240 or
                    len(PurePosixPath(fn).parts)!=1 or fn in {".",".."} or not fn.endswith(".go")):
                raise ValueError("invalid go list source filename")
            source=directory/fn
            data=_safe_original_file(source,root,MAX_SOURCE)
            rel=source.relative_to(root).as_posix()
            header=data[:HEADER_BYTES].decode("utf-8",errors="replace").lower()
            indicators=[]
            if "business source license" in header:
                indicators.append("BSL-1.1-REFERENCE")
            if "apache license" in header:
                indicators.append(
                    "APACHE-2.0-FUTURE-CHANGE-REFERENCE"
                    if "business source license" in header else "APACHE-2.0-REFERENCE"
                )
            if "mozilla public license" in header:
                indicators.append("MPL-2.0-REFERENCE")
            if "spdx-license-identifier: mit" in header:
                indicators.append("MIT-SPDX-REFERENCE")
            candidates.append({
                "package":name, "path":rel,
                "sha256":hashlib.sha256(data).hexdigest(),
                "source_header_license_indicators":sorted(indicators),
                "per_file_license_verified":False,
            })
    if not candidates:
        if not unresolved_aliases or module_records_seen == 0:
            raise ValueError("no compiled Couchbase source files in original go list")
        return {
            "schema":"ultrasec.gitea-couchbase-compiled-source-risk.v1",
            "module":MODULE,
            "module_version":"v0.3.0",
            "imported_packages":0,
            "inspected_source_files":0,
            "files":[],
            "unresolved_module_package_paths":sorted(unresolved_aliases),
            "source_scope_status":"BLOCKED_IMPORT_ALIAS_REQUIRES_REVIEW",
            "linked_license_documents":0,
            "license_documents":[],
            "licensed_work_observed":None,
            "change_date_observed":None,
            "license_applicability":"NOT_VERIFIED_IN_THIS_COMMIT",
            "files_requiring_manual_adjudication":len(unresolved_aliases),
            "commercial_distribution_cleared":False,
            "standalone_package_distribution":"BLOCKED_UNTIL_SCOPE_AND_RIGHTS_REVIEW",
            "gold_admitted":0,
            "certification":"NOT_CERTIFIED",
            "limitations":"Module recorded by Go with unmatched import path. No source file claimed audited. Investigate alias and true imported files before distribution.",
        }
    if len(roots)!=1:
        raise ValueError("ambiguous original Couchbase module roots")
    root=next(iter(roots))
    artifacts=[]
    values={}
    docs=("LICENSE.txt","licenses/BSL-Couchbase.txt","licenses/APL2.txt")
    for rel in docs:
        data=_safe_original_file(root/rel,root,MAX_LICENSE)
        artifacts.append({"path":rel,"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)})
        values[rel]=data.decode("utf-8",errors="replace")
    bsl=values["licenses/BSL-Couchbase.txt"]
    licensed=_metadata_line(bsl,"Licensed Work")
    change=_metadata_line(bsl,"Change Date")
    if ("business source license 1.1" not in bsl.lower() or
        not licensed or not change or
        "apache license" not in values["licenses/APL2.txt"].lower()):
        raise ValueError("unverified original nested license content")
    return {
        "schema":"ultrasec.gitea-couchbase-compiled-source-risk.v1",
        "module":MODULE,
        "module_version":"v0.3.0",
        "imported_packages":len({r["package"] for r in candidates}),
        "inspected_source_files":len(candidates),
        "files":sorted(candidates,key=lambda x:(x["package"],x["path"])),
        "unresolved_module_package_paths":sorted(unresolved_aliases),
        "source_scope_status":("PARTIAL_IMPORT_MAPPING_REQUIRES_REVIEW"
                               if unresolved_aliases else "FILE_HASHES_OBSERVED_APPLICABILITY_UNRESOLVED"),
        "linked_license_documents":len(artifacts),
        "license_documents":artifacts,
        "licensed_work_observed":licensed,
        "change_date_observed":change,
        "license_applicability":"REQUIRES_FILE_AND_LICENSE_SCOPE_REVIEW",
        "files_requiring_manual_adjudication":len(candidates)+len(unresolved_aliases),
        "commercial_distribution_cleared":False,
        "standalone_package_distribution":"BLOCKED_UNTIL_SCOPE_AND_RIGHTS_REVIEW",
        "gold_admitted":0,
        "certification":"NOT_CERTIFIED",
        "limitations":"Identifies only GoFiles/CgoFiles from go list -deps; file headers and BSL Licensed Work must be checked by a qualified reviewer for the exact buyer bundle.",
    }


def main(argv=None)->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--go-list",required=True,type=Path)
    ap.add_argument("--cache",required=True,type=Path)
    ap.add_argument("--output",required=True,type=Path)
    args=ap.parse_args(argv)
    try:
        from gitea_go_dependency_closure import read_stream
        packages=read_stream(args.go_list.read_text(encoding="utf-8"))
        receipt=scan_goutils_imported_files(packages,args.cache)
        args.output.write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({k:v for k,v in receipt.items() if k not in ("files","license_documents")},sort_keys=True))
        return 0
    except ValueError as exc:
        # Messages deliberately contain no raw source, local directory or secrets.
        safe_codes={
            "no original Go list result",
            "missing original module cache",
            "incomplete Go package",
            "unverified Couchbase original module mapping",
            "missing module/package directory",
            "source directory outside original Go cache",
            "no genuine compiled source files",
            "invalid go list source filename",
            "missing or unreadable original source/notice",
            "source or license outside original module",
            "missing or oversized original file",
            "empty original file",
            "no compiled Couchbase source files in original go list",
            "ambiguous original Couchbase module roots",
            "unverified original nested license content",
        }
        code=str(exc) if str(exc) in safe_codes else "UNCLASSIFIED_VALIDATION_FAILURE"
        print("FAIL_CLOSED_COUCHBASE_SOURCE_SCOPE: "+code,file=sys.stderr)
        return 1
    except (TypeError,OSError,UnicodeError,json.JSONDecodeError):
        print("FAIL_CLOSED_COUCHBASE_SOURCE_SCOPE: INPUT_OR_IO",file=sys.stderr)
        return 1


if __name__=="__main__":
    sys.exit(main())
