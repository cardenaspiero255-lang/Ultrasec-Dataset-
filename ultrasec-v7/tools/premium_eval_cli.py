#!/usr/bin/env python3
"""Owner-only review agreement CLI. Never copies private answers to stdout."""
from __future__ import annotations
import argparse
import hashlib
import io
import os
import zipfile
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from blind_appsec import agreement_report
from sealed_evidence import read_jsonl, public_receipt, write_private


def _ratings(path:Path)->tuple[dict[str,str],int,set[str]]:
    result={}
    complete=0
    identities=set()
    full={"case_id","vulnerable_side","vulnerability_evidence",
          "fix_evidence","reproduction","reviewer_id"}
    minimal={"case_id","vulnerable_side"}
    for row in read_jsonl(path):
        if (not isinstance(row,dict) or set(row) not in (full,minimal)
                or not isinstance(row.get("case_id"),str) or not row["case_id"]
                or row.get("vulnerable_side") not in {"A","B","uncertain"}):
            raise ValueError("Invalid reviewer row")
        if row["case_id"] in result:
            raise ValueError("Duplicate case rating")
        if set(row)==full:
            if (row["vulnerability_evidence"] not in {"supported","refuted","insufficient"}
                    or row["fix_evidence"] not in {"supported","refuted","insufficient"}
                    or row["reproduction"] not in {"pass","fail","not_run"}
                    or not isinstance(row["reviewer_id"],str) or not row["reviewer_id"]):
                raise ValueError("Invalid review evidence")
            if (row["vulnerability_evidence"]=="supported"
                    and row["fix_evidence"]=="supported"
                    and row["reproduction"]=="pass"
                    and row["vulnerable_side"]!="uncertain"):
                complete+=1
            identities.add(row["reviewer_id"])
        result[row["case_id"]]=row["vulnerable_side"]
    return result,complete,identities


def _owner_holdout_ids(path:Path,expected_sha256:str,required:int)->set[str]:
    """Bind reviewer answers to the exact owner-held ZIP committed out of band."""
    if not isinstance(expected_sha256,str) or len(expected_sha256)!=64:
        raise ValueError("Missing SHA-256 commitment")
    # Bound the ZIP container itself, not only its decompressed member.
    max_zip_bytes=4_000_000
    if path.stat().st_size>max_zip_bytes:
        raise ValueError("Owner ZIP container too large")
    with path.open("rb") as source:
        if os.fstat(source.fileno()).st_size>max_zip_bytes:
            raise ValueError("Owner ZIP container too large")
        verified_bytes=source.read(max_zip_bytes+1)
    if len(verified_bytes)>max_zip_bytes:
        raise ValueError("Owner ZIP container too large")
    digest=hashlib.sha256(verified_bytes).hexdigest()
    if digest!=expected_sha256.lower():
        raise ValueError("Owner manifest commitment mismatch")
    with zipfile.ZipFile(io.BytesIO(verified_bytes)) as archive:
        if set(archive.namelist())!={"owner_key.jsonl"}:
            raise ValueError("Unexpected owner archive members")
        info=archive.getinfo("owner_key.jsonl")
        if info.file_size>2_000_000:
            raise ValueError("Owner manifest too large")
        with archive.open(info) as member:
            raw=member.read(2_000_001)
    if len(raw)>2_000_000:
        raise ValueError("Owner manifest too large")
    rows=[json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    ids=[row["case_id"] for row in rows if isinstance(row,dict)]
    if (len(rows)!=required or len(ids)!=required or len(set(ids))!=required
            or any(not isinstance(i,str) or not i for i in ids)):
        raise ValueError("Owner manifest case IDs invalid")
    return set(ids)


def main(argv=None)->int:
    parser=argparse.ArgumentParser(description="Private blind-review agreement calculator")
    commands=parser.add_subparsers(dest="command",required=True)
    agree=commands.add_parser("agreement")
    agree.add_argument("--reviewer-a",type=Path,required=True)
    agree.add_argument("--reviewer-b",type=Path,required=True)
    agree.add_argument("--min-agreement",type=float,default=0.80)
    agree.add_argument("--required-cases",type=int,default=100)
    agree.add_argument("--sealed-report",type=Path,required=True)
    agree.add_argument("--session-lock",type=Path,required=True)
    agree.add_argument("--owner-key-zip",type=Path)
    agree.add_argument("--owner-key-sha256",type=str)
    args=parser.parse_args(argv)
    try:
        ratings_a,evidence_a,reviewer_a=_ratings(args.reviewer_a)
        ratings_b,evidence_b,reviewer_b=_ratings(args.reviewer_b)
        report=agreement_report(ratings_a,ratings_b,
                                args.required_cases,args.min_agreement)
        report["evidence_records"]={"reviewer_a":evidence_a,"reviewer_b":evidence_b}
        if args.owner_key_zip is None or args.owner_key_sha256 is None:
            report["agreement_gate_pass"]=False
            report["failures"]["owner_holdout_manifest_missing"]=1
        else:
            try:
                expected=_owner_holdout_ids(args.owner_key_zip,args.owner_key_sha256,args.required_cases)
                if set(ratings_a)!=expected or set(ratings_b)!=expected:
                    report["agreement_gate_pass"]=False
                    report["failures"]["owner_holdout_case_id_mismatch"]=1
            except (ValueError,OSError,KeyError,TypeError,zipfile.BadZipFile,UnicodeError,RuntimeError,NotImplementedError):
                report["agreement_gate_pass"]=False
                report["failures"]["owner_holdout_manifest_invalid"]=1
        # A text reviewer ID is NOT an authenticated cryptographic signature.
        report["reviewer_signatures"]="NOT_VERIFIED"
        if evidence_a!=args.required_cases or evidence_b!=args.required_cases:
            report["agreement_gate_pass"]=False
            report["failures"]["review_evidence_inadequate"]=1
        if len(reviewer_a)!=1 or len(reviewer_b)!=1 or reviewer_a==reviewer_b:
            report["agreement_gate_pass"]=False
            report["failures"]["reviewer_identity_not_independent"]=1
    except (ValueError,OSError,UnicodeError,RecursionError,KeyError,TypeError):
        report={
            "schema":"ultrasec.blind-appsec-agreement.v1",
            "certification":"NOT_CERTIFIED",
            "agreement_gate_pass":False,
            "failures":{"input_parse_error":1},
            "criteria":{"required_cases":args.required_cases,
                        "min_agreement":str(args.min_agreement)},
        }
    try:
        write_private(args.sealed_report,args.session_lock,report)
    except (ValueError,OSError,UnicodeError):
        print('{"status":"RECORDING_FAILED"}')
        return 2
    print(public_receipt())
    return 0


if __name__=="__main__":
    raise SystemExit(main())
