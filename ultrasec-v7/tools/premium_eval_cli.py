#!/usr/bin/env python3
"""Owner-only review agreement CLI. Never copies private answers to stdout."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from blind_appsec import agreement_report
from sealed_evidence import read_jsonl, public_receipt, write_private


def _ratings(path:Path)->dict[str,str]:
    result={}
    for row in read_jsonl(path):
        if (not isinstance(row,dict) or set(row)!={"case_id","vulnerable_side"}
                or not isinstance(row["case_id"],str) or not row["case_id"]
                or row["vulnerable_side"] not in {"A","B","uncertain"}):
            raise ValueError("Invalid reviewer row")
        if row["case_id"] in result:
            raise ValueError("Duplicate case rating")
        result[row["case_id"]]=row["vulnerable_side"]
    return result


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
    args=parser.parse_args(argv)
    try:
        report=agreement_report(_ratings(args.reviewer_a),_ratings(args.reviewer_b),
                                args.required_cases,args.min_agreement)
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
