#!/usr/bin/env python3
"""Owner-local metadata-only TRAIN-vs-TEST disjointness gate.

Fail closed on exact cross-split clones of project, vulnerability mechanism,
CVE, commits and source/fix contents. Input is an OWNER-SUPPLIED JSONL pair,
never copied into GitHub. Passing this gate does not verify ground truth,
source hash authenticity, semantic diversity, rights, or benchmark blindness.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

TOOLS_DIR=Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0,str(TOOLS_DIR))
from future_holdout_exposure import project_fingerprint, _KNOWN_CVES, _KNOWN_PROJECT_URLS

SHA40=re.compile(r'[0-9a-f]{40}\Z')
SHA256=re.compile(r'[0-9a-f]{64}\Z')
CVE=re.compile(r'CVE-[0-9]{4}-[0-9]{4,}\Z')
CWE=re.compile(r'CWE-[1-9][0-9]{0,5}\Z')
IDENT=re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
REQUIRED=frozenset({
    'case_id', 'project_url','project_fingerprint','cve_id','cwe_id',
    'mechanism_fingerprint','source_commit','fix_commit',
    'source_sha256','fix_sha256','oracle_type','oracle_run_sha256',
    'split','vulnerable',
})
ALLOWED_ORACLES=frozenset({'ORIGINAL_RED_GREEN_TEST','INDEPENDENT_STATIC_CONTRACT'})
MAX_METADATA_BYTES=32*1024*1024


def _validate_row(row: object, split: str) -> str | None:
    if not isinstance(row,dict) or set(row)!=REQUIRED:
        return 'invalid_record'
    try:
        if (not IDENT.fullmatch(row['case_id']) or
                not CVE.fullmatch(row['cve_id']) or
                not CWE.fullmatch(row['cwe_id']) or
                not all(SHA256.fullmatch(row[k]) for k in (
                    'project_fingerprint','mechanism_fingerprint',
                    'source_sha256','fix_sha256','oracle_run_sha256')) or
                not all(SHA40.fullmatch(row[k]) for k in ('source_commit','fix_commit')) or
                row['source_commit']==row['fix_commit'] or
                row['source_sha256']==row['fix_sha256'] or
                row['oracle_type'] not in ALLOWED_ORACLES or
                row['split']!=split or type(row['vulnerable']) is not bool):
            return 'invalid_record'
        if project_fingerprint(row['project_url'])!=row['project_fingerprint']:
            return 'project_fingerprint_mismatch'
    except (ValueError,TypeError,AttributeError):
        return 'invalid_record'
    return None


def audit(training:list, holdout:list, minimum_train:int=100,
          minimum_test:int=100, minimum_cwes:int=12)->dict:
    if (not isinstance(training,list) or not isinstance(holdout,list) or
            any(type(v)is not int or v<1 for v in (minimum_train,minimum_test,minimum_cwes))):
        raise ValueError('invalid_input_or_threshold')
    failures=Counter()
    clean_train,clean_test=[],[]
    for rows,split,good in ((training,'train',clean_train),(holdout,'test',clean_test)):
        for row in rows:
            problem=_validate_row(row,split)
            if problem: failures[problem]+=1
            else: good.append(row)
    if len(clean_train)<minimum_train:failures['insufficient_train']+=1
    if len(clean_test)<minimum_test:failures['insufficient_test']+=1

    # The private owner must canonicalize project URLs; opaque fields alone
    # are insufficient to prevent forged project aliases.
    studied_projects={project_fingerprint(s) for s in _KNOWN_PROJECT_URLS}
    for row in clean_test:
        if row['cve_id'] in _KNOWN_CVES:
            failures['known_research_cve']+=1
        if row['project_fingerprint'] in studied_projects:
            failures['known_research_project']+=1

    def groups(rows):
        return {
          'case': {row['case_id'] for row in rows},
          'cve': {row['cve_id'] for row in rows},
          'project': {row['project_fingerprint'] for row in rows},
          'mechanism': {row['mechanism_fingerprint'] for row in rows},
          'commit': {s for row in rows for s in (row['source_commit'],row['fix_commit'])},
          'content': {s for row in rows for s in (row['source_sha256'],row['fix_sha256'])},
        }
    x=groups(clean_train)
    y=groups(clean_test)
    for field,label in (('case','case_id_overlap'),('cve','cve_overlap'),
                        ('project','project_overlap'),('mechanism','mechanism_overlap'),
                        ('commit','commit_overlap'),('content','content_overlap')):
        if x[field]&y[field]:failures[label]+=1

    # A prospective held-out cohort must not count two variants of the same
    # public project/mechanism as independent projects; group them first.
    if len(y['project'])!=len(clean_test):failures['duplicate_test_project']+=1
    if len(y['mechanism'])!=len(clean_test):failures['duplicate_test_mechanism']+=1
    if len(y['case'])!=len(clean_test):failures['duplicate_test_case_id']+=1
    if len(y['cve'])!=len(clean_test):failures['duplicate_test_cve']+=1

    by_cwe=defaultdict(set)
    for row in clean_test:by_cwe[row['cwe_id']].add(row['vulnerable'])
    if len(by_cwe)<minimum_cwes:failures['insufficient_test_cwes']+=1
    if any(labels!={True,False} for labels in by_cwe.values()):
        failures['test_cwe_without_both_classes']+=1

    return {
       'schema':'ultrasec.private-train-holdout-disjointness.v1',
       'scope':'OWNER_LOCAL_METADATA_ONLY',
       'metadata_separation_pass':not bool(failures),
       'training_rows_checked':len(clean_train),
       'test_rows_checked':len(clean_test),
       'test_cwes_checked':len(by_cwe),
       'known_research_cves_excluded':len(_KNOWN_CVES),
       'known_research_projects_excluded':len(studied_projects),
       'causal_independence_certified':False,
       'source_provenance_externally_verified':False,
       'oracle_execution_externally_verified':False,
       'scanner_execution_verified':False,
       'commercial_rights_verified':False,
       'blind_benchmark_ready':False,
       'holdout_gold_verified':False,
       'gold_admitted':0,
       'certification':'NOT_CERTIFIED',
       'failures':dict(sorted(failures.items())),
       'limitations':'Checks owner-provided canonical metadata, not the original repository bytes, independent labels or semantic clone families.',
    }


def _read_private_jsonl(p:Path)->tuple[list,bytes]:
    if p.is_symlink() or not p.is_file() or not stat.S_ISREG(p.stat().st_mode):
        raise ValueError('unsafe_private_manifest')
    if not 0<p.stat().st_size<=MAX_METADATA_BYTES:
        raise ValueError('unsafe_private_manifest_size')
    raw=p.read_bytes()
    rows=[json.loads(line) for line in raw.decode('utf-8').splitlines() if line.strip()]
    return rows,hashlib.sha256(raw).digest()


def _write_private_receipt(p:Path,report:dict,train_sha:bytes,test_sha:bytes)->None:
    if not p.parent.is_dir() or p.parent.is_symlink():
        raise ValueError('unsafe_private_receipt_destination')
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
    with os.fdopen(os.open(p,flags,0o600),'w',encoding='utf-8') as f:
        json.dump({'report':report, 'training_manifest_sha256':train_sha.hex(),
                   'holdout_manifest_sha256':test_sha.hex(),
                   'signatures_verified':False},f,sort_keys=True)
        f.write('\n')


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description='Owner-local TRAIN vs TEST metadata exclusion gate')
    p.add_argument('--train',type=Path,required=True)
    p.add_argument('--holdout',type=Path,required=True)
    p.add_argument('--minimum-train',type=int,default=100)
    p.add_argument('--minimum-test',type=int,default=100)
    p.add_argument('--minimum-cwes',type=int,default=12)
    p.add_argument('--private-receipt',type=Path)
    args=p.parse_args(argv)
    try:
        train_path=args.train.resolve(strict=True)
        test_path=args.holdout.resolve(strict=True)
        if train_path==test_path or args.train.stat().st_ino==args.holdout.stat().st_ino and args.train.stat().st_dev==args.holdout.stat().st_dev:
            raise ValueError('same_manifest')
        repo=Path(__file__).resolve().parents[2]
        if train_path.is_relative_to(repo) or test_path.is_relative_to(repo):
            raise ValueError('private_manifest_in_public_repository')
        train,train_digest=_read_private_jsonl(args.train)
        test,test_digest=_read_private_jsonl(args.holdout)
        report=audit(train,test,args.minimum_train,args.minimum_test,args.minimum_cwes)
        if args.private_receipt:
            _write_private_receipt(args.private_receipt,report,train_digest,test_digest)
        print(json.dumps(report,sort_keys=True))
        return 0 if report['metadata_separation_pass'] else 1
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError):
        print('{"status":"FAIL_CLOSED_PRIVATE_SPLIT","certification":"NOT_CERTIFIED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
