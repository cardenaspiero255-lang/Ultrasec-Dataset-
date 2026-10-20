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
from future_holdout_exposure import project_fingerprint, _KNOWN_CVES, _KNOWN_PROJECT_URLS, _read_original_public_cves
from premium_evidence import _PINNED_MITRE_CWES

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
    # Every CVE previously recorded by public research is ineligible as new
    # held-out evidence. Missing/truncated inventory blocks the entire audit.
    known_cves = _KNOWN_CVES | _read_original_public_cves()
    for row in clean_test:
        if row['cve_id'] in known_cves:
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

    # Distinct identifiers/projects are not proof that original vulnerable/fix
    # pairs are independent. Detect same-split reuse BEFORE claiming that
    # minimum row-count thresholds represent independent examples.
    for rows, split_name in ((clean_train, 'train'), (clean_test, 'test')):
        if split_name == 'train' and len({r['case_id'] for r in rows}) < len(rows):
            failures['duplicate_train_case_id'] += 1
        original_pairs={(r['source_commit'],r['fix_commit']) for r in rows}
        content_pairs={(r['source_sha256'],r['fix_sha256']) for r in rows}
        if len(original_pairs)<len(rows):
            failures['duplicate_'+split_name+'_original_pair'] += 1
        if len(content_pairs)<len(rows):
            failures['duplicate_'+split_name+'_content_pair'] += 1
        if split_name == 'test':
            # A source reused as another case's fix creates a leakage risk,
            # even if the combined before/after pairs differ.
            all_content=[sha for r in rows for sha in
                         (r['source_sha256'],r['fix_sha256'])]
            if len(set(all_content))<len(all_content):
                failures['shared_test_content_requires_grouping'] += 1

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
    # A configurable small synthetic smoke may use fewer families, but a
    # candidate real benchmark at 12+ must include the predeclared targets.
    if minimum_cwes >= len(_PINNED_MITRE_CWES) and not _PINNED_MITRE_CWES.issubset(by_cwe):
        failures['missing_pinned_test_cwe']+=1
    if any(labels!={True,False} for labels in by_cwe.values()):
        failures['test_cwe_without_both_classes']+=1

    return {
       'schema':'ultrasec.private-train-holdout-disjointness.v1',
       'scope':'OWNER_LOCAL_METADATA_ONLY',
       'metadata_separation_pass':not bool(failures),
       'training_rows_checked':len(clean_train),
       'test_rows_checked':len(clean_test),
       'test_cwes_checked':len(by_cwe),
       'known_research_cves_excluded':len(known_cves),
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


def audit_with_history(training:list, holdout:list, history:list,
                       minimum_train:int=100, minimum_test:int=100,
                       minimum_cwes:int=12, minimum_history:int=37)->dict:
    """Enforce owner-private *prior research* exclusions before TEST selection.

    These are NOT training labels and cannot be counted as GOLD. A structurally
    valid historical row only proves it was previously considered, so it must
    be excluded from a future-unseen holdout regardless of its admission status.
    """
    if (not isinstance(history,list) or type(minimum_history) is not int or
            minimum_history < 1):
        raise ValueError('invalid_private_history')
    report=audit(training,holdout,minimum_train,minimum_test,minimum_cwes)
    failures=Counter(report['failures'])
    historical_cves=set()
    historical_projects=set()
    valid=0
    for item in history:
        if not isinstance(item,dict):
            failures['invalid_private_history_record']+=1
            continue
        try:
            cid=item.get('cve_id')
            url=item.get('repo_url')
            fix=item.get('fix_commit')
            if (item.get('schema')!='ultrasec.public-cve-candidate.v1' or
                    item.get('admission_status')!='NOT_ADMITTED' or
                    item.get('commercial_rights')!='NOT_VERIFIED' or
                    not isinstance(cid,str) or not CVE.fullmatch(cid) or
                    not isinstance(fix,str) or not SHA40.fullmatch(fix)):
                raise ValueError('invalid_private_history_record')
            fp=project_fingerprint(url)
        except (ValueError,TypeError,AttributeError):
            failures['invalid_private_history_record']+=1
            continue
        valid+=1
        if cid in historical_cves:
            failures['duplicate_private_history_cve']+=1
        historical_cves.add(cid)
        historical_projects.add(fp)
    if valid<minimum_history:
        failures['insufficient_private_history']+=1

    # Reject all original research IDs/projects, even if the new candidate
    # supplies a different CVE or a case_id not seen before.
    for row in holdout:
        if _validate_row(row,'test') is not None:
            continue  # Base audit already reported invalid rows.
        if row['cve_id'] in historical_cves:
            failures['private_history_cve_overlap']+=1
        if row['project_fingerprint'] in historical_projects:
            failures['private_history_project_overlap']+=1

    known_cves=_KNOWN_CVES|_read_original_public_cves()|historical_cves
    report.update({
        'metadata_separation_pass':not bool(failures),
        'private_prior_research_rows_checked':valid,
        'known_research_cves_excluded':len(known_cves),
        'known_research_projects_excluded':len({
            project_fingerprint(s) for s in _KNOWN_PROJECT_URLS
        }|historical_projects),
        'known_research_inventory_completeness_verified':False,
        'private_prior_research_labels_admitted':0,
        'private_prior_research_provenance_independently_verified':False,
        'blind_benchmark_ready':False,
        'gold_admitted':0,
        'certification':'NOT_CERTIFIED',
        'failures':dict(sorted(failures.items())),
    })
    return report


def _read_private_jsonl(p:Path)->tuple[list,bytes]:
    if p.is_symlink() or not p.is_file() or not stat.S_ISREG(p.stat().st_mode):
        raise ValueError('unsafe_private_manifest')
    if not 0<p.stat().st_size<=MAX_METADATA_BYTES:
        raise ValueError('unsafe_private_manifest_size')
    raw=p.read_bytes()
    rows=[json.loads(line) for line in raw.decode('utf-8').splitlines() if line.strip()]
    return rows,hashlib.sha256(raw).digest()


def _write_private_receipt(p:Path,report:dict,train_sha:bytes,test_sha:bytes,prior_sha:bytes)->None:
    if not p.parent.is_dir() or p.parent.is_symlink():
        raise ValueError('unsafe_private_receipt_destination')
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
    with os.fdopen(os.open(p,flags,0o600),'w',encoding='utf-8') as f:
        json.dump({'report':report, 'training_manifest_sha256':train_sha.hex(),
                   'holdout_manifest_sha256':test_sha.hex(),
                   'prior_research_manifest_sha256':prior_sha.hex(),
                   'signatures_verified':False},f,sort_keys=True)
        f.write('\n')


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description='Owner-local TRAIN vs TEST metadata exclusion gate')
    p.add_argument('--train',type=Path,required=True)
    p.add_argument('--holdout',type=Path,required=True)
    p.add_argument('--prior-research',type=Path,required=True,
                   help='Owner-private 37+ previously researched NOT_ADMITTED candidates')
    p.add_argument('--minimum-train',type=int,default=100)
    p.add_argument('--minimum-test',type=int,default=100)
    p.add_argument('--minimum-cwes',type=int,default=12)
    p.add_argument('--private-receipt',type=Path)
    args=p.parse_args(argv)
    try:
        # Paths and inodes must all be different, including hard-link aliases.
        inputs=[args.train,args.holdout,args.prior_research]
        canonical=[p.resolve(strict=True) for p in inputs]
        identities={(p.stat().st_dev,p.stat().st_ino) for p in inputs}
        if len(set(canonical))!=3 or len(identities)!=3:
            raise ValueError('same_manifest')
        repo=Path(__file__).resolve().parents[2]
        if any(p.is_relative_to(repo) for p in canonical):
            raise ValueError('private_manifest_in_public_repository')
        train,train_digest=_read_private_jsonl(args.train)
        test,test_digest=_read_private_jsonl(args.holdout)
        prior,prior_digest=_read_private_jsonl(args.prior_research)
        report=audit_with_history(train,test,prior,args.minimum_train,
                                  args.minimum_test,args.minimum_cwes)
        if args.private_receipt:
            _write_private_receipt(args.private_receipt,report,
                                   train_digest,test_digest,prior_digest)
        print(json.dumps(report,sort_keys=True))
        return 0 if report['metadata_separation_pass'] else 1
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError):
        print('{"status":"FAIL_CLOSED_PRIVATE_SPLIT","certification":"NOT_CERTIFIED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
