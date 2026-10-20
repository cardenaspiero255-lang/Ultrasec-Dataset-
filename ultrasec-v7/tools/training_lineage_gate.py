#!/usr/bin/env python3
"""Owner-local TRAIN inventory/lineage structural reconciliation, NOT attestation.

Works only when the OWNER supplies authentic exported training rows and the
exact full chain of private training-run receipts. Data never enter GitHub CI.
A self-declared receipt cannot independently prove that a training run occurred,
that a model consumed a case, or that no external data entered the pipeline.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from datetime import datetime

sys.path.insert(0,str(Path(__file__).resolve().parent))
from private_training_disjointness import _validate_row

SHA256=re.compile(r'[0-9a-f]{64}\Z')
RUNID=re.compile(r'[A-Za-z0-9._-]{1,96}\Z')
IDENTITY_FIELDS=(
  'case_id','project_fingerprint','mechanism_fingerprint','cve_id','cwe_id',
  'source_commit','fix_commit','source_sha256','fix_sha256','oracle_run_sha256',
  'vulnerable','split'
)


def fingerprint(row:dict)->str:
    """Collision-resistant identity of the owner-supplied TRAIN row (not its truth)."""
    if not isinstance(row,dict) or any(k not in row for k in IDENTITY_FIELDS):
        raise ValueError('invalid_train_row')
    obj={k:row[k] for k in IDENTITY_FIELDS}
    canonical=json.dumps(obj,sort_keys=True,ensure_ascii=True,
                         separators=(',',':')).encode('ascii')
    return hashlib.sha256(canonical).hexdigest()


def _valid_timestamp(value:object)->bool:
    if not isinstance(value,str) or not value.endswith('Z'):
        return False
    try:
        dt=datetime.fromisoformat(value.replace('Z','+00:00'))
        return dt.tzinfo is not None
    except ValueError:
        return False


def inspect(train_rows:object, lineage:object, minimum_train:int=100)->dict:
    if type(minimum_train) is not int or minimum_train<1:
        raise ValueError('minimum_train_must_be_positive')
    errors=Counter()
    if not isinstance(train_rows,list):
        raise ValueError('invalid_train_inventory')
    valid=[]
    seen_ids=set()
    before_after_pairs=set()
    content_pairs=set()
    for row in train_rows:
        if _validate_row(row,'train') is not None:
            errors['invalid_train_row']+=1
            continue
        if row['case_id'] in seen_ids:
            errors['duplicate_train_case_id']+=1
        seen_ids.add(row['case_id'])
        pair=(row['source_commit'],row['fix_commit'])
        content=(row['source_sha256'],row['fix_sha256'])
        if pair in before_after_pairs:
            errors['duplicate_original_train_pair']+=1
        if content in content_pairs:
            errors['duplicate_original_train_content']+=1
        before_after_pairs.add(pair)
        content_pairs.add(content)
        valid.append(row)
    if len(valid)<minimum_train:
        errors['insufficient_train']+=1

    valid_records={fingerprint(row) for row in valid}
    receipts=set()
    seen_checkpoints=set()
    seen_run_ids=set()
    previous=None
    chain_ok=True
    recorded_runs=0
    if (not isinstance(lineage,dict) or
        lineage.get('schema')!='ultrasec.owner-training-lineage.v1' or
        lineage.get('scope')!='OWNER_PRIVATE_RUN_RECEIPTS_ONLY'):
        errors['invalid_training_lineage']+=1
        runs=[]
    else:
        if lineage.get('independent_authenticity_verified') is not False:
            errors['unsupported_external_authenticity_claim']+=1
        runs=lineage.get('runs')
        if not isinstance(runs,list) or not runs:
            errors['missing_original_training_runs']+=1
            runs=[]
        expected_final=lineage.get('final_checkpoint_sha256')
        if not isinstance(expected_final,str) or not SHA256.fullmatch(expected_final):
            errors['invalid_final_checkpoint']+=1
    for index,run in enumerate(runs):
        if not isinstance(run,dict):
            errors['invalid_training_run']+=1
            chain_ok=False
            continue
        rid=run.get('run_id')
        output=run.get('checkpoint_sha256')
        parent=run.get('parent_checkpoint_sha256')
        if not isinstance(rid,str) or not RUNID.fullmatch(rid) or rid in seen_run_ids:
            errors['invalid_training_run_id']+=1
        else:
            seen_run_ids.add(rid)
        if (not isinstance(output,str) or not SHA256.fullmatch(output)
                or output in seen_checkpoints):
            errors['invalid_training_checkpoint']+=1
            chain_ok=False
        else:
            seen_checkpoints.add(output)
        if index==0 and parent is not None:
            errors['missing_genesis_or_parent_checkpoint']+=1
            chain_ok=False
        elif index>0 and parent!=previous:
            errors['broken_checkpoint_chain']+=1
            chain_ok=False
        if not all(isinstance(run.get(k),str) and SHA256.fullmatch(run[k])
                   for k in ('trainer_source_sha256','run_log_sha256')):
            errors['missing_training_pipeline_evidence']+=1
        if not _valid_timestamp(run.get('completed_at_utc')):
            errors['invalid_run_timestamp']+=1
        consumed=run.get('consumed_case_fingerprints')
        if (not isinstance(consumed,list) or not consumed
                or any(not isinstance(v,str) or not SHA256.fullmatch(v) for v in consumed)):
            errors['missing_consumed_training_fingerprints']+=1
        else:
            receipts.update(consumed)
        previous=output
        recorded_runs+=1
    if recorded_runs and isinstance(lineage,dict) and previous!=lineage.get('final_checkpoint_sha256'):
        errors['final_checkpoint_not_reached']+=1
        chain_ok=False
    if not recorded_runs:
        chain_ok=False
    if receipts-valid_records:
        errors['missing_exported_training_case']+=len(receipts-valid_records)
    if valid_records-receipts:
        errors['training_record_without_run_receipt']+=len(valid_records-receipts)
    samples_match=not bool((receipts^valid_records)) and not any(
        errors[k] for k in ('invalid_train_row','duplicate_train_case_id',
         'duplicate_original_train_pair','duplicate_original_train_content',
         'missing_consumed_training_fingerprints')
    )
    return {
      'schema':'ultrasec.training-lineage-reconciliation.v1',
      'scope':'OWNER_LOCAL_STRUCTURAL_ONLY',
      'training_run_count':recorded_runs,
      'unique_training_records':len(valid_records),
      'training_samples_match_declared_run_receipts':samples_match,
      'training_checkpoint_chain_closed':chain_ok,
      'structural_reconciliation_pass':not bool(errors),
      'complete_training_history_externally_attested':False,
      'model_training_artifacts_independently_verified':False,
      'original_case_truth_verified':False,
      'holdout_admission_allowed':False,
      'blind_benchmark_ready':False,
      'gold_admitted':0,
      'certification':'NOT_CERTIFIED',
      'failures':dict(sorted(errors.items())),
      'interpretation':'A structural checksum match against owner-supplied receipts is NOT proof of training provenance or absence of undeclared training runs.'
    }


def _read_private_file(path:Path, repo:Path)->bytes:
    if path.is_symlink() or not path.resolve(strict=True).is_file():
        raise ValueError('unsafe_input')
    if path.resolve().is_relative_to(repo):
        raise ValueError('train_metadata_must_remain_owner_private')
    mode=stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ValueError('private_input_file_permissions')
    return path.read_bytes()


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description='Owner-private original TRAIN lineage gate')
    p.add_argument('--train',type=Path,required=True)
    p.add_argument('--training-runs',type=Path,required=True)
    p.add_argument('--private-receipt',type=Path,required=True)
    p.add_argument('--minimum-train',type=int,default=100)
    args=p.parse_args(argv)
    try:
        repo=Path(__file__).resolve().parents[2]
        paths=(args.train,args.training_runs,args.private_receipt)
        if len({p.resolve() for p in paths})!=3:
            raise ValueError('same_input_or_output')
        train_bytes=_read_private_file(args.train,repo)
        lineage_bytes=_read_private_file(args.training_runs,repo)
        rows=[json.loads(line) for line in train_bytes.decode('utf-8').splitlines() if line.strip()]
        lineage=json.loads(lineage_bytes)
        result=inspect(rows,lineage,args.minimum_train)
        result.update({
          'input_train_file_sha256':hashlib.sha256(train_bytes).hexdigest(),
          'input_lineage_file_sha256':hashlib.sha256(lineage_bytes).hexdigest(),
        })
        output=args.private_receipt
        if output.resolve().is_relative_to(repo) or output.parent.is_symlink():
            raise ValueError('unsafe_output')
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
        fd=os.open(output,flags,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(result,f,sort_keys=True)
            f.write('\n')
        print(json.dumps({
          'status':'STRUCTURAL_RECONCILIATION_ONLY' if result['structural_reconciliation_pass'] else 'TRAIN_LINEAGE_BLOCKED',
          'train_records':result['unique_training_records'],
          'training_runs':result['training_run_count'],
          'holdout_admission_allowed':False,'certification':'NOT_CERTIFIED',
          'failures':result['failures'],
        },sort_keys=True))
        return 0 if result['structural_reconciliation_pass'] else 1
    except (OSError,ValueError,TypeError,UnicodeError,KeyError,json.JSONDecodeError):
        print('{"status":"TRAIN_LINEAGE_INPUT_REJECTED","certification":"NOT_CERTIFIED"}')
        return 2

if __name__=='__main__':
    sys.exit(main())
