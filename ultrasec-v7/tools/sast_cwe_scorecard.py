#!/usr/bin/env python3
"""Aggregate-only per-CWE detection arithmetic, NOT an accredited blind benchmark.

Only the external custodial process may establish upstream gold truth, semantic
independence, immutable rule chronology, and scoring authorization. This module
never sets those gates true and never emits record IDs or source bytes.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import math
import re
from premium_evidence import _PINNED_MITRE_CWES

_IDENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z')
_CWE = re.compile(r'CWE-[1-9][0-9]{0,5}\Z')
_GOLD_FIELDS = frozenset({'record_id','split','cwe_id','expected_vulnerable'})
_PRED_FIELDS = frozenset({'record_id','predicted_vulnerable'})


def _empty() -> dict:
    return {
        'schema':'ultrasec.sast-cwe-diagnostic.v1',
        'scope':'OWNER_LOCAL_ARITHMETIC_ONLY',
        'arithmetic_valid':False,
        'tested_rows':0,
        'evaluated_cwes':0,
        'overall':{},
        'micro_metrics':{},
        'macro_metrics':{},
        'by_cwe':[],
        'failures':{},
        'rules_pre_frozen_verified':False,
        'upstream_truth_independently_verified':False,
        'semantic_holdout_independence_verified':False,
        'external_chronology_verified':False,
        'blind_benchmark_accredited':False,
        'publishable_result':False,
        'gold_admitted':0,
        'certification':'NOT_CERTIFIED',
    }


def _metrics(tp:int, fp:int, tn:int, fn:int) -> dict:
    pos=tp+fn
    neg=tn+fp
    precision=tp/(tp+fp) if tp+fp else 0.0
    recall=tp/pos if pos else 0.0
    fpr=fp/neg if neg else 0.0
    f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.0
    return {k:round(v,6) for k,v in {
        'precision':precision,'recall':recall,'f1':f1,
        'false_positive_rate':fpr
    }.items()}


def calculate_diagnostic(gold_rows:list, prediction_rows:list) -> dict:
    """Validate 100+ pairs across 12+ CWE with both classes, then aggregate.

    Numbers are diagnostic/UNVERIFIED even when all arithmetic checks pass.
    No raw IDs or case-level leakage. No claim that inputs are true blind gold.
    """
    report=_empty()
    if not isinstance(gold_rows,list) or not isinstance(prediction_rows,list):
        raise ValueError('invalid_row_collection')
    problems=Counter()
    gold={}
    pred={}
    for row in gold_rows:
        if (not isinstance(row,dict) or set(row)!=_GOLD_FIELDS or
                not isinstance(row.get('record_id'),str) or
                not _IDENT.fullmatch(row['record_id']) or
                not isinstance(row.get('cwe_id'),str) or
                not _CWE.fullmatch(row['cwe_id']) or
                row.get('split')!='test' or
                type(row.get('expected_vulnerable')) is not bool):
            problems['invalid_gold']+=1
            continue
        rid=row['record_id']
        if rid in gold:
            problems['duplicate_gold']+=1
        else:
            gold[rid]=(row['cwe_id'],row['expected_vulnerable'])
    for row in prediction_rows:
        if (not isinstance(row,dict) or set(row)!=_PRED_FIELDS or
                not isinstance(row.get('record_id'),str) or
                not _IDENT.fullmatch(row['record_id']) or
                type(row.get('predicted_vulnerable')) is not bool):
            problems['invalid_prediction']+=1
            continue
        rid=row['record_id']
        if rid in pred:
            problems['duplicate_prediction']+=1
        else:
            pred[rid]=row['predicted_vulnerable']
    by_cwe=defaultdict(set)
    for cwe,vulnerable in gold.values():
        by_cwe[cwe].add(vulnerable)
    if len(gold)<100:
        problems['insufficient_test_rows']+=1
    if len(by_cwe)<12:
        problems['insufficient_cwes']+=1
    if not _PINNED_MITRE_CWES.issubset(by_cwe.keys()):
        problems['missing_pinned_cwe_family']+=1
    if any(classes!={True,False} for classes in by_cwe.values()):
        problems['cwe_without_both_classes']+=1
    missing=len(gold.keys()-pred.keys())
    extra=len(pred.keys()-gold.keys())
    if missing:problems['missing_prediction']+=missing
    if extra:problems['unknown_prediction']+=extra
    report['tested_rows']=len(gold)
    report['evaluated_cwes']=len(by_cwe)
    if problems:
        report['failures']=dict(sorted(problems.items()))
        return report

    confusion=defaultdict(Counter)
    for rid,(cwe,truth) in gold.items():
        prediction=pred[rid]
        key=('tp' if prediction else 'fn') if truth else ('fp' if prediction else 'tn')
        confusion[cwe][key]+=1
    totals=Counter()
    metrics=[]
    for cwe in sorted(confusion):
        count=confusion[cwe]
        tp,fp,tn,fn=(count[k] for k in ('tp','fp','tn','fn'))
        totals.update({'tp':tp,'fp':fp,'tn':tn,'fn':fn})
        metrics.append({'cwe':cwe,'tp':tp,'fp':fp,'tn':tn,'fn':fn,
                        'metrics':_metrics(tp,fp,tn,fn)})
    report.update({
        'arithmetic_valid':True,
        'overall':{k:totals[k] for k in ('tp','fp','tn','fn')},
        'micro_metrics':_metrics(*(totals[k] for k in ('tp','fp','tn','fn'))),
        'macro_metrics':{
            key:round(sum(row['metrics'][key] for row in metrics)/len(metrics),6)
            for key in ('precision','recall','f1','false_positive_rate')
        },
        'by_cwe':metrics,
    })
    return report
