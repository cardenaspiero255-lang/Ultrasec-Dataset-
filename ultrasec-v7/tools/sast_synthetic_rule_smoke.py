#!/usr/bin/env python3
"""Run pinned CWE-scoped research Semgrep rules only on PUBLIC synthetic controls.

No private training examples, code, true gold labels, or future heldout cases.
A syntactic positive/negative smoke cannot establish vulnerability detection
recall, causal verification, CWE coverage, or preregistration independence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
from sast_target_coverage import audit

def run(plan_file:Path, root:Path)->dict:
    doc=json.loads(plan_file.read_text(encoding='utf-8'))
    scope=audit(doc,root)
    if (scope['declared_target_cwe_count']!=12 or
        scope['missing_target_cwe_count']!=0 or
        scope['excluded_researched_public_cves']!=63 or
        not scope['all_researched_public_cves_excluded']):
        raise ValueError('unverified_scope_or_missing_exclusions')
    tests=[]
    for entry in doc['entries']:
        cwe=entry['cwes'][0]
        if cwe=='CWE-94':
            continue  # Original V1 has its own 2/2 native Semgrep smoke.
        key=cwe.lower().replace('-','')
        fixtures=root/'verification/fixtures/future-sast'
        positive=list(fixtures.glob(key+'_positive.*'))
        negative=list(fixtures.glob(key+'_negative.*'))
        if len(positive)!=1 or len(negative)!=1:
            raise ValueError('missing_or_ambiguous_public_fixture')
        rule=root/entry['path']
        with tempfile.TemporaryDirectory(prefix='ultrasec-public-sast-') as temp:
            receipt=Path(temp)/'result.json'
            env=dict(os.environ,SEMGREP_SEND_METRICS='off')
            args=['semgrep','scan','--oss-only','--disable-version-check',
                  '--metrics','off','--no-git-ignore','--json',
                  '--output',str(receipt),'--config',str(rule),
                  str(positive[0]),str(negative[0])]
            done=subprocess.run(args,capture_output=True,timeout=90,env=env)
            if done.returncode!=0 or not receipt.is_file():
                raise ValueError('semgrep_cli_failure_'+key)
            result=json.loads(receipt.read_text(encoding='utf-8'))
            if result.get('errors'):
                raise ValueError('semgrep_parser_errors_'+key)
            matches=result.get('results')
            if not isinstance(matches,list):
                raise ValueError('missing_rule_results_'+key)
            found_positive=0
            found_negative=0
            for item in matches:
                rid=item.get('check_id','')
                if not rid.endswith('.'+key):
                    raise ValueError('unexpected_rule_'+key)
                path=Path(item['path']).name
                if path==positive[0].name:
                    found_positive+=1
                elif path==negative[0].name:
                    found_negative+=1
                else:
                    raise ValueError('unrecognized_scan_target_'+key)
            if found_positive!=1 or found_negative!=0:
                raise ValueError('synthetic_detection_mismatch_'+key)
        tests.append(key)
    if len(tests)!=11 or len(set(tests))!=11:
        raise ValueError('incomplete_synthetic_scopes')
    return {
      'schema':'ultrasec.exploratory-synthetic-rule-execution.v1',
      'semgrep_cli_executed':True,
      'synthetic_rule_scopes_exercised':len(tests),
      'synthetic_positive_hits':len(tests),
      'synthetic_negative_hits':0,
      'scanned_real_holdout':False,
      'original_cve_oracles_verified':False,
      'scanner_semantics_verified':False,
      'real_cwe_recall_measured':False,
      'gold_admitted':0,
      'benchmark_ready':False,
      'certification':'NOT_CERTIFIED',
      'rulepack_sha256':scope['rulepack_sha256']
    }

def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument('--plan',type=Path,required=True)
    p.add_argument('--rules-root',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    try:
        result=run(a.plan,a.rules_root)
        with a.out.open('x',encoding='utf-8') as out:
            json.dump(result,out,sort_keys=True)
            out.write('\n')
        print(json.dumps(result,sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,subprocess.SubprocessError,json.JSONDecodeError):
        print('SYNTHETIC_RULES_NOT_VERIFIED; GOLD=0; BENCHMARK=NOT_RUN',file=sys.stderr)
        return 2

if __name__=='__main__':
    sys.exit(main())
