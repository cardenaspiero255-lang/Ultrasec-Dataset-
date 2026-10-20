#!/usr/bin/env python3
"""Twelve-CWE scanner preregistration GAP accounting: no synthetic benchmark inflation.

Inputs: ONLY already public rule bytes/manifest and 63 public CVE references.
Does not inspect or disclose the 37 owner-private historical CVEs or real holdout.
Actual detector performance, scanner execution and semantic applicability require
separate evidence. A file claiming 12 CWE does NOT prove 12 detectors.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from premium_evidence import _PINNED_MITRE_CWES
from future_holdout_exposure import _read_original_public_cves
from sast_ruleset_freeze import freeze


def audit(plan:object, rules_root:Path)->dict:
    if not isinstance(plan,dict):
        raise ValueError('invalid_plan')
    entries=plan.get('entries')
    if not isinstance(entries,list):
        raise ValueError('invalid_rule_entries')
    for entry in entries:
        if isinstance(entry,dict) and isinstance(entry.get('cwes'),list):
            # Rule family mapping needs an independently validated 1:1
            # evidence record, not arbitrary YAML/JSON labels claiming 12 CWE.
            if len(entry['cwes'])!=1:
                raise ValueError('ambiguous_multi_cwe_rule_claim')
    verified=freeze(plan,rules_root)
    public=_read_original_public_cves()
    excluded=set(plan['known_case_exclusions'])
    required=_PINNED_MITRE_CWES
    declared={c for row in entries for c in row['cwes']}
    missing=sorted(required-declared)
    unexpected=sorted(declared-required)
    return {
       'schema':'ultrasec.public-twelve-cwe-rulepack-gap-screen.v1',
       'scope':'PUBLIC_DECLARED_RULE_BYTES_ONLY',
       'rulepack_sha256':verified['rulepack_sha256'],
       'rule_bytes_verified':verified['rule_bytes_verified'],
       'verified_rule_files':verified['verified_rule_files'],
       'target_cwe_count':len(required),
       'declared_target_cwe_count':len(required & declared),
       'missing_target_cwe_count':len(missing),
       'missing_target_cwes':missing,
       'out_of_scope_declared_cwes':unexpected,
       'complete_declared_byte_scope':not missing,
       'researched_public_cves':len(public),
       'excluded_researched_public_cves':len(public & excluded),
       'unexcluded_researched_public_cves':len(public-excluded),
       'all_researched_public_cves_excluded':public.issubset(excluded),
       'owner_private_37_exclusions_checked':False,
       'scanner_semantics_verified':False,
       'effective_rule_to_cwe_mapping_verified':False,
       'external_freeze_chronology_verified':False,
       'holdout_independence_verified':False,
       'blind_benchmark_ready':False,
       'gold_admitted':0,
       'certification':'NOT_CERTIFIED',
       'interpretation':'Only identifies pinned public rule-byte declarations and gaps; no scanner may be scored on independent private holdout solely from this report.',
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description='Public-only preregistered 12-CWE rule gap audit')
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--rules-root',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        plan=json.loads(args.plan.read_text(encoding='utf-8'))
        print(json.dumps(audit(plan,args.rules_root),sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError):
        print('{"status":"FAIL_CLOSED_PUBLIC_RULE_SCOPE","certification":"NOT_CERTIFIED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
