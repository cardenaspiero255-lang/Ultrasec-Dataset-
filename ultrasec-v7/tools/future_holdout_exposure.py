#!/usr/bin/env python3
"""Offline metadata-only screen for future holdout exposure to known public research.

No raw source, private IDs or labels are printed; a clean screen is NOT
proof of unbiased selection, correct oracles, or GOLD admission.
"""
from __future__ import annotations
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

_SHA = re.compile(r'[a-f0-9]{40}\Z')
_HASH = re.compile(r'[a-f0-9]{64}\Z')
_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}\Z')
_ID = re.compile(r'[a-zA-Z0-9_-]{1,128}\Z')
_REPO = re.compile(r'/[a-z0-9_.-]+/[a-z0-9_.-]+\Z')
_WP = re.compile(r'/plugins/[a-z0-9-]+\Z')
_FIELDS = frozenset({'case_id','cve_id','project_fingerprint','mechanism_fingerprint',
    'source_commit','fix_commit','source_sha256','fix_sha256'})
_KNOWN_CVES = frozenset({
    'CVE-2026-58428','CVE-2024-2395','CVE-2024-0683','CVE-2025-69015',
    'CVE-2023-42799','CVE-2024-48645','CVE-2024-11921','CVE-2024-12514',
})
_KNOWN_PROJECT_URLS = (
    'https://github.com/go-gitea/gitea',
    'https://wordpress.org/plugins/bulgarisation-for-woocommerce/',
    'https://github.com/Automattic/crowdsignal-forms',
    'https://github.com/moonlight-stream/moonlight-common-c',
    'https://github.com/arm32x/command-block-ide',
    'https://github.com/impress-org/givewp',
    'https://wordpress.org/plugins/3dvieweronline-wp/',
    'https://github.com/couchbase/goutils',
)


def project_fingerprint(url: str) -> str:
    """Canonical public project URL hashing; owners must use same v1 scheme."""
    if not isinstance(url,str) or len(url)>512:
        raise ValueError('invalid_public_project_url')
    u = urlsplit(url)
    if u.scheme.lower()!='https' or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ValueError('invalid_public_project_url')
    host = u.hostname.lower()
    path = u.path.rstrip('/').lower()
    if host=='github.com':
        if path.endswith('.git'):
            path=path[:-4]
        if not _REPO.fullmatch(path):
            raise ValueError('invalid_public_project_url')
    elif host=='wordpress.org':
        if not _WP.fullmatch(path):
            raise ValueError('invalid_public_project_url')
    else:
        raise ValueError('unsupported_project_host')
    canonical = 'ultrasec-project-url-sha256-v1|'+host+path
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _well_formed(row: object) -> bool:
    return (isinstance(row,dict) and set(row)==_FIELDS and
        isinstance(row['case_id'],str) and bool(_ID.fullmatch(row['case_id'])) and
        isinstance(row['cve_id'],str) and bool(_CVE.fullmatch(row['cve_id'])) and
        all(isinstance(row[k],str) and _HASH.fullmatch(row[k]) for k in
            ('project_fingerprint','mechanism_fingerprint','source_sha256','fix_sha256')) and
        all(isinstance(row[k],str) and _SHA.fullmatch(row[k]) for k in ('source_commit','fix_commit')) and
        row['source_commit']!=row['fix_commit'] and row['source_sha256']!=row['fix_sha256'])


def screen(rows: list) -> dict:
    """Conservative screen before assigning splits; never infer labels."""
    if not isinstance(rows,list):
        raise ValueError('invalid_candidate_collection')
    known_projects = {project_fingerprint(url) for url in _KNOWN_PROJECT_URLS}
    errors=Counter()
    if not rows:
        errors['no_candidate_metadata'] += 1
    seen_ids=set();seen_projects=set();seen_mechanisms=set();seen_commits=set();seen_content=set()
    valid=0
    for row in rows:
        if not _well_formed(row):
            errors['invalid_record'] += 1
            continue
        valid+=1
        if row['case_id'] in seen_ids: errors['duplicate_case_id']+=1
        seen_ids.add(row['case_id'])
        if row['cve_id'] in _KNOWN_CVES: errors['previously_studied_cve']+=1
        if row['project_fingerprint'] in known_projects: errors['previously_studied_project']+=1
        for field,seen,error in (
            ('project_fingerprint',seen_projects,'reused_project_requires_grouping'),
            ('mechanism_fingerprint',seen_mechanisms,'reused_mechanism_requires_grouping')):
            value=row[field]
            if value in seen: errors[error]+=1
            seen.add(value)
        pair=(row['source_commit'],row['fix_commit'])
        if pair in seen_commits:errors['duplicate_original_pair']+=1
        seen_commits.add(pair)
        pair=(row['source_sha256'],row['fix_sha256'])
        if pair in seen_content:errors['duplicate_content_pair']+=1
        seen_content.add(pair)
    return {
      'schema':'ultrasec.future-holdout-exposure-screen.v1',
      'candidate_metadata_screen_pass':not bool(errors),
      'future_candidate_records':valid,
      'known_research_cves_excluded':len(_KNOWN_CVES),
      'known_research_projects_excluded':len(known_projects),
      'known_research_inventory_completeness_verified':False,
      'split_status':'UNASSIGNED',
      'holdout_assigned':False,
      'independence_verified':False,
      'blind_benchmark_ready':False,
      'gold_admitted':0,
      'certification':'NOT_CERTIFIED',
      'failures':dict(sorted(errors.items())),
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description='Local owner-only candidate exposure screen')
    p.add_argument('--private-metadata',type=Path,required=True)
    a=p.parse_args(argv)
    try:
        with a.private_metadata.open('r',encoding='utf-8') as f:
            rows=[json.loads(line) for line in f if line.strip()]
        report=screen(rows)
    except (OSError,ValueError,TypeError,UnicodeError,json.JSONDecodeError):
        print('{"status":"INPUT_REJECTED","certification":"NOT_CERTIFIED"}')
        return 2
    print(json.dumps(report,sort_keys=True))
    return 0 if report['candidate_metadata_screen_pass'] else 1

if __name__=='__main__':sys.exit(main())
