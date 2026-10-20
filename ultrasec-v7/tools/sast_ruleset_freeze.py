#!/usr/bin/env python3
"""Offline, fail-closed SAST rule-byte preregistration (not a blind benchmark).

A content digest is NOT evidence of temporal independence, scanner performance,
licensing, holdout integrity, or expert adjudication. No private code is loaded.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

SHA256 = re.compile(r'[a-f0-9]{64}\Z')
CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}\Z')
CWE = re.compile(r'CWE-[1-9][0-9]{0,5}\Z')
VERSION = re.compile(r'[0-9]+(?:\.[0-9]+){1,3}\Z')
MAX_RULE_BYTES = 1024 * 1024
ALLOWED_TOOLS = frozenset({'semgrep', 'codeql', 'slither'})


def _rule_bytes(root: Path, candidate: str) -> bytes:
    if not isinstance(candidate, str) or len(candidate) > 255:
        raise ValueError('unsafe_rule_path')
    rel = PurePosixPath(candidate)
    if (not candidate or rel.is_absolute() or '..' in rel.parts
            or candidate.startswith('./') or '\\' in candidate or '://' in candidate
            or rel.suffix not in {'.yml', '.yaml', '.ql', '.qls', '.json'}):
        raise ValueError('unsafe_rule_path')
    parent = Path(root)
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError('unsafe_rule_root')
    for part in rel.parts:
        parent = parent / part
        if parent.is_symlink():
            raise ValueError('unsafe_rule_path')
    if not parent.is_file() or not stat.S_ISREG(parent.stat().st_mode):
        raise ValueError('unsafe_rule_path')
    if not parent.resolve().is_relative_to(root.resolve()):
        raise ValueError('unsafe_rule_path')
    if not 0 < parent.stat().st_size <= MAX_RULE_BYTES:
        raise ValueError('invalid_rule_size')
    return parent.read_bytes()


def freeze(plan: dict, rules_root: Path) -> dict:
    """Validate exact local rule bytes; never assert temporal blindness."""
    if not isinstance(plan, dict) or plan.get('schema') != 'ultrasec.sast-rule-byte-plan.v1':
        raise ValueError('invalid_plan')
    if (plan.get('certification') != 'NOT_CERTIFIED'
            or type(plan.get('gold_count')) is not int or plan['gold_count'] != 0
            or plan.get('holdout_status') != 'UNASSIGNED'
            or plan.get('scoring_enabled') is not False):
        raise ValueError('unsupported_evaluation_claim')
    if plan.get('purpose') not in {'FUTURE_UNSEEN_PRE_REGISTRATION', 'RESEARCH_POSTHOC_ONLY'}:
        raise ValueError('invalid_purpose')
    exclusions = plan.get('known_case_exclusions')
    if (not isinstance(exclusions, list) or not exclusions
            or any(not isinstance(e, str) or not CVE.fullmatch(e) for e in exclusions)
            or len(exclusions) != len(set(exclusions))):
        raise ValueError('missing_known_case_exclusions')
    entries = plan.get('entries')
    if not isinstance(entries, list) or not 1 <= len(entries) <= 100:
        raise ValueError('invalid_rule_entries')
    checked, seen_paths = [], set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'tool', 'version', 'path', 'sha256', 'cwes'}:
            raise ValueError('invalid_rule_entry')
        tool, version, path, checksum, cwes = (entry[k] for k in ('tool', 'version', 'path', 'sha256', 'cwes'))
        if tool not in ALLOWED_TOOLS or not isinstance(version, str) or not VERSION.fullmatch(version):
            raise ValueError('unpinned_tool')
        if not isinstance(checksum, str) or not SHA256.fullmatch(checksum):
            raise ValueError('invalid_rule_digest')
        if (not isinstance(cwes, list) or not cwes
                or any(not isinstance(x, str) or not CWE.fullmatch(x) for x in cwes)):
            raise ValueError('invalid_rule_cwe_scope')
        if path in seen_paths:
            raise ValueError('duplicate_rule_file')
        seen_paths.add(path)
        payload = _rule_bytes(Path(rules_root), path)
        observed = hashlib.sha256(payload).hexdigest()
        if observed != checksum:
            raise ValueError('digest_mismatch')
        checked.append({'tool': tool, 'version': version, 'path': path,
                        'sha256': observed, 'cwes': sorted(set(cwes))})
    canonical = json.dumps({'purpose': plan['purpose'], 'known_case_exclusions': sorted(exclusions),
                            'entries': sorted(checked, key=lambda x: x['path'])},
                           sort_keys=True, separators=(',', ':')).encode('utf-8')
    return {
        'schema': 'ultrasec.sast-ruleset-byte-lock.v1',
        'rulepack_sha256': hashlib.sha256(canonical).hexdigest(),
        'rule_bytes_verified': True,
        'verified_rule_files': len(checked),
        'purpose': plan['purpose'],
        'known_research_exclusions': len(exclusions),
        'freeze_scope': 'LOCAL_BYTES_ONLY',
        'external_chronology_verified': False,
        'holdout_independence_verified': False,
        'blind_benchmark_ready': False,
        'scanner_execution_verified': False,
        'gold_admitted': 0,
        'certification': 'NOT_CERTIFIED',
        'rights_verified': False,
    }


def write_receipt(receipt: dict, destination: Path) -> None:
    """Persist a private, exclusive 0600 receipt without overwriting one."""
    destination = Path(destination)
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError('unsafe_private_output')
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(destination, flags, 0o600), 'w', encoding='utf-8') as f:
        json.dump(receipt, f, sort_keys=True)
        f.write('\n')


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='Verify local SAST rules against a pre-registration plan')
    p.add_argument('--plan', type=Path, required=True)
    p.add_argument('--rules-root', type=Path, required=True)
    p.add_argument('--private-receipt', type=Path)
    a = p.parse_args(argv)
    try:
        plan = json.loads(a.plan.read_text(encoding='utf-8'))
        result = freeze(plan, a.rules_root)
        if a.private_receipt:
            write_receipt(result, a.private_receipt)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        print('{"status":"REJECTED_NO_BLIND_CLAIM","certification":"NOT_CERTIFIED"}')
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
