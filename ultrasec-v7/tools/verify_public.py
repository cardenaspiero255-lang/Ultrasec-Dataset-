#!/usr/bin/env python3
"""Public-only GitHub repository security/metadata validation, no private UltraSec code."""
from __future__ import annotations
import argparse
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROJECT = ROOT / 'ultrasec-v7'
FORBIDDEN_SUFFIXES = {'.zip', '.zst', '.gz', '.jsonl', '.db', '.sqlite', '.parquet', '.onnx', '.pkl', '.pt', '.pth', '.safetensors', '.env', '.apk', '.exe', '.bin', '.pem', '.key', '.p12', '.keystore', '.7z', '.tar', '.jar'}
BANNED_PATH_PARTS = {'private', 'secrets', 'dataset', 'datasets', 'holdout', 'answers', 'keys', 'proprietary-core', 'credentials'}
REQUIRED_STATUS = {'distribution': 'PUBLIC_METADATA_ONLY', 'semgrep': 'NOT_RUN', 'codeql': 'NOT_RUN', 'external_certification': 'NOT_CERTIFIED', 'mechanisms_500': 'NOT_VERIFIED', 'historical_million_semantic_unique': 'NOT_VERIFIED'}
SECRET_PATTERN = re.compile(r'(?:gh[pousr]_[A-Za-z0-9_]{28,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xoxb-[0-9]+-[0-9]+-[0-9A-Za-z]+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)')
URL_SECRET_PATTERN = re.compile(r'https?://[^\s/]+:[^\s@/]+@')


def tracked_files(root: pathlib.Path) -> list[pathlib.Path]:
    out = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'], capture_output=True, check=True).stdout
    return [pathlib.Path(s.decode()) for s in out.split(b'\0') if s]


def assert_check(cond: bool, message: str):
    if not cond:
        raise AssertionError(message)


def public_assets(root: pathlib.Path) -> None:
    for rel in tracked_files(root):
        assert_check(not (set(rel.parts) & BANNED_PATH_PARTS), f'Restricted path: {rel}')
        assert_check(rel.suffix.lower() not in FORBIDDEN_SUFFIXES, f'Private/binary artifact path: {rel}')
        assert_check((root / rel).stat().st_size < 350_000, f'File too large for metadata-only repository: {rel}')
    assert_check((root/'ultrasec-v7'/'README.md').exists(), 'Missing public documentation')


def secrets(root: pathlib.Path) -> None:
    # Scan tracked textual content, including code files; avoid adding actual credentials here.
    for rel in tracked_files(root):
        full = root / rel
        if not full.is_file():
            continue
        try:
            content = full.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            raise AssertionError(f'Binary/invalid UTF-8 content: {rel}')
        assert_check(not SECRET_PATTERN.search(content), f'Potential credential in: {rel}')
        assert_check(not URL_SECRET_PATTERN.search(content), f'URL with embedded credentials: {rel}')


def rights(root: pathlib.Path) -> None:
    content = (root/'ultrasec-v7'/'LICENSE-PROPRIETARY.txt').read_text(encoding='utf-8')
    for required in ('All rights reserved', 'NO THIRD-PARTY LICENSE', 'PUBLIC VISIBILITY LIMITATIONS', 'NOT physically prevent', 'GitHub'):
        assert_check(required in content, f'Missing qualified rights term: {required}')
    assert_check(not re.search(r'(?im)^\s*SPDX-License-Identifier:\s*(?:MIT|Apache|GPL|BSD)', content), 'Contradictory public SPDX license')


def claims(root: pathlib.Path) -> None:
    status = json.loads((root/'ultrasec-v7'/'release-status.json').read_text(encoding='utf-8'))
    for k, v in REQUIRED_STATUS.items():
        assert_check(status.get(k) == v, f'Unexpected/unverified claim {k}: {status.get(k)!r}')
    assert_check(status.get('verified_external_experts', None) == 0, 'Unsubstantiated external reviewers')
    assert_check(status.get('commercial_appraisal_verified') is False, 'Price has no verified buyer quote')


def provenance(root: pathlib.Path) -> None:
    status = json.loads((root/'ultrasec-v7'/'release-status.json').read_text(encoding='utf-8'))
    assert_check(status.get('project') == 'UltraSec V7.0', 'Missing project marker')
    assert_check(status.get('repository_role') == 'PUBLIC_DOCUMENTATION_ONLY', 'Must remain documentation-only')
    assert_check(status.get('source_of_truth') == 'OWNER_CONTROLLED_PRIVATE_ARCHIVE', 'Private archive lineage missing')
    assert_check(isinstance(status.get('notes'), list) and len(status['notes']) >= 2, 'Notes not present')
    assert_check(status.get('historical_records_archived', None) == 1000000, 'Incorrect historical volume')


def links(root: pathlib.Path) -> None:
    md = (root/'ultrasec-v7'/'README.md').read_text(encoding='utf-8')
    for path in re.findall(r'\]\(([^)]+)\)', md):
        if path.startswith(('http://', 'https://', '#', 'mailto:')):
            continue
        path = path.split('#', 1)[0]
        assert_check('..' not in pathlib.PurePosixPath(path).parts, f'Disallowed backlink: {path}')
        assert_check((root/'ultrasec-v7'/path).exists(), f'Broken link: {path}')
    assert_check('LICENSE-PROPRIETARY.txt' in md, 'README omits license')
    assert_check('NOT_CERTIFIED' in md or 'certificación externa' in md.lower(), 'Documentation omits external certification caveat')


def workflows(root: pathlib.Path) -> None:
    path = root/'.github'/'workflows'/'ultrasec-public-ci.yml'
    text = path.read_text(encoding='utf-8')
    assert_check('permissions:\n  contents: read' in text, 'CI permission not restricted to read')
    assert_check('pull_request:' in text and 'push:' in text, 'CI missing PR/push triggers')
    assert_check(text.count('runs-on: ubuntu-latest') == 7, 'Expected seven jobs')
    assert_check(text.count('python3 ultrasec-v7/tools/verify_public.py') >= 7, 'Each CI job must run checks')
    for line in text.splitlines():
        if re.search(r'\buses:\s+', line):
            assert_check(bool(re.search(r'@[0-9a-f]{40}(?:\s+#.*)?\s*$', line)), f'Unpinned action: {line}')
    assert_check('pull_request_target' not in text, 'Unsafe PR target configuration')


def tests(root: pathlib.Path) -> None:
    # Unit checks enforce fail-closed behavior using precise negative cases.
    assert_check(bool(SECRET_PATTERN.search('ghp_'+'A'*40)), 'Secret detector not working')
    assert_check(not SECRET_PATTERN.search('normal_public_documentation'), 'Secret detector false positive')
    assert_check(bool(URL_SECRET_PATTERN.search(''.join(('https:', '//user:', 'password', '@host.tld')))), 'URL credential check failed')
    assert_check('.jsonl' in FORBIDDEN_SUFFIXES and '.zst' in FORBIDDEN_SUFFIXES, 'Forbidden private artifact check missing')
    assert_check('NOT_CERTIFIED' in REQUIRED_STATUS.values(), 'Status check missing')
    workflows(root)
    public_assets(root); secrets(root); rights(root); claims(root); provenance(root); links(root)

GATES = {
    '01-public-asset-boundary': public_assets,
    '02-secret-scan': secrets,
    '03-rights-notice': rights,
    '04-truthful-claims': claims,
    '05-provenance-metadata': provenance,
    '06-public-link-integrity': links,
    '07-ci-hardening-tests': tests,
}

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('gate', choices=GATES)
    p.add_argument('--root', type=pathlib.Path, default=ROOT)
    args = p.parse_args()
    try:
        GATES[args.gate](args.root.resolve())
    except Exception as ex:
        print(f'FAIL [{args.gate}]: {ex}', file=sys.stderr)
        sys.exit(1)
    print(f'PASS [{args.gate}] — public repository safety metadata only (NOT private benchmark certification)')
