#!/usr/bin/env python3
"""Owner-private original model/training bytes cross-check, NOT certification.

Requires trainer source, machine-readable run-consumption log and checkpoint
bytes for EACH declared training run. Checksum agreement never authenticates
an unsigned log or establishes absence of unknown earlier training history.
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

_SHA64 = re.compile(r'[0-9a-f]{64}\Z')
_RUNID = re.compile(r'[A-Za-z0-9._-]{1,96}\Z')
_MAX_LOG_BYTES = 16 * 1024 * 1024


def _file_bytes_digest(root: Path, path: object, is_log: bool) -> tuple[bytes | None, str]:
    if (not isinstance(path, str) or not path or len(path)>512 or
            '\\' in path or '//' in path or
            any(part in ('', '.', '..') for part in path.split('/'))):
        raise ValueError('unsafe_original_artifact_path')
    rel = PurePosixPath(path)
    if rel.is_absolute() or ':' in path or root.is_symlink() or not root.is_dir():
        raise ValueError('unsafe_original_artifact_path')
    file = root
    for part in rel.parts:
        file = file / part
        if file.is_symlink():
            raise ValueError('unsafe_original_artifact_path')
    if not file.is_file() or not file.resolve().is_relative_to(root.resolve()):
        raise ValueError('missing_original_artifact')
    try:
        fd = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError as exc:
        raise ValueError('missing_original_artifact') from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError('unsafe_original_artifact_path')
        if is_log and st.st_size > _MAX_LOG_BYTES:
            raise ValueError('oversized_original_run_log')
        h = hashlib.sha256()
        chunks = []
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(block)
                if is_log:
                    chunks.append(block)
        return (b''.join(chunks) if is_log else None), h.hexdigest()
    finally:
        os.close(fd)


def inspect_original_bytes(lineage: object, root: Path) -> dict:
    """Local original-byte consistency, never externally verified consumption."""
    if (not isinstance(lineage, dict) or
            lineage.get('schema') != 'ultrasec.owner-training-lineage.v1' or
            lineage.get('scope') != 'OWNER_PRIVATE_RUN_RECEIPTS_ONLY' or
            lineage.get('independent_authenticity_verified') is not False):
        raise ValueError('invalid_owner_lineage_contract')
    runs = lineage.get('runs')
    if not isinstance(runs, list) or not runs:
        raise ValueError('missing_original_training_run')
    checked = 0
    seen_ids = set()
    seen_checkpoints = set()
    consumed = set()
    previous = None
    for index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError('invalid_training_run')
        rid = run.get('run_id')
        if (not isinstance(rid, str) or not _RUNID.fullmatch(rid)
                or rid in seen_ids):
            raise ValueError('invalid_training_run')
        seen_ids.add(rid)
        checkpoint = run.get('checkpoint_sha256')
        if (not isinstance(checkpoint, str) or not _SHA64.fullmatch(checkpoint)
                or checkpoint in seen_checkpoints):
            raise ValueError('invalid_training_checkpoint')
        seen_checkpoints.add(checkpoint)
        parent = run.get('parent_checkpoint_sha256')
        if (index == 0 and parent is not None or
                index > 0 and parent != previous):
            raise ValueError('broken_checkpoint_chain')
        log_data = None
        for path_key, sha_key in (
                ('trainer_source_file', 'trainer_source_sha256'),
                ('run_log_file', 'run_log_sha256'),
                ('checkpoint_file', 'checkpoint_sha256')):
            source, observed = _file_bytes_digest(
                root, run.get(path_key), path_key == 'run_log_file')
            expected = run.get(sha_key)
            if not isinstance(expected, str) or not _SHA64.fullmatch(expected):
                raise ValueError('missing_original_artifact_digest')
            if observed != expected:
                raise ValueError('artifact_digest_mismatch')
            if path_key == 'run_log_file':
                log_data = source
            checked += 1
        events = []
        for line in log_data.splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if (isinstance(row, dict) and
                    row.get('schema') == 'ultrasec.training-consumption-event.v1'):
                events.append(row)
        if not events:
            raise ValueError('missing_machine_readable_consumption_event')
        if len(events) != 1:
            raise ValueError('ambiguous_consumption_event')
        ids = run.get('consumed_case_fingerprints')
        if (not isinstance(ids, list) or not ids or
                any(not isinstance(v, str) or not _SHA64.fullmatch(v)
                    for v in ids) or len(set(ids)) != len(ids)):
            raise ValueError('invalid_consumption_fingerprints')
        event = events[0]
        if (event.get('run_id') != rid or
                event.get('checkpoint_sha256') != checkpoint or
                event.get('parent_checkpoint_sha256') != parent or
                event.get('consumed_case_fingerprints') != ids):
            raise ValueError('consumption_log_mismatch')
        consumed.update(ids)
        previous = checkpoint
    if previous != lineage.get('final_checkpoint_sha256'):
        raise ValueError('final_checkpoint_mismatch')
    return {
        'schema':'ultrasec.training-original-artifact-bytes.v1',
        'scope':'OWNER_PRIVATE_STRUCTURAL_PROOF_ONLY',
        'declared_training_runs':len(runs),
        'run_artifact_files_verified':checked,
        'logged_distinct_training_fingerprints':len(consumed),
        'original_byte_digests_match':True,
        'original_log_consumption_matches':True,
        'independent_authenticity_verified':False,
        'proof_of_actual_model_input_consumption':False,
        'model_training_history_complete':False,
        'holdout_admission_allowed':False,
        'blind_benchmark_ready':False,
        'gold_admitted':0,
        'certification':'NOT_CERTIFIED',
        'limitations':'Unsigned owner-provided bytes and log declarations cannot prove historical training input consumption or absence of undisclosed runs.'
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Private original TRAIN file-byte gate')
    parser.add_argument('--lineage', type=Path, required=True)
    parser.add_argument('--artifact-root', type=Path, required=True)
    parser.add_argument('--private-receipt', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        repo = Path(__file__).resolve().parents[2]
        lineage_path = args.lineage.resolve(strict=True)
        root = args.artifact_root.resolve(strict=True)
        output = args.private_receipt
        if (args.lineage.is_symlink() or args.artifact_root.is_symlink() or
                not lineage_path.is_file() or not root.is_dir() or
                lineage_path.is_relative_to(repo) or root.is_relative_to(repo) or
                output.resolve().is_relative_to(repo) or output.is_symlink() or
                output.parent.is_symlink()):
            raise ValueError('owner_private_paths_required')
        if stat.S_IMODE(lineage_path.stat().st_mode) & 0o077:
            raise ValueError('owner_lineage_must_be_private')
        data = json.loads(lineage_path.read_text(encoding='utf-8'))
        receipt = inspect_original_bytes(data, root)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(output, flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(receipt, stream, sort_keys=True)
            stream.write('\n')
        print(json.dumps({
            'status':'ORIGINAL_ARTIFACT_BYTES_STRUCTURAL_ONLY',
            'runs':receipt['declared_training_runs'],
            'files':receipt['run_artifact_files_verified'],
            'model_consumption_independently_attested':False,
            'certification':'NOT_CERTIFIED'
        },sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        print('{"status":"ORIGINAL_TRAIN_ARTIFACTS_MISSING_OR_INVALID","certification":"NOT_CERTIFIED"}')
        return 2


if __name__ == '__main__':
    sys.exit(main())
