#!/usr/bin/env python3
"""Byte-pinned metadata-only *draft* delivery gate; NEVER rights clearance.

Confirms declared files resolve to their exact Git blob IDs, no source-file
paths appear in the scope, and all rights remain explicitly unverified.
A metadata file can still contain quotes/third-party IP: content clearance
requires a separate review. No package/archive is built by this tool.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys

_SHA1=re.compile(r'[a-f0-9]{40}\Z')
_ALLOWED_SUFFIXES=frozenset({'.md','.json'})
_MAX_SIZE=8*1024*1024
_SCHEMA='ultrasec.v7-exact-public-metadata-delivery-scope.v1'


def _read_pinned(root:Path, rel:str)->bytes:
    if not isinstance(rel,str) or not rel or len(rel)>255:
        raise ValueError('unsafe_delivery_path')
    p=PurePosixPath(rel)
    if (p.is_absolute() or '..' in p.parts or '.' in p.parts or
            not rel.startswith('verification/research/') or
            rel.startswith('./') or '\\' in rel or '//' in rel or
            '://' in rel or p.suffix not in _ALLOWED_SUFFIXES):
        raise ValueError('unsafe_delivery_path')
    if not root.is_dir() or root.is_symlink():
        raise ValueError('unsafe_delivery_root')
    selected=root
    for part in p.parts:
        selected=selected/part
        if selected.is_symlink():
            raise ValueError('unsafe_delivery_path')
    try:
        info=selected.stat()
        if not stat.S_ISREG(info.st_mode) or not selected.resolve().is_relative_to(root.resolve()):
            raise ValueError('unsafe_delivery_path')
        if not 0<info.st_size<=_MAX_SIZE:
            raise ValueError('unsafe_delivery_file_size')
        return selected.read_bytes()
    except OSError as exc:
        raise ValueError('missing_delivery_file') from exc


def inspect_scope(plan:object, root:Path)->dict:
    if not isinstance(plan,dict) or plan.get('schema')!=_SCHEMA:
        raise ValueError('invalid_delivery_manifest')
    if (plan.get('status')!='DRAFT_NOT_CERTIFIED_NOT_FOR_COMMERCIAL_DISTRIBUTION'
            or plan.get('delivery_mode')!='metadata_only'
            or plan.get('commercial_rights')!='NOT_VERIFIED'
            or plan.get('legal_opinion')!='NOT_RECEIVED'
            or plan.get('file_level_rights')!='NOT_VERIFIED'
            or plan.get('includes_gold_or_holdout') is not False
            or plan.get('source_distribution_allowed') is not False
            or plan.get('source_fragments_mode')!='OUT_OF_SCOPE_REQUIRES_SEPARATE_MANIFEST'
            or plan.get('full_source_pairs_mode')!='OUT_OF_SCOPE_REQUIRES_SEPARATE_MANIFEST'):
        raise ValueError('unsupported_rights_claim')
    files=plan.get('files')
    if not isinstance(files,list) or len(files)!=5:
        raise ValueError('invalid_delivery_files')
    seen=set()
    for entry in files:
        if not isinstance(entry,dict):
            raise ValueError('invalid_delivery_files')
        rel=entry.get('path')
        if not isinstance(rel,str):
            raise ValueError('unsafe_delivery_path')
        if rel in seen:
            raise ValueError('duplicate_delivery_path')
        seen.add(rel)
        if (entry.get('rights_status')!='NOT_VERIFIED'
                or entry.get('contains_upstream_source') is not False):
            raise ValueError('unsupported_rights_claim')
        blob=entry.get('git_blob_sha1')
        if not isinstance(blob,str) or not _SHA1.fullmatch(blob):
            raise ValueError('invalid_blob_reference')
        payload=_read_pinned(root,rel)
        observed=hashlib.sha1(f'blob {len(payload)}\0'.encode()+payload).hexdigest()
        if observed!=blob:
            raise ValueError('blob_mismatch')
    return {
        'schema':'ultrasec.v7-metadata-scope-bytes-check.v1',
        'files_inspected':len(files),
        'file_bytes_match_pins':True,
        'declared_delivery_mode':'metadata_only',
        'direct_source_code_files_in_selected_manifest':0,
        'source_content_free_verified':False,
        'commercial_rights_by_file_unverified':len(files),
        'legal_rights_verified':False,
        'commercial_distribution_allowed':False,
        'goutils_inclusion_in_final_unknown_files_verified':False,
        'status':'METADATA_SCOPE_VERIFIED_RIGHTS_UNRESOLVED',
        'certification':'NOT_CERTIFIED',
        'limitations':'Git blob equality checks exact public research-file bytes, not authorship, embedded source snippets, licensing, legal approval, or final buyer package.'
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser()
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--root',type=Path,required=True)
    args=p.parse_args(argv)
    try:
        plan=json.loads(args.manifest.read_text(encoding='utf-8'))
        print(json.dumps(inspect_scope(plan,args.root),sort_keys=True))
        return 0
    except (ValueError,OSError,TypeError,UnicodeError,json.JSONDecodeError):
        print('{"status":"BLOCKED_UNVERIFIED_RIGHTS","certification":"NOT_CERTIFIED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
