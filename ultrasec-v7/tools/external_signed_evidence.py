#!/usr/bin/env python3
"""Verify owner-local Ed25519 reviewer-report integrity; never certify identities.

This tool does not certify legal rights, vulnerabilities, independent credentials,
or the validity of claimed vulnerability evidence. The operator must establish
trusted public-key fingerprints and reviewer independence out-of-band.
All output is aggregate, never copies case IDs, code, or review contents.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def _read_private(root: Path, name: str, limit: int) -> tuple[bytes, Path]:
    if not isinstance(name, str) or not name or Path(name).is_absolute():
        raise ValueError("invalid_path")
    base=root.resolve(strict=True)
    path=(base/name).resolve(strict=True)
    if not path.is_relative_to(base) or path.is_symlink() or not path.is_file():
        raise ValueError("invalid_path")
    if path.stat().st_size>limit:
        raise ValueError("oversized_evidence")
    with path.open("rb") as handle:
        if os.fstat(handle.fileno()).st_size>limit:
            raise ValueError("oversized_evidence")
        raw=handle.read(limit+1)
    if len(raw)>limit:
        raise ValueError("oversized_evidence")
    return raw,path


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _ids(raw: bytes, *, owner: bool) -> set[str]:
    content=raw.decode("utf-8")
    if owner:
        values=json.loads(content)
        if not isinstance(values,list):
            raise ValueError("holdout_membership_invalid")
        ids=values
    else:
        rows=[json.loads(line) for line in content.splitlines() if line.strip()]
        if any(not isinstance(row,dict) or set(row)!={"case_id","vulnerable_side"}
               or row.get("vulnerable_side") not in ("A","B","uncertain") for row in rows):
            raise ValueError("holdout_membership_invalid")
        ids=[row["case_id"] for row in rows]
    if (len(ids)!=100 or len(set(ids))!=100
            or any(not isinstance(i,str) or not i or len(i)>256 for i in ids)):
        raise ValueError("holdout_membership_invalid")
    return set(ids)


def audit(root: Path, manifest: dict) -> dict:
    """Cryptographic verification only, with conservative, aggregate output.

    Manifest-supplied keys and fingerprints must be independently authenticated.
    Cryptographic integrity cannot establish that the holder is a qualified
    reviewer or that rights to redistribute third-party source were granted.
    """
    failures=[]
    root=Path(root)
    if not isinstance(manifest,dict):
        manifest={}
    expected=set()
    try:
        raw,_=_read_private(root,manifest.get("owner_ids"),2_000_000)
        if _sha256(raw)!=manifest.get("owner_ids_sha256"):
            raise ValueError("owner_hash_mismatch")
        expected=_ids(raw,owner=True)
    except (OSError,TypeError,ValueError,UnicodeError,KeyError,json.JSONDecodeError) as exc:
        reason=str(exc) if isinstance(exc,ValueError) and str(exc) in (
            "invalid_path","oversized_evidence","holdout_membership_invalid",
            "owner_hash_mismatch") else "owner_manifest_invalid"
        failures.append(reason)

    key_hashes=[]
    verified_count=0
    membership_count=0
    reviewers=manifest.get("reviewers",{})
    if not isinstance(reviewers,dict):
        reviewers={}
    for label in ("a","b"):
        item=reviewers.get(label,{})
        if not isinstance(item,dict):
            item={}
        data=None
        sig=None
        pub=None
        try:
            data,data_path=_read_private(root,item.get("report"),2_000_000)
            sig,sig_path=_read_private(root,item.get("signature"),8192)
            pub,pub_path=_read_private(root,item.get("public_key"),8192)
        except (OSError,ValueError,TypeError) as exc:
            reason=str(exc) if str(exc) in ("invalid_path","oversized_evidence") else "missing_evidence"
            failures.append(label+":"+reason)
            continue

        try:
            found=_ids(data,owner=False)
            if not expected or found!=expected:
                raise ValueError("holdout_membership_invalid")
            membership_count+=1
        except (ValueError,UnicodeError,TypeError,KeyError) :
            failures.append(label+":holdout_membership_invalid")

        if _sha256(data)!=item.get("report_sha256"):
            failures.append(label+":review_hash_mismatch")
            continue
        actual_fp=_sha256(pub)
        if actual_fp!=item.get("trusted_public_key_sha256"):
            failures.append(label+":untrusted_public_key")
            continue
        key_hashes.append(actual_fp)
        # OpenSSL supports Ed25519 raw-message verification without Python
        # non-standard dependencies. Fixed argv; no shell or external network.
        if not shutil.which("openssl"):
            failures.append(label+":crypto_verifier_unavailable")
            continue
        try:
            command=["openssl","pkeyutl","-verify","-rawin","-pubin",
                     "-inkey",str(pub_path),"-in",str(data_path),
                     "-sigfile",str(sig_path)]
            proc=subprocess.run(command,capture_output=True,timeout=10,check=False)
            if proc.returncode!=0:
                failures.append(label+":invalid_signature")
            else:
                verified_count+=1
        except (OSError,subprocess.TimeoutExpired):
            failures.append(label+":crypto_verification_failed")
    if len(key_hashes)==2 and key_hashes[0]==key_hashes[1]:
        failures.append("reviewers:same_public_key")
    return {
        "schema":"ultrasec.external-signed-reviews-integrity.v1",
        "scope":"LOCAL_CRYPTOGRAPHIC_INTEGRITY_ONLY",
        "signatures_valid":verified_count==2 and len(key_hashes)==2
                           and key_hashes[0]!=key_hashes[1],
        "membership_verified":membership_count==2 and bool(expected),
        "human_independence":"NOT_VERIFIED",
        "independent_gold":"NOT_VERIFIED",
        "real_sast":"NOT_RUN",
        "commercial_rights":"NOT_VERIFIED",
        "externally_certified":False,
        "failures":sorted(set(failures)),
        "warning":"Manifest fingerprints MUST be authenticated out-of-band; signatures do not establish reviewer qualifications or gold truth.",
    }
