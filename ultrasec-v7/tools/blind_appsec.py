#!/usr/bin/env python3
"""Owner-controlled 100-case blind AppSec review pack and agreement statistics.

No 'reviewer' is simulated. Python cannot replace licensed experts or confirm
the legal authenticity of user-supplied external provenance.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from premium_evidence import admission_report

_RUBRIC = """UltraSec V7. Reviewer protocol (independent external AppSec):
1. Work in an approved offline environment, keep cases confidential.
2. Do not access the owner's key or another reviewer's responses.
3. Select A, B or uncertain for the vulnerable side; document evidence for
   source-to-sink flow, boundary and proposed fix in a separate private file.
4. Compile/reproduce both candidates safely and record toolchain, results and
   independent failure modes. No test observed means NOT VERIFIED.
5. Return responses as JSONL with opaque case_id, vulnerable_side, evidence
   categories and reviewer attestation (identity/credentials via secure channel).
6. Do not claim audit completion until both real independent signed reviews
   and adjudication of every disagreement have been received.
"""

def _exclusive(path: Path):
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
    return os.fdopen(os.open(path,flags,0o600),"wb")


def create_reviewer_package(cases:list[dict], destination:Path,
                            secret:bytes | None = None)->dict:
    """Create two private ZIPs. Only admitted 100-case real-world evidence accepted.

    Admission is metadata screening; must independently verify all claims.
    The 100-case source must be owner-controlled and licensed before export.
    """
    if secret is None:
        secret=secrets.token_bytes(32)
    if (not isinstance(secret,bytes) or len(secret)<32
            or len(set(secret))<8):
        raise ValueError("Blinding requires a high-entropy 32-byte secret generated privately")
    if len(cases)!=100:
        raise ValueError("Exactly 100 cases required")
    report=admission_report(cases,required_cases=100,required_families=12)
    if not report["admission_pass"]:
        raise ValueError("Nonadmissible cases; cannot build blind pack")
    destination=Path(destination)
    if not destination.is_dir() or destination.is_symlink():
        raise ValueError("Private output directory required")
    public_path=destination/"reviewer_blind_100.zip"
    private_path=destination/"owner_key_100_PRIVATE.zip"
    if public_path.exists() or private_path.exists():
        raise FileExistsError("Refusing to overwrite a review package")
    payload=[]
    truth=[]
    for case in cases:
        token=hmac.new(secret,case["case_id"].encode(),hashlib.sha256).hexdigest()[:32]
        # case_id not emitted in reviewer pack; private owner mapping retains it.
        flip=hmac.new(secret,b"flip:"+case["case_id"].encode(),hashlib.sha256).digest()[0]%2
        a=case["vulnerable_code"] if not flip else case["fixed_code"]
        b=case["fixed_code"] if not flip else case["vulnerable_code"]
        payload.append({
            "case_id":token, "language":case["language"],"candidate_cwe":case["cwe_id"],
            "side_A":a, "side_B":b, "instruction":"Report A/B/uncertain without reference labels",
        })
        truth.append({
            "case_id":token,"original_case_id":case["case_id"],
            "vulnerable_side":"B" if flip else "A",
            "family_id":case["family_id"],
            "source_commit":case["source_commit"],
            "fix_commit":case["fix_commit"],
            "ground_truth_status":"OWNER_DECLARED_REQUIRES_EXTERNAL_VALIDATION",
        })
    with _exclusive(public_path) as out:
        with zipfile.ZipFile(out,"w",compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("cases.jsonl","".join(json.dumps(row,sort_keys=True)+"\n" for row in payload))
            z.writestr("REVIEWER_INSTRUCTIONS.txt",_RUBRIC)
            z.writestr("REVIEW_FORM_SCHEMA.json",json.dumps({
                "case_id":"string","vulnerable_side":"A|B|uncertain",
                "vulnerability_evidence":"supported|refuted|insufficient",
                "fix_evidence":"supported|refuted|insufficient",
                "reproduction":"pass|fail|not_run",
                "reviewer_id":"owner-approved-credentialed-reviewer",
            }))
    with _exclusive(private_path) as out:
        with zipfile.ZipFile(out,"w",compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("owner_key.jsonl","".join(json.dumps(row,sort_keys=True)+"\n" for row in truth))
    return {"count":len(cases),"reviewers_path":str(public_path),
            "owner_key_path":str(private_path),"review_status":"NOT_STARTED"}


def agreement_report(review_a:dict[str,str],review_b:dict[str,str],
                     required_cases:int=100,min_agreement:float=0.80)->dict:
    """Only authentic responses from independent humans qualify operationally."""
    if not 0 <= min_agreement <= 1 or required_cases<1:
        raise ValueError("Invalid agreement threshold")
    failures:Counter[str]=Counter()
    labels={"A","B","uncertain"}
    if (len(review_a)!=required_cases or len(review_b)!=required_cases
            or set(review_a)!=set(review_b)):
        failures["incomplete_review"]+=1
    if any(v not in labels for v in list(review_a.values())+list(review_b.values())):
        failures["invalid_review_label"]+=1
    disagreements=0; raw=0.; kappa=None
    calculated=False
    if not failures:
        ids=set(review_a)
        n=len(ids)
        disagreements=sum(review_a[i]!=review_b[i] for i in ids)
        raw=(n-disagreements)/n
        calculated=True
        left=Counter(review_a.values());right=Counter(review_b.values())
        expected=sum(left[label]*right[label] for label in labels)/(n*n)
        if expected>=1 or len(left)<2 or len(right)<2:
            failures["degenerate_review_distribution"]+=1
            kappa=None
        else:
            kappa=round((raw-expected)/(1-expected),6)
        # "uncertain" is not a substantive AppSec decision; don't let
        # abstention-heavy reviews manufacture high raw agreement.
        if (left["uncertain"]>=n*0.2 or right["uncertain"]>=n*0.2):
            failures["excessive_abstention"]+=1
    return {
        "schema":"ultrasec.blind-appsec-agreement.v1",
        "certification":"NOT_CERTIFIED",
        "external_certification":"NOT_VERIFIED",
        "reviewer_identity_verification":"OUTSIDE_THIS_TOOL",
        "criteria":{"required_cases":required_cases,"agreement_strictly_greater_than":min_agreement},
        "cases_compared":len(review_a) if calculated else 0,
        "observed_agreement":round(raw,6) if calculated else None,
        "cohens_kappa":kappa,
        "adjudication_required":disagreements if not failures else None,
        "agreement_gate_pass":not failures and raw>min_agreement,
        "failures":dict(failures),
    }
