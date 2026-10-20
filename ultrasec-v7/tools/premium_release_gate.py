#!/usr/bin/env python3
"""Conservative technical readiness gate; cannot set sale value automatically.

All inputs are external assertions; evidence hashes, legal rights and signatures
must be verified by independent professionals outside this software.
"""
from __future__ import annotations
import math


def evaluate_readiness(evidence:dict)->dict:
    corpus=evidence.get("corpus") or {}
    independent=evidence.get("independent") or {}
    benchmark=evidence.get("benchmark") or {}
    legal=evidence.get("legal") or {}
    ci=evidence.get("ci") or {}
    buyer=evidence.get("buyer") or {}

    def number(mapping,key)->float:
        value=mapping.get(key)
        return value if (isinstance(value,(int,float)) and not isinstance(value,bool)
                         and math.isfinite(value)) else -1
    problems=[]
    if number(corpus,"records")<1000000 or number(corpus,"exact_sha256_unique")<1000000:
        problems.append("million_record_integrity_not_proven")
    if corpus.get("split_leaks")!=0:
        problems.append("split_integrity_not_proven")
    if number(corpus,"lexical_patterns")<=200000:
        problems.append("lexical_diversity_not_proven")
    if (number(independent,"confirmed_real_world_cases")<100
            or number(independent,"qualified_independent_reviewers")<2):
        problems.append("independent_review_missing")
    if number(independent,"reviewer_agreement")<=0.8:
        problems.append("reviewer_agreement_below_target")
    if (independent.get("adjudication_unresolved")!=0
            or independent.get("adjudication_complete_signed") is not True):
        problems.append("unresolved_adjudication")
    if benchmark.get("baseline_real_executions") is not True or benchmark.get("low_recall_cwes")!=0:
        problems.append("real_sast_comparison_not_proven")
    if legal.get("redistribution_rights_verified") is not True:
        problems.append("commercial_rights_not_cleared")
    if (ci.get("total")!=17 or ci.get("passed")!=17
            or ci.get("unresolved_security_findings")!=0):
        problems.append("ci_or_independent_code_review_incomplete")

    # Internal technical screening remains distinct from independent certification.
    # Reviewer signatures and resale rights never count as completed by this field.
    external_only={"independent_review_missing","reviewer_agreement_below_target",
                   "unresolved_adjudication","commercial_rights_not_cleared"}
    internal_blockers=[p for p in problems if p not in external_only]
    if number(independent,"confirmed_real_world_cases")<100:
        internal_blockers.append("real_world_case_inventory_incomplete")

    commercial=[]
    if buyer.get("signed_150k_offer") is not True:
        commercial.append("buyer_offer_missing")
    if buyer.get("specified_license_scope") is not True:
        commercial.append("commercial_rights_scope_unverified")
    # Even actual transactions do not establish appraisal of all rights;
    # a contract may apply only to one limited license.
    return {
        "schema":"ultrasec.premium-readiness-evidence-v1",
        "certification":"NOT_CERTIFIED",
        "technical_release_ready":not problems,
        "internal_technical_screen_ready":not internal_blockers,
        "internal_blockers":internal_blockers,
        "external_review_phase":"DEFERRED",
        "internal_screen_assurance":"INPUT_ASSERTIONS_ONLY_NOT_CERTIFICATION",
        "blockers":problems,
        "commercial_value_usd_150k":"NOT_VERIFIED",
        "commercial_blockers":commercial,
        "caveat":"Inputs and purported independent signatures are not cryptographically verified by this gate.",
    }
