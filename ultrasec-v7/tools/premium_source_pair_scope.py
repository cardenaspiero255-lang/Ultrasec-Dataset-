#!/usr/bin/env python3
"""Validate a PUBLIC research draft for a prospective private premium source-pair SKU.

The validator NEVER grants distribution rights or gold status. It does not
copy third-party source or access the actual private evaluation holdout.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import sys

REQUIRED=[
    "reproduced_original_before_after_witness",
    "original_sha256_and_dependency_lock",
    "per_file_spdx_copyright_and_dependency_obligations",
    "commercial_license_conditions_for_actual_customer_package",
    "sealed_project_and_mechanism_disjoint_holdout",
    "scanner_baseline_on_unseen_original_cases",
    "buyer_permitted_delivery_package_manifest",
]
SHA40=re.compile(r"^[a-f0-9]{40}$")


def screen_product_scope(product:object,cohort:object)->dict:
    errors=set()
    proposed=None
    cases=[]
    if not isinstance(product,dict) or not isinstance(cohort,dict):
        return _report("UNKNOWN",[],{"invalid_input"})
    proposed=product.get("proposed_delivery_mode")
    if proposed!="minimal_reproducible_source_pairs":
        errors.add("unsupported_product_mode")
    if (product.get("schema")!="ultrasec.v7-minimal-original-source-pair-product-draft.v1"
        or product.get("status")!="DRAFT_NOT_FOR_SALE"
        or product.get("delivery_location")!="PRIVATE_OWNER_CONTROLLED_ONLY"
        or product.get("commercial_certification")!="NOT_CERTIFIED"
        or product.get("commercial_release_ready") is not False
        or product.get("real_gold_pairs_admitted")!=0
        or product.get("contains_private_source") is not False
        or product.get("human_two_reviewer_phase")!="DEFERRED"):
        errors.add("unsupported_product_claim")
    if product.get("required_release_evidence")!=REQUIRED:
        errors.add("missing_release_requirements")
    cases=product.get("candidates")
    existing=cohort.get("candidates")
    if not isinstance(cases,list) or not isinstance(existing,list) or len(cases)!=5 or len(existing)!=5:
        return _report(proposed,cases if isinstance(cases,list) else [],errors|{"invalid_cohort"})

    sources={r.get("cve_id"):r for r in existing if isinstance(r,dict)}
    current=[x.get("cve_id") for x in cases if isinstance(x,dict)]
    if len(current)!=5 or len(set(current))!=5:
        errors.add("duplicate_candidate_origin")
    if set(current)!=set(sources):
        errors.add("cohort_mismatch")
    seen_prio=set()
    for case in cases:
        if not isinstance(case,dict):
            errors.add("invalid_case");continue
        cv=case.get("cve_id")
        src=sources.get(cv)
        if src is None:
            continue
        if case.get("source_url")!=src.get("source_url"):
            errors.add("cohort_mismatch")
        for field in ("original_commit","fix_commit"):
            value=case.get(field)
            expected=src.get("source_commit" if field=="original_commit" else "fix_commit")
            if value!=expected or (value is not None and not SHA40.fullmatch(value)):
                errors.add("cohort_mismatch")
        if case.get("red_green_run_url")!=src.get("native_evidence_url") or case.get("native_regression_status")!=src.get("native_evidence"):
            errors.add("cohort_mismatch")
        priority=case.get("research_priority")
        if type(priority) is not int or priority not in range(1,6) or priority in seen_prio:
            errors.add("invalid_priority")
        seen_prio.add(priority)
        if case.get("distribution_rights")!="NOT_VERIFIED" or case.get("license_obligation_signoff")!="NOT_DONE":
            errors.add("unsupported_rights_claim")
        if case.get("gold_status")!="NOT_ADMITTED" or case.get("independent_label_adjudication")!="NOT_COMPLETED":
            errors.add("unsupported_gold_claim")
        if case.get("split")!="UNASSIGNED" or case.get("private_holdout_independence")!="NOT_VERIFIED":
            errors.add("holdout_not_sealed")
        if case.get("commercial_delivery_status")!="BLOCKED":
            errors.add("unsupported_product_claim")
        if case.get("source_pair_file_level_inventory")!="INCOMPLETE":
            errors.add("unsupported_rights_claim")
        if case.get("packaged_source_files")!=[]:
            errors.add("source_files_must_remain_unshipped")
        if case.get("upstream_license_observed")!=src.get("license_observed"):
            errors.add("cohort_mismatch")
        paths=case.get("upstream_file_paths_for_review_only")
        if not isinstance(paths,list) or len(set(map(str,paths)))!=len(paths) or any(not isinstance(p,str) or p.startswith("/") or ".." in p.split("/") for p in paths):
            errors.add("invalid_source_file_review_paths")
    return _report(proposed,cases,errors)


def _report(mode,cases,errors):
    return {
        "schema":"ultrasec.v7-premium-research-product-screen.v1",
        "proposed_delivery_mode":mode,
        "candidate_origins":len(cases),
        "admitted_reproducible_pairs":0,
        "commercially_releaseable_pairs":0,
        "ready_to_sell":False,
        "certification":"NOT_CERTIFIED",
        "human_review_phase":"DEFERRED",
        "release_requirements":REQUIRED,
        "errors":sorted(errors),
        "interpretation":"A passing scope check validates only the draft's fail-closed claims; it is not legal clearance or an SAST benchmark."
    }


def main(argv=None):
    base=Path(__file__).resolve().parents[1]/"verification"/"research"
    try:
        product=json.loads((base/"PREMIUM_SOURCE_PAIR_PRODUCT_DRAFT.json").read_text(encoding="utf-8"))
        cohort=json.loads((base/"COHORT_5_PRE_ADMISSION_PUBLIC.json").read_text(encoding="utf-8"))
        r=screen_product_scope(product,cohort)
    except (OSError,ValueError,TypeError,json.JSONDecodeError):
        print('{"errors":["INPUT_REJECTED"],"certification":"NOT_CERTIFIED"}')
        return 2
    print(json.dumps(r,sort_keys=True))
    return 0 if not r["errors"] else 1


if __name__=="__main__":
    sys.exit(main())
