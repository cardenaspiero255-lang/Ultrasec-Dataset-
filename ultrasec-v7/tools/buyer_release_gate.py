#!/usr/bin/env python3
"""Fail-closed combined ORIGINAL file-rights and prospective buyer-delivery gate.

All evidence is *public metadata*. This never grants legal permission,
ships original source, or treats a third-party root license as coverage for
its compiled dependencies or all files in a buyer package.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from gitea_file_rights_gate import validate as validate_original_files
from couchbase_bsl_distribution_gate import evaluate as evaluate_compiled_bsl
from premium_source_pair_scope import screen_product_scope


def evaluate(gitea:object, couchbase:object, product:object, cohort:object)->dict:
    try:
        originals=validate_original_files(gitea)
    except (TypeError,ValueError,KeyError) as exc:
        raise ValueError('original_file_rights_unverified') from exc
    try:
        dependencies=evaluate_compiled_bsl(couchbase,'fixed')
    except (TypeError,ValueError,KeyError) as exc:
        raise ValueError('dependency_rights_not_verified') from exc
    try:
        p=screen_product_scope(product,cohort)
    except (TypeError,ValueError,KeyError) as exc:
        raise ValueError('product_scope_unverified') from exc
    if p['errors'] or p['candidate_origins']!=5:
        raise ValueError('product_scope_unverified')
    return {
      'schema':'ultrasec.buyer-source-pairs-licensing-screen.v1',
      'scope':'ORIGINAL_GITEA_ONLY_PLUS_BSL_DEPENDENCIES_AND_FIVE_DRAFT_PRODUCTS',
      'proposed_delivery_mode':'minimal_reproducible_source_pairs',
      'candidate_source_origins':p['candidate_origins'],
      'gitea_research_overlay_files':originals['original_file_rows_inspected'],
      'gitea_files_with_original_per_file_spdx':originals['source_files_per_file_spdx_observed'],
      'gitea_template_needs_root_mit_scope_review':originals['template_without_file_spdx_requires_review'],
      'root_mit_license_observed_not_cleared':True,
      'couchbase_compiled_dependency_files_blocked':dependencies['actual_original_source_files'],
      'other_go_dependency_licenses_requiring_obligation_review':originals['go_dependency_license_exceptions_unresolved'],
      'couchbase_bsl_licensed_work_scope_resolved':False,
      'file_level_notices_fully_applied_to_actual_buyer_package':False,
      'rights_for_other_four_original_projects_verified':False,
      'signed_license_specific_to_couchbase_files_received':False,
      'legal_clearance_of_deliverable_received':False,
      'license_status':'RIGHTS_NOT_VERIFIED',
      'commercially_releaseable_pairs':0,
      'source_files_authorized_for_sale_by_this_gate':0,
      'ready_to_sell':False,
      'certification':'NOT_CERTIFIED',
      'interpretation':'The overlay is NOT a buyer-ready distribution; original MIT code may carry redistribution conditions and does not waive separate BSL/other obligations.'
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser()
    for field in ('gitea','couchbase','product','cohort'):
        p.add_argument('--'+field,type=Path,required=True)
    args=p.parse_args(argv)
    try:
        files=[json.loads(getattr(args,k).read_text(encoding='utf-8'))
               for k in ('gitea','couchbase','product','cohort')]
        print(json.dumps(evaluate(*files),sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,KeyError,UnicodeError,json.JSONDecodeError):
        print('{"status":"SOURCE_PAIR_RIGHTS_NOT_VERIFIED","certification":"NOT_CERTIFIED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
