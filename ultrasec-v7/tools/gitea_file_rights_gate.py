#!/usr/bin/env python3
"""Original Go source-pair file-level rights RESEARCH gate, never commercial permission.

A truthful source file inventory helps review legal obligations, but does not
prove chain of title, satisfy source notices, or legal license compatibility.
No code from Gitea or Couchbase is ever stored in the public dataset.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

EXPECTED_FILES={
 'routers/web/repo/release.go':('128fcd5369505d4d27c33842a646bf41d1f289af','f8757ee53d1544efaa77dd45a85a1a860568fda4','SPDX_MIT_PER_FILE'),
 'routers/web/repo/release_test.go':('82f3115ee5d34a3e09d0f8fab4fe6531e413ba8c','57f831bffda8fc9347cba771283a378a6d5d09e8','SPDX_MIT_PER_FILE'),
 'services/release/release.go':('1be60731a930b2c442aafcb5174f6b727c930b97','5d4063c083915b231c8c7dc44f317202ba637180','SPDX_MIT_PER_FILE'),
 'services/release/release_test.go':('579d92f2f4b26c4b5d3f78e50a996ef621526fe6','1c0f910bbfb712caabc4906124cbd739d38a9ae8','SPDX_MIT_PER_FILE'),
 'templates/repo/release/new.tmpl':('cc73bdf13c50e8b7e88579cd8484f0384b132890','a930664554e716872d83c2c5d6132150b42591e8','ROOT_MIT_LICENSE_ONLY_NO_FILE_HEADER'),
 'tests/integration/release_test.go':('320661420ed80b53acd5a9e85914a1176c9c74bf','f495e417d9301b00bffcb7aa49ba3a337879a8e5','SPDX_MIT_PER_FILE'),
 'LICENSE':('a8d4b49dd073a4a38a7e58385eeff7cc52568697','a8d4b49dd073a4a38a7e58385eeff7cc52568697','UPSTREAM_ROOT_MIT_LICENSE_TEXT'),
 'go.mod':('1f2e923ce21ee69e26b6e90e37146a633d3ad273','1f2e923ce21ee69e26b6e90e37146a633d3ad273','DEPENDENCY_MANIFEST_NOT_LICENSE_CLEARANCE'),
 'go.sum':('34ab2024ed6e41ae05212044f383e846901e9c5e','34ab2024ed6e41ae05212044f383e846901e9c5e','DEPENDENCY_MANIFEST_NOT_LICENSE_CLEARANCE'),
}
_FIXED='e4ef995f2a162e3aca3f3a0b536afae067975d71'
_BEFORE='7fdfb8d642201b388014f29889ef28e35b8c1872'
_LICENSE_BLOB='a8d4b49dd073a4a38a7e58385eeff7cc52568697'


def validate(doc:object)->dict:
    if not isinstance(doc,dict) or doc.get('schema')!='ultrasec.gitea-nine-file-original-rights-manifest.v1':
        raise ValueError('invalid_rights_document')
    if (doc.get('upstream')!='https://github.com/go-gitea/gitea' or
        doc.get('before_commit')!=_BEFORE or doc.get('fixed_commit')!=_FIXED or
        doc.get('origin_scope')!='ORIGINAL_NINE_RECONSTRUCTION_FILES_RESEARCH_ONLY' or
        doc.get('license_root_blob_sha')!=_LICENSE_BLOB or
        doc.get('proposed_mode')!='minimal_reproducible_source_pairs' or
        doc.get('buyer_delivery_manifest_status')!='UNDEFINED' or
        doc.get('original_patch_files')!=6 or
        doc.get('couchbase_compiled_files_unresolved')!=4 or
        doc.get('go_dependency_license_exceptions_unresolved')!=16 or
        doc.get('source_bytes_in_research_repo') is not False or
        doc.get('commercial_rights')!='NOT_VERIFIED' or
        doc.get('legal_opinion')!='NOT_RECEIVED' or
        doc.get('distribution_allowed') is not False or
        doc.get('certification')!='NOT_CERTIFIED'):
        raise ValueError('unsupported_rights_claim')
    rows=doc.get('files')
    if not isinstance(rows,list) or len(rows)!=len(EXPECTED_FILES):
        raise ValueError('missing_original_file')
    observed=set()
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('path'),str):
            raise ValueError('invalid_original_file')
        path=row['path']
        if path not in EXPECTED_FILES or path in observed:
            raise ValueError('missing_original_file')
        observed.add(path)
        orig,fix,lic=EXPECTED_FILES[path]
        if row.get('before_blob_sha')!=orig or row.get('fixed_blob_sha')!=fix:
            raise ValueError('blob_mismatch')
        if row.get('license_evidence')!=lic:
            raise ValueError('original_license_classification_changed')
        if not isinstance(row.get('copyright_observed'),str) or not row['copyright_observed']:
            raise ValueError('missing_original_rights_holder')
        if (row.get('commercial_rights')!='NOT_VERIFIED' or
            row.get('notice_obligations')!='PENDING_FILE_LEVEL_REVIEW' or
            row.get('buyer_package_inclusion')!='NOT_APPROVED' or
            row.get('source_distributed') is not False):
            raise ValueError('unsupported_rights_claim')
    if observed!=set(EXPECTED_FILES):
        raise ValueError('missing_original_file')
    return {
        'schema':'ultrasec.gitea-nine-file-rights-screen.v1',
        'original_file_rows_inspected':len(observed),
        'upstream_patch_files':6,
        'source_files_per_file_spdx_observed':sum(
            lic=='SPDX_MIT_PER_FILE' for _,_,lic in EXPECTED_FILES.values()),
        'root_license_text_observed':True,
        'template_without_file_spdx_requires_review':True,
        'dependency_manifests_not_rights_clearance':True,
        'go_dependency_license_exceptions_unresolved':16,
        'unresolved_couchbase_compiled_files':4,
        'files_commercially_cleared':0,
        'commercially_releasable_files':0,
        'buyer_package_manifest_verified':False,
        'full_source_distribution_allowed':False,
        'legal_rights_verified':False,
        'gold_admitted':0,
        'certification':'NOT_CERTIFIED',
        'limitations':'Exact Git object ID observation from public upstream is not proof of every legal obligation, dependency, inclusion in final buyer SKU, commercial rights or original oracle independence.',
    }


def main(argv=None)->int:
    p=argparse.ArgumentParser(description='Fail-closed Gitea original overlay rights inventory')
    p.add_argument('--manifest',type=Path,required=True)
    args=p.parse_args(argv)
    try:
        doc=json.loads(args.manifest.read_text(encoding='utf-8'))
        print(json.dumps(validate(doc),sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,json.JSONDecodeError,UnicodeError):
        print('{"status":"ORIGINAL_RIGHTS_NOT_VERIFIED","certification":"NOT_CERTIFIED"}')
        return 2


if __name__=='__main__':
    sys.exit(main())
