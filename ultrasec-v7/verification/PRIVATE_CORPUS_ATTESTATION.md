# UltraSec V7 — Owner-only private corpus attestation

The public code at [private_corpus_attestation.py](../tools/private_corpus_attestation.py) reproduces structural and cryptographic checks **only on a machine controlled by the owner**. Public GitHub Actions runs this tool solely with synthetic records. Never publish protected source, gold labels, private manifests, credentials, or other owner-only records here.

## Command for an authorized historical archive

    python3 ultrasec-v7/tools/private_corpus_attestation.py \
      --archive /secure-owner-storage/master.zip \
      --member internal/path/master.jsonl.gz \
      --expected-sha256 SHA256_OF_DECOMPRESSED_JSONL_BYTES \
      --sealed-report /secure-owner-storage/owner-audit.json \
      --session-lock /secure-owner-storage/owner-audit.lock

Use the actual 64-character lowercase digest from an authenticated owner-controlled manifest, not the placeholder. Both output paths must be new files in owner-only protected storage. The tool never extracts archive entries, executes example code, posts over the network, prints individual records, or exposes model test labels. Its report uses mode 0600; stdout is a constant neutral receipt. Reusing the same session lock or report is rejected.

## What the audit actually validates

- Exact SHA-256 match for decompressed JSONL bytes and strict bounded JSONL syntax.
- Exact duplicate code hashes and record IDs.
- One vulnerable and one mitigated example per pair, with consistent family, language, template and split.
- Template overlap between train, validation and test.
- Aggregated number of records, pairs, template IDs, families, languages and split sizes.
- Aggregated counts of records whose claimed independent validation or rights clearance remain outstanding.

The expected historical V4-style keys are id, pair_id, template_id, code, label, language, family, split, independently_validated (boolean), license_clearance, verification_tier, label_provenance and origin. This scanner is tailored to that historical data contract and MUST NOT reinterpret V7.9 pilot samples as compatible million-record inventory entries.

## Memory and private scratch directory

The million-record run uses **temporary SQLite indexes on disk**, not a Python set containing all records. The indexes contain SHA-256 digests of identifiers and code plus pair/split status, not raw code or identifiers. SQLite files live inside an automatically created mode-0700 subdirectory alongside the sealed report and are deleted after the audit. The owner must put `--sealed-report` inside an access-controlled directory with sufficient free disk space; physical storage or backups can still retain deleted blocks, so confidential execution requires trusted storage and appropriate disk encryption. The code checks exact deduplication, not semantic independence.

Input errors such as excessive JSON nesting and problematic compressed archive entries are recorded as `input_parse_error` in the owner-only report rather than exposing stack traces.

## Limits

Owner integrity PASS means **only** syntax, pairing, exact duplication and supplied hash consistency. It does not validate semantic or causal independence, accuracy of fixes, security of code, provenance signatures, legal rights, external certifications or any market value. A million unique source strings is not a million independent vulnerabilities. External AppSec auditors and an independent commercial buyer are still necessary.

The archive and gold truth remain on secure owner infrastructure. Never route protected data through public GitHub, prompt logs, unapproved model endpoints or an unaudited web service. Buyer-facing disclosures should be restricted to approved aggregate attestations after evaluation closure.

See [enterprise acceptance](ENTERPRISE_ACCEPTANCE.md), the [US$150,000 target evidence gates](BUYER_VALUE_150K.md) and [blind AppSec rubric](BLIND_REVIEW_RUBRIC.md).
