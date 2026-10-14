# UltraSec V7 — Local lexical diversity screening

This is a **heuristic novelty check**, not semantic deduplication, vulnerability certification or independent AppSec validation. It is designed to help the corpus owner detect **potential** redundancy without exposing protected code or training labels.

## Authorized owner-side workflow

Use a trusted manifest SHA-256 computed over the fully **decompressed JSONL stream**. Archive paths and report destination must remain inside an access-controlled owner environment.

    python3 ultrasec-v7/tools/private_lexical_novelty.py \
      --archive /secure-owner-storage/master.zip \
      --member owner/v3/data/ultrasec_v3_1m.jsonl.gz \
      --expected-sha256 SHA256_OF_DECOMPRESSED_JSONL \
      --minimum-lexical-unique-fraction 0.01 \
      --sealed-report /secure-owner-storage/lexical-audit.json \
      --session-lock /secure-owner-storage/lexical-audit.lock

The 0.01 threshold is **illustrative only**, not a product certification standard. The private report includes the exact threshold and raw exact-code, lexical-form and collision counts. A passing threshold means only that the specified fraction of lexical fingerprints is distinct. It does **not** imply one million independent vulnerabilities, correct exploit labels, usable training examples, or a commercial price.

The process prints only a neutral receipt, even if the candidate dataset fails the threshold. Only the owner may inspect the 0600 private report after the controlled evaluation has ended. Session locks prevent accidental reruns with the same lock. Keep the report, archive and temporary SQLite indexing on trusted private storage with adequate disk space.

## Screening method and strict limits

- Raw-code uniqueness is measured by SHA-256 of each code text.
- Lexical fingerprints replace identifier-like tokens with ID, numbers with NUM and compact whitespace. The fingerprint intentionally discards many semantically meaningful distinctions. **Different programs can have the same fingerprint.**
- The fingerprint is **language-agnostic**; do not describe the number of fingerprints as independent semantic mechanisms, AST classes or a deduplicated SKU.
- The tool uses SQLite temporary indices storing SHA-256 digests of strings and deletes them at the end. CI tests with synthetic code only, never the proprietary corpus.
- Input ZIP/JSONL/JSONL.gz parsing and exception sealing are shared with the existing private corpus attestation utility. Any invalid input, digest mismatch, or unmet target must fail closed.
- No individual record, source text, label, pair identifier or fingerprint is printed or returned in the report.

## Next steps for market-grade validation

1. Build separate Python AST and JavaScript parser-backed fingerprints with pinned parser versions, documenting unsupported syntax.
2. Evaluate AST-level near-duplicate candidates by multiple similarity thresholds; quantify false merges on independent human-adjudicated pairs.
3. Perform blinded AppSec correctness review of representative hard cases, including executable mitigations in an isolated sandbox.
4. Compare real baseline Semgrep and CodeQL results on eligible code with immutable versions and held-out projects, retaining false-positive/negative evidence.
5. Obtain legal clearance, audit attestations and buyer-defined economic benefits before claiming any target price.

Cross-reference [private corpus attestation](PRIVATE_CORPUS_ATTESTATION.md) and [enterprise buyer acceptance](ENTERPRISE_ACCEPTANCE.md).
