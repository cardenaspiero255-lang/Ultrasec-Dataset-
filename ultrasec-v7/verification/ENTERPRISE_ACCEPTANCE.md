# UltraSec V7 — Enterprise buyer evaluation protocol (draft)

> **Status:** pre-commercial acceptance specification, not certification or a product price. The public GitHub repository has **24 synthetic graph pairs only**. No private records, proprietary labels, withheld challenges or customer assets belong here.

## Business problem and measurable value

| Buyer | Why they would use it | Evidence required before purchase |
|---|---|---|
| Application Security teams | Reduce triage workload and verify remediation quality | Blind precision, recall, false-positive rates, replayable fixes and analyst minutes per confirmed finding |
| SAST vendors | Regression-test detection rules and assess generalisation to unseen code | Per-CWE, per-language baseline comparison and sealed project-separated holdout |
| AI coding model providers | Evaluate whether generated fixes address the underlying vulnerability | Paired vulnerable/fixed examples with sandboxed test outcomes and independent label adjudication |
| Security engineering platforms | Audit changes between ruleset/model versions | Versioned corpus manifest, deterministic scorecards, leakage evidence, reproducible evaluation harness |

**Not established yet:** financial ROI, market demand, buyer willingness to pay, or any independently measured lift over baseline tools.

## Local metadata quality-screening contract (schema v1)

Every row of the **owner-controlled** inventory is a JSON object with **exactly** the following metadata fields. The actual vulnerable/fixed code, secrets, project source paths and proprietary explanations must be stored separately and **must not be placed in this manifest**.

| Field | Type and meaning |
|---|---|
| `schema_version` | Integer `1` |
| `record_id` | Opaque unique record identifier |
| `pair_id` | Opaque identifier shared by the vulnerable and fixed variants |
| `variant` | `vulnerable` or `fixed` |
| `cwe_id` | CWE identifier, such as `CWE-89` |
| `language` | Normalized language identifier, e.g. `python` |
| `mechanism_id` | Opaque claimed causal mechanism grouping, not proof of causal independence |
| `project_id` | Opaque grouping for split isolation, not a customer name |
| `split` | `train`, `validation` or `test` |
| `content_sha256` | Lowercase 64-character SHA-256 digest of the corresponding code artifact |
| `rights_status` | `cleared`, `pending`, or `restricted`; **self-declared until legal verification** |

The report rejects malformed schemas, duplicate record IDs, exact duplicate hashes, duplicate variants, incomplete pairs, inconsistent pair metadata, cross-split project/mechanism leakage, uncleared rights declarations and unmet inventory thresholds. The owner-only **sealed report** contains aggregate counts and standardized error codes, not IDs, hashes, code or input lines. The process stdout is deliberately a fixed, non-informative receipt. Memory usage is O(number of distinct records/projects/mechanisms); run million-scale inventories on adequate owner-controlled hardware.

Run on the owner's private workstation, isolated runner or controlled storage:

```bash
python3 ultrasec-v7/tools/enterprise_metadata.py \
  --input /secure-storage/inventory.jsonl \
  --minimum-records 1000000 \
  --minimum-mechanisms 500 \
  --sealed-report /secure-storage/screening-report.json \
  --session-lock /secure-storage/screening-session.lock
```

This is a **proposed acceptance target** corresponding to the project ambition, not a verified count or evidence that one million distinct useful cases exist. The command does not make a network request or copy input to GitHub. A `metadata_screening_pass` means **only that supplied metadata passed structural checks**; digests are not recomputed from code, no semantic near-duplicate search is performed, and self-declared rights or mechanism IDs are not independently verified. `certification` is **always `NOT_CERTIFIED`**.

## Owner-hosted blind binary benchmark scorecard

A second non-proprietary tool, [enterprise_scorecard.py](../tools/enterprise_scorecard.py), calculates **binary vulnerability detection** metrics against a gold holdout retained by the owner. The buyer/model only supplies predictions keyed by opaque record IDs, not the gold labels.

- Gold JSONL: exact fields `record_id` (opaque string), `split` (must be `test`) and `expected_vulnerable` (JSON boolean).
- Prediction JSONL: exact fields `record_id` and `predicted_vulnerable` (JSON boolean).
- Both files remain **local**; duplicate/missing/unknown predictions, non-test splits, one-class holdouts and invalid schemas fail closed.
- **Only the owner-held sealed report**, never vendor-facing stdout, contains TP, FP, TN, FN, precision, recall, F1, specificity, FPR, FNR and balanced accuracy. Revealing an exact confusion matrix even without IDs can reveal gold labels via a single-case probe. In the degenerate case with no positive predictions, precision is defined as zero.
- Ratios are compared to **buyer-negotiated** thresholds using full precision; the displayed scores are rounded to six decimals. No thresholds prove statistical significance.

```bash
python3 ultrasec-v7/tools/enterprise_scorecard.py \
  --gold /secure-storage/sealed-test-gold.jsonl \
  --predictions /secure-storage/vendor-predictions.jsonl \
  --min-recall 0.80 --max-fpr 0.05 \
  --sealed-report /secure-storage/buyer-scorecard.json \
  --session-lock /secure-storage/buyer-session.lock
```

The numerical thresholds above are **illustrative contract inputs**, not passed benchmarks or real measurements for UltraSec V7. Results remain `NOT_CERTIFIED` even when `buyer_thresholds_pass` is true. This version evaluates binary detection only; confidence intervals, fix-success metrics, blind custody and baseline comparisons require further evidence and work.

## Sealed one-shot benchmark protocol

- Execute the tools **only inside an owner-controlled security boundary**. The provider never receives the gold file, evaluator executable on the private runner, the private report, or the exit/error details of label-sensitive evaluation.
- A `--session-lock` is created exclusively (mode `0600`), and the private report is written exclusively (mode `0600`). Both paths **must be on protected local owner-controlled storage**. The lock is intentionally retained; a second invocation using the same lock fails, preventing accidental adaptive resubmission. Do not reset or rename a lock to give a provider more probing attempts. Filesystem permission controls, protected backups, and owner-side monitoring remain operational responsibilities; command-line locks alone do not prove strong anti-probing security.
- Standard output is always `{"status":"SEALED"}` on a recorded run, **regardless of candidate success/failure**. Exit code 0 means the sealed report was recorded, *not* that the model passed. Internal CI tests use fabricated labels only.
- The owner reads the report after **predictions are irrevocably committed** and the evaluation is closed. Any vendor-facing score release is a **separate, owner-approved action**, preferably signed aggregate attestation after blind holdout retirement, with rate-limiting, minimum cohort sizes and independent privacy assessment.
- For a same-holdout buyer comparison use [enterprise_comparison.py](../tools/enterprise_comparison.py):

```bash
python3 ultrasec-v7/tools/enterprise_comparison.py \
  --gold /secure-storage/sealed-test-gold.jsonl \
  --candidate /secure-storage/candidate.jsonl \
  --baseline /secure-storage/incumbent.jsonl \
  --min-recall 0.80 --max-fpr 0.05 \
  --min-recall-gain 0.05 --max-fpr-increase 0.00 \
  --sealed-report /secure-storage/comparison-report.json \
  --session-lock /secure-storage/comparison-session.lock
```

- JSONL ingestion fails closed on duplicate JSON keys and nonfinite values, in addition to schema errors. Criteria are retained in the private report even on parse errors. Required recall improvement cannot be negative. Neither report nor CLI guarantees private corpus integrity or independent certification.

## Release candidate: mandatory evidence before any "premium certified" claim

1. **Inventory and ownership:** count distinct usable primary records/pairs, publish an immutable signed manifest, provenance and chain of custody; counsel verifies redistribution rights and warranties.
2. **Semantic novelty:** exact hashes **and** normalized AST/token/embedding near-duplicate searches; human audit of borderline matches, with reproducible thresholds.
3. **Causal diversity:** independently adjudicated taxonomy of at least the **claimed** number of distinct mechanisms; distinguish rule variants from genuinely distinct mechanisms.
4. **Correctness of labels and fixes:** blind dual-AppSec review with disagreements resolved; compile/run every executable remediation test in a network-isolated sandbox with pinned toolchains.
5. **Split integrity:** split by repository and mechanism before tuning, seal test/holdout labels; prevent train/test collisions and model/data contamination.
6. **External baselines:** genuinely run pinned Semgrep and CodeQL against eligible **private code**, track their errors and analyst-reviewed FP/FN; do not substitute public verifier scans.
7. **Business evidence:** blind paid or NDA-controlled pilot with participating buyers measuring precision, recall, F1, specificity, false-positive rate, analyst time saved, and repeatability versus their incumbent workflow.
8. **Independent assurance and delivery:** two independent security auditors, access-control review, artifact signatures, contract/license and update/maintenance commitments before claiming formal external approval.

Record results **per language, CWE, mechanism family and project-held-out cohort** with confidence intervals and sample sizes. Bootstrap by repository (not by related vulnerable/fixed rows) to avoid overstating precision. Publish only cleared aggregate results. Each buyer sets explicit **pass/fail thresholds in advance** and keeps the gold set blind to the evaluated model/vendor.

## Safe evaluation exchange for buyers

- Provide a public datasheet and schema, a **small synthetic** fixture, exact version hash, threat model and an evaluation agreement.
- For due diligence, perform a buyer-observed or third-party escrow evaluation against **sealed private** material. Share de-identified aggregate scores and independently signed evidence only with authorization.
- Distinguish **screening pass** (input structure) from **functional benchmark pass** (real outcomes), **independent audit** (external review) and **commercial acceptance** (signed buyer agreement).
- Do not infer a USD sale price from the sample size or green CI. Enterprise pricing requires contractual scope, exclusivity, licensing rights, measurable value and actual comparable buyer bids.

## Evidence register

Track claim-by-claim source SHA, assessor, dated artifact hash, sample size and storage location in the [V7 full audit register](FULL_AUDIT_REGISTER.md). Private blockers remain blocked until evidence is independently available. Public CI gates verify **only code and synthetic scenarios in this repository**, never the proprietary dataset.

**Potential future deliverables (not in this PR):** secure blind-holdout scoring service, executable security harnesses, semantic-dedup pipelines, signed inventory manifests, independent expert review and commercial buyer pilots.

## Additional buyer proof artifacts

- [Blind same-holdout comparison](../tools/enterprise_comparison.py) calculates candidate and incumbent recall/FPR differences and refuses missing/mismatched predictions; it is **not** a measure of statistical significance or real-world ROI.
- [US$150k evidence gates](BUYER_VALUE_150K.md) define objective price/delivery conditions without claiming current valuation.
- [Prompt Engineer assisted blind AppSec review rubric](BLIND_REVIEW_RUBRIC.md) defines cautious annotation behavior and adversarial test cases; qualified independent human review remains mandatory.
