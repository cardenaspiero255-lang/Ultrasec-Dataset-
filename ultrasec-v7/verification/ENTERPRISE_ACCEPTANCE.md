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
| \`schema_version\` | Integer \`1\` |
| \`record_id\` | Opaque unique record identifier |
| \`pair_id\` | Opaque identifier shared by the vulnerable and fixed variants |
| \`variant\` | \`vulnerable\` or \`fixed\` |
| \`cwe_id\` | CWE identifier, such as \`CWE-89\` |
| \`language\` | Normalized language identifier, e.g. \`python\` |
| \`mechanism_id\` | Opaque claimed causal mechanism grouping, not proof of causal independence |
| \`project_id\` | Opaque grouping for split isolation, not a customer name |
| \`split\` | \`train\`, \`validation\` or \`test\` |
| \`content_sha256\` | Lowercase 64-character SHA-256 digest of the corresponding code artifact |
| \`rights_status\` | \`cleared\`, \`pending\`, or \`restricted\`; **self-declared until legal verification** |

The report rejects malformed schemas, duplicate record IDs, exact duplicate hashes, duplicate variants, incomplete pairs, inconsistent pair metadata, cross-split project/mechanism leakage, uncleared rights declarations and unmet inventory thresholds. It prints **only aggregate counts and standardized error codes**, not IDs, hashes, code or input lines. Memory usage is O(number of distinct records/projects/mechanisms); run million-scale inventories on adequate owner-controlled hardware.

Run on the owner's private workstation, isolated runner or controlled storage:

\`\`\`bash
python3 ultrasec-v7/tools/enterprise_metadata.py \
  --input /secure-storage/inventory.jsonl \
  --minimum-records 1000000 \
  --minimum-mechanisms 500 \
  > /secure-storage/screening-report.json
\`\`\`

This is a **proposed acceptance target** corresponding to the project ambition, not a verified count or evidence that one million distinct useful cases exist. The command does not make a network request or copy input to GitHub. A \`metadata_screening_pass\` means **only that supplied metadata passed structural checks**; digests are not recomputed from code, no semantic near-duplicate search is performed, and self-declared rights or mechanism IDs are not independently verified. \`certification\` is **always \`NOT_CERTIFIED\`**.

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
