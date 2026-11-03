# UltraSec V8.1 — Prospective A/B preregistration

**Status:** PROTOCOL COMMITTED; MODEL FREEZE INCOMPLETE; ZERO NEW CASES AND GOLD LABELS.

This is a public research protocol, NOT a corpus distribution or a certified benchmark. It contains no protected records, hidden labels, model weights, access keys or owner files.

## Private data snapshot commitment

The owner measured SHA-256 over the exact original JSONL lines of the V8.0 `train` and `validation` splits. Owner-only audit receipt SHA-256:

`3b21f84770a8d6d419121ca734fb82843301bc66ec06a7168a3f9d7617e4b078`

The receipt remains private. This identifies a dataset snapshot, NOT two model checkpoints. It does not establish licensing rights or make the old synthetic test split independent.

## Strict order of operations

1. Commit this protocol before recruiting any prospectively new cases.
2. Hold architecture, preprocessing, tokenizer, training code, base training data, hyperparameters, seeds and **training tokens/steps** constant between model A (baseline corpus) and model B (same baseline plus UltraSec `train` only). The training recipe must specify sampling and effective mixes; report fixed-compute and optionally fixed-data comparisons separately.
3. Freeze, hash and verify both actual model checkpoints, training recipes, tokenizer and code commits before enrolling new cases. Record independently verifiable time/provenance. A JSON boolean is insufficient verification.
4. Acquire authorized new Python/JavaScript cases only after freeze. Obtain permission for inspection, testing, evaluation and any proposed redistribution separately. Previously public CVEs remain NONBLIND research even when source projects differ.
5. For each case, record exact vulnerable/fixed source revisions, native RED/GREEN, benign behavior, CWE, source/sink trace, license, provenance and deduplication against all 1M historical entries and known research cases. No model may observe reserved labels.
6. Require two independent human AppSec judgments plus external identity and signature verification. Resolve disputes separately. No self-attested reviewer IDs or metadata boolean automatically grants gold status.
7. Run A and B once on identical sealed opaque IDs, with no post-enrollment tuning. Preserve errors, missing predictions, negative results and exclusions.

## Prospective study design (target, not current data)

Aim for 30–50 vulnerable/fixed pairs from >=8 unrelated real Python/JavaScript projects with several CWE families. Report any shortfall explicitly. Do not combine public CVEs with the truly prospectively blind primary result.

**Primary endpoint:** paired improvement in **balanced accuracy** (B minus A) on the frozen holdout. Secondary: recall, false-positive rate, F1, per-project/CWE performance, runtime and compute. Use project-level cluster bootstrap, fixed seed `1781`, 2,000 repetitions, and a 95% percentile interval. Report paired disagreement counts and the interval even if improvement is negative or uncertain. Point-estimate improvement is not proof of generalization or commercial value.

Do not claim a 30–50-case cohort has statistical power for a universal generalization claim; uncertainty and limited project diversity must be explicitly discussed.

## Current gates

- Data snapshot fingerprint: COMPUTED; owner-only SHA receipt retained.
- Both model checkpoints and training recipes: **NOT FROZEN**.
- Authorized post-freeze cases: **0**.
- Independently adjudicated gold cases: **0**.
- Blind scoring or commercial release: **BLOCKED**.
- Legal title and redistribution rights: **NOT CLEARED**.
- Buyer-validated US$30,000 non-exclusive license: **NOT DEMONSTRATED**.

Public scripts/test fixtures may exercise metadata rules; such tests do not create human judgments, establish consent or constitute a benchmark.