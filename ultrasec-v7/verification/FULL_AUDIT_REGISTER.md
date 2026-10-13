# UltraSec V7 — Evidence-based audit register

This document is a work queue, **not a certification**. No private corpus is present in this repository. All private analyses must be performed in owner-controlled storage.

| Audit | Evidence required | Status |
|---|---|---|
| Public repository security | SAST, secrets, CI logs on main | PASS (public scope only, 2026-10-13) |
| Private corpus inventory | SHA-256 manifest, counts, provenance, chain of custody | BLOCKED — private archive unavailable |
| Semantic uniqueness | Normalized + embedding near-duplicate report, threshold and manually reviewed sample | BLOCKED |
| 500 independent mechanisms | Taxonomy, causal graph, independent expert spot checks | BLOCKED |
| Label correctness | Blind AppSec reviewer decisions, disagreement adjudication | BLOCKED |
| Executable fixes | Reproduction and mitigation tests in isolated sandbox | BLOCKED |
| Private Semgrep / CodeQL | Per-record findings, false-positive/negative analysis, pinned versions | BLOCKED |
| Generalization / leakage | Family-separated holdout, contamination analysis | BLOCKED |
| Reproducibility | Signed manifest, environment lock, independent rerun | BLOCKED |
| Licensing and data rights | Provenance and legal counsel review | BLOCKED |
| External security audit | Two named independent experts, signed reports | BLOCKED |
| Commercial appraisal | Buyer diligence, comparable transactions, independent valuation | BLOCKED |

## Acceptance criteria

- A PASS requires timestamped, reproducible evidence linked to an immutable artifact hash.
- A FAIL requires a documented remediation and rerun; missing evidence is BLOCKED, never PASS.
- Do not upload proprietary records, answer keys, credentials, or exploit payloads to the public repository.
- Independent audit and market valuation cannot be self-certified by a CI workflow.
- Recheck the public security gates after every change. Do not claim a certified million-record corpus until every mandatory private/external gate is independently verified.
