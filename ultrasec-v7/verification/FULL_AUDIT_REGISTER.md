# UltraSec V7 — Evidence-based audit register

This is an **evidence queue, not a certificate**. Only the public-reference security checks have recorded PASS evidence. The private corpus, answer keys, private executable fixes, external validation and commercial appraisal have **not** been inspected or certified here.

| Audit | Evidence required | Status | Evidence / blocker |
|---|---|---|---|
| Public repository security | SAST, secrets, CI logs on main | PASS | PUBLIC-REFERENCE SCOPE ONLY; 2026-10-13T19:51:00Z; commit:8d6e652e892d9beae325b9d94f7b257753d571f7; [7 policy gates](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/38457995722), [7 technical gates](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/38457995714), [Semgrep + CodeQL](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/38457995904) |
| Private corpus inventory | SHA-256 manifest, counts, provenance, chain of custody | BLOCKED | Owner-controlled private archive unavailable to this public review |
| Semantic uniqueness | Normalized + embedding near-duplicate report, threshold and manually reviewed sample | BLOCKED | Private records and adjudicated sample unavailable |
| 500 independent mechanisms | Taxonomy, causal graph, independent expert spot checks | BLOCKED | Mechanism-level independent review not supplied |
| Label correctness | Blind AppSec reviewer decisions, disagreement adjudication | BLOCKED | Blind expert labels and adjudication missing |
| Executable fixes | Reproduction and mitigation tests in isolated sandbox | BLOCKED | Private reproducible fixes and isolated test evidence missing |
| Private Semgrep / CodeQL | Per-record findings, false-positive/negative analysis, pinned versions | BLOCKED | Public verifier scanned; private corpus NOT scanned |
| Generalization / leakage | Family-separated holdout, contamination analysis | BLOCKED | Independent holdout and contamination report unavailable |
| Reproducibility | Signed manifest, environment lock, independent rerun | BLOCKED | Signed private artifacts and independent rerun unavailable |
| Licensing and data rights | Provenance and legal counsel review | BLOCKED | Counsel opinion and chain-of-title evidence unavailable |
| External security audit | Two named independent experts, signed reports | BLOCKED | Two independent signed AppSec reports missing |
| Commercial appraisal | Buyer diligence, comparable transactions, independent valuation | BLOCKED | Buyer-supported pricing and independent valuation missing |

## Acceptance criteria

- `PASS` is admissible only with a timestamp, immutable evidence revision/hash and a traceable URL; the gate verifies format and required fields, **not** that the external evidence is true.
- `BLOCKED` means insufficient evidence, not a failed security test. `FAIL` requires documented remediation and rerun.
- Green public CI validates the public Python reference checker and its tiny synthetic fixtures, **not** the 1,000,000-record proprietary corpus or any claimed commercial value.
- Recheck all applicable public security gates after each update. Never upgrade a private or independent gate by copying a public CI link.
- Do not upload proprietary examples, labels, exploit payloads, credentials, or signing keys to this public repository.
- Independent audit, licensing and market valuation require evidence from their respective qualified reviewers and cannot be self-certified by CI.
