# UltraSec V7 — Evidence gates

Status: NOT CERTIFIED. No private corpus samples may be committed.

- Diversity: >200000 lexical patterns on authorized regenerated million records; 1M unique SHA-256 and zero split leakage. BLOCKED until measured.
- Causal: executable exploit and minimal fix, reject identifier-only and trivial unverified if-only changes. BLOCKED.
- Blinded independent review: 100 authorized real cases, 12 families, two independent AppSec reviewers, labels stored outside GitHub. BLOCKED.
- Agreement: strictly >80% of 100 independent comparable decisions, report Cohen kappa and adjudication separately. BLOCKED.
- Adversarial: run pinned CodeQL, Semgrep and Slither on supported cases; TP/FP/FN by CWE, absent-rule and unsupported-language accounting. BLOCKED.
- Commercial: written sale and derivative-rights authorization, defensible benchmark vs DiverseVul/PrimeVul. BLOCKED.
- PR #6: fix remaining Unicode normalization P2 findings and obtain completed Codex review before merging.
- PR #7: require 17/17 green on exact SHA, completed Codex, no unresolved findings.

USD150000 is an aspirational target, not a verified appraisal. The training-only 24-case sample is not an independent audit.
