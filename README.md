# UltraSec V7.0 — Public verification registry

[![Public Repository Policy — 7 checks](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/workflows/ultrasec-public-ci.yml/badge.svg)](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/workflows/ultrasec-public-ci.yml)
[![Technical Reference Gates — 7 checks](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/workflows/ultrasec-enterprise-public.yml/badge.svg)](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/workflows/ultrasec-enterprise-public.yml)

UltraSec V7.0 is a **proprietary security benchmark in development**. This public repository contains documentation and a small **non-proprietary reference validator**, not the protected training corpus, its answer keys, or the commercial engine.

## Reproducible GitHub Actions checks

| Workflow | Executable checks | Scope |
|---|---|---|
| [Public repository quality](.github/workflows/ultrasec-public-ci.yml) | 7 | Public files, credentials, proprietary notice, truthful metadata, provenance, links and CI hardening |
| [Technical reference quality](.github/workflows/ultrasec-enterprise-public.yml) | 7 | Abstract causal graphs, deterministic SHA-256, real unit/branch coverage, mutation regressions, adversarial contracts, self-review and 100 repetitions |

The technical checks use **24 publicly generated abstract vulnerable/mitigated pairs (48 graphs)** from six CWE families. The reference labels Python, JavaScript and Go for scenario coverage, but a Python interpreter runs the abstract graphs. **These are not 48 executable security bugs in three languages, nor do these checks certify the private million-record corpus.**

Local evidence before publication: **37 unit tests, 97% measured reference-validator coverage, 48/48 causal mutations killed, 101/101 adversarial cases detected/rejected, and 100/100 repeatable rebuild validations.** Live results must be read from GitHub Actions at the current HEAD; green badges apply only to the corresponding public-scoped tests.

Read the [exact scope and remaining certification requirements](ultrasec-v7/verification/QUALITY_GATE_SCOPE.md) and [rights notice](ultrasec-v7/LICENSE-PROPRIETARY.txt). See [UltraSec V7.0 documentation](ultrasec-v7/README.md).

## Independent validation still outstanding

- Genuine Semgrep and CodeQL benchmarking against the protected code and relevant models.
- Causal independence review, production-equivalent fix tests, and independent expert validation.
- External certification, data rights and a buyer-verified commercial valuation.

**Do not interpret green documentation/reference CI as an external certificate or as a guarantee of resale value.**

The proprietary corpus, executable core, reserved challenges, tokens and buyer deliverables are intentionally **not published**. The restricted license does not physically prevent download/cloning of public files.

## Enterprise quality screening (proposed)

A local [metadata-only enterprise screening tool](ultrasec-v7/tools/enterprise_metadata.py) and [buyer acceptance protocol](ultrasec-v7/verification/ENTERPRISE_ACCEPTANCE.md) define repeatable input integrity checks, project/mechanism split isolation and the evidence buyers need to evaluate commercial utility. The tool is executed privately against an **owner-supplied inventory**; only synthetic examples are tested by public CI. Passing metadata checks is **not proof** of a certified million-record product or commercial demand.
