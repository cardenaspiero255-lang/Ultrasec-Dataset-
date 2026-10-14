# UltraSec V7 — Enterprise evidence dossier, target US$150,000

**Status: NOT CERTIFIED; BUYER VALUATION NOT VERIFIED.** This is not a paid offer, rights warranty or comparative study.

## Verified internal baseline

| Evidence | Verified finding | Limit |
|---|---|---|
| Historical V4 private inventory | 1,000,000 distinct IDs and SHA-256 hashes, 500,000 complete pairs, 0 exact duplicates | Syntactic only, not functional security proofs |
| Historical lexical screen | 5,760 template IDs and 11,280 coarse lexical patterns; 98.872% of records fall in a previously observed lexical bucket | Not proof of semantic duplication or independence |
| Private V7.3 ZIP | 5,000 lab pairs in C, Java, Go, Rust and Solidity | The manifest explicitly says SYNTHETIC_UNCERTIFIED |
| Independent labels | 0 records certified by outside security reviewers | 100 externally sourced cases still unavailable |
| Commercial rights | Owner's declared rights for historical source require legal clearance | Cannot sell as cleared |
| V7.9 pilot | No independently verified improvement over its baseline | Commercial superiority not demonstrated |

Do not sum counts across unrelated historical releases or represent self-labelled synthetic cases as real-world vulnerabilities.

## Research comparison

| Criterion | DiverseVul (RAID 2023) | PrimeVul (ICSE 2025) | UltraSec |
|---|---|---|---|
| Source | 7,514 security fix commits, 18,945 vulnerable functions and 330,492 benign functions across 150 CWEs | About 7k vulnerable / 229k benign real-world C/C++ functions, 140+ CWEs | Large synthetic corpus, no certified source-level real-world verification |
| Labels | Real security-fix commits with known noise concerns | Label quality methods documented, paired samples | Generator-intent labels, 0 independent adjudication |
| Evaluation | Authors report low F1 and false positives for some ML approaches | Chronological/deduplicated splits, VD-Score tradeoffs | Local structural and lexical audits; independent comparative lift pending |
| Verified superiority | Not applicable | Not applicable | **NOT DEMONSTRATED** |

Primary research: https://github.com/wagner-group/diversevul ; https://arxiv.org/abs/2304.00409 ; https://github.com/DLVulDet/PrimeVul ; https://arxiv.org/abs/2403.18624 . These datasets have different language, split and task distributions. Scores from different papers must not be treated as head-to-head measurements.

## Release and sale acceptance gates

1. **Diversity:** on a regenerated private corpus, >200,000 lexical patterns measured, 1M exact SHA-256 unique, zero project/mechanism holdout cross-contamination. Separately demonstrate real distinct causal mechanisms and executable patch effects.
2. **Real-world 100:** 100 externally sourced real vulnerability/patch cases across 12 validated families, with independently verified source/fix commit, reproducible code, distribution rights, and sealed holdout.
3. **Human AppSec:** two qualified independent reviewers give blinded ratings; agreement strictly >80%, Cohen kappa and unresolved disagreements disclosed, signed attestations verified outside GitHub.
4. **Causal proof:** exact vulnerable reproduction and fixed mitigation, minimal patch with nontrivial semantic change, negative controls for renames/cosmetic guard insertions.
5. **Static tools:** actually run pinned CodeQL and Semgrep on compatible cases; Slither only on Solidity/Vyper. Report TP/FP/FN/TN, applicability, missing detector coverage and tool errors per CWE. A recall below 20% is not success; a missing rule is not evidence of safety.
6. **Commercial:** legal provenance, warranties, permitted license scope and one or more written, comparable enterprise offers (price target US$150,000).
7. **GitHub:** exactly 17/17 green checks on the target SHA, zero confirmed Codex findings and no private corpus in public history.

The conservative release gate *always* keeps certification and US$150,000 valuation unverified. Even self-reported success metadata is not signed proof.

## Local tools, limitations and privacy

- premium_evidence.py rejects labelled synthetic cases in the 100-case real-world admission screen; individual source and rights claims still need independent validation.
- blind_appsec.py creates separate private reviewer and owner-key ZIPs and computes observed agreement, Cohen kappa and adjudication count from **real human responses**. Synthetic CI fixtures merely test its arithmetic.
- adversarial_sast.py scores supplied scanner outcomes by tool/CWE; it **does not run** CodeQL, Semgrep or Slither itself or authenticate outputs. Keep execution logs and rule identifiers in owner-only custody.
- semantic_mutations.py implements four controlled Python AST operators (control flow, data flow, sanitizer ordering, boundary conditions), returning **unvalidated candidates**. It does not regenerate one million rows or establish semantic novelty.
- premium_release_gate.py refuses buyer-readiness claims without independent evidence and never automatically values the product.

**The 100 real-world cases, >200k measured private patterns, human agreement >80%, scanner execution on those cases and a USD150k offer are all outstanding.** Do not substitute 100 V7.3 synthetic training cases or fabricated human reports.
