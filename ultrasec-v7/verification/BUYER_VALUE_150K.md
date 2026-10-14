# UltraSec V7 — Buyer diligence and US$150,000 evidence gates

**Status: TARGET ONLY. Market valuation and buyer willingness to pay are NOT VERIFIED.** This is an evidence-led checklist, not a $150,000 quote, guarantee, sales contract, or external certification. It is intentionally not tied to GitHub CI success.

## Buyer-specific product definition (must be signed before price comparison)

Record whether US$150,000 refers to an exclusive asset purchase, a perpetual non-exclusive license, a 12-month subscription, custom benchmark work, or a bundle with updates and support. Price comparisons are meaningless until term, usage rights, languages, customer count, redistribution permissions, geographic scope, warranties, liabilities and maintenance obligations are fixed.

## Non-negotiable acceptance gates

| Gate | Required objective evidence | Current standing |
|---|---|---|
| Corpus existence and reproducibility | Owner-hosted material inventory, signed content manifest, independently repeatable SHA-256 of available **actual** samples | **NOT VERIFIED** |
| Quantity & semantic novelty | Count of **independent, usable** primary records, semantic near-dedup protocol and reviewed borderline cases; report actual counts, not the historical target | **NOT VERIFIED** |
| Security realism | Reproducible vulnerable/fixed behaviors on pinned toolchains, masked credentials and network-isolated sandbox | **NOT VERIFIED** |
| Causal diversity | Independent adjudication of root mechanisms, not merely labels or variants; count only confirmed independent mechanisms | **NOT VERIFIED** |
| Generalization | Project/mechanism-grouped splits, sealed holdout with no train contamination; auditor verifies split custody | **NOT VERIFIED** |
| Objective accuracy | Blind same-holdout precision, recall, FPR, F1 and exact acceptance thresholds, plus uncertainty estimates with appropriate grouping | **NOT VERIFIED** |
| Incumbent performance | Evaluated baseline (e.g. Semgrep/CodeQL, when appropriate) with pinned versions, identical projects and gold labels; exact comparative deltas | **NOT VERIFIED** |
| Rights and privacy | Independent legal review of source provenance, training and resale rights, jurisdictional restrictions and confidentiality | **NOT VERIFIED** |
| Independent reviewers | Two named AppSec professionals, signed blinded reports, disagreements resolved and conflict-of-interest disclosures | **NOT VERIFIED** |
| Buyer validation | At least one identified qualified enterprise prospect, real use case, reproducible NDA pilot, signed acceptance and explicit procurement authority | **NOT VERIFIED** |
| Value of US$150k | Signed paid purchase/license for the exact rights offered, or multiple independent written indicative bids in a comparable scope (not AI-generated estimates) | **NOT VERIFIED** |

A paid contract for US$150,000 establishes an observed deal price for **those particular licensed rights**; it does not necessarily prove the resale value of other rights or the entire corpus. An LOI or verbal interest is not a sale. Confirm received funds and license terms before describing a sale as completed.

## Buyer pilot: preregistered evaluation agreement

Before showing the blind holdout, the parties record: intended programming languages/CWEs, project grouping, sample size, immutable benchmark revision, permitted tools, runtime/budget, candidate and baseline versions, treatment of abstentions and timeouts, allowed tuning, **exact** min recall / max FPR / required improvement and analysis method. Holdout IDs, answers and source content remain within an owner-approved and independently controlled environment. Raw records may not be copied into public GitHub, prompt logs or unapproved LLM endpoints.

The local utilities `enterprise_metadata.py`, `enterprise_scorecard.py`, and `enterprise_comparison.py` calculate **structural screening or detection statistics only**; they do not check runnable fixes, semantic novelty, chain of title, confidence intervals, or willingness to pay. Use external human reviews and real code-execution evidence for those separate gates.

### Illustrative savings model — not a valuation

Buyers should supply measured annual findings, fraction of false positives reduced, actual analyst minutes per finding, fully loaded hourly cost, retest time, integration/support cost and confidence intervals. Annual value can be approximated as:

`avoided triage cost = yearly avoided false-positive investigations × measured analyst hours per investigation × fully loaded hourly rate`

This excludes unsupported assumptions that catching a vulnerability necessarily avoids an incident. Estimate net savings over the *specified license period* and compare with the total deal price, opportunity cost, exclusivity and ongoing support. Do **not** invent these inputs or translate test accuracy directly into money.

## Evaluation protocol for AI-based reviewers

Use [BLIND_REVIEW_RUBRIC.md](BLIND_REVIEW_RUBRIC.md) to normalize a supervised review prompt, evaluate it against adversarial inputs and audit calibration. Model judgments are assistive hypotheses; security label authority rests with qualified independent human adjudicators and reproducible tests.

## Reference methodology

OWASP Benchmark uses blinded true/false cases and compares true-positive with false-positive rates; see https://owasp.github.io/www-project-benchmark/ . NIST cautions that benchmark estimates and generalization claims have different assumptions and uncertainty requirements: https://www.nist.gov/publications/expanding-ai-evaluation-toolbox-statistical-models .

**Commercial status:** Until the listed evidence exists, describe UltraSec V7 as an **in-development security dataset and benchmark with a target enterprise offer of US$150,000**, never as a product already valued at or certified for that amount.
