# UltraSec V7 — evidence-first commercial assurance (2026-10-20)

**Scope:** public metadata and test infrastructure only; NOT a certified dataset.

## Policy

No two-expert external review is required for *internal technical work*.
The review remains **DEFERRED** and must never be represented as completed.
This change does not alter `release-status.json`, private corpus custody,
external audit requirements, or the legal rights of third-party authors.

The public index `COMMERCIAL_EVIDENCE_INDEX.json` tracks six mandatory
evidence categories, all initially `NOT_VERIFIED`:

| ID | Proof needed for a future private/commercial edition |
| --- | --- |
| corpus_inventory | Authenticated inventory and independently recomputed hashes of actual bytes |
| source_reproduction | Pinned upstream vulnerable/fixed builds, same test oracle, real logs |
| causal_labels | Root-cause adjudication, CWE/commit mapping, unrelated negative controls |
| split_integrity | Private grouped train/test split, semantic leakage audit, sealed holdout |
| sast_blind | Semgrep/CodeQL on eligible gold cases, FP/FN/recall by CWE |
| distribution_rights | File-by-file license and NOTICE obligations for exact deliverable |

The verifier checks *pointer structure and SHA-256 consistency only*. A `PASS`
record requires a referenced **public**, local regular file with the claimed
digest. Its `source_kind: claimed` explicitly prevents treating the contents
as independent verification. Even when all six references validate,
`certification=NOT_CERTIFIED` and
`commercial_distribution=NOT_VERIFIED` remain unchanged. Such an index
must not be used as a legal clearance, ISO certificate or gold label.

## Run

```bash
python3 -m unittest discover -s ultrasec-v7/tests -p test_v7_evidence_release_gate.py -v
python3 ultrasec-v7/tools/v7_evidence_release_gate.py \
  --manifest ultrasec-v7/verification/COMMERCIAL_EVIDENCE_INDEX.json \
  --root . --expect-blocked
```

On malformed index, duplicate JSON keys, missing control, unsupported PASS,
symlink, path traversal, digest mismatch or >2 MiB public evidence file,
the checker exits non-zero. The public manifest is intentionally blocked.
Never add private corpus, vulnerable code samples or sealed gold labels
to this repository just to turn a badge green.

## Available standards — not certificates

- **ISO/IEC 5259-2:** candidate data-quality measures (no ISO certificate).
- **SPDX:** candidate component/rights inventory; tags do not grant rights.
- **Croissant:** planned metadata interoperability; not yet schema validated.
- **SLSA/Sigstore:** optional provenance of a *public status bundle*; does
  not prove vulnerability correctness, independence or licensing.
- **NIST SSDF / OpenSSF Scorecard:** process and repo controls, not
  external security validation of the private dataset.

## Provenance release (optional; not executed by adding the workflow)

After a reviewed merge to `main`, a maintainer may run the separate
`V7 Public Evidence Status Attestation` workflow manually. It signs a
status-only bundle containing the public index and aggregate report.
No private data are uploaded and no commercial release is authorized.

An eventual consumer with the *exact downloaded status bundle* can verify:

```bash
gh attestation verify ultrasec-v7-public-evidence-status.tar.gz \
  --repo cardenaspiero255-lang/Ultrasec-Dataset- \
  --signer-workflow cardenaspiero255-lang/Ultrasec-Dataset-/.github/workflows/v7-public-evidence-attestation.yml
```

The workflow is proposed, not executed or an attestation already issued.
See https://docs.github.com/en/actions/concepts/security/artifact-attestations
for GitHub's explicit provenance/security distinctions.

## Next work after this foundation

1. Close legal rights per deliverable and do not republish uncertain upstream code.
2. Prove first independent gold cases; benchmark only on eligible sealed data.
3. Build SPDX license inventory and Croissant representation from *validated*
   content with schema/rights tests. No synthetic CI fixture counts as gold.
4. Plan a buyer pilot and scoped claims. External certification stays unclaimed.
