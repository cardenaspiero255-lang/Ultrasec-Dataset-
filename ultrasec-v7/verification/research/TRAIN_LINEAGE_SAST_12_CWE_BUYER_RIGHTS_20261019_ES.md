# UltraSec V7 — TRAIN lineage, exploratory 12-CWE rules, and buyer rights (19 Oct 2026)

**Status: TECHNICAL RESEARCH ONLY. GOLD=0. NO full TRAIN attestation, NO unseen HOLDOUT, NO blind benchmark, NO commercial release.** Never convert synthetic detections or known CVE research into admitted gold. Two-human AppSec review remains explicitly DEFERRED.

## A. Full TRAIN inventory: real-source search and new private reconciliation gate

A non-content-leaking file-discovery investigation covered:
- GitHub `Ultrasec-Dataset-` PR #10 source tree: public CI and candidate research, not a real complete `train_metadata.jsonl` or `training_runs.json`;
- owner Library: 37 privately retained `NOT_ADMITTED` CVE candidates and an older 35-row file, **all 35 contained in the 37**, not a separate corpus;
- connected Drive folder `UltraSec Enterprise 1M V4`, including existing private research subfolders: documents and audit packets, **no complete training-lineage export located**.

This is a search coverage statement, not proof that no training logs exist elsewhere. **No sampled CVEs were promoted into TRAIN or HOLDOUT** to fill a numeric target.

**Implemented** `tools/training_lineage_gate.py` plus `tests/test_training_lineage_gate.py` (nine synthetic regressions). Each owner-private model training execution must provide: SHA-256 of trainer source, SHA-256 of its authentic log, a timestamp, exact input row fingerprints, its output model checkpoint digest and its parent checkpoint digest. The gate follows the entire claimed model ancestry from its first training run (parent=null) through every subsequent run to the final checkpoint, and reconciles the union of every `consumed_case_fingerprints` against the training inventory exported by the owner. It rejects missing ancestors, omitted records, extra records, duplicate original code pairs, repeated IDs, forged parent checkpoint references, and any self-asserted independently verified status.

Example **owner-private** command when authentic files actually exist (never run on a public fixture to claim completion):

```bash
chmod 600 /private/train_metadata.jsonl /private/training_runs.json
python3 ultrasec-v7/tools/training_lineage_gate.py \
  --train /private/train_metadata.jsonl \
  --training-runs /private/training_runs.json \
  --private-receipt /private/new-training-reconciliation.json \
  --minimum-train 100
```

The JSONL rows use the exact existing `private_training_disjointness.py` train schema. The private lineage JSON schema `ultrasec.owner-training-lineage.v1` requires `scope=OWNER_PRIVATE_RUN_RECEIPTS_ONLY`, `independent_authenticity_verified=false`, `final_checkpoint_sha256`, ordered `runs` with `run_id,parent_checkpoint_sha256,checkpoint_sha256,trainer_source_sha256,run_log_sha256,completed_at_utc,consumed_case_fingerprints`. Each consumed fingerprint derives from SHA-256 of the canonical relevant row fields (see `training_lineage_gate.fingerprint`). The receipt is written without overwrite under mode `0600`, with only aggregate counts emitted on stdout.

**Limit:** even a structurally passing run cannot independently authenticate its *self-provided* original logs or guarantee that all previous training datasets/checkpoints were disclosed. `complete_training_history_externally_attested=false` and `holdout_admission_allowed=false` remain hard-coded. External provenance/archival review is mandatory before treating future TEST as genuinely unknown.

## B. SAST V3 — 12 separate pinned syntax-risk indicators, NOT complete CWE coverage

Original V1 preholdout freeze remains intact; V2 preserves **70 distinct public historical CVE exclusions**; all 37 privately known older candidates are checked only in the owner-local separation gate (107 CVE references in union).

The **V3** manifest `FUTURE_UNSEEN_SAST_BYTE_FREEZE_PLAN_V3.json` adds exactly one separately pinned Semgrep research rule for each of 11 CWE missing from the original CWE-94 baseline, preserving the two original CWE-94 syntactic patterns. Categories/languages:

| CWE | Semgrep research scope | Proven limitation |
| --- | --- | --- |
| 22 | Python `open(os.path.join(...))` | Need attacker-control/path traversal proof |
| 78 | Python `os.system` | Shell use alone is not command injection |
| 79 | JavaScript `document.write` | Sink may receive trusted HTML |
| 89 | Python SQL concatenation passed to `.execute` | Must confirm query input provenance |
| 94 | Original two Python `exec` / `eval` patterns | Only syntactic indicators |
| 120 | C `strcpy` | Destination may be sized adequately |
| 125 | C `memcpy(... sizeof(destination))` | Neither source bound nor exploit guaranteed |
| 352 | Django `@csrf_exempt` | May have compensating controls |
| 416 | C `free(ptr)` followed by `ptr->field = ...` | Lexical sequence; aliasing/paths need dataflow |
| 434 | PHP `move_uploaded_file` | File-type/destination validation can be elsewhere |
| 787 | C `sprintf` | Destination capacity and reachability unknown |
| 862 | DRF `@permission_classes([AllowAny])` | Endpoint sensitivity and alternate guards unknown |

A **real Semgrep CLI 1.180.0 run** [GitHub Actions #39347208809](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39347208809) exercised the 11 new rule files against exactly 11 synthetic positives and 11 synthetic negatives: **11/11 positives detected, 0/11 negative alerts**, and original V1 CWE94 smoke **2/2**. Digest of committed V3 plan/rules: `cce08b49852d8fe266f662b0c9c55e6f9c40585f27f3d07d02f9b2c84269d73c`. The task separately checked V3 rule byte integrity, one CWE per rule file, 12 exact pinned target classes and all 63/63 public CVE exclusions. The V3 artifact uses only synthetic receipts, **never TRAIN/TEST original snippets**.

Public CodeQL and Semgrep security workflows still examine validator code. Intentionally vulnerable synthetic fixture files are explicitly excluded from the **public verifier's security check** via `.github/codeql/ultrasec-public-scope.yml` and the corresponding Semgrep `--exclude` clause. They **are** scanned by the dedicated synthetic SAST smoke: this is a scope distinction, not hiding production flaws.

**What remains unverified:** runtime detection over independently verified true vulnerabilities, negative controls in original upstream trees, multi-language applicability, security-rule tuning after freeze, code/data-flow analyses and full frozen CodeQL query packs. An arbitrary syntax-risk indicator *does not* establish 12-CWE coverage or 95% precision/recall, and using these known public fixtures to tune future rules invalidates chronological blindness if treated as unseen data. No blind scoring has been run.

## C. Buyer-deliverable rights: original-file gates combined, NO clearance

The [nine-file exact original Gitea research overlay](GITEA_NINE_FILE_SOURCE_RIGHTS_MANIFEST_20261019.json) has been traced to upstream Git blob IDs in vulnerable/fixed commits and checked against the root MIT license and five SPDX MIT Go headers. The template has no own SPDX header. `go.mod`/`go.sum` are dependency manifests, not grants covering their transitive source.

`tools/buyer_release_gate.py` and `tests/test_buyer_release_gate.py` combine original-file checks with the exact **four Couchbase/goutils@v0.3.0 files** and the five planned real-world source-pair origin candidates. A passing structural scope check still reports `commercially_releaseable_pairs=0`, `ready_to_sell=false`, `NOT_CERTIFIED`; adding upstream code to the proposed payload or inventing permission turns the screen into a hard failure.

The nine-file Gitea overlay does **not** itself contain Couchbase original Go source; a compiled buyer bundle linking the 4 BSL-referencing source files is **a distinct release scope**. The 16 Go license exceptions include MPL, BSD, public-domain claims and BSL, and none may be collectively swept into the root MIT. Commercial MIT-licensed upstream redistribution ordinarily requires preserving copyright and license notice from its own source; no final buyer package has been built or audited.

Couchbase's own [public explanation of BSL 1.1](https://www.couchbase.com/blog/couchbase-adopts-bsl-license/) describes restrictions on commercial source derivatives/inclusion and future relicense dates. **It is general background, not a binding interpretation of this specific module.** `github.com/couchbase/goutils@v0.3.0` contains original file headers referring to `BSL-Couchbase.txt`, which itself describes `Licensed Work: Couchbase Server Version 8.0`, with a published change date of 2029-03-01. The extent to which that document governs the independently tagged goutils files remains legally ambiguous; **no formal holder clarification or specific commercial license was obtained**. Contact/authorization questions are recorded in [the file-by-file BSL clearance packet](COUCHBASE_BSL_FILE_SCOPE_CLEARANCE_PACKET_20261019_ES.md).

The preferred premium SKU is `minimal_reproducible_source_pairs`. No buyer inventory, original-source inclusion list, per-file NOTICE compliance packet, signed rights or commercial release have been certified. The optional `metadata_only` variant is a different SKU and cannot be mistaken for clearance of original vulnerable/fixed code pairs.

## Next material actions, in order

1. Locate authentic owner training-data consumption logs and model checkpoint ancestry, export **all** consumed records, including synthetic/public/earlier training cases; run the private `training_lineage_gate`. Authenticate original source logs and model history separately.
2. Before a genuinely unseen TEST is selected, obtain an independent chronological freeze of full relevant Semgrep **plus applicable CodeQL** query versions; upgrade exploratory indicators through evaluations on **known training/reference** sources *only*, without exposing future TEST or treating trained-on samples as blind.
3. Secure an owner-controlled complete TRAIN/TEST separation (>=100 TRAIN and >=100 TEST; 12 pinned CWE in TEST with both signs), exclude 107 already studied CVE and detect semantic clones. Obtain reproductions from original upstream oracles for every admitted case before metric publication.
4. Freeze the **actual buyer-source inventory**, not just 9 Gitea references, preserve notices and determine which compilations contain BSL/Couchbase. Ask the licensor for written clarification or exclude affected source/binary bytes entirely. Complete other original project license obligations.
5. Revalidate each HEAD's complete 18-workflow Actions plus individual required checks, maintain PR #7/#10 Draft while gates are open, and do not mark V7 certified.

**No hidden success claims:** `GOLD=0`, `TRAIN_FULL=NOT_OBTAINED`, `BLIND_SAST=NOT_RUN`, `RIGHTS=NOT_VERIFIED`, `COMMERCIAL_PRODUCT=BLOCKED`, `NOT_CERTIFIED`.
