# REA pilot — deliberately optional

Official upstream: https://github.com/morluto/rea

REA is an exploratory reverse-engineering aid, **not** an external
certifier, source-code license grant, causal oracle, or substitute for
original vulnerable/fixed tests.

The workflow is **manual and main-only**, never triggered by pull
requests or on private dataset changes. It runs REA against one tiny,
synthetic, non-vulnerable JavaScript module checked into this repository.
It uses no secrets, no third-party binaries and does not upload reports.
The workflow intentionally requires an explicit input
`PUBLIC_FIXTURE_ONLY`.

It pins `rea-agents@4.1.0` as a *pilot baseline*, not a guarantee
that this version is compatible with the current GitHub runner.
The real execution has not occurred until GitHub Actions supplies a
successful run receipt. If package installation or JSON output fails,
the job fails rather than producing a false positive.

After this pilot passes, propose a separate reviewed workflow for
*licensed* real targets with pinned upstream commits, checksums,
original RED/GREEN tests and provenance. Never upload a private
holdout or commercially restricted samples into public Actions.

For native/Android reverse engineering, REA additionally needs
appropriate providers such as JADX or Ghidra; this workflow tests
only the documented static JavaScript CLI.
