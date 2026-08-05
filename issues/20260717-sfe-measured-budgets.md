# Measured size/startup claims against precommitted budgets

**Status:** Open — blocked on accepted numeric budgets and final measurements
**Impact:** 3
**Urgency:** 3
**Ease:** 4
**Confidence:** 5
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Measured size/startup claims against precommitted budgets” shows the issue materially affects reliability, verification, or developer experience; it belongs in the current program but is not an immediate blocker, while the implementation is localized and has concrete acceptance witnesses, with a direct reproduction or current implementation proof.
**Severity:** P3
**Systems:** Build, Engine
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §7 phase 7, LLP 0026
**Depends-on:** sfe-compile-cli, sfe-process-semantics

Budget numbers are fixed **before measurement begins** (register item
7 — thresholds set at measurement time can be fitted to results). Then
measure on real hardware: binary size per tuple, cold start
(copy vs mmap vs zero-copy evaluation from the OS-mapped image using
the page-aligned sections), large-graph startup, signature/footer scan
cost, factory-table vs HBC. Recorded report per the LLP 0026
performance-gate pattern; the Motivation's estimates in LLP 0029 are
replaced by measurements; factory-table's release status (register
item 3) is decided on this evidence.

**Done when:** report archived with pass/fail against the precommitted
budgets; LLP 0029 Motivation updated; register items 3 and 7 recorded.

## LLP 0047 reconciliation — 2026-08-01

This is milestone 5 work. Budgets must be recorded before final measurement,
and results cover both v1 tuples' real release envelopes. Correctness and
relocation gates remain prerequisites; measurement does not substitute for
them or restore factory-table release eligibility implicitly.

## Implementation checkpoint — 2026-08-02

The versioned gate and collector now exist in
`packages/ibex-devtools/src/scripts/sfe-performance.mjs` and
`benchmark-sfe-release.mjs`, with a synthetic refusal suite in the standalone
foundation gate. They cover both exact v1 tuples, HBC hello and large-graph
size/startup, relocation copy-and-launch, full inspection scan cost, dynamic
dependency count, and a diagnostic factory-table comparison. Reports retain
raw samples and bind the measured values to exact artifact digests, the clean
source revision, and the committed budget blob.

The collector refuses to begin when the budget is draft, missing either
tuple, outside Git, different from `HEAD`, or accompanied by tracked source
changes. It also refuses cross-host tuple claims, and a contention declaration
makes the recorded gate fail. Its named startup protocol means a fresh process
for every sample while explicitly recording that OS page-cache eviction was
not attempted; the relocation profile includes the copy inside the timer.
Budget rows also precommit record-count constraints that distinguish hello
from the large graph. Before sampling, authenticated inspection projections
must prove both HBC inputs are release-v1, static-HBC, exact-baseline artifacts
from one catalog/stub/producer family, while the comparison input is the
development-only factory-table producer. Substituted binaries, undersized
"large" graphs, and release-provenance factory inputs refuse.

No numeric budget document has been authored and no final measurement has
been collected. The ticket therefore remains open pending author register
items 3, 6, and 7, a committed two-tuple budget, and uncontended reports from
both release hosts. `scripts/build-sfe-diagnostic-factory-table.sh` now closes
the fixture-construction prerequisite without weakening the release producer:
it builds against the explicitly supplied static Hermes archive family,
requires development provenance and the diagnostic target contract, verifies
inner admission, and publishes outside the release kit. Final per-tuple hello
fixtures are measurement inputs and therefore remain unrecorded until after
the budgets are accepted and committed.
