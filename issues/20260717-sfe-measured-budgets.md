# Measured size/startup claims against precommitted budgets

**Status:** Open
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
