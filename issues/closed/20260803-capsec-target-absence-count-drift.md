# CapSec target-absence executor retained a stale fixture budget

**Status:** Closed
**Severity:** P2
**Systems:** CapSec, CI, Testing
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-08-03
**Related:** LLP 0021 §WP10; PR #25

The exact-head PR #25 macOS full-matrix job reached
`capsec_public_target_absence_batch` and failed before executing a probe. The
source-derived catalog contained the 114 target-absence rows already fixed by
the JavaScript conformance contract, while the independent Rust executor still
expected July's 112-row total.

## Resolution

A freshly generated Apple catalog proves the exact executable partition is
114 rows: 92 `ibex/capsec-target-absence-invocation/1` rows and 22
`ibex/capsec-native-global-invocation/1` rows. The Rust executor now pins both
that total and split, preserving its fail-closed guard against unaudited
catalog growth.
