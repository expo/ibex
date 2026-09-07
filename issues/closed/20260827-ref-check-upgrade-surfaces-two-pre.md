# ref-check upgrade surfaces two pre-existing broken refs

**Status:** Closed
**Systems:** Tooling, LLP
**Severity:** P3
**Author:** Charlie Cheever
**Date:** 2026-08-27

ibex was running a ref-check that predated the overlay, sub-LLP-parent, and malformed-target rules. Upgrading to the current version surfaces two problems that were always there: `patches/hermes/0015-empty-disabled-hermes-internal.patch:3` references LLP 0514, which is an Exact number with no ibex document; and `src/engine/hermes_runtime.cc:15106` carries a bare `LLP` target, which the current version correctly refuses to degrade to an unchecked shorthand. Neither is caused by the upgrade.

## Resolution — 2026-09-06

The inherited patch now cites Ibex LLP 0060 §5, which records its local
disposition. The structured-evaluation annotation names LLP 0024 §7.3 on
one line, so the checker can resolve it. `./ref-check` passes with no
errors; no checker or runtime behavior changed.
