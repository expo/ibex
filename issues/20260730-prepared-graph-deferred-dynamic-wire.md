# Prepared-graph wire lacks a deferred-dynamic field; committed admission refuses route-deferred publications

**Status:** Open
**Systems:** Module loader, Wire schemas, CapSec
**Author:** Claude Fable 5 (Claude Code)
**Date:** 2026-07-30

**Filed:** 2026-07-30 (ibex half of Exact
`issues/20260730-prepared-lane-deferred-dynamic-admission.md`, relocated per
the D2-ticket precedent)
**Related:** LLP 0026/0027 (prepared graph wire; deferred-acquisition
provider), Exact LLP 0413 §10 Phase 5 item 4 / §9.2 (dynamic boundaries as
separately authenticated carriers), Exact LLP 0128 diet (initial-route
split)

**Impact:** 4
**Urgency:** 3
**Ease:** 3
**Confidence:** 4
**Score reviewed:** 2026-07-30
**Score rationale:** Blocks the composed diet win on the prepared lane: a
route-deferred publication (Exact's initial-route split, −169 records on
the blog) refuses committed admission with `ERR_MODULE_LINK` edge
disagreement, forcing deferral-off on the prepared lane. The runtime
machinery exists; only the wire cannot express it.

The committed-admission path already has the deferral machinery
(`deferred_dynamic_sources`, `DeferredSourceDynamicBindingsV1`, the
deferred-acquisition provider), but `ibex/prepared-module-graph/2` has **no
wire field** through which a publication can declare that a record's
dynamic edge is deferred — so a publication whose records declare edges the
carrier inventory deliberately omits refuses at graph link. Exact's
producer side is done (deferral prunes traversal while records keep their
declared edges); the artifact's semantic edge table must NOT be falsified
to work around this (rejected on the Exact side as dishonest provenance).

Needed: a versioned wire field (index- or record-level) mapping declared
dynamic edges to deferred acquisition, validated at admission (a deferred
edge must still name its authenticated `SourceId` + expected digests so the
lazy carrier admits under the same commitment discipline), plus the
committed path populating the existing provider from it. Refusal semantics
for non-deferred missing edges unchanged.

## Acceptance

- A route-deferred Exact publication admits; navigating to a deferred route
  lazily admits + links its carriers under the original commitment
  discipline (Exact LLP 0413 §9.2's "separately authenticated" bar).
- A publication missing a NON-deferred edge still refuses exactly as today.
