# Tier-3 for-of quarantine blocks 28-33% of Exact first-party modules

**Status:** Open
**Systems:** Transforms, Module loader
**Author:** Claude Fable 5 (Claude Code)
**Date:** 2026-07-29

**Filed:** 2026-07-29 (Exact LLP 0416 D2 resolution — gates the adapter-2
dependency-principal end-state)
**Related:** Exact LLP 0416 §D2, LLP 0028, LLP 0034 (Hermes ES6 block
scoping); Exact `issues/closed/20260729-hermes-aot-forof-let-capture-breaks-factory-hbc.md`
(the engine divergence that makes the repair load-bearing)

**Impact:** 4
**Urgency:** 3
**Ease:** 3
**Confidence:** 4
**Score reviewed:** 2026-07-29
**Score rationale:** The D2 measurement showed the oxc producer's tier-3
for-of quarantine ("pending canonical-pass parity") refuses
break/continue/return/destructured/nested for-of shapes — 29/103 hello
first-party modules — making adapter-2 unable to publish 28-33% of real
Exact code. The gap is finite and mechanical: the canonical AST repair
already exists and is battle-tested in the compat loader and (ported)
in Exact's startup lowering.

Close the quarantine by bringing the canonical for-of repair pass to
parity for the quarantined shapes, with the hermesc-AOT engine-truth test
pattern (compile via pinned hermesc, execute on the pinned VM) as the
regression harness — Node/V8-based oracles are structurally blind to the
AOT scoping divergence.

## Acceptance

- The D2 driver publishes 100% of the hello/dynamic-import/mixed-semantics
  first-party module sets (TLA fallback excepted).
- Engine-truth tests cover the previously quarantined shapes.

## Evidence (2026-07-30, ibex 281c25d51)

The 100%-publication acceptance bullet is now evidenced at this pin.
Re-ran `tests/llp0413_d2_adapter2_producer.rs` against fresh Exact
target-graph exports (`scripts/llp0413-d2-export-target-graph.mjs` at the
Exact LLP 0413 Phase 2 M1 tree, agent-off dev server, same three fixture
lanes), serially (`--test-threads 1`; the fingerprint test reads the
producer test's output, so parallel default order races):

- `produces_adapter2_publications_from_authenticated_originals` — ok:
  hello 115/108 modules produced (**0 refusals**, 0 TLA, 12 closure
  originals); dynamic-import 117/110 (**0 refusals**); mixed-semantics
  122/116 (**0 refusals**, 1 TLA published natively). 4 carriers per lane.
  The D2-measurement baseline was 29/103 hello first-party refusals
  (`IBEX_LEGACY_TIER3_FOR_OF ... pending canonical-pass parity`); the
  quarantine no longer refuses any module in these lanes.
- `adapter2_publications_satisfy_current_transform_fingerprint` — ok:
  fingerprint currency holds for 354 records across 3 publications.
- The unchanged `llp0413_arms_ef_admission` harness admits all three
  adapter-2 publications (decode-and-admit + tamper + §14 item 16 splice
  refusals).

Remaining before close: confirm the second acceptance bullet's
engine-truth coverage for the previously quarantined shapes is the
regression harness of record (the canonical-pass parity change that
closed the gap landed before/at 281c25d51). Orchestrator closes at
landing per the Exact Phase 2 integration wave.
