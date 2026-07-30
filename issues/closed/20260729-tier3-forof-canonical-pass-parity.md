# Tier 3 for-of canonical pass parity

**Status:** Closed
**Resolution:** The Rust/Oxc producer now mirrors the LLP 0019 canonical
explicit-iterator pass. All 15 owning-corpus for-of rows are native passes;
`for await` remains the distinct typed quarantine.
**Systems:** Module Loader, Runtime, Engine
**Author:** Codex
**Date:** 2026-07-29
**Related:** LLP 0019; LLP 0028

The former Tier 3 mirror admitted only four simple for-of shapes and routed
canonical-safe destructuring, nested loops, lexical `this`/`arguments`,
assignment/`var` bindings, non-block bodies, and canonical leave-raw hazards
to `LegacyRequired`.

Resolution:

- emits the canonical live iterator protocol and IteratorClose-on-throw;
- uses arrow-scoped fresh `let`/`const` bindings, including patterns;
- recursively materializes nested right/body rewrites;
- preserves canonical raw-loop bailouts for control flow, await/yield,
  hoisting, and bound-name redeclaration while still visiting child loops;
- updates the exhaustive corpus disposition map; and
- adds loaded-Hermes engine-truth coverage combining rewrite, recursive,
  assignment/`var`, leave-raw, lexical-this, and IteratorClose branches.

The producer map and loaded-Hermes fixture pass. The pre-existing full CLI
receipt runner currently reaches unrelated target-advertisement/stdio-policy
refusals before application execution; that infrastructure drift is not
papered over by this ticket.

---

# Appendix: the relocated Exact LLP 0416 D2 ticket (merged 2026-07-30)

The D2-resolution copy of this ticket (filed 23734004) tracked one further
acceptance bullet: the Exact D2 driver publishing 100% of the fixture
first-party sets. Evidenced at pin 281c25d51: 0 tier-3 refusals across
hello/dynamic-import/mixed-semantics (was 29/103 on hello), TLA published
natively, 354/354 fingerprint-valid, admission green. Full evidence in the
merged body below.

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
