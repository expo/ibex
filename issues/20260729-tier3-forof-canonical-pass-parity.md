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
