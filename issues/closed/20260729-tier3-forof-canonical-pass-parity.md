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
