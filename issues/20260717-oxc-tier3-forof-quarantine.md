# Quarantine unproven native Tier 3 shapes (live for-of miscompile hazard)

**Status:** Complete
**Severity:** P1
**Systems:** Module Loader, Engine
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §5 (step 0), LLP 0019

The native for-of rewrite (`src/module_loader/producer_spike.rs:428-472`)
wraps any matching identifier-bound `const`/`let` block-bodied loop in an
ordinary-function IIFE with **no hazard analysis** — no
`this`/`arguments`/`break`/`continue`/`return`/`yield`/`await`/hoisting
checks — on the production-default path (module runner default since
ENG-25066). Tier 1 and Tier 2 both check these hazards. A `return` or
`this` in a matching body silently changes meaning; `break`/`await`
become downstream syntax errors. This violates LLP 0019's zero-divergence
rule today, independent of the retirement program.

Classify every Tier 3 shape not provably handled with full
canonical-pass semantics as a typed `LegacyRequired` (quarantine), and
record the divergence in LLP 0019 as a live, dated exception until the
passes land. No quarantine row may later be resolved by deleting the
fallback: each needs a landed pass or a documented unsupported
disposition with a stable diagnostic code before window close.

**Done when:** unproven shapes route to the compat loader with a typed
reason; regression fixtures cover the hazard cases (return/this/break/
await/var/destructuring/non-block bodies); LLP 0019 carries the dated
exception; landed in 0.1.

## Worktree evidence (2026-07-17)

- `LegacyModuleRunnerRequirementKind` and
  `Tier3ForOfQuarantineReason` provide stable machine-readable categories.
- The Oxc producer performs AST-based hazard classification before emitting
  the IIFE rewrite; quarantined errors are converted into
  `SourceModuleGraphBuildV1::LegacyRequired` by the graph builder.
- Regression coverage pins return, lexical `this`, break, await, `var`,
  destructured bindings, and non-block bodies; the corpus-proven simple
  capture row remains native.
- `cargo test --lib module_loader::` passes (146 passed, one intentional
  benchmark ignored).

The native real-Hermes gate now supplies source/prepared receipts for all four
admitted rows and checks every remaining corpus row against its stable typed
quarantine. The named macOS-arm64 and Linux-x64 CI cells run that gate.
