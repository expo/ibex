# LLP 0009: Runtime Transform Candidate Scope

**Type:** Decision
**Status:** Accepted
**Systems:** Module Loader, Runtime
**Author:** Charlie Cheever / Codex
**Date:** 2026-06-14
**Related:** LLP 0007

## Decision

The runtime module loader keeps SWC as the default transform engine for now.
The implementation of LLP 0007 adds an explicit in-process Oxc candidate behind
`IBEX_RUNTIME_TRANSFORM=oxc` (or the legacy alias `EXACT_RUNTIME_TRANSFORM=oxc`)
and separates its cache entries from SWC output, but it does **not** switch the
default runtime transform engine.

The candidate is pinned to Oxc `0.121.0`. It is allowed to prove parser,
TypeScript stripping, JSX, diagnostics, and target behavior in the embedded
runtime, but it must fail clearly when general ESM import/export lowering or
top-level await handling is required. SWC remains the compatibility path for
the current synchronous CommonJS loader contract.

## Context

LLP 0007 required a staged implementation rather than a forced swap. The spike
confirmed three constraints:

- `rolldown` `1.1.1` pulls Oxc `0.135.0`, which requires Rust `1.94.0`; this
  repo currently pins Rust `1.93.1`.
- `rolldown` `1.0.0` and direct Oxc `0.133.0` still route through
  `oxc_transformer` code that Rust `1.93.1` rejects because of unstable
  `if let` match guards.
- Direct Oxc `0.121.0` compiles on Rust `1.93.1` and supports the syntax
  transforms we need to test, but it does not provide the general ESM-to-CJS
  lowering that SWC currently supplies for the synchronous `require()` path.

Because of that, the first implementation can safely add an Oxc candidate and
parity fixtures, but it cannot honestly claim to replace SWC for runtime-loaded
`.ts`, `.tsx`, `.mts`, `.cts`, and `.jsx` modules.

## Consequences

- Cache keys include the selected in-process transform engine.
- `EXACT_TRANSPILE_SCRIPT` remains the explicit subprocess override.
- `IBEX_RUNTIME_TRANSFORM=oxc` is useful for fixture work and future migration
  spikes, not production default behavior.
- The default switch is blocked on either a Rolldown/Oxc path compatible with
  the pinned Rust toolchain and synchronous loader contract, or a later
  ModuleRunner-style loader redesign.

## Follow-ups

- Re-test Rolldown once the repo can move to a Rust toolchain that supports the
  current Oxc/Rolldown crates.
- Decide separately whether the runtime loader should become async or
  ModuleRunner-shaped to make Vite/Rolldown semantics the actual execution
  model instead of a file-by-file CommonJS transform.
