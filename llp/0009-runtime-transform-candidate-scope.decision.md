# LLP 0009: Runtime Transform Candidate Scope

**Type:** Decision
**Status:** Accepted
**Systems:** Module Loader, Runtime
**Author:** Charlie Cheever / Codex
**Date:** 2026-06-14
**Revised:** 2026-07-17 (LLP 0028 pin rotation adopts Rust 1.97.0, the Oxc 0.140.0 lockstep set, oxc_resolver 11.24.2, and oxc_sourcemap 8.1.1 under the generated transform manifest); 2026-07-15 (ENG-25066 completed the LLP 0026 ordinary-ESM default switch and retained this Decision only for the bounded legacy window); 2026-07-15 (LLP 0026 adoption admits the ModuleRunner architecture as the selected replacement path); 2026-07-07 (ENG-22991: first-class TypeScript runtime direction clarified without reopening the transform-engine choice)
**Related:** LLP 0007; LLP 0026 (accepted ModuleRunner architecture); LLP 0027 (artifact and interop contract)

## Decision

The authenticated LLP 0026 module runner is the default for ordinary ESM.
SWC is retained only as the file-at-a-time compatibility engine for explicitly
unsupported graph shapes during the Ibex 0.1 window; setting
`IBEX_LEGACY_MODULE_LOADER=0` closes that window early.

Historically, the runtime module loader kept SWC as the default transform engine.
The implementation of LLP 0007 adds an explicit in-process Oxc candidate behind
`IBEX_RUNTIME_TRANSFORM=oxc` (or the legacy alias `EXACT_RUNTIME_TRANSFORM=oxc`)
and separates its cache entries from SWC output, but it does **not** switch the
default runtime transform engine.

The producer is pinned to the Oxc `0.140.0` lockstep set, with
`oxc_resolver 11.24.2` and `oxc_sourcemap 8.1.1`, on Rust `1.97.0`. The exact
direct set and complete lock-resolved source/version/checksum closure are
authoritative in `config/module-transform.json` and its generated receipt. It
is allowed to prove parser,
TypeScript stripping, JSX, diagnostics, and target behavior in the embedded
runtime, but it must fail clearly when general ESM import/export lowering or
top-level await handling is required. SWC remains the compatibility path for
the current synchronous CommonJS loader contract.

The accepted successor architecture is LLP 0026's ESM ModuleRunner. Its
Rust/Oxc producer emits versioned `ModuleArtifact`s for a native-owned graph
and a Hermes-owned runner rather than lowering each ESM file into an isolated
CommonJS wrapper. This decision now governs only the compatibility period.
Authentication, parsing, linking, or evaluation failures in the native runner
never retry through SWC.

## TypeScript runtime direction

Runtime-loaded TypeScript remains a first-class Ibex capability. The direction
is not "TypeScript only at build time" and not "require a Node/Bun/Vite
subprocess at runtime"; the loader must continue to support `.ts`, `.tsx`,
`.mts`, `.cts`, and `.jsx` files from the hermetic embedded runtime path.

That commitment is independent of the implementation choice above. SWC is the
current compatibility engine because it satisfies the synchronous CommonJS
loader contract today. Future Oxc/Rolldown work may replace or reshape that
engine only after the LLP 0007 fixture gates prove the same runtime contract
or a later Decision explicitly changes the loader architecture. Dropping
runtime TypeScript support would likewise require a new Decision.

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

That was the first implementation's constraint. Re-measurement on 2026-07-17
showed the current coherent set requires Rust 1.95 or newer; the repository
therefore rotated atomically to Rust 1.97.0 and Oxc 0.140.0. The native module
producer, its deterministic artifact corpora, source-map composition, and the
full module-loader unit suite compile and pass on those pins. This does not by
itself make Oxc a general ESM-to-CJS lowering engine: the retained synchronous
compatibility path remains governed by the bounded window until LLP 0028
deletes it.

## Consequences

- Cache keys include the selected in-process transform engine.
- `EXACT_TRANSPILE_SCRIPT` remains an operator-trusted developer escape hatch,
  not a hermetic package resolver. Ibex identity-binds and stages the entry's
  immediate parent subtree and invokes it with a closed environment, private
  configuration, and an authenticated runner. Overrides must therefore keep
  every executable dependency self-contained in that subtree and must not rely
  on ancestor `node_modules`, package metadata, environment files, or runner
  configuration discovery.
- `IBEX_RUNTIME_TRANSFORM=oxc` affects only the retained legacy transform path;
  it does not select the ordinary-ESM implementation.
- Hosted platform and performance evidence remains a release gate, while the
  code default is exercised continuously by the module-loader workflow.

## Follow-ups

- Re-test Rolldown once the repo can move to a Rust toolchain that supports the
  current Oxc/Rolldown crates.
- Remove the compatibility engine after the 0.1 window and LLP 0024's
  parser-equivalence gate, or revise the governing contracts explicitly.
