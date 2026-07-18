# Behavioral transform corpus, first tranche

**Status:** Complete
**Severity:** P2
**Systems:** Module Loader, Engine
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §5 (Phase 0), LLP 0007, LLP 0026

The spike manifest has a single TSX fixture; TS/JSX preservation claims
need a behavioral corpus. Extend the existing single-owner
module-semantics corpus (not a parallel one): enums, namespaces,
`import =`, JSX runtime configuration, type-only imports/exports,
CJS/ESM interop, TLA, dynamic import and `import.meta`, diagnostics,
composed source maps — on real Hermes, source and prepared modes.
Include the shim-to-runner behavior-delta family (sloppy CJS entries
the shim wrapped leniently vs. runner goal detection, `.cjs`
passthrough included).

**Done when:** first tranche lands and gates step 1 (the pin
rotation); corpus home (LLP 0007 successor vs new LLP) recorded.

**Completion evidence (2026-07-17):** The existing single-owner
`module-semantics-corpus.mjs` now owns all twelve first-tranche rows,
including the two shim/runner delta rows. The native runner executes every
row through the real `ibex` binary and Hermes in both source and prepared
profiles, requires authenticated execution receipts for successful rows, and
requires stable refusal text with no receipt for expected failures. The named
CI job is wired in `module-loader-baselines.yml`; the pinned Node 24.13.1
oracle run passed 24/24 locally. The corpus exposed and now permanently covers
the Oxc enum semantic prerequisite, imported object-shorthand rewriting,
microtask-only TLA settlement, preserved Hermes error stacks, and composed
prepared-carrier source-map offsets. Corpus ownership remains with LLP 0007's
existing module-semantics fixture family rather than creating a parallel LLP.
