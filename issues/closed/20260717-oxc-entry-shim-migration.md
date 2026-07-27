# Entry-shim and .hbc-fallback migration to the producer

**Status:** Closed
**Resolution:** Closed from the result recorded in f5688afb: authenticated entries and stale-bytecode fallback now use the producer path with legacy behavior pinned.
**Severity:** P2
**Systems:** Runtime, Module Loader
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §4b
**Depends-on:** oxc-behavioral-transform-corpus

`run_entry_with_tla_shim` lowers every source-extension entry except
`.cjs` through SWC, outside the window gate, and is also reached via
the engine `!supports_feature(TopLevelAwait)` branch and the `.hbc`
stale-bytecode source fallback. Migrate entries on advertised tuples to
the module-runner producer; the shim's residual argv-wrapping role
keeps no parser; rewire the `.hbc` fallback to the producer path. The
shim-to-runner behavior-delta fixture family (from the corpus ticket)
gates the migration.

**Done when:** no entry path invokes `transpile_to_cjs`; delta fixtures
green; `.cjs` passthrough behavior pinned.

## Result

Advertised authenticated source entries return through the native
`SourceModuleGraphV1` runner before legacy entry selection. The residual
`run_legacy_entry_shim` now reads prepared compatibility bytes and owns only
the existing argv/async wrapper; no entry path calls `transpile_to_cjs`.
Stale `.hbc` source fallback reuses an existing bundle or prepares source
through the bounded Rolldown path before invoking that wrapper.

Raw `.cjs` remains loader-served instead of being compiled as a bare script,
which preserves `require`, `module`, `exports`, `__filename`, `__dirname`, and
the LLP 0024 `this === module.exports` contract. The full
`cli_runtime_execution` suite (seven tests, including the new passthrough
fixture and the TLA/source-marker/stale-bytecode deltas) and the deterministic
module-loader path-inventory test pass.
