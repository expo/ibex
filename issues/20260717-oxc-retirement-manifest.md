# Retirement manifest + cargo-metadata prefix gate

**Status:** Open
**Impact:** 4
**Urgency:** 3
**Ease:** 3
**Confidence:** 5
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Retirement manifest + cargo-metadata prefix gate” shows the issue materially affects a supported product or engineering path; it belongs in the current program but is not an immediate blocker, while the fix requires a few coordinated implementation and test surfaces, with a direct reproduction or current implementation proof.
**Progress:** In Progress
**Severity:** P2
**Systems:** Build, CI, Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §4

Generate (from the capsec inventory and symbol table), then freeze, the
checked-in retirement manifest: exact identifiers only — all ten
`surface.loader.*.swc.*` registry IDs (five base + five `.main`
variants; digest tails make substring gates unsound), crate names,
symbols (`TransformEngine`, SWC `transpile_to_cjs` body,
`transpile_esm_to_script`), cache tags and namespaces
(`in-process-swc-v2`, `loader-transpile-v14-content-addressed`,
`transpile-tool-directory-v1`, `subprocess-transpile-toolchain-v2`,
`subprocess-transpile-script`, `in-process-transpile-engine`), env
contracts (`IBEX_RUNTIME_TRANSFORM`, `EXACT_RUNTIME_TRANSFORM`,
`EXACT_TRANSPILE_SCRIPT`, `IBEX_LEGACY_MODULE_LOADER`,
`IBEX_TRANSPILE_CACHE_MAX_BYTES`, `IBEX_TEST_TRANSPILE_INPUT_BARRIER`).
Add the new CI check over `cargo metadata`/`Cargo.lock` rejecting any
resolved package whose name starts with `swc_`, per retained profile
(cargo-deny bans cannot express name-prefix globs; it may carry the
enumerated crates).

**Done when:** manifest generated+frozen with the negative gate wired
in CI (initially passing in "SWC still present" inverse mode or staged
off); prefix check green with a self-test.

## Worktree evidence (2026-07-17)

- `config/oxc-retirement-manifest.json` freezes the exact ten
  CapSec IDs, CapSec symbol references, named source/cache/env needles,
  retained Cargo profiles, and resolved `swc_*` crate inventory.
- `bun run check:oxc-retirement` validates the inverse inventory now and
  is wired into preflight CI; its `forbid-prefix` mode is the retirement
  end-state gate over both `cargo metadata --locked` and `Cargo.lock`.
- `oxc-retirement-manifest.test.mjs` self-tests exact-inventory drift and
  rejection of a future, previously unenumerated `swc_*` package.

This remains **In Progress** until the engine-surgery change flips the
manifest to its negative end state and the prefix gate passes with no SWC
packages.
