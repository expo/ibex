# LLP 0005: The Build Pipeline and the Hermetic-Default Invariant

**Type:** Explainer
**Status:** Draft
**Systems:** Build, Engine, Runtime
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Related:** LLP 0000; LLP 0001 (platforms); LLP 0003 (engine bridge); LLP 0004 (module loading)

## Summary

`build.rs` does three jobs: (1) it materializes the **generated JS layer** — the
builtin manifest, the transformed builtin modules, and the bundled shared
runtime — either by copying committed `vendored-generated/` artifacts (the
default, hermetic path) or by regenerating them from JS sources with bun (the
`IBEX_REGENERATE_RUNTIME=1` dev path); (2) it precompiles bootstrap and bundle
JS to Hermes bytecode via `hermesc` when versions match; and (3) it compiles the
C++ engine (`src/engine/*.cc`) with `cc` and links the prebuilt Hermes. The
headline invariant is that the default `cargo build` must succeed without bun or
`node_modules`. This explains the flow; it does not restate the platform/crypto
matrix ([LLP 0001](./0001-target-platforms-and-ci-matrix.rfc.md)).

## The hermetic-default invariant

A plain `cargo build` (or `--features openssl-crypto`) with no env flags MUST
NOT require bun or `node_modules` `[observed]` (`vendored-generated/README.md`;
LLP 0000 §Key invariants). `build.rs` enforces this with a three-way branch
(`build.rs:321-351`) `[observed]`:

- `standalone = !IBEX_REGENERATE_RUNTIME && vendored-generated/ exists`
  (`build.rs:328`). In standalone mode it copies the committed artifacts into
  `OUT_DIR` (`build.rs:329-334, 361-369`).
- If **not** regenerating and the vendored dir is **missing**, it
  `panic!`s loudly rather than silently shelling out to the bun/node generators
  (`build.rs:335-345`). The in-code comment is explicit: because the generators
  now live in this repo, a missing-artifacts fallback "would quietly become
  non-hermetic" (`build.rs:336-340`, annotated `@ref LLP 0086 review F7`).
- If `IBEX_REGENERATE_RUNTIME=1` but the manifest generator is missing, it
  `panic!`s too (`build.rs:346-351`).

`[inferred: the loud-failure choice is deliberate — the regression that started
the whole extraction (a Linux build that shipped broken, LLP 0001 / exact LLP
0180) is the class of bug a silent fallback hides; failing closed makes
"is this build hermetic?" observable at build time rather than at runtime.]`

## The generated JS layer

Three artifact families flow from JS authoring into the compiled binary:

### 1. Builtin manifest

`generate_builtin_manifest` (`build.rs:353`) produces
`builtin_manifest.generated.rs`, authored from `modules.ts` by
`packages/ibex-devtools/src/scripts/generate-module-manifest.ts` `[observed]`
(`vendored-generated/README.md`). The Rust loader `include!`s it
(see [LLP 0004](./0004-module-loading-and-builtins.explainer.md)).

### 2. Transformed builtin modules

`build.rs:355-452` produces `OUT_DIR/builtins/*.js` `[observed]`:

- **standalone**: copies `vendored-generated/builtins/*.js` into `OUT_DIR`
  (`build.rs:361-369`).
- **regenerate**: runs `build-builtins.mjs` (preferring bun, else node) over
  `src/builtins`, transforming through the shared Hermes transforms
  (`build.rs:370-393`). On failure it tries a primary-checkout toolchain, and
  only falls back to copying sources if `EXACT_ALLOW_FALLBACK` is set —
  otherwise it `panic!`s (`build.rs:395-447`).

### 3. The shared runtime bundle

`generate_runtime_bundle_source_header` (`build.rs:454-459, 1288-1400`) wraps
`embedded_runtime_bundle.js` into a C++ raw-string header
(`runtime_bundle_source.h`, symbol `SHARED_RUNTIME_BUNDLE_SRC`) `[observed]`. In
standalone mode the source is the vendored bundle (`build.rs:1310-1326`);
otherwise it is rebuilt by `rolldown-bundle.mjs` from
`packages/ibex-runtime-js/src/runtime-entry.ts` (`build.rs:1300, 1346`;
`vendored-generated/README.md`). The engine installs this bundle at startup
([LLP 0003 §The bootstrap sequence](./0003-hermes-engine-bridge.explainer.md#the-bootstrap-sequence)).

## Bytecode precompilation (hermesc)

When a compatible `hermesc` is available, `build.rs` compiles the bootstrap
`*.js` and the runtime bundle to Hermes bytecode and emits C++ headers with
static byte arrays (`bootstrap_bytecode.h`, `runtime_bundle_bytecode.h`)
`[observed]` (`build.rs:471-562, 1400`). It checks the HBC version of `hermesc`
against the linked Hermes and **skips** precompilation on mismatch (or `panic!`s
if `EXACT_ALLOW_FALLBACK` is unset) `[observed]` (`build.rs:487-527`). The engine
prefers bytecode and falls back to source at startup
([LLP 0003](./0003-hermes-engine-bridge.explainer.md), `hermes_bootstrap.cc:44-69`).

These bytecode headers are **not vendored** — they are regenerated each build
from the committed JS, because they are tied to the local Hermes version
`[observed]` (`vendored-generated/README.md` "NOT vendored").

## What is and isn't vendored

From `vendored-generated/README.md` `[observed]`:

- **Vendored** (committed): `builtin_manifest.generated.rs`,
  `builtins/*.js` (47 transformed modules), `embedded_runtime_bundle.js`.
- **Regenerated each build** from in-repo sources: `bootstrap_source.h`,
  `bootstrap_bytecode.h`, the per-file `*.hbc`, `runtime_bundle_bytecode.h`, and
  platform object/archive products (`*.o`, `*.a`).

## Refreshing the snapshot

`IBEX_UPDATE_VENDORED_GENERATED=1` (which requires `IBEX_REGENERATE_RUNTIME=1`,
else `panic!`) re-runs the generators and refreshes `vendored-generated/` from
the freshly-built `OUT_DIR` artifacts `[observed]` (`build.rs:327, 461-467`;
README "Regenerating"):

```
IBEX_REGENERATE_RUNTIME=1 IBEX_UPDATE_VENDORED_GENERATED=1 cargo build --features openssl-crypto
```

## C++ compilation

`build.rs` compiles `src/engine/*.cc` with the `cc` crate, setting per-platform
defines (`EXACT_NO_OPENSSL`, `EXACT_PLATFORM_IOS`, `EXACT_PLATFORM_WINDOWS`,
`EXACT_HAS_CURL`, `HERMES_ENABLE_DEBUGGER`, …) and selecting the crypto/fetch/
websocket source files per OS `[observed]` (`build.rs:751-1058`). Crypto-backend
selection and the platform matrix are owned by
[LLP 0001](./0001-target-platforms-and-ci-matrix.rfc.md) and mapped in
[LLP 0003](./0003-hermes-engine-bridge.explainer.md#crypto-is-platform-dependent-the-fragile-axis).
Prebuilt Hermes (headers + lib) is located via `HERMES_*` env vars / platform
defaults and is **not** committed (`build.rs:289-296`; LLP 0001 §4).

## Boundaries

- The JS authoring lives in `modules.ts`, `src/builtins/`, `src/engine/bootstrap/`,
  and `packages/ibex-runtime-js`; generators are in `packages/ibex-devtools`.
- Decision rationale for *why* extraction chose "vendor generated artifacts"
  (option a) over alternatives is exact LLP 0180 §1.4 (referenced by the
  commit `Vendor generated runtime artifacts...`); not re-derived here.
