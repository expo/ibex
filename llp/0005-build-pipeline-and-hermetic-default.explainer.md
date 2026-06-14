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
default, hermetic path) or by regenerating them from JS sources with bun/the JS
tooling (the `IBEX_REGENERATE_RUNTIME=1` dev path); (2) it emits source and
optional Hermes bytecode headers for bootstrap/runtime JS; and (3) it compiles
the C++ engine (`src/engine/*.cc`) with `cc` and links Hermes from
platform-specific paths or env overrides `[observed]` (`build.rs:321-351,
454-548, 711-781, 804-1224`). The headline invariant is narrower than "the
whole native build is self-contained": the default generated-JS path must not
require bun or `node_modules` `[observed]` (`vendored-generated/README.md:3-9`).
This explains the flow; it does not restate the platform/crypto matrix
([LLP 0001](./0001-target-platforms-and-ci-matrix.rfc.md)).

## The hermetic-default invariant

A plain `cargo build` (or `--features openssl-crypto`) with no regeneration env
flags must not require bun or `node_modules` for the generated JS snapshot
`[observed]` (`vendored-generated/README.md:3-9`). `build.rs` enforces this
with a three-way branch
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

`generate_builtin_manifest` (`build.rs:353, 1123-1179`) produces
`builtin_manifest.generated.rs`, authored from `modules.ts` by
`packages/ibex-devtools/src/scripts/generate-module-manifest.ts` `[observed]`
(`vendored-generated/README.md:13-16`). In standalone mode it copies the
vendored manifest; with `IBEX_REGENERATE_RUNTIME=1` it runs the local bun-based
generator `[observed]` (`build.rs:1123-1179`). The Rust loader `include!`s it
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
`vendored-generated/README.md:23-27`). The engine installs this bundle at startup
([LLP 0003 §The bootstrap sequence](./0003-hermes-engine-bridge.explainer.md#the-bootstrap-sequence)).

## Bytecode precompilation (hermesc)

`build.rs` always emits bootstrap source headers from the JS files `[observed]`
(`build.rs:671-709`). For bootstrap bytecode, it checks the HBC version of
`hermesc` against linked Hermes. Missing or mismatched `hermesc` **panics**
unless `EXACT_ALLOW_FALLBACK` is set; with fallback allowed it emits an empty
bytecode header and the engine uses source `[observed]` (`build.rs:487-527,
555-669`). The runtime bundle source header is generated separately
`[observed]` (`build.rs:1288-1400`). Runtime-bundle bytecode generation also
checks `hermesc`, but skips with warnings on unavailable/mismatched compilers
instead of using the bootstrap panic path `[observed]` (`build.rs:1482-1583`).
The engine prefers bytecode and falls back to source at startup
([LLP 0003](./0003-hermes-engine-bridge.explainer.md),
`src/engine/hermes_bootstrap.cc:44-69`).

These bytecode headers are **not vendored** — they are regenerated each build
from committed JS or replaced by fallback headers, because they are tied to the
local Hermes version `[observed]` (`vendored-generated/README.md:29-35`).

## What is and isn't vendored

From `vendored-generated/README.md` `[observed]` (`vendored-generated/README.md:11-35`):

- **Vendored** (committed): `builtin_manifest.generated.rs`,
  `builtins/*.js` (47 transformed modules), `embedded_runtime_bundle.js`.
- **Regenerated each build** from in-repo sources or platform toolchains:
  `bootstrap_source.h`, `bootstrap_bytecode.h`, the per-file `*.hbc`,
  `runtime_bundle_bytecode.h`, and platform object/archive products (`*.o`,
  `*.a`).

## Refreshing the snapshot

`IBEX_UPDATE_VENDORED_GENERATED=1` (which requires `IBEX_REGENERATE_RUNTIME=1`,
else `panic!`) re-runs the generators and refreshes `vendored-generated/` from
the freshly-built `OUT_DIR` artifacts `[observed]` (`build.rs:327, 461-467,
1769-1799`; `vendored-generated/README.md:37-46`):

```
IBEX_REGENERATE_RUNTIME=1 IBEX_UPDATE_VENDORED_GENERATED=1 cargo build --features openssl-crypto
```

## C++ compilation

`build.rs` compiles `src/engine/*.cc` with the `cc` crate, setting per-platform
defines (`EXACT_NO_OPENSSL`, `EXACT_PLATFORM_IOS`, `EXACT_PLATFORM_WINDOWS`,
`EXACT_HAS_CURL`, `HERMES_ENABLE_DEBUGGER`, etc.) and selecting the crypto/fetch/
websocket source files per OS `[observed]` (`build.rs:804-1224`).
Crypto-backend selection and the platform matrix are owned by
[LLP 0001](./0001-target-platforms-and-ci-matrix.rfc.md) and mapped in
[LLP 0003](./0003-hermes-engine-bridge.explainer.md#crypto-is-platform-dependent-the-fragile-axis).
Hermes headers/libs are located via `HERMES_*` env vars or platform defaults
`[observed]` (`build.rs:172-227, 289-304`). Android additionally consumes React
Native JSI headers/libs via `JSI_*` env vars or the default Android PREFAB
extract under `android/react-android` `[observed]` (`build.rs:199-227`).
Android native fetch/WebSocket are compiled from `native_android_networking.cc`
and delegate to the Java OkHttp bridge shipped under `platform/android/java`.
That bridge also supplies Android clipboard, raw DNS, locale/screen/appearance,
accessibility, and platform-version data to Hermes host globals
`[observed]` (`src/engine/native_android_networking.cc`;
`src/engine/hermes_runtime_android.cc`;
`platform/android/java/dev/ibex/runtime/IbexNetworking.java`; `build.rs`). This
is a separate concern from the vendored-generated JS snapshot.

## Boundaries

- The JS authoring lives in `modules.ts`, `src/builtins/`, `src/engine/bootstrap/`,
  and `packages/ibex-runtime-js`; generators are in `packages/ibex-devtools`.
- Decision rationale for *why* extraction chose "vendor generated artifacts"
  (option a) over alternatives is exact LLP 0180 §1.4 (referenced by the
  commit `Vendor generated runtime artifacts...`); not re-derived here.
