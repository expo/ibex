# LLP 0007: Converging Runtime Transforms on Vite, Rolldown, and Oxc

**Type:** RFC
**Status:** Draft
**Systems:** Module Loader, Build, Runtime
**Author:** Charlie Cheever / Codex
**Date:** 2026-06-13
**Revised:** 2026-07-15 (ENG-25064 made source-table and Rolldown/HBC preparation share one authenticated carrier/artifact contract); 2026-07-15 (architecture fork resolved to the accepted LLP 0026 ModuleRunner branch); 2026-06-13 (Claude independent review — `llp/reviews/0007-vite-rolldown-oxc-runtime-transforms.claude.md`); 2026-06-14 (Codex second-pass revision); 2026-07-04 (devtools parser convergence: Acorn removed from first-party transform/import-grants scripts in favor of Rolldown/Oxc parser utilities); 2026-07-07 (Hermes-compat for-of / async-generator authority delegated to LLP 0019)
**Related:** LLP 0000; LLP 0004 (module loading); LLP 0005 (build pipeline); LLP 0006 (design principles); LLP 0009; LLP 0026 (accepted ModuleRunner architecture)

## Summary

Ibex should converge its JavaScript/TypeScript transform story on the Vite 8
toolchain family: **Vite, Rolldown, and Oxc**. The generated JS layer already
uses Rolldown for builtins and the shared runtime bundle `[observed]`
(`packages/ibex-devtools/src/scripts/build-builtins.mjs:1-70`;
`packages/ibex-devtools/src/scripts/rolldown-bundle.mjs:1-58`). The remaining
major exception is the runtime module loader's in-process SWC pipeline for
on-disk `.ts/.tsx/.jsx/.mts/.cts` files `[observed]`
(`src/module_loader/transpile.rs:1-41`; `Cargo.toml:56-64`).

This RFC proposes making SWC a temporary compatibility implementation rather
than a strategic dependency. The desired end state is:

1. Bundled/generated artifacts use Vite/Rolldown/Oxc semantics.
2. Runtime on-disk transforms use Oxc/Rolldown in-process, or an architecture
   that exposes the same semantics without requiring a Node/Bun subprocess.
3. The default embedded runtime remains hermetic for consumers: no `node_modules`,
   Bun, or Node is required to load TypeScript at runtime.

The migration should be staged. We should not simply swap crates until a spike
proves that Oxc/Rolldown can preserve the current loader's synchronous
execution, CommonJS interop, top-level-await entry handling, import-meta
behavior, and Hermes-specific lowering requirements.

The first implementation of this RFC should therefore be interpreted as:

- add parity fixtures and a benchmark harness before changing defaults;
- implement an in-process Oxc/Rolldown candidate behind an explicit opt-in;
- align generated-artifact transforms where the existing Rolldown/Oxc path can
  replace Babel or bespoke syntax transforms without behavior drift;
- switch the runtime default only if the fixture suite, downstream smoke test,
  and hermetic-build checks pass.

If the candidate cannot satisfy the runtime-loader contract without changing
loader architecture, the correct completion state is not a forced default
switch; it is a documented Decision choosing a ModuleRunner-style redesign or a
temporary SWC extension window.

### Resolved architecture fork

LLP 0026 is the accepted resolution: Ibex will move ordinary ESM from
file-at-a-time CommonJS lowering to a native-owned module graph with a
Rust/Oxc `ModuleArtifact` producer and Hermes runner. The bounded producer
spike passed its precommitted real-Hermes bars on the pinned toolchain. SWC
remains a compatibility implementation during the staged migration; the
accepted direction does not bypass this RFC's fixture, hermeticity,
performance, or default-switch gates.

The prepared-carrier seam is now concrete (`commit:c6d2aefe`). The in-process
producer's verified artifacts can be deterministically assembled into a
per-principal JavaScript factory table, or that exact table can be compiled by
the matching `hermesc` into HBC. Both representations retain the same
`ModuleSemanticsV1`, semantic digest, original `SourceId`, typed edges, and
source map; only the separately authenticated carrier encoding/digest changes.
This is the contract the existing Rolldown cache and chunk publisher must emit,
not a second bundled-module semantics.

## Motivation

### Standardize on the chosen web toolchain

The current repo already points toward the Vite stack:

- `package.json` lists Vite 8 and Rolldown as build-time devDependencies
  `[observed]` (`package.json:22,25`) — note `rolldown` is `^1.0.0-rc.4`, a
  pre-1.0 release candidate, which bears on the Rust API maturity risk below.
- The build pipeline bundles `packages/ibex-runtime-js/src/runtime-entry.ts`
  with `rolldown-bundle.mjs` `[observed]`
  (`package.json:10`; `llp/0005-build-pipeline-and-hermetic-default.explainer.md:76-86`).
- Builtin JS files are compiled as per-module CommonJS outputs through Rolldown
  `[observed]` (`packages/ibex-devtools/src/scripts/build-builtins.mjs:1-70`).
- Module resolution already uses `oxc_resolver` `[observed]`
  (`src/module_loader/mod.rs:10,67-105,626`).

The broader Vite ecosystem has also moved in this direction. The Vite 8
migration guide says Vite 8 uses Rolldown and Oxc-based tools instead of the
older esbuild/Rollup split, and its transform migration guidance points users
from esbuild options toward Oxc options
(`[official docs]` <https://vite.dev/guide/migration#rolldown>). Rolldown's own
docs describe it as the bundler designed to underlie Vite and replace that
split with one unified build tool
(`[official docs]` <https://rolldown.rs/guide/introduction#why-rolldown>).

Keeping SWC as a separate runtime-only transform stack makes it easier for
bundled code and directly loaded code to disagree on TypeScript, JSX,
import/export lowering, helpers, interop, and future syntax. That is the wrong
long-term shape if "Vite stack" is the standard for app code.

### Reduce bespoke transform maintenance

Today Ibex has several transform mechanisms:

- Rolldown plus shared JS transforms for generated builtins/runtime bundles
  `[observed]` (`packages/ibex-devtools/src/scripts/transforms.mjs:848-877` —
  `createRolldownConfig`; the Hermes passes at `:62-251,392-597`).
- Rust SWC for runtime TypeScript/JSX/ESM-to-CJS lowering `[observed]`
  (`src/module_loader/transpile.rs:1-41`).
- Handwritten Hermes syntax *scanners* in the module loader that flag files for
  transpile `[observed]` (`src/module_loader/mod.rs:188-228,585-605`).
- Rolldown/Oxc-backed JS source rewrites in the devtools transform script —
  `fixForOfScoping`, `transformAsyncGenerators`, `replaceModuleDirnameBindings`
  `[observed]`
  (`packages/ibex-devtools/src/scripts/transforms.mjs:10,62-251,392-597,672-777`).

Some amount of Hermes-specific compatibility code may remain necessary, but
maintaining a whole separate SWC pipeline should need a strong reason. This RFC
sets the bar: SWC is acceptable while it is the only reliable in-process path,
but not as a permanent architecture.

## Current state

### Generated artifacts

The generated JS layer is already mostly aligned with the proposal:

- `build-builtins.mjs` calls Rolldown and writes one CommonJS module per source
  file `[observed]` (`packages/ibex-devtools/src/scripts/build-builtins.mjs:55-70`).
- `rolldown-bundle.mjs` calls Rolldown for the shared runtime bundle and writes
  CJS or IIFE output `[observed]`
  (`packages/ibex-devtools/src/scripts/rolldown-bundle.mjs:42-58`).
- `build.rs` vendors the generated outputs for hermetic default builds
  `[observed]` (`llp/0005-build-pipeline-and-hermetic-default.explainer.md:22-45`).

Known drift remains. `rolldown-bundle.mjs --lower-classes` still uses Babel for
class lowering `[observed]`
(`packages/ibex-devtools/src/scripts/rolldown-bundle.mjs:90-131`), and that
escape hatch sits on the default build path — `build:runtime` passes
`--lower-classes` `[observed]` (`package.json:10`). The shared transform script
still contains custom Oxc-parsed rewrites for Hermes workarounds `[observed]`
(`packages/ibex-devtools/src/scripts/transforms.mjs:62-251,392-597`).

### Runtime module loading

The runtime loader resolves files with `oxc_resolver`, then reads and
transpiles when needed `[observed]`
(`src/module_loader/mod.rs:67-110,163-186`). Files with TypeScript/JSX-like
extensions are always transformed; some `.js/.mjs/.cjs` files are *flagged for
transpile* when scanners detect unsupported Hermes syntax — async generators,
`for await`, `using`, block-scoped loop closures `[observed]`
(`src/module_loader/mod.rs:188-228,585-605`).

The actual in-process lowering goes through SWC. The Rust code strips types,
compiles JSX, lowers ESM to CommonJS, injects helpers inline, and emits JS for
the synchronous `require()` path `[observed]`
(`src/module_loader/transpile.rs:36-41,88-124`). The tests document important
contract points: ESM imports lower to `require`, JSX is compiled, top-level
await passes through for entry wrapping, and import-meta/dynamic-import behavior
is a known compensation point `[observed]`
(`src/module_loader/transpile.rs:142-176`).

One subtlety the migration must not paper over: the scanners pick a down-level
`target` (`"es5"`/`"es2015"`, `src/module_loader/mod.rs:599-605`), but the
**default in-process engine does not honor it.** `run_transpile_command` calls
`transpile_to_cjs(&source, entry)` with no target `[observed]`
(`src/module_loader/mod.rs:942`), and `transpile_to_cjs` hardcodes `Es2022` and
runs no compat/down-level pass — there is no `swc_ecma_transforms_compat`
dependency `[observed]` (`src/module_loader/transpile.rs:68,88-120`;
`Cargo.toml:56-64`). The `target` is consumed only by the cache key
(`src/module_loader/mod.rs:828`) and by the opt-in `EXACT_TRANSPILE_SCRIPT`
subprocess (`src/module_loader/mod.rs:966-967`). The Hermes-compat
for-of/async-generator rewrite authority is now specified by LLP 0019: the
canonical AST implementation is `hermes-compat.mjs` (re-exported by
`transforms.mjs`), with a constrained loader scanner held to the shared corpus.
Those build-time rewrites apply to generated builtins and the runtime bundle via
a Rolldown plugin, not to runtime-loaded on-disk files `[observed]`
([LLP 0019](./0019-hermes-compat-transform-authority.decision.md)).
So "down-leveled when scanners detect unsupported syntax" holds for the
*generated* layer and the subprocess path, but **not** for the default
in-process loader, which today strips types, compiles JSX, and lowers modules
without applying the Hermes syntax lowerings the scanners select a target for.
`[inferred: the cache key still varies on a target the in-process engine
ignores, which looks like residue from when the subprocess was the default
loader path.]`

The file comment explains why SWC was chosen: at the time of the spike,
`oxc_transformer` did not provide the needed general ESM-to-CJS lowering, and
Oxc's ModuleRunner transform implied an async loader ABI rather than the
current synchronous `require()` chain `[observed]`
(`src/module_loader/transpile.rs:8-15`). That is a good historical reason, not
a permanent decision.

## Goals

- Make **Vite/Rolldown/Oxc the canonical transform family** for Ibex JS/TS
  code, including generated artifacts and runtime-loaded source.
- Preserve the hermetic default: consumers who embed Ibex must not need Bun,
  Node, `node_modules`, or a repo checkout to load TypeScript at runtime.
- Keep the runtime/API boundary narrow. This is not an RFC to turn Ibex into an
  app framework or full Vite dev server.
- Preserve existing loader semantics unless intentionally changed in a later
  RFC: builtins, Node-ish resolution, CJS `require()`, import aliases, JSON
  modules, top-level await entry behavior, and current capability checks.
- Make transform drift observable through fixtures, cache-key versioning, and
  CI, rather than discovering it as application runtime bugs.

## Non-goals

- Type checking. Vite and Oxc transforms do not replace `tsc --noEmit` or an
  editor/language-service workflow.
- A public `ibex run app.tsx` product surface. Direct TSX execution may fall
  out of the loader work, but this RFC is about transform architecture.
- Full Vite plugin compatibility inside the embedded runtime loader.
- Replacing Hermes, the host ABI, or the runtime's security model.
- Requiring a JS subprocess in production just to load `.ts` or `.tsx`.

## Proposal

### 1. Treat SWC as a compatibility fallback

Document SWC in code and docs as the current fallback for a loader contract
that Oxc/Rolldown has not yet been proven to satisfy in-process. Do not add new
SWC-only behavior unless it is needed to keep existing users working. The
fallback is a compatibility mechanism, not the semantic source of truth once
the fixture suite exists.

The cache key should continue to include a transform-engine version tag
`[observed]` (`src/module_loader/mod.rs:827-860`). When an Oxc/Rolldown path is
added, the cache key must include the engine, version, target, and all relevant
options so stale SWC output cannot be reused.

### 2. Define the runtime-loader transform contract

Before replacing SWC, write a fixture suite that captures the behavior the
loader depends on. At minimum:

- TS type stripping, TSX/JSX transform, decorators parse behavior, and import
  type handling.
- ESM import/export lowering or equivalent execution under the runtime loader.
- CJS interop for default, named, namespace, and `__esModule` cases, matching
  the bootstrap loader's behavior `[observed]`
  (`src/engine/bootstrap/module-loader.js:4012-4027`).
- Dynamic `import()`, `import.meta.url`, `import.meta.dirname`,
  `import.meta.filename`, and `import.meta.main`.
- Top-level await behavior for entry files and failure behavior for dependency
  modules.
- NodeNext-style extension aliases (`./x.js` resolving to `./x.ts` where
  appropriate) `[observed]` (`src/module_loader/mod.rs:88-98`).
- Hermes compatibility lowerings: async generators, `for await`, `using`,
  block-scoped loop closures, and the for-of scoping workaround. LLP 0019 owns
  the for-of / async-generator conformance seam; this RFC only records that the
  runtime-loader transform contract must make the generated and on-disk paths
  converge. These are *detected* by runtime scanners `[observed]`
  (`src/module_loader/mod.rs:217-228,585-605`) but *applied* only by build-time
  Hermes-compat transforms over generated artifacts; the default in-process
  runtime path applies neither today (see Current state). The fixture suite
  should pin the behavior we *want*, then make the engine match it.
- No unresolved runtime helper imports unless those helpers are embedded
  builtins.
- Diagnostics that preserve useful filenames and source locations.

The suite should run against SWC and the candidate Oxc/Rolldown path, then
execute representative outputs in Hermes where possible. Textual output
comparison alone is insufficient because helpers and interop wrappers can vary
while semantics remain equivalent.

### 3. Prefer an in-process Rust path

The preferred replacement is an in-process Rust implementation using Oxc and/or
Rolldown crates. This preserves the current "standalone runtime" property and
does not reintroduce the old Bun/Node subprocess dependency. Oxc's transformer
supports TypeScript and JSX transforms in the current public docs
(`[official docs]` <https://oxc.rs/guide/usage/transformer/typescript>,
`[official docs]` <https://oxc.rs/guide/usage/transformer/jsx>), and the
general transformer docs list TypeScript, JSX, syntax lowering, inject, and
define in the pipeline
(`[official docs]` <https://oxc.rs/guide/usage/transformer>).

There are two candidate shapes:

1. **Oxc single-file transform plus local module lowering.** Use Oxc for TS,
   JSX, syntax lowering, and Hermes target transforms; keep or implement the
   minimal ESM-to-CJS/module glue needed by the existing synchronous loader.
   This is closest to the current SWC file-at-a-time model, but the ESM/CJS
   lowering question must be proven. Wiring Oxc's syntax lowering and target in
   would also *close* the current in-process gap (Current state), where the SWC
   path ignores the `es5`/`es2015` target the scanners select — making this a
   behavior fix, not only a swap.
2. **Rolldown graph transform for runtime-loaded modules.** Use Rolldown as the
   runtime graph transformer with externals for builtins and package
   boundaries. Rolldown exposes transform options for target, TypeScript, JSX,
   define, inject, helpers, and plugins, and its docs state that it uses Oxc
   under the hood for transformation
   (`[official docs]` <https://rolldown.rs/reference/InputOptions.transform>).
   This may better match Vite semantics, but it risks changing `require.cache`,
   per-file evaluation, dynamic import, and capability boundaries.

The RFC's default preference is **Oxc single-file first**, because it minimizes
loader architecture churn. If that cannot satisfy ESM/CJS semantics without
rebuilding a fragile mini-bundler, move to a separate RFC for an async
ModuleRunner-style loader.

### 4. Align generated artifact transforms first

The generated artifact path is lower risk than runtime-loaded arbitrary files.
Move it first:

- Replace the Babel-only `--lower-classes` escape hatch with Rolldown/Oxc target
  configuration if current Rolldown can produce Hermes-compatible class output.
  If not, document the remaining Babel exception with a failing fixture and a
  removal condition.
- Audit custom Oxc-parsed rewrites in `transforms.mjs`. Where Oxc/Rolldown can now
  perform the same lowering, delete the custom rewrite. Where the rewrite is a
  Hermes bug workaround rather than a language transform, keep it but isolate
  it as an Ibex/Hermes pass.
- Keep the hermetic vendored-generated invariant from LLP 0005. Regeneration may
  need the JS toolchain; default builds must continue to consume committed
  artifacts.

### 5. Add the Oxc/Rolldown runtime path behind a flag

Introduce an experimental path, for example:

- Cargo feature: `experimental-oxc-loader`
- Runtime env override: `IBEX_RUNTIME_TRANSFORM=oxc|swc`

The exact names are not prescribed, but the behavior is:

- SWC remains the default until the fixture suite and downstream smoke tests
  pass.
- CI runs the fixture suite under both engines.
- Debug logging reports the selected transform engine and cache key version.
- The existing `EXACT_TRANSPILE_SCRIPT` subprocess override remains a developer
  escape hatch, not a production recommendation `[observed]`
  (`src/module_loader/mod.rs:932-979`).

### 6. Switch defaults only after semantic parity

Make Oxc/Rolldown the default when all of these are true:

- Fixture suite passes on macOS, Linux, and Windows.
- At least one downstream app exercises direct runtime TS/TSX loading without a
  bundler.
- Generated artifacts are reproducible with the aligned Vite/Rolldown/Oxc path.
- Runtime builds still work without JS tooling or `node_modules`.
- Binary size and compile-time changes are understood and accepted.
- Known non-parity is explicitly documented in this RFC or a follow-up Decision.

After the switch, keep SWC as an opt-in fallback for one release window, then
remove SWC dependencies from `Cargo.toml` if no blocking regressions remain.

## Migration plan

### Phase 0: Baseline and fixtures

- Add fixture coverage for the runtime-loader transform contract.
- Record current SWC behavior for edge cases, including import-meta and dynamic
  import.
- Add a small benchmark: cold transform, warm cache load, and runtime execution
  for representative modules.

### Phase 1: Generated artifacts

- Update devtools scripts to use current Rolldown/Oxc transform options wherever
  they replace Babel or custom syntax transforms.
- Keep Hermes-only workarounds clearly named as Hermes workarounds.
- Refresh `vendored-generated/` and confirm default `cargo build` remains
  hermetic.

### Phase 2: Experimental runtime Oxc/Rolldown path

- Implement the candidate in-process Rust path.
- Add cache-key separation from SWC.
- Run fixture suite under both engines in CI.
- Keep the Oxc/Rolldown path opt-in until Phase 3 proves at least one real
  downstream direct-TS/TSX workflow.

### Phase 3: Downstream shadowing

- Enable the experimental path in one downstream CLI/app environment where
  direct TS/TSX loading matters.
- Collect failures as fixtures before fixing them.
- Decide whether single-file Oxc is sufficient or whether a ModuleRunner-style
  architecture is required.

### Phase 4: Default switch and cleanup

- Make Oxc/Rolldown the default transform engine only if the Phase 0-3 gates
  pass. Otherwise write a Decision capturing the blocker and the next
  architecture choice.
- Keep SWC fallback temporarily.
- Update LLP 0004 to describe the new loader path.
- Remove SWC dependencies after the fallback window.

## Risks

- **ESM/CJS interop drift.** Vite 8 explicitly changed some CJS interop behavior
  during the Rolldown migration (`[official docs]`
  <https://vite.dev/guide/migration#consistent-commonjs-interop>). Ibex's
  runtime loader has its own interop shim, so parity must be tested rather than
  assumed.
- **Async architecture pressure.** The cleanest Oxc/Rolldown path may want an
  async module runner, while the current loader is synchronous. Forcing that
  through the old shape may create more complexity than it removes.
- **Hermes target gaps.** The generated-artifact path already pins a Hermes
  target: `hermesRolldownTarget = 'es2020'` `[observed]`
  (`packages/ibex-devtools/src/scripts/transforms.mjs:23,867`). Rolldown's
  transform target otherwise defaults to `esnext`, and its documented lowest
  target is `es2015` (`[official docs]`
  <https://rolldown.rs/reference/InputOptions.transform#target>) — so a Rolldown
  graph path could not reach the `es5` the loader's scanners select for
  loop-scope downleveling `[observed]` (`src/module_loader/mod.rs:599-605`).
  Two caveats compound this: (a) that `es5` request is today honored only by the
  subprocess path, not the default in-process engine (see Current state); and
  (b) `es2015` is Rolldown's floor. The migration must define a real Hermes
  target — taking `es2020` as the existing baseline — and decide whether the rare
  `es5` loop-scope cases stay a separate Ibex/Hermes pass, rather than assuming
  browser targets map cleanly.
- **Decorator behavior.** Vite's migration docs note that Oxc does not lower the
  latest native decorators yet and suggests Babel or SWC as temporary lowering
  options (`[official docs]`
  <https://vite.dev/guide/migration#javascript-transforms-by-oxc>). Ibex should
  decide whether runtime-loaded decorators are supported, parsed-only, or
  rejected.
- **Rust API maturity.** The JavaScript Rolldown/Oxc APIs may be ahead of Rust
  crate APIs. The spike must verify the actual Rust integration point, not only
  the npm/Vite surface.
- **Binary size and compile time.** Replacing SWC with Oxc/Rolldown may reduce
  or increase native build cost depending on crate graph and feature selection.

## Acceptance criteria

This RFC is complete when:

- A fixture suite defines the transform contract.
- Generated artifact transforms are aligned with current Rolldown/Oxc where
  practical.
- An experimental in-process Oxc/Rolldown runtime transform exists behind a
  flag.
- The project has a Decision LLP, or this RFC is revised to `Accepted`, choosing
  one of:
  - Oxc single-file transform as the default runtime loader transform.
  - Rolldown graph transform as the default runtime loader transform.
  - A ModuleRunner-style loader redesign before replacing SWC.
  - A documented reason to keep SWC longer.

## Open questions

- Which exact Hermes target should the Oxc/Rolldown path use? The generated path
  already uses `es2020` (`transforms.mjs:23`); is that the runtime target too, and
  do the `es5` loop-scope cases stay a separate Hermes pass?
- Should `import.meta.main` and top-level await remain loader shims, or become
  transform-time rewrites? The bundle path already rewrites `import.meta.*` at
  transform time via Rolldown `define` `[observed]`
  (`packages/ibex-devtools/src/scripts/transforms.mjs:25-34`) — the question is
  whether to extend that to the runtime loader.
- Are decorators in runtime-loaded TypeScript part of the supported surface?
- Should the generated artifact path and runtime loader share one transform
  configuration file, or only share named constants and fixtures?
- How long should the SWC fallback remain after an Oxc/Rolldown default switch?
