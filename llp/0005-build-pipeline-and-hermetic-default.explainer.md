# LLP 0005: The Build Pipeline and the Hermetic-Default Invariant

**Type:** Explainer
**Status:** Draft
**Systems:** Build, Engine, Runtime
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Revised:** 2026-07-15 (Hermes source-cache/asset identity binds every source receipt authority and the Darwin/Linux builders share one kernel-backed build lock); 2026-07-14 (ENG-24851: `hermesc -output-source-map` is a boolean and the compiler-derived `<-out>.map` is published to the caller's requested path); 2026-07-12 (ENG-24264: Windows Hermes DLL publication is content-digest checked, atomic per file, and bundle-serialized across build processes, with real Windows locked-file coverage); 2026-07-07 (run-time entry-bytecode cache fallback rule — ENG-23484); 2026-07-07 (run-time compile gate keys on the HBC bytecode version line — ENG-23495); 2026-07-11 (generated capsec registry bindings and drift gate — ENG-24145)
**Related:** LLP 0000; LLP 0001 (platforms); LLP 0003 (engine bridge); LLP 0004 (module loading)

## Summary

`build.rs` does three jobs: (1) it materializes the **generated JS layer** — the
builtin manifest, the transformed builtin modules, and the bundled shared
runtime — either by copying committed `vendored-generated/` artifacts (the
default, hermetic path) or by regenerating them from JS sources with bun/the JS
tooling (the `IBEX_REGENERATE_RUNTIME=1` dev path); (2) it emits source and
optional Hermes bytecode headers for bootstrap/runtime JS plus the Rust
`embedded_runtime.rs` module consumed by the `ibex` binary; and (3) it compiles
the C++ engine (`src/engine/*.cc`) with `cc` and links Hermes from
platform-specific paths or env overrides `[observed]` (`build.rs:321-351,
454-548, 711-781, 804-1224`). The binary ownership boundary is recorded in
[LLP 0010](./0010-ibex-binary-ownership.decision.md).
The headline invariant is narrower than "the whole native build is
self-contained": the default generated-JS path must not
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
  non-hermetic" (`build.rs:336-340`).
- If `IBEX_REGENERATE_RUNTIME=1` but the manifest generator is missing, it
  `panic!`s too (`build.rs:346-351`).

`[inferred: the loud-failure choice is deliberate — the extraction history
records a Linux build regression, which is exactly the class of bug a silent
fallback hides; failing closed makes "is this build hermetic?" observable at
build time rather than at runtime.]`

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

`generate_runtime_bundle_source_header` (`build.rs`) wraps
`embedded_runtime_bundle.js` into a C++ raw-string header
(`runtime_bundle_source.h`, symbol `SHARED_RUNTIME_BUNDLE_SRC`) and writes the
Rust `embedded_runtime.rs` module used by `src/bin/ibex/engine/hermes.rs`
`[observed]`. In standalone mode the source is the vendored bundle;
otherwise it is rebuilt by `rolldown-bundle.mjs` from
`packages/ibex-runtime-js/src/runtime-entry.ts` (`build.rs`;
`vendored-generated/README.md:23-27`). The engine installs this bundle at startup
([LLP 0003 §The bootstrap sequence](./0003-hermes-engine-bridge.explainer.md#the-bootstrap-sequence)).

## Bytecode precompilation (hermesc)

`build.rs` always emits bootstrap source headers from the JS files `[observed]`
(`build.rs:738-770`). For bootstrap bytecode, it checks the HBC version of
`hermesc` against linked Hermes. Missing or mismatched `hermesc` **panics**
unless `EXACT_ALLOW_FALLBACK` is set; with fallback allowed it emits an empty
bytecode header and the engine uses source `[observed]` (`build.rs:522-574,
576-735`). The runtime bundle source header is generated separately
`[observed]` (`build.rs:1288-1400`). Runtime-bundle bytecode generation also
checks `hermesc`, but skips with warnings on unavailable/mismatched compilers
instead of using the bootstrap panic path `[observed]` (`build.rs:1676-1735`).
The engine prefers bytecode and falls back to source at startup
([LLP 0003](./0003-hermes-engine-bridge.explainer.md),
`src/engine/hermes_bootstrap.cc:44-69`).

At run time the CLI keeps a parallel cache for **entry** bytecode: a bundled
(or standalone) entry is compiled to a sibling `.hbc` when `hermesc` is
available and reused while fresh (`src/bin/ibex/runtime.rs`,
`prepare_bytecode_entry`). Like the build-time paths, the run-time compile gate
(`compile_to_bytecode`) keys on the `HBC bytecode version:` line of both tools'
`--version` output — the version that determines load compatibility — and
proceeds when either line is absent, deferring to load-time rejection. It must
never compare positional tokens of the multi-line output: the runtime binary's
trailing `Features:` block made a last-token comparison fail on every call and
silently disabled this cache for the checked-in toolchain (ENG-23495). The
fall-back-to-source rule is deliberately
narrower here than at startup: only a genuine **load** failure — the buffer
rejected before any of the program ran (`is_bytecode_load_error`: version
mismatch, sanity-check rejection, prepare-time rejection) — may delete the
cached `.hbc`, set the process-wide bytecode-incompatible flag, and re-run the
JS source. An error thrown by the *program* must propagate as-is: unlike the
side-effect-free bootstrap, the entry's side effects (stdout, writes, network)
have already happened by the time the error surfaces, so a fallback re-run
would perform them all twice (ENG-23484).

When that run-time compiler is asked for a source map it passes
`-output-source-map` as a boolean flag. `hermesc` derives the staged map name as
`<-out>.map`; Ibex rewrites and digest-binds that generated file, then atomically
publishes it to the caller's requested map path. Passing that requested path as
the next argument is invalid because Hermes parses it as an additional input
(ENG-24851).

The per-file exception is `web-streams-polyfill.js`: it is optional startup
code, installed only when `EX_WEB_STREAMS_POLYFILL=1`, and Hermes 0.11-era
compilers reject its modern syntax. If `hermesc` fails only for this file,
`build.rs` emits an empty `WEB_STREAMS_POLYFILL_HBC` slot while preserving
precompiled HBC for the required bootstrap files `[observed]`
(`build.rs:609-722, 1562-1585`). If the polyfill is enabled at runtime, the
engine falls through to the source header and logs evaluation failures rather
than making the default runtime startup depend on the optional polyfill
`[observed]` (`src/engine/hermes_bootstrap.cc:768-796`;
`src/engine/hermes_runtime.cc:1442-1448`).

Windows is the exception to the strict bootstrap-HBC path: the
`ReactNative.Hermes.Windows` 0.71.x compiler can report a matching HBC version
while still rejecting modern optional bootstrap/runtime syntax such as async
functions and classes. `build.rs` therefore skips bootstrap HBC precompilation
on Windows and emits source headers as the supported startup artifact
`[observed]` (`build.rs:528-536`). It also skips shared-runtime-bundle HBC on
Windows because Windows startup does not install that bundle `[observed]`
(`src/engine/hermes_bootstrap.cc:81-91`; `build.rs:1691-1697`).

The macOS Hermes 0.11 compiler is stricter than the runtime authoring surface
too: it rejects BigInt literal syntax in bootstrap files while accepting
`BigInt(...)` constructor calls. Bootstrap code that must be precompiled on
macOS therefore avoids `123n` / `0x...n` literals even when the value is
semantically a BigInt `[observed]` (`src/engine/bootstrap/module-loader.js:1405-1446`).
The generated-artifact path handles the same parser limitation centrally:
`transforms.mjs` rewrites BigInt literals to `BigInt("...")` in bundled runtime
and builtin outputs before they are vendored or embedded `[observed]`
(`packages/ibex-devtools/src/scripts/transforms.mjs`).

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

## Capability-registry bindings

LLP 0021's capability registry is a separate committed generated-artifact
family. `generate-capsec-registry.mjs` discovers live runtime surfaces and
emits the production coverage/target datasets, observed-source manifest,
stable-ID schema, review tables, and Rust/C++/JavaScript/TypeScript bindings
`[observed]` (`packages/ibex-devtools/src/scripts/generate-capsec-registry.mjs`;
`capsec/registry/`; `capsec/generated/`; `src/capsec_registry_generated.rs`;
`src/engine/capsec_registry_generated.h`). The default native build consumes
only committed outputs, so it does not add a bun or `node_modules` dependency.

`scripts/regenerate-vendored.sh` refreshes this family before refreshing the
contract digests, while `scripts/check-generated-drift.sh` runs both generators
in non-writing check mode. A source-surface, classification, binding, or digest
change therefore fails the repository's single drift gate until all dependent
outputs are regenerated `[observed]` (`scripts/regenerate-vendored.sh`;
`scripts/check-generated-drift.sh`).

## C++ compilation

`build.rs` compiles `src/engine/*.cc` with the `cc` crate, setting per-platform
defines (`EXACT_NO_OPENSSL`, `EXACT_PLATFORM_IOS`, `EXACT_PLATFORM_WINDOWS`,
`EXACT_HAS_CURL`, `HERMES_ENABLE_DEBUGGER`, etc.) and selecting the crypto/fetch/
websocket source files per OS `[observed]` (`build.rs:804-1255`).
Crypto-backend selection and the platform matrix are owned by
[LLP 0001](./0001-target-platforms-and-ci-matrix.rfc.md) and mapped in
[LLP 0003](./0003-hermes-engine-bridge.explainer.md#crypto-is-platform-dependent-the-fragile-axis).
Hermes headers/libs are located via `HERMES_*` env vars or platform defaults
`[observed]` (`build.rs:180-260, 262-335`). Android additionally consumes React
Native JSI headers/libs via `JSI_*` env vars or the default Android PREFAB
extract under `android/react-android` `[observed]` (`build.rs:185-198,
212-247, 276-314`). Android native fetch/WebSocket are compiled from
`native_android_networking.cc` and delegate to the Java OkHttp bridge shipped
under `platform/android/java`. That bridge also supplies Android clipboard, raw
DNS, location, camera permission/device metadata, locale/screen/appearance,
accessibility, app-state/deep-link/configuration events, and platform-version
data to Hermes host globals `[observed]` (`src/engine/native_android_networking.cc`;
`src/engine/hermes_runtime_android.cc`;
`platform/android/java/dev/ibex/runtime/IbexNetworking.java`; `build.rs`). This
is a separate concern from the vendored-generated JS snapshot.

The default Hermes source ref is centralized in `scripts/hermes-version.sh`,
which pins an exact commit (`IBEX_HERMES_SOURCE_COMMIT`) because the upstream
`260318099.0.0-stable` branch name moves (ENG-23092), and upstream publishes
no prebuilt Darwin runtime/CLI tarballs for this release `[observed]`.
`scripts/download-hermes.sh` is the installer entry point; the from-source
builders are `scripts/build-hermes.sh` (Darwin: host `hermesc`/`hermes`, iOS
device/simulator frameworks, a macOS `hermesvm.framework`, headers) and
`scripts/build-hermes-linux.sh` (Linux: `libhermesvm`, `hermesc`, headers)
`[observed]` (`scripts/hermes-version.sh`; `scripts/download-hermes.sh`;
`scripts/build-hermes.sh`; `scripts/build-hermes-linux.sh`). `build.rs`
resolves either `hermesvm.framework` or `hermes.framework` from a macOS
framework parent and links the detected framework name; it intentionally does
not treat a Catalyst slice as a macOS runtime `[observed]` (`build.rs`).

### Prebuilt Hermes artifact bundles

A cold clone should not pay the ~hour patched-Hermes build (nor inherit
upstream toolchain breakage mid-bootstrap, the ENG-22565 failure class), so
`download-hermes.sh` is download-first (ENG-23147): it derives the **artifact
identity** `<hermes-commit-12>-<patch-digest-12>` — the pinned upstream commit
plus a digest of the carried `patches/hermes/` stack, one shared derivation in
`scripts/hermes-version.sh` (`ibex_hermes_patch_digest`) — and tries the GitHub
Release `hermes-<identity>` on `ccheever/ibex` before building. Each platform
asset and local source cache use a stronger key derived from that identity plus
the platform-builder and patch-application-authority digests. Downloads are
sha256-verified against the published `.sha256`, and a bundle is rejected
unless any applicable mapped-object source-profile receipt names that exact
stronger key, it carries the patched `ex_hermes_vm_current_package_id` export,
and it has a runnable
`hermesc` (an unpatched engine would make the LLP 0013
frame-attribution suite skip vacuously). On Darwin the bundle is unpacked into
`build-hermes.sh`'s cache and installed through its cache-hit path, so
downloaded and built installs share one codepath. Any miss, checksum mismatch,
or validation failure falls back to the from-source build; if the download
path was attempted and the source build also fails, the script exits nonzero
naming both causes (LLP 0018 — never a quiet partial install) `[observed]`
(`scripts/download-hermes.sh`; `scripts/hermes-version.sh`).

Bundles are published by `.github/workflows/hermes-artifacts.yml` (manual
dispatch, or push to `main` touching the pin, the patch stack, or the build
scripts). It builds via the same `build-hermes*.sh` builders (so the patch
stack is applied), asserts the patched export with `nm` before uploading, and
uploads authority-keyed per-platform tarballs + checksums idempotently (`--clobber`) to a
prerelease tagged `hermes-<identity>` — clearly an artifact cache, not a
product release. Because the identity includes the patch digest, editing a
patch or bumping the pin makes downloads miss (falling back to source builds)
until the workflow publishes the new identity; editing either builder, the
patch-application verifier, or the shared receipt/identity derivation selects a
new asset within that release and a new local cache key on both platforms.
Darwin and Linux source builders hold one kernel advisory file lock across
their complete checkout/patch/compile/cache/receipt mutation, and the downloader
joins it while installing a prebuilt bundle. The lock's inherited descriptor
survives while build descendants run and kernel close-on-exit recovers crashes
without an unlink or stale-owner race. The download path only serves
the pinned-commit, default-configuration build; non-default configurations
(`HERMES_ENABLE_DEBUGGER=false`, Linux `HERMES_ENABLE_INTL=true`) and
`IBEX_HERMES_FORCE_BUILD=1` go straight to source `[observed]`
(`.github/workflows/hermes-artifacts.yml`; `scripts/download-hermes.sh`).

Android remains a separate artifact channel. It consumes Maven/PREFAB artifacts
through `scripts/install-android-hermes.sh`; Maven Central does not yet publish
`com.facebook.hermes:hermes-android:260318099.0.0`, so the default Android
Hermes artifact remains `250829098.0.14` while React Android moves to the
published `0.86.0` JSI artifact `[observed]`
(`scripts/hermes-version.sh`; `scripts/install-android-hermes.sh`).

Hermes C++/JSI headers are not identical across the supported SDKs. The macOS
Hermes 0.11 headers do not expose native `MutableBuffer` ArrayBuffer creation,
`Runtime::queueMicrotask`, or `RuntimeConfig::MicrotaskQueue`; newer SDKs may.
`build.rs` probes the checked-in header text and defines
`EXACT_HAVE_JSI_MUTABLE_BUFFER`, `EXACT_HAVE_JSI_QUEUE_MICROTASK`, and
`EXACT_HAVE_HERMES_MICROTASK_CONFIG` only when those SDK APIs exist. It also
probes whether `HermesRuntime::hermesBytecodeSanityCheck` exists as a static
method before compiling the bytecode sanity-check call, because Android Hermes
exposes a similarly named interface method but not the static runtime method.
The C++ adapter can therefore keep one source tree without binding feature
availability to an OS name `[observed]` (`build.rs:1035-1048`;
`src/engine/hermes_runtime_internal.h:143-197`;
`src/engine/hermes_runtime_timers.cc:128-134`;
`src/engine/hermes_runtime.cc:1396-1402, 1520-1542`).

On Windows, the Hermes NuGet package separates import libraries under `lib/`
from runtime DLLs under `bin/`. `build.rs` therefore resolves a Windows
`HERMES_BIN_DIR` (defaulting to `tools/hermes/windows-$arch/bin`), emits it as
an additional native link-search path, and stages its DLLs into Cargo's profile
directory plus `deps/` so `cargo test` and `cargo run` binaries can load
`hermes.dll` and its companion DLLs at process start `[observed]`
(`build.rs`; `crates/windows-dll-staging`). Staging compares SHA-256 content,
not length or timestamps. A bundle-wide interprocess lock prevents concurrent
builds with different Hermes sources from interleaving the profile and `deps`
sets; each changed file is copied to a verified unique sibling and atomically
renamed into place. The profile also records its complete bundle digest; a
concurrent build selecting a different Hermes source fails before mutation and
must use a distinct `CARGO_TARGET_DIR` (or explicitly `cargo clean`). This
extends serialization across the later executable-launch window, when the
build-script lock itself is no longer held. A mismatched loaded/locked
destination is a build error, never a warning followed by stale reuse. The Hermes-independent staging crate
behaviorally tests same-length tamper plus future clock skew and concurrent
different-source refusal on every host; Windows CI additionally holds the
destination with an exclusive Windows handle and proves publication fails
without changing it `[observed]` (`crates/windows-dll-staging/src/lib.rs`;
`.github/workflows/ci.yml`).

The `host-http-server` feature controls whether the real Rust
`ex_host_http_*` implementation is linked. The `ibex` binary can compile
without that feature by using no-op Rust-side bridge shims, and should enable
it for the full runtime CLI profile ([LLP 0010](./0010-ibex-binary-ownership.decision.md)).
When the feature is off, `build.rs`
defines `EXACT_RUNTIME_USE_HTTP_STUBS` so the C++ adapter supplies no-op stubs
and the default build remains linkable `[observed]` (`build.rs:1059-1060`;
`src/engine/hermes_runtime.cc:2059-2086`). Non-MSVC builds mark those stubs weak
so an external strong implementation can override them; MSVC has no weak
symbols, so Windows gets strong stubs only in the feature-off build and omits
them when `host-http-server` is enabled `[observed]`
(`src/engine/hermes_runtime.cc:2060-2064`).

## Boundaries

- The JS authoring lives in `modules.ts`, `src/builtins/`, `src/engine/bootstrap/`,
  and `packages/ibex-runtime-js`; generators are in `packages/ibex-devtools`.
- Decision rationale for *why* extraction chose "vendor generated artifacts"
  over alternatives is inherited extraction history; not re-derived here.
