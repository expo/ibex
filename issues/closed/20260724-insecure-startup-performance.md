# Restore fast Ibex startup, prioritizing insecure REPL and embedded use

**Status:** Resolved 2026-07-26.
**Severity:** P1
**Systems:** CLI Runtime, REPL, Embedded API, CapSec, Performance
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-24
**Related:** LLP 0038; LLP 0039; ENG-24720; ENG-24643; issues/20260717-sfe-measured-budgets.md

## Resolution (2026-07-26)

The end-to-end completion meets the precommitted startup budgets on both
supported development platforms and both runtime profiles. The committed
benchmark in `benches/startup_performance.rs` observes a real REPL prompt
through a pseudoterminal, measures trivial `eval`, `run`, package dispatch, and
the direct embedder boundary, and reports min/median/MAD/p95/max for five
discarded warmups plus forty measured samples. A fresh `HOME` and application
cache define the cold distribution; the warm distribution reuses them. Both
retain normal operating-system page cache. All measurements below are release
builds.

Final p95 process results, in milliseconds:

| host/profile | warm REPL | warm eval | warm run | warm package | cold REPL | cold eval | cold run | cold package |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Apple-silicon Mac mini, insecure | 39.441 | 22.565 | 45.305 | 7.340 | 113.001 | 96.561 | 114.709 | 7.464 |
| Apple-silicon MacBook Air, secure | 165.821 | 100.738 | 285.658 | 7.273 | 215.494 | 143.225 | 327.256 | 7.373 |
| Minisforum x86-64 Linux, insecure | 57.135 | 39.594 | 50.529 | 9.534 | 78.151 | 48.498 | 66.390 | 9.248 |
| Minisforum x86-64 Linux, secure | 118.197 | 78.445 | 134.823 | 9.103 | 125.832 | 80.443 | 135.904 | 8.924 |

Final direct-embedder p95 results:

| host/profile | runtime + Host | bootstrap complete | first evaluation | ready total |
|---|---:|---:|---:|---:|
| macOS, insecure | 4.230 | 4.230 | 0.038 | 4.267 |
| macOS, secure | 3.577 | 3.577 | 0.033 | 3.610 |
| Linux, insecure | 5.147 | 5.147 | 0.054 | 5.197 |
| Linux, secure | 4.988 | 4.988 | 0.052 | 5.039 |

The macOS insecure run also rebuilt and measured the named pre-CapSec revision
`3a0c1b6c91ff568169f6a03e611f226eb7e6b99b` on the same machine and toolchain:
current/baseline p95 was 2.273× for trivial eval and 2.984× for trivial run,
both within the precommitted 3× ceiling. The complete JSON reports retain the
machine uname, revision, every distribution, budget, comparison, and failure
list.

The final attributable fixes were:

- compile-time insecure mode no longer hashes the roughly 108 MB executable
  for every module-producer identity when that build makes no binary
  authentication claim; it uses the canonical transform-contract fingerprint.
  Secure builds retain mapped-executable authentication.
- build.rs emits the exact canonical registry-record bytes it already derives,
  and runtime validates/pins those bytes instead of reparsing and
  re-canonicalizing roughly 17 MB on every cold registry construction.
- Linux Hermes source/prebuilt artifacts now publish the matching Hermes VM
  CLI beside `hermesc`. `build.rs` can therefore prove compiler/runtime HBC
  version 99 and precompile the core runtime bundle. Linux trace attribution
  moved `shared_runtime_bundle` from roughly 60–100 ms of source evaluation to
  2.5 ms of HBC loading; embedded constructor p95 moved from 71.12 ms to
  5.15 ms without changing the 70 ms budget.
- authenticated module graph preparation, linking, evaluation, registry
  construction, engine creation, bundle evaluation, and readiness boundaries
  now have distinct phase marks. One-shot insecure module-graph preparation
  fell from roughly 270 ms to 27 ms after removing the executable rescan.

The weekly/manual `.github/workflows/startup-performance.yml` matrix enforces
all absolute budgets on macOS arm64 and Linux x86-64 for insecure and secure
builds, performs the named baseline comparison for insecure builds, and
retains each JSON report for 90 days. Baseline Hermes state is isolated from
the current mutable source cache, and the Linux lane installs the complete
native source-build prerequisites.

Completion audit:

| required outcome | evidence |
|---|---|
| reproducible cold/warm REPL, CLI, package, and embedded distributions | benchmark harness, fixtures, JSON schema/report, real PTY prompt observation, 5 + 40 measurement policy |
| insecure and secure measurements on supported development platforms | four full enforced distributions above, all with empty failure lists |
| attributable startup phases | launcher and native trace marks; targeted before/after traces above |
| pre-regression comparison and budgets before optimization | budget-only commit `895552da`; named revision and same-host 2.273×/2.984× comparison |
| compile-time-only insecure deviation; secure fail-closed behavior preserved | insecure identity test, secure build/checks, unchanged secure executable authentication, shared canonical-byte verification |
| stable periodic regression gate | weekly/manual four-cell workflow with p95 enforcement and retained artifacts |

The benchmark uncovered a separate secure-REPL lifecycle bug: after publishing
a usable prompt, operator EOF is denied and exits status 1. Prompt measurement
now terminates and reaps its PTY wrapper after the observed readiness boundary;
the functional EOF defect remains tracked independently in
`issues/20260726-secure-repl-operator-exit-denied.md`.

## Progress (2026-07-25)

### Historical deferred WebGPU activation follow-up (superseded)

This section is retained as measurement and extraction history only. Its
`webgpu-binding`, embedded secondary bundle, GPU provider registration, and
`ex_hermes_activate_webgpu_runtime_v1` prescriptions are no longer current
work. LLP 0040 now owns Ibex's generic extension substrate; Exact LLPs 0115 and
0405 own WebGPU startup and conformance decisions.

The next implementation phase moves the remaining feature-on startup penalty
off Exact's startup-critical path rather than making WebGPU unavailable. The
approved design is governed by LLP 0002, with LLP 0003, LLP 0005, and LLP 0022
synchronized:

- every build starts with the 1.17 MB core runtime bundle, including
  `webgpu-binding` builds;
- the approximately 1.19 MiB production wrapper/codec graph is a second
  hermetic vendored source/HBC artifact embedded only by `webgpu-binding`;
- provider registration/finalization authenticates and retains a dormant
  provider but does not evaluate that artifact, open a realm, or publish
  `navigator.gpu`;
- Exact calls the additive owner-thread
  `ex_hermes_activate_webgpu_runtime_v1` after first paint or immediately before
  loading a GPU-backed feature;
- activation excludes user and debugger ingress, evaluates the trusted
  secondary artifact, opens/captures/seals the provider, refreshes only the
  generated conditional WebGPU compartment roots, and repeats the exact
  descriptor sweep before resuming;
- activation failure after any mutation is terminal. Before activation,
  feature detection truthfully reports WebGPU absent, so Exact must activate
  before importing TypeGPU or other code that caches that result.

Acceptance for this phase:

1. A `webgpu-binding` build with a registered but dormant provider has startup
   within measurement noise of the core build and exposes no WebGPU roots.
2. Activation works both before and after bootstrap closure, opens one realm,
   evaluates the secondary bundle once, and is idempotent after success.
3. Late activation makes WebGPU visible to the root realm and existing package
   compartments without capturing unrelated application-created globals.
4. Provider, bundle, capture, baseline-refresh, sweep, or debugger-restoration
   failures leave no ambiguous usable runtime.
5. Benchmarks report startup and activation distributions separately. The
   expected result is to remove roughly 65–70 ms from Exact startup while
   retaining that cost at the explicitly scheduled activation point.

Implementation and focused verification completed on 2026-07-25. The
feature-on and feature-off release executables were measured in an alternating
40-pair warm-launch run on the Apple M5 Max host so unrelated machine load
affected both configurations symmetrically:

| phase | feature off median | feature on median | paired feature-on delta |
|---|---:|---:|---:|
| shared core runtime bundle | 7.17 ms | 7.24 ms | **+0.45 ms** |
| Hermes runtime total | 17.81 ms | 17.60 ms | **+0.30 ms** |
| CLI runtime initialized and ready | 30.07 ms | 31.36 ms | **+0.79 ms** |

The paired delta is the median of the 40 individual feature-on minus
feature-off pairs, not the difference between the two independently sorted
medians. Heavy concurrent compiler activity made the tails unsuitable as a
baseline, but the controlled median comparison establishes that retaining the
dormant WebGPU artifact does not recreate the old 65–70 ms eager-evaluation
penalty. In a separate less-contended 40-launch feature-on sample, the shared
bundle, Hermes runtime total, and CLI-ready medians were 5.47 ms, 13.18 ms,
and 22.91 ms respectively.

Release-mode activation passed and emitted distinct
`deferred_webgpu_runtime` and `webgpu_runtime_activation_total` phases. A clean
activation distribution still needs to be captured: repeated runs during this
pass were dominated by approximately 20 unrelated compiler processes and are
deliberately not adopted as performance evidence. The earlier clean eager
penalty remains the useful scheduling estimate until that remeasurement.

Focused behavior verification covers feature-off stable unsupported status,
dormant registration, activation after bootstrap closure, activation after
user work with targeted compartment refresh, idempotency, synchronous and
service-thread provider callbacks, and terminal rollback/quarantine when the
post-publication root sweep discovers an undispositioned root. Vendored
regeneration, generated-artifact drift, C ABI compilation, and `ref-check`
also pass.

The default/insecure release runtime now reaches the initialized-and-loaded
ready point within the raw-Hermes comparison band. Measured on an Apple M5 Max,
macOS 26.5.2 arm64, warm filesystem cache, this repository as the project root,
with five warmups and 40 measured process launches:

| phase | min | median | p95 | max |
|---|---:|---:|---:|---:|
| runtime/Host construction | 7.75 ms | **10.04 ms** | 11.54 ms | 12.12 ms |
| Hermes creation + core shared bundle | 13.91 ms | **15.68 ms** | 17.56 ms | 18.24 ms |
| final runtime loading/sealing | 1.22 ms | **1.95 ms** | 2.39 ms | 2.47 ms |
| CLI runtime initialized and ready | 25.59 ms | **27.87 ms** | 30.63 ms | 31.16 ms |
| complete trivial-eval process wall | 45.38 ms | **48.33 ms** | 51.70 ms | 53.22 ms |

After the final generated-profile rotation and exact-tree rebuild, a separate
three-warmup/20-launch confirmation measured runtime-ready at 28.63 ms median
and 34.40 ms p95 (34.63 ms max).

Before this pass, three release traces put runtime-ready at 89.3, 101.3, and
120.0 ms. The principal cause was not raw Hermes allocation (roughly 1–4 ms):
ordinary builds embedded and evaluated the optional production WebGPU wrapper
and generated codec graph even though `webgpu-binding` was disabled. That graph
was about 1.03 MiB and made shared-bundle evaluation take roughly 72–88 ms.

The runtime build now has two startup/activation hermetic vendored bundles:

- `embedded_runtime_bundle.js` is the 1,168,433-byte core/default bundle. It
  retains the small one-shot GPU construction-capture fence but cannot publish
  WebGPU without the compile-time provider seam.
- `embedded_runtime_webgpu_bundle.js` is the 1,251,045-byte deferred
  production wrapper/codec graph embedded only by `webgpu-binding`.
  The canonical `build:runtime` command still builds a separate maximal tooling
  entry so CapSec surface discovery covers the union profile;
  `build:runtime:core` and `build:runtime:webgpu` produce the two runtime
  artifacts.

Representative core shared-bundle evaluation is now 6–9 ms. The feature-on
build now starts from those identical core bytes and retains the deferred
artifact without evaluating it. Provider activation pays the wrapper/codec
evaluation cost at the explicit activation point instead.

Additional default/insecure savings are compile-time only, under LLP 0038:

- engine identity uses the build receipt plus mapped-object identity instead of
  rescanning the Hermes image;
- the precomputed registry record avoids rereading its 17 MiB authenticated
  artifact after cheap file/object checks;
- `Host` skips protected-artifact and duplicate engine proof passes that make
  no security claim in a fully-open build;
- builtin registry aliases borrow one embedded static source rather than
  cloning about 2 MiB for every Host;
- the final generated root-global disposition proof is compiled out only of
  `insecure`; lifecycle setup, bridge capture, cleanup, sealing, and bootstrap
  closure still run.

The secure development profile compiled and executed successfully with the
same core bundle. Its trace retained engine hashing, registry hashing,
protected-artifact validation, and a 36.8 ms
`runtime_finish_bootstrap` disposition proof, demonstrating that the
insecure-only gates did not weaken the secure artifact.

Tracing now distinguishes runtime construction, actual Hermes initialization,
shared-bundle evaluation, preload, native global sealing, compartment
finalization, bootstrap closure, runtime-ready, and user evaluation. Focused
tests cover borrowed builtin aliases and equality between insecure receipt
identity and the fully verified engine identity. The full generated-artifact
drift workflow, CapSec reviewed-range digests, environment inventory, contract,
policies, both runtime bundles, and `ref-check` were refreshed and verified.

At the end of this pass, the broader original scope still required
precommitted budgets, REPL/embedded/package-script benchmark harnesses, a
baseline comparison, and a CI regression gate; the 2026-07-26 resolution above
completed them.

## Progress (2026-07-24)

Phase tracing now covers the arming ceremony: `IBEX_STARTUP_TRACE=1` emits
`arm_readiness_check`, `arm_engine_identity`, `arm_policy_load`,
`arm_packages_auth`, `arm_snapshot_document`, `arm_registry_record`,
`arm_artifact_materialize`, `arm_snapshot_build`, `arm_snapshot_load`,
`arm_host_new`, `engine_create`, and `eval_runtime_from_cli`
(`StartupPhaseTrace` in `src/bin/ibex/runtime.rs`).

Measured on the default/insecure **debug** build (macOS arm64, M-series, warm
cache, this repo as project; single-run wall times via `time`, spread across
3 runs ≤0.02s unless noted):

| route | before | after |
|---|---|---|
| `ibex eval '1+1'` | 3.9–4.9 s | **0.26 s** |
| stdin worker program (`echo … \| ibex`) | ~5 s | **0.55 s** |
| `ibex run` trivial `.mjs` | ~5.9 s | **1.17 s** |

Two causes dominated, both fixed:

1. **Debug codegen on startup-critical crates.** SHA-256 and JSON work ran at
   opt-level 0: the engine-identity digest of the 8.5 MB hermesvm dylib took
   533 ms, snapshot/protected-artifact hashing ~1 s, registry JSON handling
   ~2 s. Fixed with `[profile.dev.package.*]` opt overrides for `sha2`,
   `serde_json`, `ryu`, `itoa`, and `capsec-semantics` (Cargo.toml; release
2. **The registry record was reconstructed every launch.** Arming re-parsed
   ~17 MB of embedded registry JSON and re-JCS-canonicalized it (450 ms even
   with optimized crates) only to byte-compare against the already-pinned
   cache artifact. build.rs now precomputes the record's JCS content digest
   with the same capsec-semantics code (byte-identical by construction; a
   skew-guard test `precomputed_registry_record_digest_matches_runtime_construction`
   pins that), and warm startups authenticate the pinned artifact by digest —
   SHA-256-equivalent to the byte comparison, same regular-file/read-only
   pinning checks, any doubt falls back to the full cold construction.
   Warm `arm_registry_record`: 450 ms → ~35 ms; cold first run: ~950 ms once
   per registry change.

Notes against the original suspect list:

- ENG-24720 (node_modules hashed twice): `arm_packages_auth` measured only
  ~12 ms in this repo for trivial startup, so it is not the inner-loop
  bottleneck here; the duplicate graph-prep hashing
  (`runner_pipeline.rs#package_tree_integrity`) still exists and still
  matters for bundled startup on real dependency trees. Left open.
- These were shared-path fixes: secure (`standard,unadvertised-dev-arming`)
  startup takes the identical warm-pin and codegen improvements, and
  `scripts/check-secure-mode.sh` passes on the same tree.

At that point, the remaining work was a reproducible cold/warm benchmark
harness for REPL first-prompt and embedded runtime creation, a pre-CapSec
baseline comparison, precommitted budgets (author decision, per
issues/20260717-sfe-measured-budgets.md item 7 — budgets before measurement),
and a CI regression gate that reports distributions. The resolution above
records their completion.

## Precommitted budgets (2026-07-26)

Before implementing or running the completion harness, the startup budgets were
committed in `benches/startup-budgets-v1.json`. The authoritative comparison
revision is `3a0c1b6c91ff568169f6a03e611f226eb7e6b99b`, immediately before the
first LLP 0013 implementation commit. The harness must report median, MAD, and
p95 over five warmups and forty measured launches for both fresh application
cache and reused application cache. "Cold" deliberately means a fresh `HOME`
and Ibex cache while retaining ordinary operating-system page cache; dropping
the machine-wide page cache would require privileged, disruptive measurement
and would not model the developer loop.

The default/insecure p95 limits are the acceptance budgets. Secure-development
limits are explicit but wider because loaded-engine, registry, protected
artifact, snapshot, policy, and final root-disposition proofs are part of that
profile's security claim. Package-script dispatch is expected to remain nearly
mode-independent because it does not create a Hermes runtime. The direct
embedder diagnostic has the same limit in both builds because it does not
install the launcher's insecure ambient-environment projection.

The pre-CapSec comparison additionally requires current trivial `eval` and
`run` p95 to remain within 3× of the named revision. That ratio is intentionally
looser than the absolute Apple Silicon budget: it accommodates old/new compiler
and engine artifacts while still detecting the multi-second regression that
opened this ticket.

## Problem

Ibex startup has become painfully slow during the CapSec work. The delay is
especially visible when starting the default/insecure REPL, where time to first
prompt is part of the inner development loop. Trivial `eval`/`run` invocations
may share the same fixed costs, and embedded Ibex may be paying authentication,
registry, snapshot, graph, bundle, worker, or engine setup costs that are
unnecessary or repeatedly recomputed.

Insecure mode currently retains much of the secure arming/authentication
startup machinery even though it disables enforcement. That may be valuable
for shared-path coverage, but it is not free and has not been justified against
a startup budget. Secure mode should also improve where work can be shared or
cached safely, but insecure developer experience is the first acceptance
target.

Existing Linear investigations cover known contributors:

- ENG-24720: recursively hashing all of `node_modules` twice during bundled
  startup.
- ENG-24643: cold diagnostic startup costs causing integration-test timeouts.

This ticket owns the end-to-end latency outcome and may close, split, or absorb
those contributors based on measurement.

## Required work

1. Establish reproducible cold and warm benchmarks for:
   - process start to first usable REPL prompt;
   - trivial `ibex eval` and `ibex run`;
   - package-script dispatch;
   - embedded runtime creation, bootstrap completion, and first evaluation.
2. Measure both the default/insecure build and the secure development build
   (`standard,unadvertised-dev-arming`), with insecure as the immediate
   priority. Record hardware, build profile, cache state, and distributions
   rather than a single best run.
3. Add or extend phase tracing so time is attributable to engine loading,
   artifact/registry authentication, policy and snapshot construction, module
   graph preparation, bundle evaluation, worker creation, and duplicated
   parent/worker work.
4. Compare against a pre-regression Ibex commit or release and agree on
   explicit cold/warm budgets before fitting optimizations to the current
   measurements.
5. Remove, cache, defer, or share unnecessary work. In insecure mode,
   security-only proofs may be skipped only when the compile-time mode makes
   the lack of a security claim explicit; do not create a runtime-controlled
   bypass that can weaken a secure build.
6. Apply mode-independent improvements to secure and embedded paths where they
   preserve authentication and fail-closed behavior.

## Guardrails

- Do not fix benchmarks by hiding startup work after the prompt if the runtime
  is not actually ready or if the deferred work causes the first command to
  stall unpredictably.
- Keep the insecure warning visible without making warning emission a
  measurable startup bottleneck.
- Do not weaken secure target advertisement, artifact identity, protected
  object, snapshot, or policy checks.
- Treat CLI parent/worker duplication and embedded repeated-runtime creation as
  first-class cases; optimizing only one-shot `eval` is insufficient.

## Done when

- Benchmarks and phase traces identify the dominant costs on current `main`.
- Precommitted cold and warm budgets exist for REPL, trivial CLI execution, and
  embedded first evaluation.
- Default/insecure startup meets those budgets on supported development
  platforms and is materially comparable to the recorded pre-CapSec baseline.
- Secure mode is no slower as a result except for measured, documented checks
  that are necessary to its security claim.
- CI has a stable regression gate or periodic benchmark that reports the
  relevant distributions without relying on flaky wall-clock test timeouts.
