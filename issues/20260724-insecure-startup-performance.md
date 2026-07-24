# Restore fast Ibex startup, prioritizing insecure REPL and embedded use

**Status:** Open — dominant costs fixed 2026-07-24; budgets, CI gate, and
embedded benchmarks remain.

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
   builds unaffected).
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

Remaining for this ticket: reproducible cold/warm benchmark harness for REPL
first-prompt and embedded runtime creation, a pre-CapSec baseline comparison,
precommitted budgets (author decision, per
issues/20260717-sfe-measured-budgets.md item 7 — budgets before measurement),
and a CI regression gate that reports distributions.
**Severity:** P1
**Systems:** CLI Runtime, REPL, Embedded API, CapSec, Performance
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-24
**Related:** LLP 0038; LLP 0039; ENG-24720; ENG-24643; issues/20260717-sfe-measured-budgets.md

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

