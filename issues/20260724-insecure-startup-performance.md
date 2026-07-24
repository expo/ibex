# Restore fast Ibex startup, prioritizing insecure REPL and embedded use

**Status:** Open
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

