# LLP 0038: Unadvertised Dev Arming

**Type:** Decision
**Status:** Draft
**Systems:** Runtime, CapSec, Build
**Author:** Charlie Cheever / Claude
**Date:** 2026-07-22
**Related:** LLP 0021 (target advertisement + conformance report); LLP 0023 (mount table, project root); LLP 0029 (compiled-mode authority); LLP 0036 (target advertisement completion)

## Context

Ibex arms fail-closed. A production launch requires a checked *target
advertisement* — a conformance report that promotes coverage edges to armed
target cells — and the runtime refuses anything less. That is the correct
posture, but the advertisement pipeline is not finished (LLP 0036 measures what
remains: ~22k unresolved rows, no cheap bulk win). Until it lands, a default
build of `ibex` cannot arm at all, so `ibex eval`, `ibex repl`, and
`ibex run <file>` are unusable — the product does not run locally.

Two independent things blocked a local run, and both had to be resolved:

1. **Arming**: no advertisement exists, so target promotion fails outright.
2. **Authorization**: even once armed, the *synthesized* default policy grants
   the root principal nothing, so the root principal cannot read its own entry
   program or any project file.

## Decision

Add a **compile-time** Cargo feature, `unadvertised-dev-arming`, off by default
and never enabled in a shipped build. It makes exactly two changes.

### 1. Synthetic complete target cells

`Host::new_armed_unadvertised_dev` builds a complete cell map directly from
`CAPSEC_COVERAGE_EDGE_IDS` instead of deriving promotion from a conformance
report. Every other startup authenticator still runs unchanged: loaded-engine
identity, protected artifacts, root bindings, and snapshot authentication.

### 2. Root authority ceiling raised to the project subtree

The synthesized default policy carries an empty `rootCeiling`. The root
authority ceiling is a **hard gate**: `evaluate_decision_set_inner` denies at the
`RootAuthorityCeiling` stratum (step 6) *before* reaching any floor stratum or
the `AmbientRoot` stratum (step 15) that would otherwise authorize a root
principal. With an empty ceiling, ambient root is constrained to nothing, so
every root `fs:*` effect is denied — including the entry-program read that
`ibex run <file>` performs, and every `fs.*` call in the REPL.

Under the feature, and **only when synthesizing the default policy**, the
ceiling is raised to `fs:list`, `fs:read`, and `fs:write` over the project
subtree (`path-tree` rooted at `project`). Ambient root then authorizes reads
and writes inside the project.

This is deliberately the *ceiling*, not the floor. The floor strata are never
reached for these effects, so a floor grant — static or bootstrap — does not
authorize them:

- the **bootstrap floor** applies only while `bootstrap_phase_active()`, a
  startup window already closed when a program reads files;
- the **static floor** is evaluated at step 11, after the step-6 ceiling gate
  has already returned `Deny`.

### What this does *not* relax

- **The mount boundary still holds.** Paths outside the project resolve to
  `ERR_IBEX_OUTSIDE_MOUNT` — the ceiling covers the project subtree only.
- **Non-`fs` effects stay closed.** Network, environment, and every other
  capability remain outside the ceiling and are still denied.
- **Authored policies are never widened.** The ceiling is raised only on the
  synthesized default; an `ibex-policy.json` is untouched.
- **No new runtime surface.** Being compile-time, the feature adds no
  environment variable and no CLI flag. This is why it is a feature and not a
  runtime flag: an earlier env-var design (`IBEX_EXPERIMENTAL_UNADVERTISED_DEV`)
  was rejected because the environment surface inventory prohibits process-global
  `set_var` writes, and the flag would have been new attack surface in a
  production binary.

A loud banner is printed on every run so an unadvertised build is never mistaken
for a conforming one.

## Consequences

`ibex eval`, `ibex repl`, and `ibex run <file>` work locally. Because the REPL's
worker snapshot is built by the parent (`prepare_session_worker_runtime` →
`build_host_with_route` → `build_default_armed_host`) and passed to the worker,
the single ceiling change covers both the in-process and worker paths.

The security claim of a feature-on build is materially weaker than a conforming
build: it asserts only that effects outside the project subtree are enforced. It
is a development convenience, not evidence of correctness.

## Removal condition

Delete this feature once the advertisement pipeline of LLP 0036 lands and a
default build can arm from a real conformance report. This document should be
tombstoned at that point.
