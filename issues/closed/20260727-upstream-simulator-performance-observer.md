# Upstream the simulator performance observer before consumer adoption

**Status:** Closed
**Severity:** P2
**Systems:** Engine, Host ABI, Build, CapSec
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-27
**Related:** LLP 0039 (secure/insecure modes and observer boundary); LLP 0041
(main-lineage consumer pins)

## Problem

Exact's native performance instrumentation has executable evidence against
Ibex commit `45dc954a`, but that commit is reachable only from
`codex/llp0373-partitime-observer`. Committing that side-branch SHA as Exact's
`vendor/ibex` pin would violate LLP 0041's main-lineage and upstream-first
rules.

The required work is the seven-commit observer closure:

- `837b4674` — feature-gated simulator observer;
- `ef319099`, `f6c9dad5`, `d7a07b72` — loaded Hermes image attestation;
- `90f737fc` — patched-Hermes build probe;
- `4204c98e` — fail-closed image-auth diagnostics;
- `45dc954a` — cached Apple artifact authentication.

The closure is intentionally release-only, iOS-Simulator-only, absent from
default features, and governed locally by LLP 0039. It must remain an
instrumentation carrier rather than a product mode.

## Resolution criteria

1. Replay the seven commits onto current Ibex `origin/main` and preserve their
   feature and platform guards.
2. Run focused unit/build checks, secure-mode checks proportional to the CapSec
   change, `./ref-check --verbose`, and the downstream Exact/Snapback native
   carrier.
3. Land the verified closure on Ibex `origin/main`.
4. Advance Exact to the landed main-lineage SHA and remove its dependency on
   the observer side branch.

## Resolution

Closed 2026-07-27. The patch-equivalent observer closure landed on Ibex
`origin/main` through `11d15593`, followed by the authenticated canonical
registry reuse and focused cache-authentication coverage through
`28db869b`. The checks retained 4/4 precomputed-registry authentication
tests, the CLI/runtime canonical-byte equivalence test, the two open-file
identity tests, formatting, and `./ref-check --verbose`.

Exact `origin/main` now consumes `28db869b` at `ffd91d562`. A clean Air
Release/iOS-Simulator run against that Exact revision retained every
authenticated observer marker, rendered the first frame, and emitted real
first-authoritative-data custody. The observer remains feature-gated,
Release/iOS-Simulator-only, absent from default features, and separate from
ordinary Exact native artifacts.
