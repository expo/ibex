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
ceiling is raised to:

| capability | resource | why |
|---|---|---|
| `fs:list`, `fs:read`, `fs:watch`, `fs:write` | `path-tree` rooted at `project` | file I/O within the project |
| `path:cwd-observe` | `session-state` `cwd` | **required for relative paths** |

Ambient root then authorizes reads and writes inside the project.

`path:cwd-observe` is not optional in practice. Resolving a relative path such
as `README.md` observes the session cwd *before* any `fs` effect is evaluated,
so with the `fs` capabilities alone every relative access still fails with
`EACCES: cwd: filesystem policy denied` — only absolute `/project/...` paths
work. Granting the `fs` family without it produces a REPL that looks fixed
under absolute-path testing and is still broken in ordinary use.

`path:cwd-mutate` (`process.chdir`) is deliberately omitted: the registry
restricts it to `path-exact`, so it could only ever name a single exact
directory rather than the project subtree.

Capability names here are the **decision** vocabulary from
`vendored-generated/capsec-runtime-projection.canonical.json`, not the legacy
bit-plane names in `src/host/capability_bits.rs` (`path:cwd-observe`, not
`process:cwd`). That file is also the authority for which resource kinds each
capability may select; arming refuses a mismatch, and refuses a ceiling that is
not canonically sorted and unique.

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
- **Other effects stay closed.** Network, environment, process spawn, and every
  other capability remain outside the ceiling and are still denied
  (`process.env.HOME` reads as `undefined`). The only non-`fs` grant is
  observing the cwd.
- **Traversal does not escape.** `../../../etc/passwd` resolves to
  `ERR_IBEX_OUTSIDE_MOUNT`, same as an absolute outside path.
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

## Fully open mode (insecure)

`insecure` implies `unadvertised-dev-arming` and turns **all** enforcement off.
It exists so that Ibex's own development is not blocked by a security model that
is still being built.

Enforcement is not one mechanism, so the feature reaches three:

1. **Typed decision engine** — arms `rootAuthorityCeiling` as
   `{"kind": "unbounded"}`, so `ceiling_allows` is true for every effect and
   ambient root authorizes any typed capability.
2. **Legacy capability shim** — `Host::check_capability` and friends return
   `false` whenever `decision_context.is_some()`, which closes capabilities that
   have no typed path yet (notably `process:spawn`). The feature makes them
   answer permissively.
3. **Native armed gates** — `ex_host_is_armed()` reports `0`. Roughly 46 call
   sites across `hermes_runtime_{fetch,net,http,fs,process,sqlite}.cc` refuse
   outright while armed; reporting unarmed sends each down its diagnostic path.
   This single point is what opens both the network and the host filesystem —
   the VFS mount restriction is enforced on the armed path.

Measured behaviour under `insecure`:

| effect | result |
|---|---|
| project fs, relative and absolute | works |
| `/etc/hosts`, and **writes outside the project** (`/tmp/...`) | works — no sandbox |
| `child_process` spawn | works |
| `fetch` over the real network | works (verified against a live local server) |
| `process.env` | still empty — see below |

`process.env` is **not** a security gate: Ibex never populates it from the host
environment, by design. It stays empty in every mode, so scripts that read
`process.env` need their values supplied another way.

### This is a real "no sandbox" build

Under `insecure` the process has the ambient authority of the user running it.
It must never be shipped or published, and untrusted code must never be run
under it. A red banner says so on every run, and the wording is deliberately
different from the `unadvertised-dev-arming` banner because the two make very
different claims.

### Layers or one switch?

The three mechanisms above are an artefact of an **incomplete migration** — the
typed engine is replacing the legacy shim, and the native gates are waiting on
typed transports — not a deliberate product design. They should not be exposed
as separate user-facing knobs: each additional toggle multiplies the matrix of
security postures that can ship by accident, and nobody debugging their own
script wants to reason about which of four layers is refusing.

The intended end state is therefore **one switch**, plus a policy file for
legitimate production grants:

| mode | purpose |
|---|---|
| default | secure; requires a real target advertisement |
| `unadvertised-dev-arming` | enforcement **on**, advertisement not yet required — how to exercise the security model while LLP 0036 is unfinished |
| `insecure` | everything off |

The middle mode is **transitional**: it disappears when the advertisement
pipeline lands, leaving exactly one security switch. Distinguishing *why*
something was refused is a job for error messages — which already differ
(`ERR_IBEX_OUTSIDE_MOUNT` vs a typed `EACCES` with a decision digest vs
`transport is unavailable`) — not for build flags.

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
