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

## Fully open mode (dev-capsec-off)

`dev-capsec-off` implies `unadvertised-dev-arming` and additionally:

1. arms `rootAuthorityCeiling` as `{"kind": "unbounded"}`, so `ceiling_allows`
   is true for every effect and ambient root authorizes any typed capability
   rather than only the project fs subtree; and
2. lets the legacy capability shim (`Host::check_capability` and friends)
   answer normally instead of hard-denying. Those methods return `false`
   whenever `decision_context.is_some()`, which closes capabilities that have
   no typed path yet.

**Enforcement is not one switch.** Capability families are gated by different
mechanisms, and this feature only reaches two of them. Measured behaviour:

| effect | `dev-capsec-off` | gated by |
|---|---|---|
| project fs (relative + absolute) | works | typed decision engine — root ceiling |
| `child_process` spawn | works | legacy shim (`checkCapability("process:spawn")`) |
| paths outside the project | **still refused** | VFS mount, single backing root |
| `fetch` / network | **still refused** | native armed gate, see below |
| `process.env` | **still empty** | never populated from the host env |

Two of these are not permission problems and cannot be granted:

- **Network.** `src/engine/hermes_runtime_fetch.cc` throws
  `"typed network:fetch transport is unavailable"` whenever
  `ex_host_is_armed() == 1`. Armed fetch is deliberately closed until the
  transport reports the requested/candidate/verified-peer facts the typed model
  needs, and must not fall back to the legacy string oracle (LLP 0021 WP6).
  Enabling it is feature work, not configuration.
- **Paths outside the project.** `VirtualFileSystem` has a single
  `BackingMount` (`/project` → one host root), so a wider mount is an
  architectural change rather than a grant. The practical workaround is to run
  Ibex from a project root that contains what the script needs.

So `dev-capsec-off` means "capability *decisions* stop refusing", not "the
sandbox is gone". Do not read it as a way to reach the host filesystem or the
network.

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
