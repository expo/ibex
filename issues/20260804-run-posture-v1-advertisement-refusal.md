# `ibex run` refuses with "legacy v1 target advertisements are diagnostic-only" for a plain script consumer

**Date:** 2026-08-04
**Reporter:** Weird Castle dogfooding (multiplayer sim-core differential gate; Claude on behalf of Charlie)
**Binary:** `target/release/ibex` built 2026-08-03

## What happened

Weird Castle uses ibex as a native-Hermes host for its deterministic
simulation gate (`weird-castle/server/sim-core/ibex-host/launcher.mjs`).
Invoking:

```
ibex --history off --project-root <server-dir> run <generated>.mjs
```

on a trivial script (`console.log("weird-castle-ibex-ok")`) fails with:

```
capsec readiness: frame-attribution=present package-isolation=per-package lockdown=on dynamic-ceiling=not-configured
error: authorization context refused arming: legacy v1 target advertisements are diagnostic-only and remain closed
```

(`portable_target_admission.rs` — the checked target advertisements
resolve to schema v1, which is refused.)

Meanwhile, inside Codex's sandbox on the same machine, the same
invocation fails *earlier* with EPERM materializing the CapSec cache. So
the `run` posture is currently unusable for this consumer in both
environments, for two different reasons.

## Workaround in the consumer

`ibex --history off capsec audit <script>` runs the same engine fine
(exit 0, audit report noting `env:read:*` would-deny under enforce), so
the launcher falls back to audit posture on either failure signature.
This is fine for a benchmark/gate host, but enforce-mode is the posture
Weird Castle would eventually want on phones.

## Ask

Whichever is intended: (a) a supported way for a plain script consumer to
run under enforce without hand-authoring v2 target advertisements, (b)
`--project-root` generating/refreshing a v2 advertisements document, or
(c) documentation of the expected setup for external project roots. Also:
the HBC path (`ibex build`) hit the protected-bundle-cache write refusal
inside sandboxes — same cache-materialization theme.
