# `ibex compat --probe`: executable three-point fault localization for engine-attributed bugs

**Filed:** 2026-07-26 (from Exact LLP 0404 N-1; both of that plan's review
families independently asked for this to be executable rather than
procedural)

Exact LLP 0404 establishes an observation discipline for engine-attributed
incompatibilities: measure at **raw engine** (pinned `hermes` binary, no
bootstrap), **post-bootstrap** (after prelude/polyfills/lockdown), and
**app-module evaluation** (served module record; ideally also packaged HBC)
before choosing a fix tier. The `Error.prototype.name` P0 showed why: the
raw engine was spec-correct and the lockdown was the cause (repaired on main
by the fix/lockdown-error-prototype-overrides merge) — an engine patch would
have been the wrong tier and a wasted rebase burden.

Today that measurement is a hand-rolled two-line script per investigation.
Make it a harness:

- `ibex compat --probe '<expr>'` (or a probe file) runs the same probe at
  each observation point and emits the measurement tuple as JSON, naming
  the **first edge where behavior diverges**.
- Output shape feeds the LLP 0404 N4 registry row directly (and can be
  keyed by the runtime-profile receipt once that exists), so "a fix landed
  without the measurement is a process violation" becomes mechanically
  checkable.
- Registration note: the `ibex compat` surface is governed by
  `runtime-surface.json` — the new flag needs its row.

Scope: raw + post-bootstrap points first (both are pure ibex); the served
module-record and HBC points can land later behind the same flag once a
host is available to the harness.
