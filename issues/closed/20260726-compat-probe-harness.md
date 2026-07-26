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

## Resolution

**Shipped (2026-07-26):** `ibex compat --probe '<expr>'` — the first two
observation points, per this ticket's scope note.

What landed:

- `src/bin/ibex/compat/probe.rs` — the probe harness. One shared JS wrapper
  (identical at every point; only the environment varies) evaluates the
  expression, JSON-serializes the completion value (`undefined` → `null`),
  and captures throws as `{"error": {"name", "message"}}`. Harness-level
  faults at a point (engine exit, timeout, unparseable output) are
  normalized to `{"error": {"name": "EngineFailure", ...}}` so the tuple
  stays comparable; a missing raw binary is a hard, actionable error
  instead (fail-loud, per the ENG-23131 lesson).
- **rawEngine** — the pinned standalone `hermes` binary, no bootstrap.
  Resolution mirrors `run-hermes-compat-corpus.mjs::resolveHermesBin`:
  `IBEX_HERMES_BIN` wins, then a checkout-local `tools/hermes/hermes`
  found by walking up from the executable/cwd (which also covers the
  exact monorepo's copy when ibex is vendored at `vendor/ibex`). Runs
  with `-Xes6-block-scoping` unless `IBEX_LEGACY_HERMES_BLOCK_SCOPING`
  opts out, same as the conformance corpus; output travels via `print`.
- **postBootstrap** — a fresh in-process engine after `load_runtime()`
  (prelude, polyfills, intrinsics lockdown), constructed in the same
  Audit-host + unarmed-engine posture as `ibex capsec audit`
  (`Runtime::from_audit_cli`), i.e. no widening of production startup.
- **moduleRecord / packagedHbc** — explicitly deferred; always emitted as
  JSON `null` so the report shape is forward-compatible, and the
  divergence walk skips absent points (the edge-naming already handles
  them joining later).

JSON shape (one document on stdout):

```json
{
  "probe": "<expr>",
  "points": {
    "rawEngine":     {"value": ...} | {"error": {"name", "message"}},
    "postBootstrap": {"value": ...} | {"error": {"name", "message"}},
    "moduleRecord":  null,
    "packagedHbc":   null
  },
  "firstDivergence": "rawEngine->postBootstrap" | null
}
```

Divergence = deep JSON inequality between consecutive measured points;
`firstDivergence` names the first such edge (`null` when all measured
points agree).

Registration: `runtime-surface.json` gained the `probe` option row on the
`ibex compat` clap inventory plus its `utf8-string` entry in
`semanticRelations.nonEnumeratedParsers`; pinned by
`cli::tests::surface_manifest_matches_clap_tree` (green).

Verification evidence (macOS, tools/hermes present):

- `cargo test --bin ibex compat::probe` — 7 unit tests for the divergence
  computation and report shape, all green.
- `cargo test --test compat_probe` — 3 end-to-end tests driving the real
  binary (cli_eval.rs conventions; they skip with a note on machines
  without a standalone Hermes): `1+1` reports `firstDivergence: null`;
  `Object.getOwnPropertyDescriptor(Error.prototype,'name')` reproduces
  the motivating P0 measurement — rawEngine
  `{value:"Error", writable:true, enumerable:false, configurable:true}`
  vs postBootstrap the override-enabled accessor (no `writable`,
  `configurable:false` after JSON drops get/set), localized to
  `rawEngine->postBootstrap`; `null.missing` captures identical
  TypeErrors at both points and reports no divergence.
- `cli::tests::compat_probe_flag_parses`,
  `surface_manifest_matches_clap_tree`, `cargo fmt --check`, `./ref-check`
  all green; full `scripts/run-tests.sh --scope bin` run recorded in the
  landing commit.

Deferred: the served-module-record and packaged-HBC observation points
(land behind the same flag once a host is available to the harness), and
keying the tuple by the runtime-profile receipt for the LLP 0404 N4
registry row.
