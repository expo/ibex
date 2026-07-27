# Seven `--bin ibex` observer tests are red on a secure build of main

**Status:** Open
**Severity:** P2
**Systems:** Engine, Module Loader, Runtime, Testing
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-27
**Related:** [20260727-armed-observer-suite-needs-secure-build](./20260727-armed-observer-suite-needs-secure-build.md), LLP 0039

Measured 2026-07-27 on main at 43ef63e9 with the explicit secure observer
build:

```
cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer
```

Result: 612 passed, 8 failed, 1 ignored. One failure
(`public_os_read_denial_stops_before_commit_and_data_access`) passes when the
suite runs `--test-threads=1`, so it is parallelism-flaky rather than red.
The other seven fail deterministically, and fail **identically on
pre-landing main (3c1f24b3)** in a clean worktree — they are pre-existing,
not caused by the 2026-07-26/27 capsec restamp/regen landings. Since no CI
job runs this exact suite, they accumulated silently (same mechanism as the
sibling ticket).

## The seven, by family

**A. Frozen cross-language vector drift (1):**
- `capsec_exact_fixture_evidence_batch::portable_fixture_domain_matches_the_frozen_cross_language_vector`
  — computed `sha256-kWrfSYj6t1fD1xc6dMEmD_sJLSd1oJ7KytBj3M5VJ6M` vs frozen
  `sha256-swK95uvOY_8ch8RLuQDEVKtG2PPRIpsay-nUU6dUAEw`
  (capsec_exact_fixture_evidence_batch.rs:368). Same restamp discipline as
  the other frozen vectors: find the drifting commit, review, re-freeze —
  don't blind-restamp.

**B. Armed startup root-global disposition refusal (1):**
- `capsec_public_callback_invariant_batch::capsec_callback_invariant_mechanisms_smoke`
  — armed startup refuses with `extra post-bootstrap roots: $_` (then
  endowment install returns -6). `$_` is the structured-session last-value
  accessor (hermes_runtime.cc ~10392, present since 9e1e5d8e); either the
  smoke test's boot path started binding the structured session before the
  disposition sweep, or the sweep started observing an accessor it used to
  skip. The generated root-global-disposition manifest contains no `$_`
  entry.

**C. Compat-loader / manifest resolution (5):**
- `runtime::tests::authenticated_commonjs_require_uses_call_time_compatibility_vfs_context`
  and `authenticated_native_tla_wakes_from_host_io_without_a_javascript_timer`
  — graph preflight fails with `internal builtin resolution requires an
  exact manifest specifier`.
- `authenticated_compatibility_loader_stays_alive_through_delayed_dynamic_import`
  — `an authored dynamic import entered the eager native graph`.
- `closed_compatibility_window_fails_loudly_for_authored_call_time_edges`
  — expected a closed-window refusal, got a plain
  `Cannot find module './missing.mjs'` resolution error.
- `compatibility_call_time_refusals_preserve_import_and_require_error_timing`
  — expected `Completed`, got `authenticated module graph preparation
  failed`.

  All five smell like one root cause in the compatibility-window /
  builtin-manifest classification path (LLP 0026/0027 territory); bisecting
  family C first will probably explain all five at once.

**Done when:** the seven pass (or are individually dispositioned with a
review) on the secure observer build, and the flaky
`public_os_read_denial_stops_before_commit_and_data_access` either survives
parallel runs or is documented as serial-only.
