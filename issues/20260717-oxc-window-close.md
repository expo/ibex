# Close the legacy window at 0.2

**Status:** Open
**Impact:** 5
**Urgency:** 4
**Ease:** 1
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Close the legacy window at 0.2” shows the issue reaches a security, correctness, release, or core product boundary; delay compounds an active rollout, reliability, or verification risk, while delivery is a dependency-heavy, multi-stage program, with specific cited code, progress, or acceptance criteria.
**Severity:** P2
**Systems:** Runtime, Module Loader, Engine, Build
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §4b/§5
**Depends-on:** oxc-platform-decision, oxc-audit-admission-impl, oxc-minimal-script-frontend, oxc-entry-shim-migration, oxc-compat-selector-split, oxc-legacyrequired-telemetry, oxc-invocation-error-taxonomy

Blocked on: accepted platform Decision; accepted+implemented
audit-admission; archived telemetry report reviewed (register items 2
and 3 recorded); every quarantine row resolved by pass or documented
unsupported disposition; minimal script frontend landed.

The close itself: remove the fence and `IBEX_LEGACY_MODULE_LOADER`;
make `module-runner` unconditional (retire the `--no-default-features`
runtime profile from CI); remove the Tier 2 bootstrap scanner and the
compat loader's string rewrites (dynamic-import / `import.meta` /
ESM-to-CJS); retire `EXACT_TRANSPILE_SCRIPT` (deprecation diagnostic
during the window) and the handwritten host string transforms
(`transpile_esm_to_script`, raw rewrites, `mod.rs` scanners) with the
legacy bundle pipeline; repoint `run-hermes-compat-loader.mjs` at the
runner pipeline. Release coupling per the RFC: 0.2 is release-blocked
on these gates, or the fence constant is revised (register item 6).

**Done when:** LLP 0019 revised to the two-tier end state (exceptions
cleared); loader runner green against the runner pipeline; all §4b
rows show their end state.
