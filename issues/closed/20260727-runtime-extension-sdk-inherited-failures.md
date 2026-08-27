# Inherited failures on main after the native runtime-extension SDK merge

**Status:** Closed
**Resolution:** 2026-07-27 — both families fixed; secure suites 612/0 and 659/0
**Severity:** P2
**Systems:** Engine, Host, Testing
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-27
**Related:** LLP 0040 (native runtime-extension SDK); `aaedddb3` (the merge)

Measured 2026-07-27 on the secure observer build
(`--no-default-features --features standard,capsec-conformance-observer`,
`--test-threads=1`) at the merge of the native runtime-extension SDK.
**Verified inherited**: both families fail identically with an unrelated
working tree stashed, so they are not caused by the eval-time-limit
upstreaming that was in flight.

## 1. `--lib`: runtime-extension builder rejects its own test specifier

`host::embedder_artifacts::tests::target_local_runtime_extension_builder_refuses_core_builtin_collision`
panics at `src/host/embedder_artifacts.rs:2227`:

```
called `Result::unwrap()` on an `Err` value: ArmRefused(
  "runtime-extension module specifier does not use canonical module-specifier grammar")
```

The test unwraps a builder call that the canonical-grammar check refuses, so
the failure is in the *setup* rather than at the collision assertion the test
is named for — i.e. the test never reaches its subject. Either the specifier
in the fixture is not canonical (fix the fixture) or the grammar check is
stricter than the SDK intends for target-local extensions (fix the check).
Worth resolving deliberately: a fail-closed grammar check refusing a
legitimate specifier and an over-permissive fixture are opposite defects.

## 2. `--bin ibex`: terminal-session SIGINT tranche

Ten distinct tests fail (63 harness results, since these spawn per-test
child processes), all in `terminal_session::tests`, e.g.

- `authenticated_interactive_adapter_consumes_ctrl_c_during_wedged_completion`
- `authenticated_interactive_adapter_routes_external_sigint_during_wedged_completion`
- `direct_engine_execution_sigint_flushes_and_exits_130_without_engine_cooperation`

These exercise signal delivery through the interactive adapter and the
direct-engine execution path. They were green on the pre-merge secure suite
(620 passed / 0 failed on 2026-07-27 earlier the same day), so the SDK merge
is the change in scope — most likely its runtime quiescing/teardown
interaction with the SIGINT path (`ibex::runtime_extension::internal::quiesce`
now runs early in `ex_hermes_try_destroy`), but that is a hypothesis, not a
diagnosis.

**Done when:** both families pass on the secure observer build, or each is
individually dispositioned with a recorded reason.


## Resolution — 2026-07-27

Both families are fixed and the secure observer suites are fully green
(`--bin ibex` 612 passed / 0 failed, `--lib` 659 / 0, serial).

**The SIGINT tranche was one disposition defect, not a signal bug.** The
engine deliberately captures `__ibexRegisterRuntimeExtensionModule` (and its
`inspectModules` companion) into retained native handles inside the fixed
bootstrap window and then **deletes the global** via `Reflect.deleteProperty`
before any extension bootstrap byte runs — the loader capability must not be
JS-reachable (LLP 0040 §3). But the generated root-global disposition row
declared it `exposed`/`reachable`/`always`, so the live sweep found a
permitted-reachable root missing and refused armed startup:

```
Armed startup refused: root-global disposition (...):
  missing permitted reachable roots: __ibexRegisterRuntimeExtensionModule
→ Hermes refused to seal armed bootstrap (fault 4)
```

The ten terminal-session tests then failed on their *setup* ("eval did not
enter Hermes wedge") because their child `ibex` process could not arm at all —
the SIGINT paths themselves were never exercised, which is why the symptom
looked like signal handling.

Fix: add the registrar to `PRIVATE_CONSUMERS` in
`capsec-root-global-dispositions.mjs` (consumer `runtime-extension-loader`),
alongside the other capture-then-remove rendezvous
(`__ibexEndowRaw`, `__ibexRefreshCompartmentBaseline`, the trusted-loader
bridges). The row regenerates as `private`/`absent`, which is what the engine
actually does. Note the generated header comes from
`generate:root-global-dispositions`, not from `generate:capsec-registry` — the
registry run alone leaves the stale row in place.

**The lib failure was a test that never reached its subject.**
`target_local_runtime_extension_builder_refuses_core_builtin_collision` set
its specifier to `node:fs`, which capsule validation refuses first for
non-canonical grammar (runtime-extension specifiers are bare package-style
names; no scheme colon), so `validate().unwrap()` panicked in setup and the
builder's collision fence was never consulted. Changed to the bare `fs`
spelling — grammatical *and* a registered builtin — so the collision refusal
is actually exercised, and added
`runtime_extension_capsule_refuses_scheme_prefixed_module_specifiers` to pin
the grammar fence separately (`node:fs`, `bun:sqlite`, `exact:process`). Both
fences are now distinguishable, which matters because the collision test
depends on its specifier passing grammar.
