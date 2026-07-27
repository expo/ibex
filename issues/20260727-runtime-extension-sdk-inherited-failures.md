# Inherited failures on main after the native runtime-extension SDK merge

**Status:** Open
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
