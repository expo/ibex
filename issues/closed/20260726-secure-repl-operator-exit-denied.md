# Secure REPL rejects operator Ctrl-D after publishing its prompt

**Status:** Resolved
**Impact:** 3
**Urgency:** 4
**Ease:** 4
**Confidence:** 5
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Secure REPL rejects operator Ctrl-D after publishing its prompt” shows the issue materially affects reliability, verification, or developer experience; delay compounds an active rollout, reliability, or verification risk, while the implementation is localized and has concrete acceptance witnesses, with a direct reproduction or current implementation proof.
**Date:** 2026-07-26
**Related:** issues/20260724-insecure-startup-performance.md

## Problem

An Ibex secure-development build reaches and publishes the REPL prompt, but
Ctrl-D on an empty edit buffer exits with status 1:

```text
error: operator exit was denied by the typed lifecycle route
```

The same operator EOF exits successfully in the default/insecure build.

## Reproduction

```sh
cargo build --release --bin ibex --no-default-features \
  --features standard,unadvertised-dev-arming
printf '\004' | script -q /dev/null target/release/ibex repl
```

## Expected

Operator EOF after a ready prompt follows an authorized lifecycle route and
terminates the secure REPL successfully.

## Notes

This was discovered while adding the startup distribution harness. That
harness measures only process launch through truthful prompt publication and
now terminates and reaps its pseudoterminal wrapper after the measured
boundary, keeping this functional lifecycle bug independently visible here.

## Resolution (2026-07-30)

**Root cause.** The typed lifecycle route was working exactly as designed; the
authority it checks against was not. `Host::request_operator_exit`
(`src/host/mod.rs`) authorizes the operator route with a typed decision
(`lifecycle:exit` / `session-lifecycle` disposition `exit-request`, edge
`surface.cli.repl.command.exit.10n4ki2`) at both `Requested` and `Commit`
stages. Under `unadvertised-dev-arming` the synthesized default policy's root
authority ceiling (LLP 0038 §2) contained only the `fs:*` project-tree rows and
`path:cwd-observe` — no `lifecycle:exit` row — and the root ceiling is a hard
gate evaluated before every floor stratum, so the decision denied at the
`RootAuthorityCeiling` stratum (confirmed by instrumented decision evidence:
`outcome: Deny, decisive_stratum: RootAuthorityCeiling`). The insecure build
was unaffected because it arms the ceiling `unbounded`.

**Fix.** Added one row to the dev-arming synthesized ceiling in
`src/bin/ibex/runtime.rs`: `lifecycle:exit` on `session-lifecycle` disposition
`exit-request` (canonically sorted between `fs:write` and `path:cwd-observe`).
This authorizes the legitimate route *through* the existing typed lifecycle
machinery — no enforcement was bypassed or weakened, no new ABI symbol or
coverage surface was added (the coverage edge and decision vocabulary already
existed), so no capsec registry regeneration is required. The
`exit-code-get`/`exit-code-set` dispositions remain deliberately outside the
ceiling: `process.exitCode` reads/writes still deny loudly under dev arming,
so orderly shutdown consistently exits 0.

**Adjudication against the contract.** LLP 0025 §8 pins orderly shutdown
(Ctrl+D at an empty prompt, `.exit`) and root-attributed cooperative
`process.exit(n)` as *the* authorized lifecycle routes — only non-root
attribution receives the typed denial. The dev ceiling omitting the row was
the bug; the expected behavior in the ticket is the documented contract.
Fully-armed (advertised-target) builds are untouched: their ceiling comes from
the authored/advertised policy, not the synthesized default this change edits
(and `insecure` overrides the ceiling to unbounded regardless). LLP 0038 §2
updated in this commit to document the new row and its bound.

**Also fixed by the same row** (verified): `.exit`/`.q`/`.quit` in the secure
dev REPL, and root-attributed `process.exit(n)` (`ibex eval 'process.exit(5)'`
now exits 5 instead of being ceiling-denied).

**Evidence.**
- Exact repro (release, `--no-default-features --features
  standard,unadvertised-dev-arming`): `printf '\004' | script -q /dev/null
  target/release/ibex repl` → prompt published, clean exit, `$?` = 0, no
  denial line (was: exit 1 with "operator exit was denied by the typed
  lifecycle route", re-verified red at both base 16ede2c7 and rebased
  661dd16e before fixing).
- Default secure build: unchanged (still refuses arming before the prompt —
  LLP 0038 context; the fix is `#[cfg(feature = "unadvertised-dev-arming")]`).
- Insecure build: `printf '\004' | script -q /dev/null target/debug/ibex repl`
  still exits 0.
- Regression test `tests/secure_repl_operator_eof.rs` (real PTY via
  `openpty`, controlling terminal via `setsid`+`TIOCSCTTY`, waits for the
  ready prompt, sends 0x04, asserts exit 0 and no denial): red without the
  fix, green with it. Run:
  `scripts/run-tests.sh --secure --features unadvertised-dev-arming --test secure_repl_operator_eof`.
- Gates: `cargo test --lib` 682 passed / 3 failed — the three pre-existing
  known reds (module_runner call-time/TLA ×2, vfs chdir StaleIdentity) owned
  by a concurrent fix; `./ref-check` 0 errors; touched files `cargo fmt`
  clean (pre-existing fmt drift in `src/module_loader/{admission_cost_profile,runner_pipeline}.rs`
  and `tests/llp0413_dev_committed_embedder.rs` from origin/main left alone).

**Follow-up (not filed as a ticket).** `process.exitCode` get/set remain
denied under dev arming (loud, fail-closed, documented in LLP 0038 §2); widen
with the `exit-code-*` dispositions only if dev workflows need root-scripted
exit codes.
