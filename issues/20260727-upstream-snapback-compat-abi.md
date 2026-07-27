# Upstream the snapback compat ABI to main (LLP 0041 remediation steps 1–2)

**Status:** In Progress (audit complete; ENG-24340 time limits upstreamed 2026-07-27; ex_hermes_create_no_eval remains)
**Severity:** P2
**Systems:** Engine, Build, CapSec
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-27
**Related:** LLP 0041 (consuming ibex — remediation steps 1–2); snapback
`issues/20260727-vendor-ibex-advance-blocked-on-compat-abi.md`;
[20260727-schedule-time-capture-security-delta](./20260727-schedule-time-capture-security-delta.md)

## Step-1 audit result (2026-07-27, read-only, verified against origin/main)

Disposition of the six compat commits `accb686f..bfbc6133`
(archive tip; base now 892 commits behind main):

| Commit | Subject | Disposition |
|---|---|---|
| `24610d9e` | ENG-24340 eval time limits | **NEEDS-UPSTREAM** |
| `f8d26ce8` | ENG-24383 TLS PEM parsing | SUBSUMED (main uses `rustls-pki-types` and went further) |
| `f3c3fe73` | ENG-25006 fetch keepalive | SUBSUMED (on main as `a4555941`) |
| `b129c8e0` | ENG-25006 fetch cleanup | SUBSUMED (on main as `f9ca3fcf`) |
| `c791baa2` | async continuation auth + `ex_hermes_create_no_eval` | SPLIT: no-eval **NEEDS-UPSTREAM**; continuation-auth core DROPPABLE for the pin advance (see the security-delta ticket) |
| `bfbc6133` | principal sentinels portable | SUBSUMED (identical relocation on main) |

Snapback's actual link dependency (verified in its `src/runtime.rs`) is
exactly three symbols: `ex_hermes_create_no_eval`,
`ex_hermes_watch_time_limit`, `ex_hermes_unwatch_time_limit`. This selects
**option 2** of snapback's blocker ticket, in its minimal form.

## Step-2 work plan

1. **ENG-24340 time limits (small-to-medium, ~a day).** Start from the
   existing re-port `d93d3620` (local `integrate/worktree-salvage-20260724`;
   `git merge-tree` confirms it merges clean onto today's origin/main;
   already adapted to `ExactRuntimeDriveGuard` + `ex_hermes_try_destroy`
   idioms; wraps stock Hermes `watchTimeLimit` — no Hermes patch needed).
   Do NOT start from the stale `57b4fb5e`. Remaining work: the capsec chain
   for two new `ex_hermes_*` symbols (reviewed host-ABI rows +
   classification + output templates + ingress-range repins +
   registry/contract/policy/vendored regen + test-count pins).
   **Design decision to settle:** snapback arms the watch from another
   thread (`RuntimeInterrupt::signal`, 1 ms) while an eval runs; the re-port's
   drive guard would refuse that off-owner-thread call. Either add an
   any-thread, nonce-authenticated interrupt path (an `asyncTriggerTimeout`
   analog of `ex_hermes_cancel_structured_work_target`, scoped to plain
   evals) or have snapback adapt `signal()` (small option-3 sliver).
2. **`ex_hermes_create_no_eval` (medium, multiple days — the calendar cost).**
   Engine side largely liftable from `c791baa2` (creation variant, one-way
   VM latch, fail-closed NULL when the linked Hermes lacks the latch,
   build.rs symbol probe; LLP 0002 text on the archive tip reusable), plus
   one more ABI symbol through the capsec chain. The heavy part: compat
   Hermes patch 0010 must be **renumbered** (main's stack now ends at 0012)
   and rebased, and the patched Hermes framework rebuilt for every platform
   with new artifact-cache tags/receipts. Note main's Mechanism 1 lockdown
   is NOT equivalent for this use case (opt-in env/CLI activation, heavier
   intrinsic-freeze semantics, no fail-closed creation contract, no VM
   latch).
3. Then snapback's prepared `chore/advance-vendor-ibex-jsi-owner-fix`
   branch links (or needs the one-line `signal()` adaptation), the SIGSEGV
   verification rerun unblocks, and LLP 0041 steps 3–4 (pin advance, ref
   retirement after recorded dispositions — this table is that record for
   four of six) proceed.

**Done when:** both capabilities land on `main` through the full review
discipline; snapback links against a `main` pin; the compat refs retire per
LLP 0041 step 4.


## Progress — 2026-07-27: eval time limits upstreamed

Two of the three symbols snapback links now exist on `main`, plus a third the
audit's design review showed was actually required:

- `ex_hermes_watch_time_limit` / `ex_hermes_unwatch_time_limit` — owner-thread
  (`ExactRuntimeDriveGuard`), wrapping stock Hermes `watchTimeLimit`, with the
  `time_limit_watched` flag and a defensive unwatch inside
  `ex_hermes_try_destroy` after the owner-thread teardown gate. Ported by hand
  rather than cherry-picked: `d93d3620` no longer merges clean since the
  runtime-extension SDK reshaped the same files.
- `ex_hermes_interrupt_eval(runtime, nonce)` — **new**, and the resolution of
  the design gap the audit flagged. Snapback arms a 1 ms limit from a foreign
  thread (`RuntimeInterrupt::signal`) to stop a running eval, which the
  drive guard would silently refuse; Hermes documents only
  `asyncTriggerTimeout` as any-thread. This takes the nonce-authenticated
  `ScopedRuntimeControlLease` (the same primitive
  `ex_hermes_cancel_structured_work_target` uses) so a foreign thread can
  interrupt while a stale caller cannot hit a runtime that reused the address.
  Snapback's `signal()` should call this instead of arming a short limit
  off-thread — a one-line consumer change, and the honest mapping.

Tests (`src/engine/mod.rs`): a CPU-bound `while (true) {}` is terminated with
Hermes' stable timeout error; zero timeout is refused and idle/repeat unwatch
is safe; the off-thread interrupt stops a runaway and refuses a stale nonce.
Capsec chain complete: three reviewed host-ABI rows classified
`authority-release`/WP7 (interruption control stops work another decision
authorized and grants nothing), output-disposition `catalogKeyDigest`
repinned, registry → ingress inventory → contract → policies → compiled
profile → vendored regenerated, `check:drift` green, and the seven moved
count pins in `capsec-surface-inventory.test.mjs` updated (host-ABI 349).

**Remaining:** `ex_hermes_create_no_eval` — the expensive half. Engine work is
modest but the compat Hermes patch 0010 must be renumbered past main's stack
and the framework rebuilt per platform with new artifact-cache receipts.
