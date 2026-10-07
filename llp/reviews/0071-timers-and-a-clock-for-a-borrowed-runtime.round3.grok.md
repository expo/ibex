# Review of LLP 0071 r3 and implementation (2ddd846) — Grok 4.7, xhigh

Run: `grok --reasoning-effort xhigh --permission-mode plan --no-subagents --output-format streaming-json`, 2026-10-07, blind to the other review. Final message verbatim.

I'll audit the r3 design and commit 2ddd846 against the two r2 reviews, staying inside this checkout and reading the design, reviews, and the diff myself.The r2 reviews name six material findings. Next I’ll read the r3 diff and the timer, drive, and clock paths those findings turn on.The six material findings from the r2 reviews are resolved in r3 and in commit `2ddd846`. One new material defect remains: `Adapter::cycle` does not handle an exception from `drainMicrotasks` the way the cycle it claims to run does.

## 1. r2 material findings

**Astra M1 — the drive flag did not cover the borrowed cycle. RESOLVED.**

r3 D5 makes `Adapter::cycle` the cycle and holds the flag across both checkpoints. A nested `cycle()` returns `Nested` and does not release the flag. `deliver_one` throws `std::logic_error` before `ibex2_take_task` when `begin_drive` fails, and its `DriveRelease` is constructed only after a successful acquire (`crates/ibex2/src/bindings/install.cc:2311-2339`). The owning pump still acquires the same `RuntimeState::driving` bit and returns without running when it loses it (`crates/ibex2-runtime/src/engine/hermes_shim.cc:535-540`, `crates/ibex2/src/task.rs:1021-1028`, `crates/ibex2-runtime/src/loader_state.rs:195-203`). Step 3 of a cycle is `deliver_next` under the acquisition `cycle()` already holds, so the caller's own delivery is not refused. The nesting test sees `nested` from both the timer callback and the post-checkpoint microtask (`crates/ibex2-runtime/tests/embedding/borrowed_timers.rs:213-236`).

**Astra M2 — reservation was treated as the timer commit without amending the contract. RESOLVED.**

r3 D6 amends that sentence for timers: taking the task from the FIFO is the commit. Both drivers do that through `ibex2_take_task` → `RuntimeState::take_task`, which drops the subscription lock and then calls `timer_taken` (`crates/ibex2/src/task.rs:1243-1256`, `crates/ibex2/src/task.rs:1128-1136`, `crates/ibex2/src/boundary_abi.rs:1216-1232`). The owning pump calls that take and then `fire_timer` (`hermes_shim.cc:555-562`). `clear` removes the queued record so a cleared interval is not rescheduled (`crates/ibex2/src/stdlib/timers.rs:142-147`). The parent spec file still has the old sentence at `llp/0058.000.000-rust-capability-context-and-engine-adapter.spec.md:453-462`; the amendment is the RFC text, and the code follows the RFC.

**Astra M3 — an unconditional 4 ms repeat floor. RESOLVED.**

r3 applies HTML's clamp after five occurrences, not on every repeat. `take_due_micros` stores `runs + 1` in the queued record; `delivered` uses the original interval until `runs >= 5`, then `max(interval, 4ms)` (`timers.rs:71-77`, `timers.rs:166-186`). The first five zero-delay occurrences stay at time 0 and the sixth is due at 4 ms. `setTimeout` is not an interval, so it is not clamped. The unit test and the borrowed test both lock that count (`timers.rs:292-305`, `borrowed_timers.rs:149-171`).

**Astra M4 — the reentrant-clock test contradicted D3. RESOLVED.**

r3 test 13 is a diagnostic outside the contract, with a one-shot guard (`borrowed_timers.rs:328-355`). The clock is invoked only from `now_micros`, and every production caller samples before taking the timer mutex. The guard keeps the reentry from recursing. The test would deadlock if that sample ran under the wheel mutex. It would not deadlock if the sample ran under the subscription lock, because the reentry only calls `millis_until_next_timer`. The implementation does drop that lock first (`task.rs:1253-1255`); the test does not prove it. That gap is minor and is under the test section.

**Grok A — reschedule was attached to the adapter, which the owning pump never calls. RESOLVED.**

Reschedule is `timer_taken` inside `take_task`, not `deliver_one`. The owning pump and the borrowed cycle both reach it. `take_due` no longer schedules the next occurrence (`timers.rs:159-169`). The wheel tests call `delivered` themselves (`timers.rs:266-337`). `an_interval_repeats_until_cleared` still uses a 5 ms interval (`hermes_tests.rs:2555-2566`), which is above the floor and fires three times on the pump path.

**Grok B — `deliver_one` taking the flag was not the cycle, and it changed storage without saying so. RESOLVED.**

`cycle()` is the four-step cycle. `deliver_one` remains one task, no checkpoint, no admission, and it throws rather than returning a quiet false when the flag is already held (`install.cc:2319-2327`, `ibex2_jsi.h:362-377`). r3 states the storage change: a settlement callback that calls `deliver_one` again is refused. A call that lost `begin_drive` does not call `end_drive`. The nesting test would deliver the second timer from the post-checkpoint microtask if either nested call cleared the outer flag.

## 2. Implementation against r3

**Clock and locks.** The caller clock runs with no Ibex mutex held. `set_timer`, `admit_due_timers`, `millis_until_next_timer`, and `timer_taken` all call `now_micros` before `timers.lock()` (`task.rs:1075-1135`). `take_task` pops under the subscription lock, drops it, then samples (`task.rs:1243-1256`). `OnceLock::get_or_init` only installs `ClockSource::Instant`; the user closure runs after that call returns (`task.rs:1050-1061`). `is_idle` reads time only when the queue is empty and nothing is in flight (`task.rs:1031-1035`), which matches D3.

**Sealing and the atomic maximum.** `set_clock` is `OnceLock::set` and the first read is `get_or_init` (`task.rs:1040-1052`). One of those wins. An `Instant` sample is taken only after the cell is already `Instant`, so it cannot be applied on top of a caller clock. Invalid readings and panics leave `clock_micros` unchanged; the first of those returns 0 (`task.rs:1063-1066`). Accepted samples go through `fetch_max` (`task.rs:1064`).

**Panic and FFI.** `catch_unwind` is inside `now_micros`, around the caller closure, before `now_micros` returns to `ibex2_host_call`, `ibex2_take_task`, or `ibex2_adapter_admit_due_timers` (`task.rs:1055-1060`, `boundary_abi.rs:514-520` and `1216-1232`). A panic in the clock does not cross that FFI boundary.

**Integer microseconds.** `millis_until_next_timer` subtracts the deadline and the sample as `u64`, then divides (`task.rs:1119-1125`). Due is `deadline_micros > now_micros` (`timers.rs:161-162`). The distance is 0 exactly when the timer is due. `run_to_quiescence` treats 0 as "pump again" (`hermes.rs:960-969`), so a held clock does not busy-spin on a not-yet-due timer.

**Drive flag.** One `AtomicBool`. `begin_drive` is a `swap(true)`; `end_drive` stores `false` with no owner token (`task.rs:1021-1028`). Both the pump's `DriveGuard` and the adapter's `DriveRelease` call `end_drive` only after their own `begin_drive` returned true (`hermes_shim.cc:537-540`, `install.cc:2322-2326` and `2333-2334`). A nested `cycle()` returns before constructing `DriveRelease`. A nested `deliver_one` throws before constructing it. The pump never calls `deliver_one`, so it does not double-release against itself.

**Intervals, clear, and `performance.now`.** One queued record per handle, rescheduled from the take-time sample, clamped from the sixth occurrence as above. `clear` drops that record; the FIFO entry is still delivered, and `timers.js` has already deleted the callback (`timers.js:58-63`, `timers.js:69-71`). `performance.now` is assigned unconditionally in strict mode (`timers.js:96-101`). A non-writable property throws during script eval, which is after `mutation_started`, so installation fails with the existing discard error (`install.cc:1640-1669`, `install.cc:1883-1887`). `scripts()` evaluates `timers` before `events` (`bindings.rs:347-358`); `events.js` captures that function for `timeStamp` (`events.js:30-33`, `events.js:97-99`).

**Owning runtime.** The pump's order and flag handling are unchanged. What changes on `Instant` is what section 3 names: microsecond quantization, reschedule at take, and the five-then-4 ms interval rule. Adoption copies the host bindings into the Hermes runtime's own state (`bindings.rs:645-664`) and does not copy `clock`. `set_clock` on the source `Context` does not become the owning clock. `performance_now_advances_and_shares_the_runtime_origin` and the deadline spin still observe a runtime-relative clock that moves with wall time (`hermes_tests.rs:2642-2658`, `hermes_deadline_tests.rs:25-31`).

**`Adapter::cycle` and `drainMicrotasks`. MATERIAL.**

`cycle()` calls `drainMicrotasks` with no catch (`install.cc:2330-2339`). The owning pump does not. Its `checkpoint` loop catches the engine error, reports it, and drains again, because Hermes retires the throwing job before running it (`hermes_shim.cc:252-279`, `llp/0058.000.000-rust-capability-context-and-engine-adapter.spec.md:533-543`). Promise reactions and `queueMicrotask` do not throw out of the drain. An engine-raised error does.

The drive flag is cleared. `DriveRelease`'s destructor runs during C++ unwind and calls `ibex2_adapter_end_drive` (`install.cc:2311-2316`). A nested call is not what releases it. `storage_consumer_cycle` then catches `std::exception` and returns -1 (`embedding.cc:331-339`), so the exception does not cross into Rust on that path.

The host-task FIFO depends on which drain throws.

- Pre-checkpoint: `admit` and `deliver_next` have not run. The FIFO is unchanged. Due timers stay on the wheel. Later microtasks stay queued. Nothing is reported through `report_error`.
- Post-checkpoint: `deliver_next` has already taken the task (`install.cc:2337`, `task.rs:1253-1256`). An interval is already rescheduled. The callback has finished. The caller still sees an exception, not `Delivered`. Microtasks queued behind the retired job stay queued.

A caller that catches and calls `cycle()` again makes progress: the next pre-checkpoint continues the microtask queue, then admission runs. A caller that treats the exception as "this cycle did not run" is wrong for the post-checkpoint case, because the task is already committed. r3's four steps do not include the report-and-resume loop, and the header for `cycle()` does not say it throws (`ibex2_jsi.h:371-377`). Callback exceptions are a different path: `deliver_next` catches those (`install.cc:2353-2384`), and the throwing-timer test covers them.

## 3. Tests

The borrowed tests that match their names, and would fail if the behavior were wrong:

- Order, wall-clock hold, and reschedule-from-delivery (`borrowed_timers.rs:57-82`). At clock 25 the distance is 20 ms, so the next deadline is 45. A reschedule from the original 20 ms deadline would not yield 20.
- Clear inside the callback (`86-100`).
- One queued occurrence, five immediate zero-interval runs, then not at 3.999 ms and once at 4.0 (`149-171`). Four or six immediate runs would fail the length check.
- Admitted at 25 and delivered at 60 yields distance 20, so the next deadline is 80, not 45 (`175-187`). If it were still due, the distance would be 0.
- Clear between admit and take delivers one no-op and does not reschedule (`191-209`). `step(true) == 1` plus an empty log plus `millis_until_next_timer() == None` is not vacuous.
- Nested `cycle` / `deliver_one` from a callback and from the post-checkpoint (`213-236`). This also fails if the refused call clears the outer flag, because the microtask would then acquire the flag and run the second timer.
- Shared FIFO order (`240-253`).
- Backward step, non-finite readings, panic, and a value above 2^53 (`257-281`), through `performance.now`, so the panic is caught inside the host-call FFI.
- Fractional due versus distance (`285-293`), for a 1 ms timer. Deterministic, not a load flake. It does not reach the range where an `f64` subtraction of two large microsecond counts would collapse; the implementation no longer does that subtraction.
- Sealing by an idle `is_idle`, by `millis_until_next_timer`, by a second `set_clock`, and by `setTimeout` (`297-321`). The "deadline did not move" assert is weak on its own, because both clocks are 0; the `is_err()` checks are the real ones.
- Cancelable `error` and a following timer (`357-371`), via `cycle()`.
- Wheel tests call `delivered` and would fail if `take_due` still rescheduled (`timers.rs:266-337`).

**MINOR — `the_pre_checkpoint_runs_before_a_due_timer` does not call `cycle()`.** It drains with `step(false)`, admits from Rust, and delivers with `step(true)` (`borrowed_timers.rs:103-128`). That is the caller's own checkpoint around `deliver_one`. Deleting the first `drainMicrotasks()` in `cycle()` (`install.cc:2335`) would not fail this test or the nesting test. The post-checkpoint half of `cycle()` is tested; the pre-checkpoint half is not.

**MINOR — the lock diagnostic does not observe the subscription lock** (`borrowed_timers.rs:333-342`). Reentry calls `millis_until_next_timer`, which takes only the timer mutex. A regression that sampled the clock before `drop(subscriptions)` would still pass. The wheel-mutex check is real: that reentry would deadlock.

**MINOR — untested edges that the code does implement.** A non-idle `is_idle` does not seal. A non-writable `performance.now` fails installation and discards the runtime. A settlement callback that calls `deliver_one` again is refused. An engine-raised `drainMicrotasks` error releases the flag and leaves a later `cycle()` able to run. A sub-4 ms but non-zero interval clamps only after five runs (the tests use 0).

**MINOR — WebSocket timing.** `until` gives the echo and the reconnect 10 seconds of real I/O (`borrowed_timers.rs:449-460`, `465-504`). Under a stalled machine that bound can fail. The 150 ms sleep is not a race against the reconnect timer: the clock is held at 0, and a wall-clock leak would make `accepted == 2`, which is what the assert checks. The denial test stops at the first throw or `close:1006` and never checks the log (`507-524`). `prepare_garbage_collection` is now called from `storage_consumer_collect_garbage` (`embedding.cc:295-301`); no borrowed test collects a socket that still has buffered output.

**MINOR — stale comment.** `admit_due_timers` still says intervals reschedule inside `take_due` (`task.rs:1090-1095`). They reschedule in `delivered`.

VERDICT: NOT READY