# Review of LLP 0071 r5 and implementation (f0f16b3) — Grok 4.7, xhigh

Run: `grok --reasoning-effort xhigh --permission-mode plan --no-subagents --output-format streaming-json`, 2026-10-07, blind to the other review. Final message verbatim.

I'll audit LLP 0071 revision r5 against the round-4 findings and the implementation diff, reading only the checkout and using git, rg, and wc.Round 4’s two material findings are about detach-during-a-cycle and the detach test. I’ll compare r5’s text and the `f0f16b3` diff against those, then read the cycle, clock, and wheel code.Round 4’s two material findings are fixed in `f0f16b3`. The r5 text matches the adapter, clock, and wheel, and the borrowed-runtime tests cover section 4. Nothing left would make timers, the clock, WebSocket events, or storage settlements misbehave, deadlock, crash, or leak.

This is a static reading of revision r5 and `git diff 6396901 f0f16b3`. The reported test run was not repeated.

## Round 4

**MATERIAL 1 — detach must stop later jobs inside an entrance.** Resolved by stating what the adapter can actually do. A detach ends the cycle when that entrance returns; the engine finishes the rest of that drain or error-listener dispatch, and the cycle then starts no checkpoint, admission, or task (`llp/0071-timers-and-a-clock-for-a-borrowed-runtime.rfc.md:151-156`, `crates/ibex2/include/ibex2_jsi.h:378-380`).

The code does that. `checkpoint()` returns false as soon as `alive` or `runtime_` is clear, both before `drainMicrotasks` and after it returns (`crates/ibex2/src/bindings/install.cc:2340-2345`). `cycle()` admits and delivers only when the pre-checkpoint returned true, and the post-checkpoint bails out before any further JavaScript (`install.cc:2370-2374`). A timer callback that detaches therefore gets no post-checkpoint. Jobs already inside the current `drainMicrotasks`, and listeners already inside the current `report_error`, still run. That is the entrance r5 allows.

**MATERIAL 2 — the detach test accepted `t,late`.** Resolved. The callback detaches and queues `late`, and the test now requires the log to be exactly `t`, the first `cycle()` to return delivered (`1`), and the next to return idle (`0`) (`crates/ibex2-runtime/tests/embedding/borrowed_timers.rs:573-584`). `0` also shows the drive flag was released; a stuck flag would return nested (`2`).

**MINOR 3 — `Duration::MAX` did not distinguish truncation.** Resolved. The wheel test schedules `Duration::from_secs(u64::MAX)` at 1 ms and requires deadline `u64::MAX` (`crates/ibex2/src/stdlib/timers.rs:343-346`). Truncating the microsecond count and then adding the 1000 µs origin yields `u64::MAX - 998999`, so the old conversion fails this assertion. `schedule` saturates the `u128` before the add (`timers.rs:123-124`).

**MINOR 4 — lock wording, escaped errors, and “never due.”** Resolved in the RFC. Test 13 claims only the wheel lock (`rfc.md:267-269`). Checkpoint throws include a raw `HermesInternal.enqueueJob` (`rfc.md:145-148`). A delay past the wheel’s microseconds saturates at the last representable deadline (`rfc.md:288-289`, `rfc.md:301-302`).

## Implementation against r5

`Adapter::cycle` holds one `DriveHold` across both checkpoints, admission, and one delivery. A nested `cycle()` returns `Nested` without taking the flag. `deliver_one` takes the same flag and throws `std::logic_error` before `take_task` when it is already held (`install.cc:2314-2332`, `2364-2376`). `begin_drive` keeps an `Arc` for the guard; a failed acquire drops that temporary and leaves the existing flag held; `end_drive` drops exactly one `Arc` (`crates/ibex2/src/boundary_abi.rs:1276-1308`).

The clock is one `OnceLock` sample, `floor(ms × 1000)`, kept as an atomic maximum. Non-finite, negative, above-2^53, and panicking reads repeat the last sample, or 0 if none (`crates/ibex2/src/task.rs:1040-1067`). Sampling is outside the wheel lock and, on take, after the subscription lock is released (`task.rs:1082-1086`, `1133-1138`, `1256-1259`). `is_idle` reads time only when the queue is empty and nothing is in flight (`task.rs:1031-1035`). Intervals leave the wheel until `delivered`, clamp from the sixth run, and saturate the run count (`timers.rs:160-188`). `performance.now` is assigned unconditionally in strict mode, so a non-writable property fails install and the existing “discard the runtime” path applies (`crates/ibex2/src/bindings/timers.js:96-101`, `install.cc:1883-1887`). `scripts()` still installs timers before events, so `timeStamp` calls that function.

## Section 4

Each listed case has a matching test in `borrowed_timers.rs` or `stdlib/timers.rs`. Order, clear-from-callback, manual pre-drain versus one delivery, nested `cycle`/`deliver_one`, one queued interval and the 4 ms clamp, reschedule-from-delivery, clear-between-admit-and-deliver, shared FIFO, rejected samples (including a first NaN), fractional due, sealing, both checkpoints’ thrown jobs, detach’s exact log, the subscription-lock watchdog, far-origin agreement, `1e300`, and the WebSocket echo, reconnect count, and `error,close:1006` log are all asserted, not merely named. The wheel tests match the last paragraph of section 4, including saturation versus wrap.

## Residual findings

**MINOR — `Adapter::checkpoint`’s comment still says only an engine-raised error can escape** (`install.cc:2336-2337`). r5 and test 17 include `HermesInternal.enqueueJob`. The code reports those jobs; the comment does not.

**MINOR — `ibex2_adapter_end_drive`’s safety line still requires a non-null token** (`boundary_abi.rs:1301`). The function returns immediately on null (`boundary_abi.rs:1304-1306`). `DriveHold` never passes null.

**MINOR — `set_timer` still says a huge delay “is never due”** (`task.rs:1076-1077`). The deadline is `u64::MAX`, which `take_due_micros(u64::MAX)` would release. No accepted caller sample (≤ 2^53 ms) reaches that deadline, and test 22 locks the behavior.

**MINOR — three coverage gaps that the code already handles.** The wheel-lock diagnostic can still hang the process with no watchdog (`borrowed_timers.rs:329-356`); only the subscription-lock test is bounded (`borrowed_timers.rs:620-627`). `is_idle`’s in-flight short circuit is untested; the queued-work short circuit is tested (`borrowed_timers.rs:646-658`). A non-writable `performance.now`, detach from inside a checkpoint, and dropping `Context` while `DriveHold` is active are untested. None of those paths crash or stick the flag on inspection: host calls after detach throw `"Ibex2 bindings are detached"` (`install.cc:73-76`), and the guard releases the flag on every return.

VERDICT: READY