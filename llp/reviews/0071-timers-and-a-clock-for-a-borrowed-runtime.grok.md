# Review of LLP 0071 r1 (75b8ba9) — Grok 4.7, xhigh

Run: `grok --reasoning-effort xhigh --permission-mode plan --no-subagents --output-format streaming-json`, 2026-10-07, blind to the other review. Final message verbatim.

I'll audit the draft against the checkout as it stands, starting with the RFC and the timer, context, and delivery code it cites.The RFC is 135 lines at commit `75b8ba9`. Next I’ll read the timer path, delivery, and the three specs it says it amends.The borrowed timer design is not safe to implement as written. `deliver_one` can fire timers, and WebSocket events already arrive that way, but the caller loop, the wake rule, and the clock callback disagree with the code and with specs this RFC does not amend.

## 1. Decisions versus the clients

**MATERIAL — The caller cycle fires a construction-time timer before the microtasks that construction queued.** LLP 0058 §8 and the owning pump drain microtasks, then admit, then run one task, then drain again (`llp/0058.000.000-rust-capability-context-and-engine-adapter.spec.md:449-465`, `crates/ibex2-runtime/src/engine/hermes_shim.cc:542-596`). The existing borrowed loop checkpoints before it delivers (`crates/ibex2-runtime/tests/embedding.rs:1976-1992`, `404-416`). D1 and §5 only drain after `deliver_one` (`llp/0071-timers-and-a-clock-for-a-borrowed-runtime.rfc.md:49-50`, `125-127`). `setTimeout(fn, 0)` is due immediately (`crates/ibex2/src/stdlib/timers.rs:65-68`, `227-232`). Supabase and Convex schedule promises and timers during construction; this order runs the timer first.

**MATERIAL — "Admission does not wake" is false for the method D2 says to forward.** `admit_due_timers` calls `CompletionQueue::admit`, which `notify_all`s `wait` and runs the wake callback on the admitting thread before `admit_due_timers` returns (`crates/ibex2/src/task.rs:1024-1036`, `203-208`, `230-248`, `337-346`). A due timer that has not been admitted does not signal anything: `set_timer` only inserts into the wheel (`1006-1012`). The caller must sleep no longer than `millis_until_next_timer`. Admission itself does wake.

**MINOR — §5's install set is rejected.** `TIMERS` requires `CONSOLE`, and `WEBSOCKET` requires `PURE|EVENTS` (`crates/ibex2/src/bindings.rs:156-163`). `TIMERS|EVENTS|WEBSOCKET` (`llp/0071:123`) fails `Groups::validate`. D4's `PURE|EVENTS|WEBSOCKET` (`91`) is valid and still has no `TIMERS`. Fetch for these clients already exists as `FETCH` (needs `PURE|ABORT`) and is not part of this RFC; `AbortSignal.timeout` is a `setTimeout` and would follow the caller clock (`crates/ibex2/src/bindings/abort.js:160-168`).

**MINOR — Convex `Date.now()` backoff is outside D3**, as the RFC says (`84-86`). `events.js` also captured `Date.now` for `timeStamp` when `performance.now` was absent (`crates/ibex2/src/bindings/events.js:30-34`, `97-99`). A clock jump does not expire that backoff unless the caller's prelude replaces `Date`.

D1's delivery shape is otherwise right: `ibex2_take_task` already reports a timer as kind 2 (`crates/ibex2/src/boundary_abi.rs:1233-1237`), and `deliver_one` currently throws that away before the containment try (`crates/ibex2/src/bindings/install.cc:2308-2317`). `fire_timer` is what the owning pump calls (`crates/ibex2-runtime/src/engine/hermes_shim.cc:561-562`). Interval reschedule-before-callback matches the wheel (`crates/ibex2/src/task.rs:1018-1023`, `crates/ibex2/src/stdlib/timers.rs:111-126`).

## 2. Hazards

**MATERIAL — The clock callback has no lock, thread, or re-entry contract, and the monotonic floor is not tied to `set_clock`.** `now` is `started.elapsed()` (`crates/ibex2/src/task.rs:389-391`, `1002-1004`). Callers are `set_timer` (before the timers mutex, `1006-1011`), `admit_due_timers` (`1025`), `millis_until_next_timer` (`1041-1047`), `is_idle` (`995-998`), and `performance.now` (`crates/ibex2/src/boundary_abi.rs:319-320`). No worker calls `now` today. D3 types the clock `Send + Sync` (`llp/0071:70`) and does not say it runs only on the owner thread, runs with no Ibex mutex held, or must not call back into `set_timer`, `admit_due_timers`, `wait`, or `deliver_one`. `Context::is_idle` is already callable off the owner thread (`crates/ibex2/src/bindings.rs:567-568`). A floor stored as "the largest value `now` has ever returned" (`llp/0071:76-78`) also keeps an `Instant` sample from any `is_idle` before `set_clock`, so a caller clock at 0 is already in the future.

**MATERIAL — `deliver_one` does not take the drive flag, so `fire_timer` can nest another task.** The owning pump refuses a nested drive (`crates/ibex2-runtime/src/engine/hermes_shim.cc:535-540`, `crates/ibex2/src/task.rs:980-987`). `deliver_one` does not. During `fire_timer` (`install.cc:2133-2142`) the callback's `setTimeout` calls `now`. If that clock, or the wake `admit` runs inline, calls `deliver_one` again, a second timer or socket event runs inside the first, before the caller's microtask drain. LLP 0058 §8 forbids that nesting (`llp/0058.000.000:466-467`).

**MATERIAL — A stalled clock can busy-spin because due-ness and the sleep value are different predicates.** The wheel is due when `deadline_micros <= (now * 1000.0) as u64` (`crates/ibex2/src/stdlib/timers.rs:90-90`, `111-115`). `millis_until_next_timer` returns `(deadline_micros as f64 / 1000.0 - now).max(0.0)` (`131-135`, `task.rs:1041-1047`). The owning loop treats 0 as "pump again" and wall time moves `Instant` (`crates/ibex2-runtime/src/engine/hermes.rs:960-969`). A held caller clock does not. The f64 clamp does not make those two comparisons agree. Integer millisecond deadlines used by the 25–30 s intervals are the safe case; the RFC does not require an integer clock.

**MINOR — `set_clock` after install is not observable from `Context`.** Nothing in `Adapter::install` records installation on `RuntimeState` (`install.cc:1563-1574`). "Refuse after installation" (`llp/0071:82-83`) needs a flag the RFC never names. Refusing a second call, and refusing once any timer exists, is the right rule: deadlines are absolute milliseconds computed at `set` (`timers.rs:88-96`).

**MINOR — Non-finite clocks are unspecified.** `(NaN as u64)` is 0 and an infinity saturates, so a NaN sample collapses a new deadline toward the origin while older deadlines stay large (`timers.rs:90`).

**Instant readers that stay on the wall clock,** which D3 and the open question leave there: the Hermes deadline (`hermes_shim.cc:193-198`, `1048-1049`), `run_to_quiescence`'s budget (`hermes.rs:937-944`), fetch connect budgets (`crates/ibex2/src/transport/rustls_http.rs:206-218`, `246-326`), and the WebSocket write stall and close linger (`crates/ibex2/src/transport/websocket.rs:765-770`, `1692-1720`, `1813-1821`). An idle socket does not ping on that clock. A held clock still will not stop a stuck write from failing the socket after 15 s of real time, and that failure is delivered through `deliver_one`.

`is_idle` is false when the only pending work is a future timer (`task.rs:994-998`), and also while a socket holds `in_flight` (`613-613`, `620-628`). `wait` does not return for that timer until its timeout (`337-346`). Scheduling a timer does not wake. After admission, `wait` does return.

## 3. WebSocket (D4)

D4 is true for delivery. Kind 3 is an event (`boundary_abi.rs:1254-1263`). `deliver_one` already calls `deliver_event` for it (`install.cc:2320-2321`). The worker publishes into that same FIFO (`task.rs:592-629`, `1104-1147`). The borrowed fixture already delivers a failed open as `error` then `close` using only `deliver_one` (`crates/ibex2-runtime/tests/embedding.rs:584-635`). The installer-endowed global matches LLP 0059 §3.12 (`install.cc:1821-1822`, `llp/0059.000-v1-api-specifications.spec.md:824-833`). Grants stay `net.websocket` per origin.

**MINOR — A borrowed runtime misses two owning-runtime side paths, neither of which the echo needs.** The pump wraps the event in microtask checkpoints and the deadline (`hermes_shim.cc:542-596`); D4 correctly leaves checkpoints to the caller. `ibex2_hermes_collect_garbage` calls `prepare_garbage_collection` (`hermes_shim.cc:495-496`, `install.cc:2235-2236`). Listener changes already update the strong root through `setKeepalive` (`websocket.js:186-199`, `install.cc:1512-1549`). Skipping the GC hook only lags the buffered-amount root. There is no socket timer the owning pump admits.

## 4. Tests

Not enough, and test 1 as written cannot pass.

**MINOR — Test 1 contradicts the wheel.** At t=25, `g` (10) then `h` (20) is right, and `h` is rescheduled from 25 to 45 (`timers.rs:120-124`). At t=60 the due order is `h`, then `f` (50), not "f and h". `clearInterval` inside the first `h` removes that 45 ms occurrence, so `h` does not fire at 60. The sentence asserts both (`llp/0071:109-112`).

**MINOR — The plan puts the tests in `crates/ibex2`.** The borrowed Hermes fixture, `deliver_one`, and the existing refusal test are in `crates/ibex2-runtime/tests/embedding.rs:639-659`. `crates/ibex2` has no JSI adapter. That refusal test has to be replaced or it fails the moment kind 2 is delivered.

Add:

- A zero-delay timer scheduled in the same turn as a promise reaction runs only after the caller's pre-checkpoint, and one `deliver_one` runs one callback.
- `set_wake` during `admit_due_timers` must not run `fire_timer` inside `fire_timer`. A clock that calls `setTimeout` from `now` must not deadlock.
- `is_idle` is false for a future timer; `wait` does not return until the caller-supplied timeout; `set_timer` does not signal.
- Step the clock backward after a timer is scheduled: it stays due in insertion order, and `performance.now` does not drop. Include a non-integer sample so a 0 ms sleep that is not yet due is visible.
- `set_clock` after `is_idle`, and after the first `setTimeout`, is refused without moving deadlines already stored.
- A thrown timer calls the cancelable `error` listener, `preventDefault` suppresses the host reporter, and the next `deliver_one` still runs. This is the existing event test (`embedding.rs:1512-1546`) applied to `fire_timer`.
- WebSocket echo with `net.websocket` for that origin, text send/receive/close, caller checkpoints only, on each CI transport. Also the grant-denied `error`/`close(1006)` path, which already exists and should keep working with timers installed.
- `performance.now` and a WebSocket event `timeStamp` both follow the caller clock. `timers.js` leaves a pre-existing `performance.now` in place (`timers.js:96-101`), so the test must show Ibex's function is the one installed.

## 5. Spec text this RFC does not amend

**MATERIAL — LLP 0059.000 §2 and LLP 0059 §3.** `performance.now` is specified as a shared-memory read of the frame-clock base, not a host call, and it must be the same base as `requestAnimationFrame` (`llp/0059.000-v1-api-specifications.spec.md:183-186`, `llp/0059-standard-library-surface-v1.spec.md:66`, `83-85`). D3 makes it `state.now()` through the host op (`boundary_abi.rs:320`) and a caller clock that is defined to be different from the steady deadline clock (`llp/0071:101-103`). The RFC's related list cites §3.2 and §3.12 only.

**MATERIAL — LLP 0058 §8's cycle, which §3 says does not change.** The normative order is pre-checkpoint, then one task, and a drive request during a task must not start another (`llp/0058.000.000:449-467`). D1/D2/§5 specify admit-then-deliver-then-drain and do not use `begin_drive`. D2's "admission does not wake" also contradicts LLP 0068 §3's wake paragraph, which the RFC does not rewrite: every admission is an edge that may invoke the callback (`llp/0068-the-standard-library-for-a-rust-consumer.spec.md:339-347`). The one sentence at `0068:333-334` is the sentence D1 replaces; that part is explicit.

**MINOR — D1 drops "only when not canceled."** The following 0068 sentence still says the host reporter runs only when the error event is not canceled (`0068:337-339`, `events.js:453-458`). D1's paraphrase (`llp/0071:47-49`) says the event and then the host reporter, with no cancel.

VERDICT: NOT READY