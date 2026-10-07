# LLP 0071: Timers and a clock for a borrowed runtime

**Type:** RFC
**Status:** Draft
**Systems:** Engine adapter, Tasks, Timers, Rust Stdlib
**Author:** Claude (Opus 5.5) for Charlie Cheever
**Date:** 2026-10-07
**Revised:** 2026-10-07 (r5, after a round-4 delta review: a detach from inside JavaScript takes effect when that entrance returns, which is what the adapter can do and now what the text says; the detach test checks the exact log; the saturation tests and wording are exact) 2026-10-07 (r4, after round-3 reviews of r3 and its implementation, both NOT READY on implementation findings: `cycle()`'s checkpoints report a job that throws out of the queue and resume, as the owning pump's do; a callback that detaches the adapter ends the cycle; the drive guard retains the runtime state; the interval run count saturates; a delay too large for a `Duration` is never due instead of panicking across the ABI; the tests named by the reviews are added) 2026-10-07 (r3, after the same reviewers' r2 reviews, both NOT READY, and with the implementation in hand: the cycle is an adapter method, `Adapter::cycle()`, holding the drive flag across both checkpoints, and a nested cycle returns as the owning pump's does; `deliver_one` stays the storage primitive and refuses nesting; for a timer, taking it from the FIFO is its delivery commit, the reschedule point both drivers share, with the clock sampled after the subscription lock is released; intervals meet HTML's nesting clamp after five runs instead of an unconditional floor; the sealing, first-sample and `is_idle` edges are stated; test 7 is a bounded diagnostic; LLP 0059 §3 is named; the tests list what the implementation runs) 2026-10-07 (r2, after GPT-6-Astra xhigh and Grok 4.7 xhigh reviews of r1, both NOT READY: the clock gets a contract — read outside every Ibex lock, sealed at first read, invalid readings ignored, kept as integer microseconds so "due" and "how long to sleep" agree; the caller's cycle is normative, with its pre-checkpoint, and `deliver_one` refuses to nest; admission does wake; intervals reschedule when delivered, have at most one queued occurrence, and repeat no sooner than 4 ms; `performance.now` is always Ibex's under `TIMERS`; the amended text of LLP 0058.000.000 §8, LLP 0059.000 §2 and LLP 0068 §3 is named; the tests move to the borrowed fixture and replace its refusal test)
**Related:** LLP 0058.000.000 §8 (the one-task-per-cycle driver), LLP 0068 §3 (the caller-owned runtime), LLP 0059.000 §2 (`performance.now`), §3.2 (the timer wheel) and §3.12 (WebSocket), exact2 LLP 1016.000 (answers that keep coming), the exact2 SDK spike (branch `spike/sdk`, 2026-10-07); reviews under `llp/reviews/0071-*`

## Summary

A caller-owned ("borrowed") runtime can install `TIMERS` today, and its
`setTimeout` schedules, but no timer ever fires: `deliver_one` refuses a timer
task (a test pins the refusal), `Context` exposes neither admission nor the
next deadline, and the wheel reads `Instant` alone. This RFC lets the caller
drive timers through the same cycle Ibex's own runtime runs, and lets it supply
the clock that timers and `performance.now` read. It also fixes two defects of
the wheel that a held clock exposes. The `WEBSOCKET` group needs nothing new; a
test pins it.

## 1. Why now

Exact 2 runs an app's data module in a Hermes runtime it owns, with Ibex's
adapter installed into it (LLP 0068 §3). A spike on 2026-10-07 ran supabase-js
and the Convex client, unmodified, in that data module on the web: native
realtime, token refresh and reconnection all worked in the browser. On a device
the module needs what the browser gave it, and Ibex has it — the timer wheel,
the WebSocket client, the FIFO — but only Ibex's owning runtime can drive the
timers. Each SDK the spike ran sets timers at construction: Supabase's token
refresh (an interval, every 30 s) and Realtime's Phoenix heartbeat (25 s),
Convex's reconnect and server-inactivity timers and its `Date.now()` backoff,
postgrest's retry backoff (`fetchWithRetry`).

The caller also needs to move time. Exact 2's agent holds the app's clock
(`clock +N` moves it, `clock settle` lands what is in flight): a test that
wants a token refreshed must make the refresh due without waiting for it, and a
drive that does not move the clock must not see a timer fire because the wall
clock did.

## 2. Decisions

### D1 — A borrowed adapter delivers timer tasks

`Adapter::deliver_one()` takes the oldest ready task as today. A timer task
(`kind == 2`) is delivered with the existing `fire_timer`, inside the same
containment as an event callback: an exception is dispatched through the
cancelable global `error` event, and reaches the host reporter only when that
event is not canceled. A timer task with `TIMERS` not installed cannot be
admitted (nothing schedules one) and remains a logic error.

LLP 0068 §3's sentence becomes: "The adapter delivers at most one settlement,
subscribed event or admitted timer when asked; it runs no microtask
checkpoints and admits no timers of its own (LLP 0071 D2)." The borrowed
fixture's `borrowed_adapter_refuses_a_timer_task` is replaced by D1's tests.

### D2 — `Context` admits due timers and reports the next deadline

`Context::admit_due_timers() -> usize` and
`Context::millis_until_next_timer() -> Option<f64>` forward to the runtime
state, the methods Ibex's owning runtime calls. Admission is separate from
delivery.

**Wakes.** Admission puts tasks in the FIFO, so it wakes as every admission
does (LLP 0068 §3): it notifies `wait` and may invoke the wake callback on the
admitting thread before returning. A caller must not hold, across
`admit_due_timers`, a lock its wake callback takes. Scheduling a timer and
moving the clock wake nothing: a caller sleeps no longer than
`millis_until_next_timer`, measured on its own clock (D3) — for a held clock,
until it moves the clock.

### D3 — The caller may supply the clock

`Context::set_clock(clock: Arc<dyn Fn() -> f64 + Send + Sync>) -> Result<(), ClockSealed>`
makes `clock` the runtime state's time source: milliseconds, read for timer
scheduling and admission, `millis_until_next_timer`, `is_idle` and
`performance.now`. Without it the source is `Instant` since construction, as
today.

- **Sealed at first read.** Choosing the source and sealing it are one atomic
  decision: the first read of time fixes the source as `Instant` unless
  `set_clock` already fixed it as the caller's, and `set_clock` is refused once
  the source is fixed (`ClockSealed`). Reads of time are a `setTimeout`,
  `performance.now`, admission, `millis_until_next_timer`, a timer's take, and
  `is_idle` when nothing is queued or in flight (otherwise it answers without
  reading time). A caller sets the clock right after creating the `Context`.
  No deadline is ever computed in two clock domains. The clock belongs to the
  `Context`'s runtime state; an owning runtime that adopts a `Context` does not
  adopt its clock.
- **One reading, integer microseconds.** Each read takes one sample,
  `floor(ms × 1000)`, and every consumer — the wheel's "is it due", the
  deadline's distance, `performance.now` — uses that integer. So
  `millis_until_next_timer` is `0` exactly when a timer is due, and a held
  clock cannot busy-spin a loop that sleeps for the reported time.
- **Monotonic.** The state keeps the largest accepted sample (an atomic
  maximum; no mutex) and never returns less. A clock that steps back stalls
  time until it passes its old maximum: no remaining delay grows, the wheel's
  order is untouched, and `performance.now` does not decrease.
- **Valid readings.** A reading that is not finite, is negative, or exceeds
  2^53 ms is ignored: the sample is the previous one, 0 before any. A panic
  in `clock` is caught inside Rust, before any FFI boundary, and treated the
  same way; neither is retried or reported per read. Every comparison and
  difference is taken on the integer microseconds; only the result is
  converted to milliseconds.
- **The callback's contract.** Ibex calls `clock` with no Ibex lock held, on
  the thread calling the method that reads time — the owner thread for
  JavaScript, timer scheduling and admission; any thread for `Context::is_idle`
  and `millis_until_next_timer`. It must return promptly and must not call into
  this runtime's `Context` or adapter.
- **Moving the clock wakes nothing.** The caller that moved it runs cycles
  (D5). Ibex does not poll the clock.
- **What stays on real time.** The execution deadline (LLP 0058.000.000 §8,
  "The deadline"), transport budgets (fetch connect, the WebSocket write stall
  and close linger), and `wait`'s timeout: they bound real work. A JavaScript
  timer is on the caller's clock wherever it is used, `AbortSignal.timeout`
  included.
- **`Date`.** Not covered: `Date.now()` is the engine's. A caller that wants
  `Date` on its clock replaces it in its own prelude; an SDK backoff computed
  from `Date.now()` follows `Date`, not this clock.

### D4 — `performance.now` is the runtime's clock

Under `TIMERS`, Ibex installs `performance.now` reading the runtime state's
time, replacing any earlier `performance.now` (today it keeps one it finds).
A `performance.now` that cannot be replaced (non-writable) fails installation,
and the installer's existing rule for a failure after publication applies:
the runtime is partially mutated and must be discarded.
`EVENTS` therefore stamps `timeStamp` from the same clock when `TIMERS` is
installed before it, as `scripts(groups)` orders them. LLP 0059.000 §2
("a shared-memory read of the frame clock's base, not a host call") is amended:
`performance.now` reads the runtime's clock through its host operation; a frame
clock, when Ibex has one, takes its base from the same clock — which is how
LLP 0059 §3's "must share the frame clock's time base" now reads.

### D5 — The cycle is the adapter's, and does not nest

`Adapter::cycle()` runs one LLP 0058.000.000 §8 cycle for a borrowed runtime,
holding the runtime state's drive flag throughout:

1. drain microtasks (the pre-checkpoint);
2. admit due timers;
3. deliver at most one task — settlement, event or timer;
4. drain microtasks (the post-checkpoint).

Each checkpoint is the owning pump's: a job that throws out of the microtask
queue — on the ordinary paths only an engine-raised error can, since Promise
reactions and `queueMicrotask` catch their own; a raw
`HermesInternal.enqueueJob` job can too — is reported through the `EVENTS` error
path (reaching the host reporter only when the event is not canceled, or when `EVENTS` is absent) and the drain
resumes behind it, the engine having retired the job before running it. A
callback or microtask that detaches the adapter ends the cycle once the
entrance it ran in returns: the engine finishes that entrance (the rest of the
drain it was in, or the rest of an error dispatch's listeners), and the cycle
then starts no other JavaScript — no checkpoint, admission or task. The
adapter cannot stop the engine inside an entrance; a caller that needs that
stops from inside its own JavaScript. The guard, which retains the runtime
state, releases the flag even if the caller's `Context` is dropped meanwhile.

It returns `Delivered`, `Idle` (nothing was ready) or `Nested`. A cycle
requested while the flag is held — from a callback or microtask of a cycle in
progress, through whatever native function an embedder exposes, or beside an
owning pump — runs nothing and returns `Nested`: §8's "a drive request made
while the driver is not Idle records a wakeup", as the owning pump returns OK
without running. The flag is released on every way out, a throw included, and
never by a call that did not take it.

`deliver_one` stays what a storage embedder calls: at most one task, no
checkpoint, no admission. It takes the drive flag for its duration and, when
the flag is already held, throws `std::logic_error` naming nested delivery
before it takes anything: its boolean already means "a task was delivered",
so it cannot report a nested call as a quiet no-op. This changes one storage
behavior: a settlement callback that calls `deliver_one` again is refused. A
caller that drives with `deliver_one` and its own checkpoints owns §8's
no-nesting rule for those checkpoints; `cycle()` is how it gets it from Ibex.

**Settled at this clock** is a cycle that returns `Idle`: admission found
nothing due and nothing was queued. A future timer, an open socket or work in
flight does not prevent it; `is_idle` is not the test. A caller bounds a
settle by a cycle budget: a `setTimeout(f, 0)` chain is due forever at a held
clock, as an endless microtask chain is today.

### D6 — Intervals: one queued occurrence, rescheduled when taken

LLP 0058.000.000 §8 says an interval reschedules when its delivery commits;
the wheel reschedules it at admission. With a clock that need not move, that
admits a second occurrence of one interval when admission runs twice before
delivery, and loops forever inside one admission call for
`setInterval(f, 0)`. This RFC moves the reschedule:

- Admission removes a due timer from the wheel and records an interval as
  queued, with its count of delivered occurrences.
- **Taking a timer task from the FIFO is its delivery commit.** It happens in
  `RuntimeState::take_task`, which both drivers reach through
  `ibex2_take_task` — the owning pump before `fire_timer`, a borrowed cycle or
  `deliver_one` before theirs — after the subscription lock is released, so
  the clock is sampled with no Ibex lock held. An interval still queued is
  rescheduled from that sample. Nothing between the take and the callback can
  fail and retry: the adapter invokes it, inside the containment of D1, or the
  runtime is shutting down and nothing is delivered again. §8's "reservation
  is not an irreversible timer transition" is amended for timers to this.
- `clear` removes a handle from the wheel and from the queued record, so a
  cleared interval is not rescheduled; its queued occurrence is delivered as
  the no-op `timers.js` already makes it.
- An interval meets HTML's nesting clamp as HTML's timer steps apply it to a
  repeating timer: its first five occurrences repeat at the interval given,
  and from the sixth it repeats no sooner than 4 ms after its last delivery.
  A `setInterval(f, 0)` at a held clock therefore runs five times and waits.
  The run count saturates; only whether it has reached five matters.
  LLP 0059.000 §3.2's "HTML clamping" holds for intervals; `setTimeout`'s
  nesting clamp remains unimplemented, as today.

These rules hold for the owning runtime too, on its own clock.

### D7 — WebSocket in a borrowed runtime: pinned, not changed

A borrowed runtime that installs `PURE | EVENTS | WEBSOCKET` receives the
installer-endowed `WebSocket` (LLP 0059.000 §3.12, LLP 0068 §3). Its events are
subscribed host events, delivered by `deliver_one` today and by `cycle()`.
One existing obligation is stated, and the borrowed fixture now meets it:
before an explicit garbage collection, a borrowed owner calls
`Adapter::prepare_garbage_collection()`, as the owning runtime does, so a
socket's keepalive root follows its buffered output.

## 3. What does not change

- The owning runtime's driver and its order. D3's integer sampling, D4 and D6
  apply to it on `Instant`: `performance.now` is quantized to microseconds,
  an interval reschedules when taken, and a zero interval no longer hangs
  admission.
- Grants: a timer needs none; a socket needs `net.websocket <origin>`.
- Group dependencies: `TIMERS` needs `CONSOLE`; `WEBSOCKET` needs `PURE | EVENTS`.

## 4. Tests

In `crates/ibex2-runtime/tests/embedding/borrowed_timers.rs`, on the borrowed
fixture (replacing `borrowed_adapter_refuses_a_timer_task`), with a caller
clock unless stated, settling with `cycle()`:

1. Order: at 0, `setTimeout(f, 50)`, `setTimeout(g, 10)`, `setInterval(h, 20)`;
   nothing at 0, nor after 100 ms of real time at 0; at 25, g then h, and the
   next deadline is 45; at 60, h then f.
2. `clearInterval` in h's first callback: nothing more for h, and an empty
   wheel.
3. Pre-checkpoint: a promise reaction queued with `setTimeout(t, 0)` clears it
   before admission; of two ready timers, one delivery runs one callback and
   leaves its microtask undrained.
4. A delivery while the drive flag is held is refused before it takes
   anything; the task is delivered once the flag is released.
5. Reentry from JavaScript: inside a cycle, a timer callback's `cycle()` is
   `Nested`, its `deliver_one()` is refused, and a microtask's `cycle()` in
   the post-checkpoint is `Nested`; the next timer waits for its own cycle.
6. Intervals: two admissions before delivery queue one occurrence;
   `setInterval(f, 0)` at a held clock runs five times, then not at 3.999 ms,
   then once at 4 ms.
7. An interval admitted at 25 and delivered at 60 is next due at 80.
8. An interval cleared between admission and delivery is delivered as a no-op
   and never rescheduled.
9. An event and a timer share one FIFO, in admission order.
10. The clock: a backward step, NaN, infinity, a negative value, a value above
    2^53 and a panic leave time where it was; the distance to a deadline is
    unchanged by them.
11. A fractional clock: `millis_until_next_timer() == 0` exactly when
    admission admits.
12. Sealing: an idle `is_idle`, `millis_until_next_timer`, a second
    `set_clock`, and a `set_clock` after a `setTimeout` are refused, and a
    stored deadline does not move.
13. A diagnostic, outside D3's contract: a clock that reads the wheel once,
    behind a one-shot recursion guard, completes — it could not if the clock
    ran under the wheel's lock (test 19 covers the subscription lock).
14. A throwing timer reaches a cancelable `error` listener; `preventDefault`
    suppresses the host reporter; the next timer still runs.
15. `performance.now` and an event's `timeStamp` read the caller's clock.
16. A cycle runs its own pre-checkpoint: a reaction that clears a due
    timer runs before admission.
17. A job that throws out of the pre- or post-checkpoint (raised through
    `HermesInternal.enqueueJob`) reaches the cancelable `error` event, the
    drain resumes behind it, and the flag is released.
18. A timer callback that detaches the adapter and queues a microtask ends
    the cycle: the microtask never runs, nor a second timer; the next cycle
    runs nothing.
19. The clock read at a timer's take runs outside the subscription lock: a
    clock that publishes an event on that read completes (a watchdog fails
    the test rather than hanging).
20. Sealing that the test's own `set_clock` cannot satisfy: an unclocked
    runtime's `setTimeout` seals; a busy `is_idle`, which reads no time, does
    not.
21. Due and the distance to due agree 10^12 ms from the origin.
22. `setTimeout(f, 1e300)` does not panic and is not due anywhere in the
    accepted clock range (its deadline saturates).
23. WebSocket (`websocket` feature): a borrowed runtime with `CONSOLE | PURE |
    EVENTS | TIMERS | WEBSOCKET` sends to a local echo server under its grant,
    receives the echo and closes cleanly, waiting on real time for I/O; a
    reconnect scheduled for 100 ms does not happen at a held clock and does
    when the clock reaches 100 (the JavaScript reconnect count, not only the
    server's accept count, is checked); an origin outside the grants gives
    exactly `error` then `close:1006` with timers installed.

In `crates/ibex2/src/stdlib/timers.rs`: the interval tests reschedule on
delivery; zero and 1 ms intervals meet the clamp after five runs; an
interval repeats from its delivery, not its admission; the run count
saturates; a delay beyond the wheel's microseconds saturates to the last
representable deadline instead of wrapping. The existing owning-runtime
suites (`hermes_tests`, the deadline tests) run unchanged on `Instant`.

## 5. What a caller does with it (Exact 2, non-normative)

Exact 2 creates the `Context`, sets its clock to the runner's (the agent's
when an agent drives, the wall clock otherwise), installs
`CONSOLE | PURE | ABORT | CRYPTO | EVENTS | TIMERS | WEBSOCKET` beside its
storage adapter, and between answers calls `cycle()` until `Idle`, then sleeps
until the next deadline (on its clock) or a wake. When the agent moves the clock it runs cycles until
settled at the new time before reporting the step. Which module code may live
between answers, `exactSubscribe`, `Date` and the build are an Exact 2 RFC.

## 6. Open questions

1. Should a caller clock also govern `fetch`'s and the WebSocket's own time
   budgets? This RFC says no (D3): they bound real I/O against real time.
