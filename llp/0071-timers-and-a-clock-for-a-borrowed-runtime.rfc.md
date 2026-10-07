# LLP 0071: Timers and a clock for a borrowed runtime

**Type:** RFC
**Status:** Draft
**Systems:** Engine adapter, Tasks, Timers, Rust Stdlib
**Author:** Claude (Opus 5.5) for Charlie Cheever
**Date:** 2026-10-07
**Revised:** 2026-10-07 (r2, after GPT-6-Astra xhigh and Grok 4.7 xhigh reviews of r1, both NOT READY: the clock gets a contract — read outside every Ibex lock, sealed at first read, invalid readings ignored, kept as integer microseconds so "due" and "how long to sleep" agree; the caller's cycle is normative, with its pre-checkpoint, and `deliver_one` refuses to nest; admission does wake; intervals reschedule when delivered, have at most one queued occurrence, and repeat no sooner than 4 ms; `performance.now` is always Ibex's under `TIMERS`; the amended text of LLP 0058.000.000 §8, LLP 0059.000 §2 and LLP 0068 §3 is named; the tests move to the borrowed fixture and replace its refusal test)
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

- **Sealed at first read.** `set_clock` is refused once anything has read the
  runtime's time (a `setTimeout`, `performance.now`, `is_idle`, admission, a
  second `set_clock`). A caller sets it right after creating the `Context`.
  No deadline is ever computed in two clock domains.
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
  2^53 ms is ignored: the sample is the previous one. A panic in `clock` is
  caught and treated the same way; neither is retried or reported per read.
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
`EVENTS` therefore stamps `timeStamp` from the same clock when `TIMERS` is
installed before it, as `scripts(groups)` orders them. LLP 0059.000 §2
("a shared-memory read of the frame clock's base, not a host call") is amended:
`performance.now` reads the runtime's clock through its host operation; a frame
clock, when Ibex has one, takes its base from the same clock.

### D5 — The caller's cycle, and no nesting

A caller that drives a borrowed runtime runs LLP 0058.000.000 §8's cycle:

1. drain microtasks (the pre-checkpoint);
2. `admit_due_timers`;
3. `deliver_one` — at most one settlement, event or timer;
4. drain microtasks (the post-checkpoint).

`deliver_one` takes the runtime state's drive flag for its duration and is
refused, with a logic error naming nested delivery, when the flag is already
held — by a delivery in progress (a timer callback whose code reaches the
caller's loop) or by an owning pump. The checkpoints remain the caller's.

**Settled at this clock** is a cycle in which step 2 admits nothing and step 3
delivers nothing. A future timer, an open socket or work in flight does not
prevent it; `is_idle` is not the test. A caller bounds a settle by a cycle
budget: a `setTimeout(f, 0)` chain is due forever at a held clock, as an
endless microtask chain is today.

### D6 — Intervals: one queued occurrence, rescheduled on delivery

LLP 0058.000.000 §8 says an interval reschedules when its delivery commits;
the wheel reschedules it at admission. Together with a clock that need not
move, that admits two occurrences of one interval if admission runs twice
before delivery, loops forever in one admission call for `setInterval(f, 0)`,
and leaves a Rust timer firing forever after `clearInterval` clears an
occurrence already admitted. This RFC makes the code match the spec:

- Admission removes a due timer from the wheel and records it as queued.
- When the adapter takes a timer task for delivery, an interval still recorded
  as queued is rescheduled from that moment's time, then forgotten as queued.
- `clear` removes a handle from the wheel and from the queued record, so a
  cleared interval is not rescheduled; its queued occurrence is delivered as
  the no-op `timers.js` already makes it.
- An interval repeats no sooner than 4 ms after its last delivery (HTML's
  clamp, which every interval reaches after its fifth run). Its first
  occurrence is at the delay given.

The owning runtime gets the same behavior; nothing it relies on changes.

### D7 — WebSocket in a borrowed runtime: pinned, not changed

A borrowed runtime that installs `PURE | EVENTS | WEBSOCKET` receives the
installer-endowed `WebSocket` (LLP 0059.000 §3.12, LLP 0068 §3). Its events are
subscribed host events, delivered by `deliver_one` today. One existing
obligation is stated: before an explicit garbage collection, a borrowed owner
calls `Adapter::prepare_garbage_collection()`, as the owning runtime does, so
a socket's keepalive root follows its buffered output.

## 3. What does not change

- The owning runtime's driver and its order, beyond D4 and D6.
- Grants: a timer needs none; a socket needs `net.websocket <origin>`.
- Group dependencies: `TIMERS` needs `CONSOLE`; `WEBSOCKET` needs `PURE | EVENTS`.

## 4. Tests

In `crates/ibex2-runtime/tests/embedding.rs`, on the borrowed fixture, with a
caller clock unless stated:

1. Order: at clock 0, `setTimeout(f, 50)`, `setTimeout(g, 10)`,
   `setInterval(h, 20)`; nothing is admitted at 0, nor after 100 ms of real
   time at 0; at 25, g then h; h's next occurrence is at 45; at 60, h then f.
   A second run where the first h calls `clearInterval`: nothing fires for h
   at 60, and nothing is ever admitted for it again.
2. Pre-checkpoint: a promise reaction queued in the same turn as
   `setTimeout(t, 0)` and clearing it runs first; t never runs. One
   `deliver_one` runs one callback and drains nothing.
3. Nesting: a timer callback that reaches the caller's `deliver_one` gets the
   nested-delivery refusal; the queue is unchanged.
4. Intervals: admitting twice before delivering queues one occurrence;
   `setInterval(f, 0)` at a held clock admits once per cycle and then not
   again until the clock moves 4 ms.
5. The clock: a backward step leaves pending timers due when they were and
   `performance.now` where it was; NaN, infinity, a negative value and a
   panic leave time where it was; a non-integer reading gives
   `millis_until_next_timer() == 0` exactly when admission admits.
6. Sealing: `set_clock` after `is_idle`, after a `setTimeout`, or a second
   time, is refused, and stored deadlines do not move.
7. A clock that calls `setTimeout`'s scheduling path from inside `clock` is
   not a deadlock (no Ibex lock is held).
8. Errors: a throwing timer reaches a cancelable `error` listener;
   `preventDefault` suppresses the host reporter; the next `deliver_one`
   still runs.
9. `performance.now` and an event's `timeStamp` follow the caller clock, also
   when a `performance.now` existed before installation.
10. Without `set_clock`, today's behavior on `Instant`.
11. WebSocket: a borrowed runtime with `CONSOLE | PURE | EVENTS | TIMERS |
    WEBSOCKET` opens a socket to a local echo server under its grant, sends,
    receives the echo, closes, driven only by the cycle; the denied-origin
    `error`/`close(1006)` path keeps working with timers installed; a
    reconnect scheduled by a timer opens a second socket.

## 5. What a caller does with it (Exact 2, non-normative)

Exact 2 creates the `Context`, sets its clock to the runner's (the agent's
when an agent drives, the wall clock otherwise), installs
`CONSOLE | PURE | ABORT | CRYPTO | EVENTS | TIMERS | WEBSOCKET` beside its
storage adapter, and between answers runs D5's cycle, sleeping until the next
deadline or a wake. When the agent moves the clock it runs cycles until
settled at the new time before reporting the step. Which module code may live
between answers, `exactSubscribe`, `Date` and the build are an Exact 2 RFC.

## 6. Open questions

1. Should a caller clock also govern `fetch`'s and the WebSocket's own time
   budgets? This RFC says no (D3): they bound real I/O against real time.
