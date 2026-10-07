# LLP 0071: Timers and a clock for a borrowed runtime

**Type:** RFC
**Status:** Draft
**Systems:** Engine adapter, Tasks, Timers, Rust Stdlib
**Author:** Claude (Opus 5.5) for Charlie Cheever
**Date:** 2026-10-07
**Related:** LLP 0058.000.000 §8 (the one-task-per-cycle driver, owned by Ibex's own runtime), LLP 0068 §3 (the caller-owned runtime: "the adapter delivers at most one settlement or subscribed event when asked; it runs no timers or microtask checkpoints"), LLP 0059.000 §3.2 (the timer wheel) and §3.12 (WebSocket), exact2 LLP 1016.000 (answers that keep coming), the exact2 SDK spike (branch `spike/sdk`, 2026-10-07)

## Summary

A caller-owned ("borrowed") runtime can install `TIMERS` today, and its
`setTimeout` schedules, but no timer ever fires: `deliver_one` refuses a timer
task, `Context` exposes neither admission nor the next deadline, and the wheel
reads `Instant` alone, so nothing but the wall clock can make a timer due. This
RFC lets the caller drive timers exactly as Ibex's own runtime does, and lets
the caller supply the clock that timers and `performance.now` read. The
`WEBSOCKET` group needs nothing new for a borrowed runtime; this RFC pins that
with a test.

## 1. Why now

Exact 2 runs an app's data module in a Hermes runtime it owns, with Ibex's
storage adapter installed into it (LLP 0068 §3). A spike on 2026-10-07 ran
supabase-js and the Convex client, unmodified, in that data module on the web:
native realtime, token refresh and reconnection all worked in the browser. On
a device the same module needs what the browser gave it, and Ibex already has
it — the timer wheel, the WebSocket client, the FIFO — but only Ibex's owning
runtime (`ibex2-runtime`'s Hermes shim) can drive the timers. Every SDK the
spike ran sets timers at construction: Supabase's token refresh (an interval,
every 30 s) and Realtime's Phoenix heartbeat (25 s), Convex's reconnect and
server-inactivity timers and its `Date.now()` backoff, postgrest's retry
backoff (`fetchWithRetry`).

The caller also needs to move time. Exact 2's agent holds the app's clock
(`clock +N` moves it, `clock settle` lands what is in flight): a test that wants
a session to expire must be able to make a two-hour token's refresh due
without waiting two hours, and a drive that does not move the clock must not
see a timer fire because the wall clock did.

## 2. Decisions

### D1 — A borrowed adapter delivers timer tasks

`Adapter::deliver_one()` takes the oldest ready task as today; a timer task
(`kind == 2`) is delivered with the existing `fire_timer`, under the same
containment as an event callback: a callback's exception is dispatched
through the cancelable global `error` event and falls back to the host
reporter. One task per call, no checkpoint: the caller drains microtasks
after, as it does after a settlement. A timer task when `TIMERS` is not
installed cannot be admitted (nothing sets one) and remains a logic error.

LLP 0068 §3's sentence becomes: "The adapter delivers at most one settlement,
subscribed event or due timer when asked; it runs no microtask checkpoints and
admits no timers of its own (D2)."

### D2 — `Context` admits due timers and reports the next deadline

`Context::admit_due_timers() -> usize` and
`Context::millis_until_next_timer() -> Option<f64>` forward to the runtime
state, the same methods Ibex's owning runtime calls (`ibex2_runtime_admit_due_timers`,
`ibex2_runtime_millis_until_next_timer`). Admission stays separate from
delivery (LLP 0058.000.000 §8): the caller admits, then delivers one task per
cycle. Admission does not wake: a caller sleeping on `wait` or a wake callback
also sleeps no longer than `millis_until_next_timer`, as the owning runtime
does.

### D3 — The caller may supply the clock

`Context::set_clock(clock: Arc<dyn Fn() -> f64 + Send + Sync>)`, called before
installation, replaces the runtime state's monotonic origin as the source of
`now()`: milliseconds, read by the wheel (`set_timer`, `admit_due_timers`,
`millis_until_next_timer`, `is_idle`) and by `performance.now`. Without it,
`now()` is `Instant` since construction, as today.

- **Monotonic.** The state keeps the largest value it has returned and never
  returns less, so a clock that steps back cannot reorder the wheel or make
  `performance.now` decrease. A caller's clock that stalls (an agent's held
  clock) stalls every timer; that is the point.
- **Moving the clock wakes nothing.** The caller that moved it calls
  `admit_due_timers` and delivers. Ibex does not poll the clock.
- **Set once.** A second `set_clock`, or one after installation, is refused:
  timers already scheduled were scheduled against the first clock.
- **`Date`.** Not covered. `Date.now()` is the engine's; a caller that wants
  `Date` on its clock replaces it in its own prelude (Exact 2 already guards
  `Date` there). Ibex adds no `Date` binding.

### D4 — WebSocket in a borrowed runtime: pinned, not changed

A borrowed runtime that installs `PURE | EVENTS | WEBSOCKET` receives the
installer-endowed `WebSocket` (LLP 0059.000 §3.12, LLP 0068 §3). Its events are
subscribed host events, delivered by `deliver_one` today. A test pins it: a
borrowed runtime opens a socket to a local server, sends, receives the echo,
and closes, driven only by `deliver_one` and the caller's checkpoints.

## 3. What does not change

- The owning runtime's driver and its order (LLP 0058.000.000 §8).
- Grants: a timer needs none; a socket still needs `net.websocket <origin>`
  in the `Context`'s grant set.
- The deadline (LLP 0058.000.000 §8, "The deadline"): it reads the steady
  clock, not the caller's. A caller's clock governs when JavaScript is due to
  run, never how long it may run.

## 4. Tests

In `crates/ibex2`, beside the borrowed-runtime fixture:

1. With a caller clock at 0: `setTimeout(f, 50)`, `setTimeout(g, 10)`,
   `setInterval(h, 20)`; nothing is due until the clock moves; at 25 the
   admitted order is g, h; at 60, f and h again; `clearInterval` from inside
   `h` removes the next occurrence, not the one in flight.
2. No wall-clock dependence: the clock held at 0 for real 100 ms admits nothing.
3. A clock that steps back: `performance.now()` and `millis_until_next_timer`
   do not move backward.
4. `set_clock` twice, or after install, is refused.
5. A timer callback that throws: the `error` event sees it; delivery goes on.
6. Without `set_clock`, behavior is today's (`Instant`).
7. WebSocket echo through a borrowed runtime (D4), on the transports CI has.

## 5. What a caller does with it (Exact 2, non-normative)

Exact 2 installs `TIMERS | EVENTS | WEBSOCKET` beside its storage adapter, sets
the clock to its runner's clock (the agent's when an agent drives, the wall
clock otherwise), and between answers keeps a loop that admits due timers,
delivers one task, drains microtasks, and sleeps until the next deadline or a
wake. When the agent moves the clock it admits and delivers before reporting
the step settled. Exact 2's own design — which module code may live between
answers, `exactSubscribe`, `Date` and the build — is an Exact 2 RFC.

## 6. Open questions

1. Should `set_clock` also govern `fetch`'s and the WebSocket's timeouts
   (`exactTimeout`, close linger)? This RFC says no: those bound real I/O
   against real time.
