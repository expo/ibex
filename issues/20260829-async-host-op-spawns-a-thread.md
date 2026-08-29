# An async host op round trip costs ~1.3 ms: the loop polls with a 1 ms sleep

**Status:** Open
**Impact:** 3
**Urgency:** 3
**Ease:** 3
**Confidence:** 5
**Severity:** P2
**Systems:** Runtime, Host ABI, Transport
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-08-29
**Related:** LLP 0058.000.000 §8 (the drive cycle), LLP 0059.000 §1 (the boundary), `scripts/metrics.mjs`

Found on the first run of `scripts/metrics.mjs`: an `fs.readFile` of one byte,
delivered back through the loop and its microtask, costs **~1,260 µs** per
round trip (median over 300 sequential calls). A synchronous host call is
60 ns, so the boundary is not the cost.

**Corrected the same morning, after measuring rather than reading.** The first
version of this ticket blamed the `std::thread::spawn` per operation in
`boundary_abi.rs` (`ibex2_host_call_async`). That spawn is real and is worth
a pool, but it is tens of microseconds. The millisecond is
`Hermes::run_to_quiescence` in `engine/hermes.rs`: when the loop is not idle
it does `std::thread::sleep(1 ms)` and polls again, so every completion waits
out the remainder of a sleep before it is delivered. `task.rs` has a `Condvar`
whose own comment says "an embedder that polls in a loop burns a core to do
nothing" — and the embedder polls. The fix is the one the Condvar was built
for: wait on it, with the next timer's deadline as the timeout
(`RuntimeState` already exposes milliseconds-until-next-timer for exactly
this). The thread-per-op is the second item, once the first is gone and the
number can show it.

**Done when:** the loop waits on the Condvar rather than sleeping, async ops
then run on a bounded pool (or the platform's queue where one exists —
`NSURLSession` already has its own), the round trip in `scripts/metrics.mjs`
is under 100 µs, and the quiescence accounting still passes its tests.
