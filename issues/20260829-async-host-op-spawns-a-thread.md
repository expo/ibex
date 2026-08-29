# Every async host op spawns a thread, so a round trip costs ~1.3 ms

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

`crates/ibex2/src/boundary_abi.rs` (`ibex2_host_call_async`) does
`std::thread::spawn` per operation. Thread creation on macOS is on the order
of tens of microseconds, but the spawn plus the wake-up of the loop's thread
plus the join of the worker each time is what the number measures, and it
scales with every async op an application makes — a `fetch` pays it on top of
the network, every `fs` call pays it, and a program doing 1,000 small reads
pays over a second.

Not a correctness bug: the `task_started`/`task_finished` accounting is right
and quiescence is honest. A design that was fine for proving the boundary
(LLP 0058.000.000's mock hooks) and is now the largest per-call cost the
runtime has.

**Done when:** async ops run on a bounded pool (or the platform's queue where
one exists — `NSURLSession` already has its own), the round trip in
`scripts/metrics.mjs` drops by an order of magnitude, and the quiescence
accounting still passes its tests.
