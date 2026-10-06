# WebSocket: a full-duplex I/O pump for the portable transport

**Opened:** 2026-10-04 (deferred from L4's review, LLP 0057.000 §6 L4)
**Area:** `crates/ibex2/src/transport/websocket.rs` (non-Apple transport)

## Today

The portable transport (Linux, Windows, and Apple's test-support path) keeps
one rustls connection behind `SharedWire`: a `Mutex<Wire>` shared by the
receive loop and the writer thread. rustls holds read and write protocol state
in one `ClientConnection`, so the two socket halves can't use independent
`StreamOwned`s.

Two bounds keep this from deadlocking:

- **Writer priority.** A queued writer sets `writer_waiting`, and the receive
  loop yields the lock to it. Without that, Linux's unfair mutex let a reader
  that had just timed out reacquire the lock forever (`85936368`).
- **Write-stall timeout.** The retained socket has a 15 s write timeout
  (`WRITE_STALL_TIMEOUT`). If the peer stops reading while a frame drains, the
  write fails the connection instead of blocking forever (`f715f8f1`).

The receive loop polls with a 25 ms read timeout so it releases the lock
regularly.

## What's wrong with it

It's half-duplex by construction. While a large frame drains to a slow peer,
the receive side can't read, so control frames (ping/pong, close) and inbound
data wait behind it for up to the stall bound. The 25 ms poll also costs
wakeups on idle connections and adds up to 25 ms of receive latency under
contention.

## Follow-up

Replace the shared-lock design with a single I/O pump thread per connection
that owns the `Wire` and multiplexes both directions: non-blocking socket,
`rustls::Connection::{read_tls, write_tls, process_new_packets}` driven by
readiness (poll/epoll/kqueue or `mio`, subject to D5's size budget), outbound
frames fed by the existing bounded command channel, inbound messages delivered
through the existing receive queue. Keep the current external contract:
bounded queues, `bufferedAmount`, the stall bound (now measured as "no write
progress for 15 s"), and close semantics.

**Done when:** a peer that stops reading no longer delays inbound pings or
close frames; the existing websocket tests (including the ping-flood and
stalled-writer cases) pass on Linux and Windows; there's no 25 ms poll; and the
D5 metrics row for `WEBSOCKET` is re-measured.

## 2026-10-06: attempt parked (branch `wip/websocket-pump-poll`)

Lane S2 implemented this follow-up as one `poll(2)`/`WSAPoll` pump per connection with a
loopback UDP wake pair (+67 KB stripped; pong during an 8 MiB send 10.2 s → 8.8 ms; zero idle
wakeups; Linux and Windows suites green at `426d2f4`). It did not land. After three review
rounds (two blind families each) the findings were not converging; round 3 still had:

- A peer Close + FIN is reported as 1006 when it arrives while receive is paused and a frame is
  draining (terminal readiness tears the pump down before reading the buffered Close).
- An idle pump waits only on the UDP wake socket, so an abort or a fatal `notify` error (which
  shut down TCP) may never wake it; thread, socket and wake pair can leak.
- `Interrupted` writes retry without checking the absolute stall deadline.
- IPv6 fallback covers only `bind`, not a post-bind connect/self-test failure.
- Two regressions inject below the branch they claim to test (zero `write_tls`, wake `POLLERR`).

**Recommendation for the redo:** use `mio` (its measured size cost, +68 KB, is now the same as the
hand-rolled shim). `mio::Waker` (eventfd/pipe/IOCP) and `Poll` remove the UDP wake pair, the
`WSAPoll` quirks and the EINTR handling outright, leaving the protocol-level work (bounded read
batches, stall deadline, latching terminal readiness until buffered input is parsed) — which the
parked branch's tests and the findings above already specify. Until then the shared-lock
transport stays: half-duplex but bounded by the 15 s write-stall timeout.
