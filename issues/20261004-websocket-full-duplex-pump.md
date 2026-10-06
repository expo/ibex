# WebSocket: a full-duplex I/O pump for the portable transport

**Status:** Open
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

## Attempted resolution (2026-10-06)

Replaced the portable shared-lock reader/writer with one `mio` pump per
connection (`1faf427`, `e5d6220`, `a729607`). The pump owns the nonblocking TCP
socket and rustls state, uses `mio::Poll` for TCP readiness and `mio::Waker` for
commands and cancellation, bounds read work, uses an absolute no-progress
deadline, and drains/latches a buffered Close before reporting terminal EOF.
The existing Windows connect-readiness path still establishes the standard
socket before `MioTcpStream::from_std`; `mio` supplies its IOCP backend.

The portable suite passed 16/16 three consecutive times. Pong latency during
an 8 MiB send was 0.748–1.479 ms, Close handling was 8.7–9.1 ms, idle polling
returned zero times over a measured 150 ms, and the 500 ms stall cases failed
at 503–506 ms. A stripped minimal WebSocket consumer grew 33,208 bytes versus
main (1,531,024 to 1,564,232), inside D5's 150 KB budget. Direct regressions
cover Close plus FIN during a pending large write, pong-flood fairness, idle
abort, final-handle drop, peer RST, and a real zero-length socket write beneath
rustls.

The runtime all-features suite and explicit WebSocket WPT report (41/41) pass.
The exact ibex2 all-features command has only the expected macOS Keychain
environment failure (`User interaction is not allowed`); the remainder passes
when that single fixture is skipped. Both mandated Clippy commands, formatting,
and `ref-check` pass. Linux and Windows execution remains pending for the
orchestrator and is not claimed by this closure.

## 2026-10-06: cross-platform fix round 1

The attempted resolution remained open in practice: Linux failed the
Close+FIN regression 4/4 and Windows failed it 2/4. Both platforms delivered
the peer Close to `next()`, but a read-half close deregistered the TCP source
while the echo was blocked, so writable readiness could never resume it.

The pump now has separate caller admission, wire Close-sent/Close-received,
read-side, and write-side state. A peer Close has priority in the terminal
latch and cannot be replaced by a later write EOF or error. Terminal draining
skips data incrementally within `max_message`, retains control frames, and
never accumulates an unread message. A read EOF stops further data but keeps
the current fragment and Close echo writable; the TCP source changes to
WRITABLE-only until they drain. Pings remain answerable until a Close is
actually on the wire, and sending a generated Close drops queued pongs.

Mac verification is recorded with the landing commit. Linux and Windows must
both rerun green before this issue closes; that evidence is pending from the
orchestrator.

The expanded portable suite passes 19/19 for five consecutive macOS runs. A
fresh probe observed zero idle `Poll::poll` returns over 150 ms, 1.20 ms Pong
latency and 12.6 ms Close latency during an 8 MiB send. The same stripped
minimal-consumer fixture is 2,130,152 bytes, 720 bytes above the pre-fix mio
pump binary and still within D5. `ibex2-runtime --all-features`, both mandated
Clippy commands, formatting, and `ref-check` pass. The exact `ibex2
--all-features` command has only the declared macOS Keychain environment
failure; with that one fixture skipped, 238 library tests and every integration
test pass. Linux and Windows remain pending from the orchestrator.

## 2026-10-06: Linux fix round 2

Linux epoll exposed two readiness assumptions. The pump could wait for a new
writable edge after changing the registered interest even when the socket was
already writable at `EPOLL_CTL_MOD`; it now probes nonblocking I/O immediately
after re-registration and every poll wake, then continues each ready direction
through `WouldBlock`. More importantly, Linux's autotuned TCP send buffer had
already accepted roughly 2.5 MiB before `WouldBlock`. A Close generated after
that point could not overtake those kernel bytes, and the 500 ms test stall
deadline fired while the small-window peer was still draining them. The client
now requests a one-fragment native send buffer, bounding the data ahead of a
control frame on every backend.

The close-lifecycle review fixes now keep generated terminal Close frames ahead
of terminal delivery, supersede an admitted but unstarted local Close with
1009, retain admitted Close commands when terminal state discards queued data,
and give the terminal-drain parser exclusive ownership once reading or writing
closes. Pump regressions cover the watch drop path, demand and terminal 1009,
Close admission plus FIN, and a peer Close behind unread data when writing
dies.

The expanded portable suite passes 24/24 for ten consecutive Linux runs.
`cargo test -p ibex2 --all-features` and `cargo test -p ibex2-runtime
--all-features` pass, including the WebSocket WPT gate. Both mandated Clippy
commands, formatting, and `ref-check` pass. The Windows IOCP rerun remains
pending from the orchestrator, so this issue stays open.
