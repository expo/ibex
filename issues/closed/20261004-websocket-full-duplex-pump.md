# WebSocket: a full-duplex I/O pump for the portable transport

**Status:** Closed (2026-10-07): the mio pump is qualified on macOS, Linux, and Windows
**Systems:** Runtime, Transport, WebSocket
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-10-04
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

**Done when:** a blocked data write does not stop the pump from reading inbound
Ping or Close frames; their replies are selected at the next WebSocket frame
boundary, with bytes already accepted by TCP still ahead of them; the existing
websocket tests (including the ping-flood and stalled-writer cases) pass on
Linux and Windows; there's no 25 ms poll; and the D5 metrics row for
`WEBSOCKET` is re-measured. This is an ordering guarantee, not a fixed-duration
guarantee against a peer that controls how quickly the kernel queue drains.

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
temporarily requested a one-fragment native send buffer, bounding the data
ahead of a control frame on every backend. Round 3 rejects that throughput
tradeoff; the readiness fix remains.

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

## 2026-10-07: Linux fix round 3

The client no longer changes `SO_SNDBUF` and does not substitute
`TCP_NOTSENT_LOWAT`. A Pong, Close echo, or generated 1009 is written at the
next frame boundary after the pump's current 16 KiB fragment. TCP remains an
ordered byte stream, so data the kernel already accepted still goes first. A
slow reader must therefore drain that native queue plus the current fragment
before it sees the control frame, but the unsent remainder of the fragmented
message does not go ahead of it. No duration independent of the peer's read
rate is promised; earlier millisecond measurements are observations from their
specific hosts, not latency limits.

The portable tests now set a small `SO_RCVBUF` on the listening peer before
`accept`, use the maximum-admissible 16 MiB message (1,024 fragments), and read
at a controlled rate. They validate client masking, reserved bits, opcodes,
minimal lengths, control-frame bounds, and fragmented-message sequencing, then
require Pong, Close echo, and 1009 before the data message's final fragment.
Close+FIN, admitted local Close, 1009 supersession, watch delivery after reply
drain, and read-FIN retention keep their sent/delivered assertions without a
deadline for kernel acceptance. A peer that reads nothing still fills the
kernel buffers, and the stall checks time 500 ms from the last successful
socket write. On Linux, the uncapped 24-test portable suite passes ten
consecutive runs. The `ibex2` and `ibex2-runtime` all-features suites pass,
including the 41/41 WebSocket WPT gate, as do both mandated Clippy commands,
formatting, and `ref-check`. macOS and Windows qualification remains with the
orchestrator, so the issue stays open.

A five-run Linux release probe with a normal autotuned receive buffer and a
reader consuming one 16 KiB frame per millisecond observed Pong in
275.5–281.7 ms during a 16 MiB send. A separate 256 MiB loopback transfer
(sixteen 16 MiB messages) measured median throughput of 590.3 MiB/s with the
cap and 638.1 MiB/s without it, an 8.1% increase; the five-run ranges were
553.0–640.9 and 627.6–653.1 MiB/s respectively. These are host observations,
not protocol limits.

## 2026-10-07: cross-platform qualification (macOS, Linux, Windows)

The first three-platform runs of round 3 (`afb4de3`) were green on Linux but
failed three Windows tests every run and two macOS tests intermittently (7 of
16 mini runs under load). The causes, in order of consequence:

- **A peer FIN discarded the messages ahead of it (macOS flake in the core
  conversation test).** FIN readiness started the terminal drain, which skips
  data payload. When the FIN's readiness reached the pump before receive
  demand, `/drop`'s `"x"` was thrown away and the caller saw 1006 first. A FIN
  is now the in-order end of the stream: its readiness only enables
  control-frame parsing without demand, data ahead of it is delivered, and EOF
  takes effect when a read reaches it. Terminal draining is reserved for a dead
  write side. New regression:
  `messages_before_a_peer_fin_survive_fin_readiness_without_demand`.
- **Teardown reset slow peers on Windows (both too-large tests).** The pump
  ended with `shutdown(Both)` while the oversized message's bytes were still
  unread. Windows answers `SD_RECEIVE`/`SD_BOTH` with unread input by sending
  RST, which also discards our unsent queue — the 1009 the slow peer had not
  read yet. (Closing the last handle with unread input does the same on every
  platform.) A finished pump now half-closes, reads and discards until the
  peer's FIN or a bounded linger, then shuts down; a socket dropped after its
  Close was sent leaves teardown to the pump. The too-large regressions now
  also require a clean EOF after 1009.
- **Windows discards received-but-unread bytes on RST.** In
  `write_failure_drains_unread_data_before_publishing_a_peer_close` the peer
  resets after sending data and Close. Linux and macOS keep those bytes
  readable; Windows does not, so the Close is lost and the result is 1006 or
  the write error (both surface as `error` then `close(1006)`). The test keeps
  the Close assertion on Linux and macOS and expects the abnormal end on
  Windows. Probed directly with a standalone TCP program on all three OSes.
- **The tests assumed one `WouldBlock` meant a full kernel (macOS).** macOS
  grows an autotuned send buffer and admits zero-window probes, so the "blocked"
  reply could legitimately drain before the test looked. The watch and
  too-large tests now read the pump's own test-only latch history (deferred at
  latch, Close sent, then deliverable — all under the send-state lock) instead
  of a parse flag plus an empty event queue. This also answers the review
  finding that the watch test could pass after a premature publication.

## Resolution (2026-10-07)

The portable transport is one `mio` pump per connection (epoll, kqueue, IOCP)
with the close lifecycle, FIN handling, graceful teardown, and platform
differences specified in LLP 0059.000 §3.12. The done-when conditions above
hold on all three platforms: control replies are written at the next frame
boundary behind bytes TCP has already accepted, the ping-flood, stalled-writer,
and close-lifecycle regressions pass, and there's no 25 ms poll.

Evidence at `4a407e9` (later commits on the branch change only issue and LLP
text):

- **Portable suite** (`cargo test -p ibex2 --all-features
  transport::websocket`, 25 tests): ten consecutive green runs on each of the
  mini (macOS), the Linux build host, and the NUC (Windows). Earlier runs at
  `e702ce8` were 12/12 on all three.
- **`ibex2 --all-features`**: green on Linux and on Windows (three runs). On
  the mini everything passes except
  `secrets::darwin::tests::the_keychain_round_trips`, which can't reach the
  Keychain over SSH. It passes on this Mac's interactive session.
- **`ibex2-runtime --all-features`**: green on Linux and macOS. On Windows the
  only failure is `garbage_collection_releases_rust_key_handles`, which also
  fails 30 of 30 isolated runs on main `c3fd74a`. It's filed as
  `issues/20261007-windows-crypto-key-gc-test.md`.
- **Clippy, formatting, references**: both mandated Clippy commands exit 0 on
  Linux and Windows; `cargo fmt --all --check` and `./ref-check` pass.
- **Not reproduced**: the once-seen Windows failure of
  `transport::stream_tests::abort_interrupts_body_reads_and_drop_closes_an_unread_body`
  (fetch streaming, not touched here). Its peer's final `read` returned an
  error instead of EOF. It didn't recur in 25 isolated runs and 8 full-suite
  runs on main, or in 3 full-suite runs on this branch. It's left unfiled
  because nothing ties it to this branch or shows it on main. If it recurs,
  the Windows reset-on-unread-input behavior recorded in §3.12 is the first
  thing to check.
