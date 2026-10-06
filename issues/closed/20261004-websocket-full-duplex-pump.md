# WebSocket: a full-duplex I/O pump for the portable transport

**Status:** Closed (2026-10-06)
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

## Resolution

**Resolved:** 2026-10-06

Commits `09c9bcd` and `5b6f27c` replace `SharedWire`, the reader/writer
competition, and the 25 ms read timeout with one nonblocking pump per
connection. The pump owns the socket and rustls state, drives
`read_tls`/`process_new_packets`/`write_tls` from readiness, and wakes from the
existing bounded command/receive paths through a connected loopback UDP
socket. Peer pong and close replies take priority between 16 KiB data
fragments. The same 272-command budget covers channel commands and
pump-generated controls; data/message limits, `bufferedAmount`, teardown,
close semantics, and the 15 s no-write-progress bound remain.

The selected readiness implementation is a 194-line `poll(2)`/`WSAPoll` shim
over dependencies already linked by the crate. A working `mio` 1.2.4 variant
passed the same macOS portable control test. Identical stripped release probes
were 2,112,080 bytes for the shim and 2,129,424 for `mio`, so the shim is
17,344 bytes smaller and both are within D5's 150 KiB mechanism budget.

The identical slow-reader fixture measured the old design at 10.219 s and all
8 MiB before pong; the pump measured 8.8 ms and 16 KiB before pong, then
45.9 ms and 240 KiB before the close reply. An idle pump stayed inside one
readiness wait for 150 ms with zero returns. The focused Apple portable suite
passes 10/10, including plaintext/TLS conversations, ping flood, close
ordering, legacy receive behavior, and the 500 ms test write-stall bound.

No Linux or Windows execution is claimed from this lane: the Unix `poll(2)`
branch was exercised on macOS; the Linux and `WSAPoll` branches were checked by
inspection. The orchestrator owns those two platform runs.
