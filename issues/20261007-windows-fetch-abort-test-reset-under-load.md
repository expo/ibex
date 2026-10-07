# Windows: fetch `abort_interrupts_body_reads_and_drop_closes_an_unread_body` sees a reset under load

**Status:** Open
**Systems:** Runtime, Transport, Fetch
**Severity:** P3
**Author:** Claude (Opus 5.5), from the WebSocket cross-platform qualification
**Date:** 2026-10-07

`transport::stream_tests::abort_interrupts_body_reads_and_drop_closes_an_unread_body`
sometimes fails on Windows. The test's HTTP peer expects EOF once the client
aborts or drops an unread body. Instead its final `socket.read` returns
`ConnectionReset` (os error 10054), so the client tore the connection down
abortively, not with a FIN (`stream_tests.rs:96`; the test thread then fails
joining the peer at `:120`).

This happens on main, independent of the WebSocket pump. The NUC (Windows,
MSVC) ran the `ibex2` lib test binary built from expo/ibex main `c3fd74a` 30
times while two other processes looped the `transport::websocket` suite as
background load. It failed 2 of 30 runs, both with this reset. Without load,
main passed 25 isolated runs of `transport::stream_tests`, 240 runs of 6
parallel copies, and 16 full `cargo test -p ibex2 --all-features` runs. On
branch `ws-xp`, whose full suite is longer and heavier on Windows (the pump's
16 MiB loopback regressions), the full suite hit it 2 times in 16 runs. The
fetch transports (`dev_tcp.rs`, `rustls_http.rs`) are untouched there.

Not yet diagnosed. Windows resets on abortive teardown in cases where Unix
sends a FIN: `shutdown(SD_RECEIVE | SD_BOTH)` or `closesocket` with unread
input, and possibly closing a socket while another thread's blocking `recv` on
a duplicated handle is still pending. LLP 0059.000 §3.12 records the WebSocket
side of the same platform behavior. Next steps: find which transport and which
arm (`abort` true or false) fails, then whether the abort registration's
`shutdown(Both)` or the body drop races a pending receive. A one-process stress
reproducer is in the NUC scratch scripts (`stress2.ps1`: the full lib binary in
a loop beside two `transport::websocket` loaders).
