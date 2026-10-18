# Portable fetch silently skips a SOCKS proxy from the environment

**Status:** Closed
**Resolution:** RustlsHttpTransport now snapshots and validates the environment proxy it installs in pooled agents, rejects SOCKS before DNS or connection with credential-free diagnostics, and preserves NO_PROXY plus HTTP/HTTPS CONNECT behavior.
**Systems:** Runtime, Transport
**Author:** Claude (Opus 5.5), for Charlie Cheever
**Date:** 2026-10-14

`RustlsHttpTransport`'s ureq agent reads its proxy with `Proxy::try_from_env()`, which accepts `socks4`, `socks4a`, `socks5` and `socks5h` URLs. Its connector chain (`crates/ibex2/src/transport/rustls_http.rs`) has no SOCKS connector, and ureq's CONNECT connector declines SOCKS (`Config::connect_proxy_uri`, ureq 3.4.0 `src/config.rs:192`), so the proxy is never used. With `socks4` or `socks5`, ureq resolves the target itself, and the request goes direct, DNS included. With `socks4a` or `socks5h` it does not, and the request fails with "no resolved address".

The portable WebSocket transport refuses a proxy it cannot speak (LLP 0059.000 §3.12). Fetch should do the same, with an error that names the proxy without its credentials, or gain a SOCKS connector.

## Resolution evidence

Before the fix, a fresh-process test configured
`ALL_PROXY=socks5://user:secret@127.0.0.1:9`, sent an actual
`RustlsHttpTransport` request to a loopback HTTP peer, and received that
peer's `direct` response. This reproduced the silent bypass without requiring
a functioning SOCKS server: reaching the target at all proved the configured
proxy had been skipped.

The transport now snapshots ureq's parsed proxy and `NO_PROXY` values at
construction, explicitly installs that snapshot in each pooled agent, and
validates the target against it before agent lease, resolver, or connector
work. Fresh-process regressions cover SOCKS4, SOCKS4a, SOCKS5, and SOCKS5h;
each asserts zero resolver calls, no target connection, and an error containing
the proxy scheme/host/port but neither username nor password. Separate tests
exercise `NO_PROXY`, a real HTTP CONNECT exchange, and reuse of that supported
proxy after the child process changes its environment.

Focused verification on macOS used:

```text
CARGO_TARGET_DIR=<run>/target cargo test -p ibex2 --no-default-features --lib -j2 transport::rustls_http::tests -- --test-threads=2 --nocapture
```

It passed five tests with the one child-only entry ignored by the parent
harness.
