# Portable fetch silently skips a SOCKS proxy from the environment

**Status:** Open
**Systems:** Runtime, Transport
**Author:** Claude (Opus 5.5), for Charlie Cheever
**Date:** 2026-10-14

`RustlsHttpTransport`'s ureq agent reads its proxy with `Proxy::try_from_env()`, which accepts `socks4`, `socks4a`, `socks5` and `socks5h` URLs. Its connector chain (`crates/ibex2/src/transport/rustls_http.rs`) has no SOCKS connector, and ureq's CONNECT connector declines SOCKS (`Config::connect_proxy_uri`, ureq 3.4.0 `src/config.rs:192`), so the proxy is never used. With `socks4` or `socks5`, ureq resolves the target itself, and the request goes direct, DNS included. With `socks4a` or `socks5h` it does not, and the request fails with "no resolved address".

The portable WebSocket transport refuses a proxy it cannot speak (LLP 0059.000 §3.12). Fetch should do the same, with an error that names the proxy without its credentials, or gain a SOCKS connector.

An adversarial review traced this through the source; it has not been reproduced against a running SOCKS proxy.
