# LLP 0068: The standard library for a Rust consumer

**Type:** Spec
**Status:** Draft
**Systems:** Rust Stdlib, Host ABI, CapSec, Build
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-29
**Revised:** 2026-09-03 (LLP 0057.000 plans how `Bindings` grows — one field per family, feature-gated where a family pulls a dependency or a framework, present and refusing when the feature is off — and answers OQ3 in its lane L3 with a `Receiver`; neither is built yet) 2026-08-30 (§1: `Bindings` grew `secrets` (LLP 0069) and `kv` (LLP 0070), and `Host` carries their stores beside the transport — caught by the LLP 0070 review as drift on this page; §3: the whole-surface sentence now says where the fourth and fifth bindings' tests live, caught by its round 2)
**Related:** LLP 0057 (§3.1 — the split, and the reason for a Rust standard library that survived: the non-JS consumer), LLP 0067 (the capability model this states in Rust), LLP 0059.000 (§4 — the families; §3.8 — the env snapshot), `rules/NOT-DOING.md` (the bar: a no-JS consumer gets the same standard library with no engine in the process)

## Summary

Charlie Cheever decided on 2026-08-29 that the no-JS consumer of Ibex 2's
standard library is Exact 2's plan runner, which is Rust, and that this must
be supported. This document is the surface: `ibex2::host`. It is not a second
implementation — every function is the one the JavaScript bindings call,
behind the same `boundary::admit`, taking the same `GrantSet` a manifest
section parses to — and it links no engine. What it states in Rust is
LLP 0067's model: a consumer is endowed with bindings that carry their grant.

## 1. The shape

```rust
let host = Host::new();                       // the platform transport, once per process
let app = host.endow(GrantSet::parse(
    "net.fetch https://api.example.com\nfs.read /data\nenv.read HOME\n")?);
let response = app.fetch.get("https://api.example.com/things")?;   // Rust's redirects, headers, errors
let bytes    = app.fs.read_file("/data/things.json")?;            // checked as spelt and as realized
let home     = app.env.get("HOME");                               // None if not granted: absent, not refused
```

`Host` is the runtime without an engine: the platform transport, the secret
store, the kv store, and nothing else. `endow` is instantiation:
`Bindings { fetch, fs, env, secrets, kv }` (the last two are LLP 0069 and
LLP 0070) is the module parameter list as a struct, each binding holding an
`Arc` of the grant set for its whole life. A binding handed from one consumer to another carries the
first's authority, as LLP 0067 §3 says a JavaScript binding does. A consumer
granted nothing holds bindings that refuse — not absent bindings — so the
failure is a denial rather than a panic.

`Fs` offers the ten operations the JavaScript `fs` has, with the same rules:
absolute paths, normalized lexically and checked as spelt and as the
filesystem will really resolve them; read on the source and write on the
destination for `rename` and `copy_file`. `Env` is the snapshot LLP 0059.000
§3.8 specifies. The pure tier — `stdlib::url`, `base64`, `text`, `headers` —
is plain Rust and needs no host at all.

## 2. Synchronous, and why

The primitives block. An executor is the consumer's: a runner with its own
loop — Exact 2's has a seekable clock and a data seam — puts them on its own
workers, or wraps them in whatever future type it already uses. Ibex 2 does
not pick an async runtime for a consumer, and does not ship timers here,
because the consumer's clock is its own. The JavaScript path's task queue
(`task.rs`) is the engine's executor, not a general one.

## 3. No engine in the process

The `hermes` feature is the engine. With it off — the crate's default — no
Hermes is linked, and `cargo test -p ibex2 --no-default-features` runs the
whole surface: `--test rust_consumer` covers a fetch through `NSURLSession`,
filesystem operations inside and outside a granted prefix, an env snapshot,
and the pure tier; the fourth and fifth bindings run beside it — secrets in
the crate's `--lib` suite (LLP 0069 §5), kv there and end-to-end in
`--test kv` (LLP 0070 §5). The platform
transport is compiled whether or not there is an engine; it had been gated
on the engine by accident of `build.rs`, which would have left a Rust
consumer with the development TCP transport and no TLS.

## 4. Exact 2

The runner creates one `Host` at boot with the platform's transport and
endows each application from its manifest — the same manifest grammar as
LLP 0065 §4.2, minus the sections that name JavaScript modules — so an
application's data seam holds a `Bindings` and nothing ambient. Whether an
application's Rust code is trusted (a crate the author wrote) or endowed
(code the author did not write, as wasm with explicit imports per LLP 0057
OQ4) is Exact 2's decision; this surface serves both, since a `Bindings` is
what a wasm host would hand its module as imports.

## 5. Open questions

**OQ1 — The crate boundary.** *Resolved the same day:* the loader — Oxc's
parser, transformer, and resolver — is behind the `loader` feature, on by
default. A Rust consumer depends on `ibex2` with `default-features = false`
and compiles none of it; the same cut is the run-only binary of LLP 0065
§3.3, 5.6 MB against 9.6 MB.

**OQ2 — Linux.** *Resolved 2026-08-30, for Exact 2's Linux host (its LLP
1016 D2):* the default transport off Apple platforms is
`transport::rustls_http` — HTTP/1.1 over rustls through `ureq`, the webpki
roots compiled in, a thirty-second timeout, no redirect following (that is
`fetch`'s, above, as on Apple). Pure Rust: a builder with no system TLS and no
-dev packages runs it as is. It is a transport and not a second `fetch`: every
status is a response, and what never connected is `TypeError: Failed to
fetch`. **Trust is the platform's**, as §3 of LLP 0057 says and as
`NSURLSession` has it on Apple: the roots are the machine's CA bundle
(`rustls-native-certs`: `/etc/ssl/certs`, `SSL_CERT_FILE`/`SSL_CERT_DIR`), so
an enterprise CA or a development proxy works there as everywhere else; only a
machine with no bundle at all gets the compiled-in webpki roots — Mozilla's
set, the one a distro installs — and `RustlsHttpTransport::roots` says which,
for the consumer's journal (Charlie, 2026-08-30). The development TCP transport
stays for tests that want plaintext and no dependency. A
`cfg(not(target_vendor = "apple"))` dependency, so an Apple build carries none
of it.

**OQ3 — Async.** If every consumer ends up wrapping these in the same future
type, that type belongs here. Not before.
