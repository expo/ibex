# LLP 0068: The standard library for a Rust consumer

**Type:** Spec
**Status:** Draft
**Systems:** Rust Stdlib, Host ABI, CapSec, Build
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-29
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

`Host` is the runtime without an engine: the platform transport and nothing
else. `endow` is instantiation: `Bindings { fetch, fs, env }` is the module
parameter list as a struct, each binding holding an `Arc` of the grant set for
its whole life. A binding handed from one consumer to another carries the
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
Hermes is linked, and `cargo test -p ibex2 --test rust_consumer` runs the
whole surface: a fetch through `NSURLSession`, filesystem operations inside
and outside a granted prefix, an env snapshot, the pure tier. The platform
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

**OQ2 — Linux.** The default transport off Apple platforms is the development
TCP transport, which speaks no TLS. A Linux transport is owed before the
Linux/DRM path is a consumer, and it is a transport, not a second `fetch`.

**OQ3 — Async.** If every consumer ends up wrapping these in the same future
type, that type belongs here. Not before.
