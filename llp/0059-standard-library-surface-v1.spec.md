# LLP 0059: The v1 standard library surface

**Type:** Spec
**Status:** Draft
**Systems:** Runtime, Engine, Host ABI, Build
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-27
**Revised:** 2026-08-27 (initial draft)
**Related:** LLP 0057 (Ibex 2 — this discharges its OQ1 with measurement), LLP 0058 (the engine seam — the intrinsics tier below), LLP 0004 (module loading and builtins — the surface this replaces)

## Summary

Ibex 2 implements **what Exact measurably uses**, not what Node and the web
platform define. This document is that inventory, taken from Exact's real
560-module native boot graph rather than from the repository's mentions.

The headline: **the used surface is smaller than expected, and smaller than
the author's estimate.** `node:fs` is never used at runtime. `WebSocket` is
never used by application code. SQLite is already a thin JavaScript wrapper
over a native module — the Ibex 2 pattern, already built.

This spec answers LLP 0057 OQ1 — *port Node compatibility or delete it?* — with
evidence: **delete it.** Nothing in Exact's runtime uses `http`, `net`, `tls`,
`child_process`, or `fs`.

## 1. Method, and what it does not cover

Scanned: the 560 first-party modules and 9 vendored modules in the real macOS
native boot graph (4.79MB and 0.68MB of source respectively), cross-checked
against 2,358 runtime JavaScript and TypeScript files in the Exact repository.

Excluded, deliberately: build and authoring tooling (Vite plugins, generators,
`check-*` scripts), which runs on Bun and never reaches this runtime; and the
server adapters, which run on Node, Vercel, or Cloudflare. Nearly every
`node:fs` hit in the repository is one of those two.

**Two known gaps.** The sampled boot graph is agent-off, so the agent server's
own surface is not represented. And a boot graph is boot-eager by definition —
lazily loaded routes are covered only by the repository-wide cross-check.
Neither gap changes a tier below, but both mean this inventory is a floor.

## 2. Tier E — the engine provides these

No Ibex work. Listed because they are load-bearing and must not be assumed
absent when choosing an engine (LLP 0058 §1.4).

`Promise`, `async`/`await`, `queueMicrotask` (60 uses / 46 files), typed arrays
and `DataView` (761 / 174), `WeakRef`, `Intl` (17 / 12, requires an ICU-bearing
build), `WebAssembly` (47 / 12, and 22 more in vendored Rive and Lottie).

## 3. Tier I — Ibex implements these

The v1 surface. Everything here is measured in the boot graph.

| API | uses / modules | notes |
|---|---|---|
| `console.{log,warn,error,info,debug}` | 214 / 89 | the most-used API by a wide margin |
| `setTimeout` `setInterval` `clear*` | 64 / 33 | |
| `TextEncoder` `TextDecoder` | 47 / 38 | |
| `URL` `URLSearchParams` | 36 / 25 | pure computation; no platform |
| `performance.now` | 23 / 10 | must share the frame clock's time base |
| `localStorage` | 22 / 7 | key-value, synchronous, small |
| `process.env` | 12 / 6 | read-only view is sufficient |
| `fetch` | 12 / 8 (+13 vendored) | see §5 |
| `AbortController` `AbortSignal` | 12 / 5 | |
| `atob` `btoa` | 5 / 3 | |
| `crypto.randomUUID` `crypto.getRandomValues` | 2 / 2 | |
| `structuredClone` | 1 / 1 | |
| `CustomEvent` `EventTarget` | 2 / 2 | |
| `Blob` | vendored only | required by Rive and Lottie |

Per LLP 0057 §3, each is Rust-owned semantics over a platform-owned transport
where a transport exists. `URL`, `TextEncoder`, `atob`, and `structuredClone`
have no platform component and are pure Rust.

## 4. Tier H — the host provides these, not Ibex

`requestAnimationFrame` (38 / 28) belongs to the frame clock, not the runtime.
It must be the *same* clock that drives motion and layout, or animation and
scheduling drift apart. Ibex exposes the binding; the host owns the tick.

Native module bindings — SQLite, camera, clipboard, filesystem access where an
app needs it — are host modules reached through the module registry, not
standard-library surface. `@exact/sqlite` already has exactly this shape: a
typed JavaScript wrapper over `ModuleRegistry` and `callModuleSync`, not boot
eager, with no JavaScript SQLite anywhere. **It is the pattern this whole
program generalizes, and it already works.**

## 5. `fetch` is bigger than its call count

Twelve call sites understate it. `fetch()` returns a `Response`, which implies
`Headers`, `Request`, body accessors (`json`, `text`, `arrayBuffer`, `blob`),
redirect policy, and abort integration. The measured 61 uses of
`new Headers|Request|Response` across 21 files confirm the object surface is
touched directly as well.

So `fetch` is a v1 item and it is the single largest one. Per LLP 0057 §3, Rust
owns header case-folding, redirect handling, the body state machine, abort, and
the error taxonomy; the platform owns sockets, TLS, proxy configuration, HTTP/2
and /3, and pooling.

## 6. Not in v1

Each of these is measured absent from application code, not merely deprioritized.

- **`node:fs`, `node:path`, `node:os`** — zero runtime uses. Every hit is a
  build plugin, a generator, or a script.
- **`node:http`, `net`, `tls`, `child_process`, `zlib`** — zero uses anywhere in
  Exact's runtime.
- **`WebSocket`** — two files, one a build script and one a test harness. Ibex
  uses WebSocket *internally* for the dev connection; that is a runtime-internal
  transport, not standard-library surface an app calls. Revisit when an
  application needs it.
- **`Buffer`** — 36 uses in 16 files, and only two of those reach the native
  path. Not implemented; the two call sites move to `Uint8Array`.
- **`crypto.subtle`** — 18 uses in 10 files, all server-side (`exact-server`,
  `exact-uploads`, response-cache digests) or build-time. Not needed by the app
  runtime.
- **`sessionStorage`, `indexedDB`, `EventSource`, `XMLHttpRequest`,
  `FormData`** — absent or single-use. `XMLHttpRequest` appears only inside
  vendored Rive, which falls back to `fetch` when it is missing.
- **`Worker`, `MessageChannel`** — vendored only, one use each. Deferred until
  an application needs them.

## 7. How this list grows

Adding to Tier I requires a measured call site in application code, not an
anticipated one. "The web platform defines it" is not a reason; a program that
implements the web platform is how the current standard library reached 46,000
lines of JavaScript for a surface this small.

Web and Node APIs beyond this list are filled in on demand, one at a time,
with the same evidence standard.
