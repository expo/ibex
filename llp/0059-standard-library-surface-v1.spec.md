# LLP 0059: The v1 standard library surface

**Type:** Spec
**Status:** Draft
**Systems:** Runtime, Engine, Host ABI, Build
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-27
**Revised:** 2026-09-03 (§8: the ceiling restated against WinterTC and the Expo-shaped platform layer — LLP 0057.000 carries the tables, the packaging decision, and the lanes; nothing in the measurement changed) 2026-08-28 (LLP 0057 §5.2: the target is Exact 2. This inventory was measured from Exact 1 and is now a *ceiling*, not a specification — nothing in it is built without a measured call site in Exact 2's own JavaScript, which today is none. `MessageChannel` removed under that rule.) 2026-08-27 (§6 amended — `fs`, `WebSocket`, `Buffer`, and `crypto.subtle` move into v1 by the author's decision, as APIs he intends to build on. The measurement is unchanged and stands: none are used by Exact's runtime today. LLP 0059.000 specifies them and marks them *author-required*.) 2026-08-27 (initial draft)
**Related:** LLP 0057 (Ibex 2 — this discharges its OQ1 with measurement), LLP 0058 (the engine seam — the intrinsics tier below), LLP 0004 (module loading and builtins — the surface this replaces)

## Summary

Ibex 2 implements **what Exact measurably uses**, not what Node and the web
platform define. This document is that inventory, taken from Exact's real
560-module native boot graph rather than from the repository's mentions.

The headline: **the used surface is smaller than expected, and smaller than
the author's estimate.** `node:fs` is never used at runtime. `WebSocket` is
never used by application code. SQLite is already a thin JavaScript wrapper
over a native module — the Ibex 2 pattern, already built.

This spec answers LLP 0057 OQ1 — *port Node compatibility or delete it?* — in
two parts. The **measurement** is that nothing in Exact's runtime uses `http`,
`net`, `tls`, `child_process`, or `fs`. The **decision**, which is the author's
and not the measurement's, is that a small, promise-only `fs` returns in v1
along with `WebSocket`, `Buffer`, and `crypto.subtle`, because he intends to
build on them. Node's server surface — `http`, `net`, `tls`, `child_process`,
`zlib` — is deleted and does not return. §6 records which is which.

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
| `queueMicrotask` | 22 / 13 (boot graph, LLP 0066) | added 2026-08-29; a name for the engine's Promise jobs |
| `TextEncoder` `TextDecoder` | 47 / 38 | |
| `URL` `URLSearchParams` | 36 / 25 | pure computation; no platform |
| `performance.now` | 23 / 10 | must share the frame clock's time base |
| `localStorage` | 22 / 7 | key-value, synchronous, small |
| `process.env` | 12 / 6 | read-only view is sufficient |
| `fetch` | 12 / 8 (+13 vendored) | see §5 |
| `AbortController` `AbortSignal` | 12 / 5 | |
| `atob` `btoa` | 5 / 3 | the engine's (Tier E, found 2026-08-29); the Rust base64 stays for the Rust consumer |
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

## 6. Measured absent, and what the author put back

Everything below is measured absent from application code today. That finding
is a fact and does not change. What follows it is a **decision**, which is the
author's to make against intent rather than usage: four of these return in v1
because he named them as things to build on. They are specified in
LLP 0059.000 and marked *author-required* there, so no later reader mistakes
an intent for a measurement.

**Returning in v1 by decision:** `fs` (promise-only, no sync variants),
`WebSocket`, `Buffer`, `crypto.subtle`.

**Staying out:**

- **`node:fs`** — zero runtime uses; every hit is a build plugin, a generator,
  or a script. **Returns in v1 by decision** as a promise-only subset over the
  virtual filesystem namespace. `node:path` and `node:os` stay out.
- **`node:http`, `net`, `tls`, `child_process`, `zlib`** — zero uses anywhere in
  Exact's runtime.
- **`WebSocket`** — two files, one a build script and one a test harness. Ibex
  uses WebSocket *internally* for the dev connection. **Returns in v1 by
  decision**; the application binding and the internal transport share one Rust
  implementation rather than growing a second.
- **`Buffer`** — 36 uses in 16 files, only two on the native path. **Returns in
  v1 by decision** as a `Uint8Array` subclass, for ergonomics rather than
  need.
- **`crypto.subtle`** — 18 uses in 10 files, all server-side or build-time.
  **Returns in v1 by decision**, scoped to digest, HMAC, ECDSA, Ed25519,
  AES-GCM, and the two KDFs.
- **`sessionStorage`, `indexedDB`, `EventSource`, `XMLHttpRequest`,
  `FormData`** — absent or single-use. `XMLHttpRequest` appears only inside
  vendored Rive, which falls back to `fetch` when it is missing.
- **`Worker`** — vendored only, one use. Deferred until an application needs it.
- **`MessageChannel`** — vendored only, one use. Added to Tier I on 2026-08-28
  because React's renderer built one at module scope, and **removed the same
  evening** when LLP 0057 §5.2 moved the target to Exact 2, which has no React
  tier. The rule in §7 cuts both ways: an API with no measured call site in
  the target is not in v1, however recently it had one elsewhere. `Worker`
  stays out with it.

## 7. How this list grows

Adding to Tier I requires a measured call site in application code, not an
anticipated one. "The web platform defines it" is not a reason; a program that
implements the web platform is how the current standard library reached 46,000
lines of JavaScript for a surface this small.

Web and Node APIs beyond this list are filled in on demand, one at a time,
with the same evidence standard.

## 8. Restated against WinterTC, 2026-09-03

The inventory above was measured from Exact 1 and has been a ceiling since
2026-08-28. LLP 0057.000 restates that ceiling against the WinterTC Minimum
Common Web Platform API — item by item, what is built, what is specified, and
which side of LLP 0057 §3.1's split each item falls on — and maps the Expo
SDK's module catalog onto LLP 0067's grant families for the platform layer
this document never covered. §7's rule is unchanged: that document orders the
work; a measured call site, or the author naming an item, is still what
starts it.
