# LLP 0066: What Exact's native entry asks of Ibex 2

**Type:** Research
**Status:** Draft
**Systems:** Runtime, Module Loader, Rust Stdlib, Host ABI, Build
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-28
**Revised:** 2026-08-28 (reframed after LLP 0057 §5.2 moved the target to Exact 2)
**Related:** LLP 0057 (§5.2 — Ibex 2 targets Exact, which is why this run was the next thing to do), LLP 0059 (the v1 surface, measured from a 560-module graph; §7 — how the list grows), LLP 0062 (§3 — the freeze this run changed; §3.1 — the `for-of` gap this run sizes), LLP 0064 (§8 — JSON modules, from this run), LLP 0065 (§8 — platform variants, from this run), LLP 0058.000.001 (§7 — the vertical slice this does not replace)

## Summary

The first attempt to run Exact's real native entry under `ibex2`, taken before
filling in any API speculatively, so that the failure list would order the
work. It did. Four walls were hit in sequence and three were Ibex 2 defects,
each fixed with a test; the fourth is Exact's Contract DSL, which no
JavaScript runtime loads without Exact's compiler. Beside the walls, a graph
walk found two more things a run alone would not have: 22 platform variants
the resolver was ignoring, and `module.exports = 'text'` coming back as an
empty object.

With those fixed the runtime evaluates Exact's entry, its runtime globals, its
document-meta and oracle-environment modules, and reaches route mounting. What
stands between that and a first frame is measured below and ordered in §7.

**Reframed the same evening.** LLP 0057 §5.2 now records that Ibex 2 targets
*Exact 2*, the from-scratch rewrite, which runs no application JavaScript
before first pixel and forbids the conventions §4 asks Exact to change. What
survives of this document: the three runtime defects and their fixes (§2), the
`URL` binding gap (§3), the floor and the one number (§6), and the graph walk
as an instrument. What does not: §4 as a work list, and §7's order — the JS
surface is now measured from Exact 2, with the counts in §3 a ceiling. The
`--platform` policy from §2 serves a convention Exact 2 bans and is a deletion
candidate. Kept whole rather than rewritten, because the measurement is what a
research document is for.

## 1. Method

`crates/ibex2/examples/graph.rs` walks a graph exactly as `ibex2 build` does —
strip, lower, scan, resolve — and reports every failure instead of the first.
The run itself was

    ibex2 run <exact>/js/src/main.tsx --root <exact> --platform native --no-compile

against Exact at `a8e633907`, with the initial path steered to a TSX route
through a probe entry in Exact's git-ignored `tmp/` that set
`globalThis.__exactInitialPath` the way the native host does. Evidence:
`0066-exact-native-entry-3311c097cc44e90ea39ffd43787f6b5f8f05d492180b81e148d6647f76a72dce.json`.

Two definitions. *Reachable* is everything the walk finds following static and
dynamic imports from `main.tsx`: 1,028 modules for `native`, 107 of them under
`node_modules`. The *boot graph* is what a real boot evaluates before the
first route mounts: `main.tsx` dynamic-imports `main-router.tsx` on every path
but `/`, so it is the static closure of both — **511 modules**, 12 under
`node_modules` (`react`, `react-reconciler`, `scheduler`), which matches the
560-module graph LLP 0059 measured from Ibex 1's bundle closely enough to
trust both.

## 2. The walls, in the order they were hit

1. **`overlapping module declarations`**, from `esm.rs`, on `main-shim.tsx`.
   An `export async function load() { return import('./x') }` produced two
   splices over one range: the export rewrite copies the declaration's span
   verbatim, and the dynamic import inside it was a top-level splice of its
   own. 21 of Exact's modules failed this way — every route loader. Expression
   forms now render inside whatever copies them (LLP 0064 §7), and a lowering
   error names its module.
2. **`@exact/core/src/style/color-v1.policy.json`**: the first non-JavaScript
   module the entry reaches. JSON modules are a format now (LLP 0064 §8), and
   the open ticket that asked for this measurement is closed by it.
3. **`Cannot read property 'verdictsByInstance' of undefined`**, three modules
   after the cause. `harden.js` froze `globalThis` itself, so
   `globalThis.__exactContractMonitorState ??= {…}` silently did nothing.
   Exact anchors shared state on the global object under 193 distinct
   `__exact*` names. The global object is extensible now; its bindings and
   every intrinsic under them stay locked (LLP 0062 §3).
4. **`js/src/app/routes/index.contract`**: Contract DSL, not JavaScript. Also
   reached from `/settings`, because the router's own `router-link`,
   `router-outlet`, `router-slot`, `router-action` components and
   `web-fallback-screen` are `.contract` — five on the boot graph, 44
   reachable. This is the wall that stands.

Found beside them: **`module.exports = 'js'` returned `{}`** — the module
registry held `jsi::Object`s, so a primitive export was dropped for the empty
original. And **22 files with a `.native` sibling** were resolving to the
unsuffixed web file, four on the entry's first import line; the first walk's
`node:crypto`/`node:http` refusals were both on those web paths. `--platform`
exists now (LLP 0065 §8), and the numbers below are for `native`.

## 3. What the boot graph uses

Counted over the 511-module boot graph. Files, then occurrences.

**Missing from Ibex 2, in order of use:**

| API | files | uses |
|---|---|---|
| `URL` / `URLSearchParams` | 19 | 36 |
| `AbortController/AbortSignal` | 14 | 39 |
| `queueMicrotask` | 13 | 22 |
| `localStorage` | 4 | 16 |
| `requestAnimationFrame` | 4 | 8 |
| `structuredClone` | 2 | 3 |
| `EventTarget` | 2 | 3 |
| `Buffer` | 2 | 3 |
| `WebAssembly` | 1 | 8 |

**`URL` is implemented and not bound.** `stdlib/url.rs` passes the WPT
suite, but no JavaScript binding wraps it: `install_bindings` installs
`esm`, `headers`, `timers`, and `message_channel`, and `URL` is not in
`ALLOWED_GLOBALS`. Found while timing (§6): Exact's `pathnameForRoute`
wraps `new URL(path, 'https://exact.local')` in a `try/catch` that falls
back to `/`, so every initial path became the labs home and the `/settings`
steering in §1 never took effect. The run in §2 therefore only ever walked
the `/` path; the five router `.contract` modules are on the router
closure by the static walk, not by observation. `queueMicrotask` was not on
LLP 0059's Tier I list either, and is on 13 boot files.
`WebAssembly` is one file, `exact-contract`'s `aquifer-machine.ts`
(not guarded by a `typeof` check), and vanilla Hermes has
no WebAssembly at all — LLP 0057 §5.2 put it in Tier E, and Tier E cannot
provide it. That is a decision, not a gap to fill.

**Present:** `TextEncoder/TextDecoder`, `process.env`, `setTimeout/setInterval`, `performance.now`, `fetch(`, `MessageChannel`, `import.meta`, `atob/btoa`, `Intl`
(`Intl` is an object on the vanilla macOS build; its completeness is untested).

**Zero on the boot graph:** `CustomEvent`, `Blob`, `crypto.randomUUID`, `crypto.getRandomValues`, `crypto.subtle`, `WebSocket`. `Blob` is 7
files reachable (Rive, Lottie); `crypto.randomUUID` 2; `CustomEvent` 5.

**Tier H, the host:** `hostCallAsync(` / `__hostCall` / `invokeHostAsync` on
13 boot files. Exact reaches its host through three shapes in
`@exact/core/host-call-bridge.ts`: `globalThis.exact.invokeHostAsync(operationId,
Uint8Array) → Promise<Uint8Array>` (the typed ingress), `globalThis.__hostCallAsync`,
and the legacy synchronous `globalThis.__hostCall(operation, argsJson)`. Ibex 2
has no host-op mechanism yet; this is the Rust-side boundary LLP 0059 §4
assigns to the host, and nothing renders without it. `requestAnimationFrame`
is Tier H as well.

## 4. What Exact must change

- **Contract modules must arrive as JavaScript.** Five on the boot graph,
  44 reachable. The compiler is `packages/exact-contract/src/compiler`, run
  today by a Vite plugin; Ibex 2 should consume its output, not host it —
  `rules/NOT-DOING.md` forbids compiling at runtime, and a DSL compiler is
  not a standard library.
- **`exact` and `exact/app` are Vite aliases**, not packages: 20 importers,
  all lazy routes. A workspace package with an `exports` map is the fix on
  Exact's side; honouring `tsconfig` `paths` would be the fix on this side,
  and LLP 0065 argues against bundler-shaped policy.
- **One `.css` import** in a fixture route, also a Vite plugin's.
- Route delivery is fine: `NATIVE_ROUTE_REGISTRY_LOADERS` dynamic-imports
  registries, and the `globalThis.require` branch is Ibex 1's HBC path,
  skipped here.

## 5. Risks measured, not resolved

- **`for (const x of …)`** appears in 179 boot files, 967 times. LLP 0062 §3.1
  records that the pinned engine gives the loop one binding, so a closure
  made inside it captures the last value — silently. Only loops whose body
  closes over the variable are affected, and `oxc_semantic` can count those.
  Worth counting before anything renders, because this miscomputes rather
  than refuses.
- **The lowered wrapper is sloppy.** ES modules are strict by definition; the
  factory `wrap` produces is not, which is why wall 3 surfaced three modules
  late instead of as a `TypeError` at the write. A `"use strict"` prologue for
  lowered ES modules is small and makes the next such failure loud.
- `document.` on 14 boot files and `window.` on 26 — Exact sets `window`,
  `self`, and `global` itself and guards `document`; nothing failed on them.

## 6. What this does not measure

Time, except for one number. Every run here loaded source with
`--no-compile`; the 30 ms budget in `rules/RULES.md` is measured against
bytecode, and the boot graph cannot be built ahead of time until it can load.
The number: `main.tsx`'s static closure — 72 modules, TypeScript and JSX
through Oxc and then Hermes parsing source — evaluates in **~490 ms** on this
machine (three runs: 585, 493, 493; process baseline 0), about 7 ms a module.
That is the cost LLP 0063 measured and bytecode removes; it says nothing about
what a bytecode boot will cost, and LLP 0063's 13 ms for a 570-module
bytecode graph remains the expectation, not a result.

## 7. Next, in order

1. Contract modules as JavaScript, on Exact's side (§4). Nothing mounts
   until then.
2. The host-op ingress (§3, Tier H): the shape Exact calls, over the Rust
   boundary. The largest Ibex 2 item, and the one LLP 0058.000.001 §7's
   vertical slice was meant to prove first.
3. `URL`/`URLSearchParams` (bind what exists), `queueMicrotask`,
   `AbortController`/`AbortSignal`, `localStorage`, `structuredClone`,
   `EventTarget` — Tier I, in that order of use.
   `structuredClone` also closes the `MessageChannel` ticket.
4. `requestAnimationFrame` (Tier H) and the `WebAssembly` decision.
5. `"use strict"` for lowered modules; the `for-of` capture count.
6. `ibex2 build --platform native` over the boot graph, and the first honest
   startup number.
