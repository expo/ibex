# LLP 0067: Capabilities in Ibex 2

**Type:** Spec
**Status:** Draft
**Systems:** CapSec, Module Loader, Runtime, Host ABI, Build
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-29
**Related:** LLP 0057 (§3.1 the boundary split, §4, and OQ2 — the decision this states), LLP 0059.000 (§4 — the capability families), LLP 0062 (the measurements: the escape inventory and the freeze), LLP 0065 (§4 — grants and resolution), LLP 0058.000.000 (the adapter protocol the runtime follows), LLP 0060 and LLP 0058.000 (superseded by this document for the model), LLP 0058.000.001 (tombstoned — the program this replaces with tests)

## Summary

Authority is an object a module is handed. A module's `fetch` carries its
grant in its closure; the runtime checks a request against that grant at one
Rust chokepoint and never asks who is calling. Nothing capability-bearing is on
the global object, so a module that was not handed a capability has no
expression that evaluates to one. That is the whole model. This page states it
in full so it can be tested rather than proven, and says what it does not
claim.

## 1. Five properties

Cited from code as R1–R5.

- **R1 — Nothing capability-bearing is on the global object.** `globalThis`
  carries `console`, timers, `performance`, `Headers`, `atob`/`btoa`, the
  lowering helpers, and nothing that reaches.
- **R2 — Capabilities arrive as parameters of the module's own scope.** Every
  module is evaluated as
  `function (module, exports, require, fetch, fs, process, __ibex2_meta)`, and
  the `fetch`, `fs`, and `process` it receives were built for it with its
  grant captured. A module cannot borrow another's binding by name.
- **R3 — Modules ship as bytecode.** Compiled ahead of time against the engine
  this binary links (§5); a `--precompiled` run compiles nothing and refuses
  what was not built. So do the runtime's own bindings, compiled by
  `build.rs` with the engine's `hermesc`: a runtime parses no JavaScript at
  start. Grants are not part of the artifact key, so changing a manifest
  never recompiles anything.
- **R4 — Intrinsics are frozen before any module code runs.** Every existing
  global binding is locked and everything reachable from it is frozen; the
  global object itself stays extensible (§4).
- **R5 — The global name list is asserted before anything runs.** R1 is a
  property of a list, and a list nothing checks drifts: `run` refuses to start
  if the global object carries a name outside `ALLOWED_GLOBALS`.

## 2. Grants

A manifest keyed by module identity (LLP 0065 §4): a section names a file, a
package, a directory, or `*`; a module gets the most specific section naming
it, nothing is combined, and an empty section means nothing. Package identity
comes from the path — the innermost `node_modules/<name>/` — never from a
package's own `package.json`; a workspace package is bound to its real
directory at load; a section naming something not installed is refused before
any module runs. No manifest means no authority.

Three families exist, each a parameterized question:

| family | grant | the question |
|---|---|---|
| `net.fetch` | origin | may this request go to this origin? |
| `fs.read` / `fs.write` | path prefix | may this path be read, or written? |
| `env.read` | variable name | is this variable in the snapshot? |

`process.env` is the model in one object: a snapshot of exactly the granted
variables, so an ungranted one is undefined because it is absent, not because
a check refused it. LLP 0059.000 §4 specifies three more (`net.websocket`,
`storage.local`, `sqlite.open`); each arrives with a measured call site
(LLP 0059 §7), not before.

## 3. The check

One chokepoint, in Rust, at the host-call boundary (LLP 0059.000 §1). It reads
the grant the invoked binding carries and answers the family's question. It
never inspects a stack, a frame, a domain, or a job queue; there is no
attribution and no registry to keep. An operation touching two paths
(`rename`, `copyFile`) needs read on the source and write on the destination.
Paths are normalized lexically before the check, so `/data/../etc/passwd` does
not pass a `/data` grant and a symlink cannot change what a grant covers
between the check and the use. An async operation carries its grant into the
host task; a synchronous host call is permitted only for an operation that
never leaves the calling thread.

A binding handed from module A to module B and invoked by B attributes to
**A** — it is A's authority. That is a different fact from what a stack walk
reports, and a truer one.

## 4. Integrity

The freeze (`harden.js`) runs after the standard library and bindings are
installed and before the first module: each existing global binding is made
non-writable and non-configurable — `Array` cannot be pointed elsewhere — and
every object reachable from them is frozen, so `Array.prototype.map` cannot be
replaced and `Object.prototype` cannot be polluted. The global object stays
extensible, because a property an application adds is state, not authority.
Budget: **2 ms**, declared in `rules/RULES.md` and enforced by
`the_freeze_stays_within_its_budget`; 0.7–1.0 ms today.

Dynamic code is closed at construction (`withEnableEval(false)`): `eval`,
`new Function`, and every form that compiles are refused. Hermes's cached
`Function("return this")` fast path is not closed by it and yields the global
object — accepted, because the global object is empty of authority (R1) and
reaching it buys nothing. Pinned by a test.

## 5. The engine and the artifacts

The engine is unpatched upstream Hermes at the pinned commit, and
`ibex2 build` requires a `HermesInputReceipt` beside it attesting zero
patches, verified against the engine and `hermesc` on disk at build time. The
runtime hashes nothing at start: the archive it links is digested once at link
time (`IBEX2_LINKED_ENGINE_DIGEST`), folded into every artifact key, and
recorded in the manifest, which is checked before any module loads — artifacts
built by another binary are refused under `--precompiled` and ignored
otherwise. Resolution is contained: a module cannot resolve outside the
declared root, on either arm, after canonicalization (LLP 0065 §3–§5). The
closure scan (`tests/closure.rs`) keeps the legacy runtime's authority
machinery out of this crate's source and link closure.

## 6. What it is not

Supply-chain integrity against packages that were not granted — not a sandbox.
Not defended, and not going to be: **voluntary handoff** (a module may pass a
capability it holds to any other; a test pins that this works); **resource
exhaustion** (a module may spin, allocate, or recurse); **channels** between
modules, the extensible global object among them; **anything done before the
freeze**, which only trusted boot code can do; and **whatever the platform
hands back** — a platform API's defaults assume a browser with ambient
authority, and each is checked on its own (cookies are off, LLP 0059.000
§3.5). No compartments, no per-package intrinsics, no caller attribution.

## 7. Evidence

Tests that fail: grants honoured and denied per module, per package, and per
directory (`tests/loader.rs`, `tests/resolution.rs`); the R1 and R5
assertions; the freeze's effect and its budget (`tests/harden.rs`); the
closure scan; the receipt refusals; the manifest-engine refusal; `fs` path
normalization and the two-path operations. That is the evidence, and the whole
of it.

Not evidence, and not sought: proofs that no path bypasses the boundary;
receipts beyond the artifact-to-engine binding; graduation manifests, tier
definitions, policy generations, revocation ancestry, or a five-platform
ceremony. LLP 0058.000.001's program is tombstoned for this reason. Adding an
item to this section requires removing one; the moment the claim becomes
"prove it," it is Ibex 1 again, and the answer is no.

## 8. How it grows

A family is added with a measured call site and a test, never ahead of one.
Revocation arrives when something needs revoking. Package grants exist because
a real manifest was unwritable without them. Nothing else is planned.
