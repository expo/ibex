# LLP 0057: Ibex 2 — a Rust standard library with JavaScript bindings

**Type:** RFC
**Status:** Draft
**Systems:** Runtime, Engine, Host ABI, Module Loader, CapSec, Build
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-27
**Revised:** 2026-08-28 (OQ2 answered — in, whole — with the bounded list; OQ4 on third-party Rust) 2026-08-28 (§5.2: the target is Exact 2, not Exact; §3.1 states the Rust/JS split and why load time is not its reason; §6 OQ2 restated as whole-or-absent, with the deciding question and a recommendation) 2026-08-27 (initial draft)
**Related:** LLP 0063 (where startup time goes — the measurement §7 said had not been taken), LLP 0000 (Ibex — the root this amends), LLP 0002 (host embedding ABI — the boundary this generalizes), LLP 0004 (module loading and builtins — the JS standard library this inverts), LLP 0013 (per-package capability compartments — the enforcement point this relocates), LLP 0039 (secure and insecure modes — the cost record this cites), LLP 0058 (the engine seam)

## Summary

Ibex today is a Rust runtime hosting a JavaScript standard library. Ibex 2 is
the inversion: **a Rust standard library that exposes JavaScript bindings**,
with platform-native implementations where the platform has one, and with
JavaScript optional rather than required.

This is not a rewrite. The runtime core — engine embedding, module loader,
host services, VFS, capsec semantics — is roughly 152K lines of Rust that
largely survives. What moves is the ~46K lines of `src/builtins/*.js`, and
what changes is the direction the sandwich faces.

Three things follow, and each is the reason for a different part of this
document: **no-JS consumers get a standard library at all**; **capsec's
enforcement point collapses from thousands of global references to one
host-call boundary**; and **the engine becomes a swappable component**
(LLP 0058) rather than a foundation.

## 1. Why

**No-JS consumers get nothing today.** A Rust-owned UI root or a Linux/DRM
display path has no `fetch`, no filesystem, no crypto — those live behind
`globalThis` in a JavaScript engine. Every capability Ibex provides is
reachable only by starting Hermes and evaluating JavaScript.

**capsec is expensive because capabilities live in JavaScript.** When a
capability is a property on a global object, enforcing it means per-package
private globals, frozen intrinsics, and interposed accessors — about 7,700
lines of engine glue in `src/bin/ibex/engine/`, a 19K-line semantics crate, and
a 4.16MB generated registry. LLP 0039 records the remainder honestly: roughly
16,628 unresolved rows, no cheap bulk win found, and "months of work, not days"
before a default build can arm at all. That cost is a property of the
enforcement point, not of the idea.

**The boot path is the clearest symptom.** Measured on the real 570-module
macOS boot graph: it ships **5.47MB of ESM module sources as string literals**
inside `startup.js`, and the loader transpiles each one to CommonJS at runtime
before Hermes compiles it — through SWC, because Oxc cannot lower general ESM
import/export syntax for the synchronous loader yet.

<!-- @ref src/module_loader/transpile.rs — the runtime ESM→CJS transpile this proposal deletes -->

Compiling the outer bundle to bytecode does not help, because the module
sources are string literals inside it: the wrapper measures 33ms from bytecode
against 155ms from source, while the 5.47MB inside is transpiled and compiled
on every launch regardless. A Rust standard library is not shipped as source
strings, cannot be transpiled at runtime, and does not participate in this at
all.

## 2. The inversion

Ibex's surface splits into three categories with three different answers. The
split is the design; treating the surface as one thing is what makes "move it
all to Rust" sound either trivial or impossible.

**Platform-delegating** — `fetch`, WebSocket, filesystem, crypto, storage,
timers, location. Rust interface, platform implementation. The sandwich model:
Rust computes, the platform executes.

**Pure computation** — `URL`, `TextEncoder`, base64, the streams state machine,
`Intl`. Rust, no platform involved. Straightforward and correctness-critical.

**Engine-intrinsic** — `Promise` and the microtask queue, `async`/`await`,
module resolution semantics, GC interaction, error stacks, `WeakRef`. **These
cannot move.** They belong to the engine, and the interleaving of a Rust
executor with the engine's own job queue is the one part of this proposal with
no clean off-the-shelf answer. It is where Node, Deno, and Bun each spend a
disproportionate share of their complexity. LLP 0058 owns it.

## 3. The boundary

The rule that makes this the sandwich model rather than a thin shim over
platform APIs:

> **Rust owns semantics. The platform owns transport.**

For `fetch`, Rust owns header case-folding, redirect policy, the body and
stream state machine, abort, and the error taxonomy. The platform owns sockets,
TLS, proxy configuration, HTTP/2 and /3, and connection pooling — which is how
system proxy settings, VPN awareness, and the OS certificate store come for
free. Inverting this gives four platforms four different `fetch`es, which is
the failure mode a cross-platform runtime exists to prevent.

Two properties the boundary must have, both of which are cheap to state now and
expensive to retrofit:

- **Primitives and handles, not serialization.** A `fetch()` that crosses a
  JSON-encoding FFI hop has traded parse time for call time. A host call should
  be sub-microsecond.
- **Async by default.** No new synchronous cross-thread call surface.

### 3.1 What goes in Rust, and what does not

Stated 2026-08-28, after it had been implied for a month and after the reason
usually given for it turned out to be the weak one.

**Load time is not the reason.** LLP 0063 §2 measures the per-runtime floor at
1.5 ms in release: construction 0.36 ms, Rust stdlib host functions 0.02 ms,
the JS bindings ~1.0 ms, the intrinsic freeze 1.7 ms. The 956 ms boot this
program exists to delete was module source being parsed, and bytecode removes
it (851 ms → 13 ms for a 570-module graph). Moving what is left of the JS
bindings to Rust would recover about a millisecond; the freeze alone costs more.

**The reason is the non-JS consumer.** `rules/NOT-DOING.md` sets the bar: a
Rust root, or the Linux/DRM path, gets the same standard library with no engine
in the process. Exact 2's plan runner is that consumer — it is Rust, it runs
the application, and it needs `fetch`, `fs`, timers, and `URL` itself. One
implementation serves it directly and the JavaScript bindings thinly. The
second reason is the one §4 gives: one boundary is one place to check.

**So the split is by what a thing touches, not by preference for a language:**

- **Rust owns** semantics, state the platform touches, transport, byte-level
  parsing (`URL`, base64, `crypto`), and anything a Rust consumer needs.
- **JavaScript owns** object shape and plumbing over JavaScript values —
  `EventTarget`, `AbortController`, `MessageChannel`, the mutation surface of
  `URLSearchParams`. LLP 0059.000 §1.3 measures why: bytes cross for free,
  strings at 2–3.5 ms/MB, and every host call has a fixed price. An API that
  is nothing but object plumbing gets slower and larger if each operation
  crosses.
- **The engine keeps** what it does natively — `TextEncoder`, `JSON`, `Intl`.

Two rules that follow. Modules load as bytecode only, and the floor stays at
or under 2 ms, measured by `caps` rather than asserted. And authority arrives
as objects at the boundary — a module's `fetch` carries its grant in its
closure — so the Rust side checks a grant against a request and never asks who
is calling. That property, not the language, is what keeps §4 from growing the
attribution machinery Ibex 1 grew.

## 4. capsec moves to the boundary

With the standard library in Rust, every capability is reached through one
host-call surface. A capability check becomes a few lines at one chokepoint
instead of a policy applied to thousands of bare global references.

This changes what is *enforced*, not what is *claimed*. It eliminates the
ambient-authority-through-globals class — precisely what the 7,700 lines of
engine glue fight today. It leaves the explicit-handoff class, where a package
passes another package a handle it legitimately obtained, exactly as out of
scope as LLP 0013 already documents. **The honest threat-model language does
not change: supply-chain integrity, not a sandbox.**

The per-package compartment machinery is not ported. Whether it is ever
rebuilt depends on §6's open question, because compartments defend a dependency
graph and a runtime that has no npm graph has nothing to defend.

## 5. What this deletes

The runtime ESM→CommonJS transpile and the second transform engine behind it.
`src/builtins/*.js` as a JavaScript standard library. The per-package
compartment machinery and its engine glue. The 4.16MB generated capsec
registry in its current shape. And, separately but in the same window, most of
`src/bin/` — 137K lines of CLI against a 152K-line runtime core, where `run`,
`build`, and probably `repl` is the whole surface a runtime needs.

## 5.2 What Ibex 2 is for

*(Numbered 5.2, not 5.1: LLP 0058.000.001 §1 cites "LLP 0057 §5.1" as the
superseded incremental-in-place strategy, and a section carrying two meanings
is worse than a gap in the numbering.)*

**Revised, later on 2026-08-28: Ibex 2 targets Exact 2** — the from-scratch
rewrite in the `exact2` repository (its LLP 1000 is the root map), not the
Exact this section was written against that morning. The earlier decision and
its consequences are kept below because they drove a day's work (LLP 0066) and
because most of what that work found about the *runtime* still holds; what it
found about the *application* was Exact 1's shape.

What Exact 2 says, and what follows for Ibex 2:

- **No application JavaScript runs before first pixel** (`rules/RULES.md`
  there: 100 ms p50 cold start to interactive first frame; "App JS executed
  before first pixel: none"). Contract compiles in Rust to a plan, a Rust VM
  runs it, and the web host is kernel and runner as wasm over the DOM. Ibex 2
  is therefore off the first-pixel path by construction. Its startup job is
  its own floor (§3.1) and a small bytecode graph, not a 511-module boot in
  30 ms.
- **The v1 surface is measured from Exact 2's JavaScript**, which is currently
  none. LLP 0059's 560-module inventory becomes a ceiling, not a
  specification; the list shrinks from there, one measured call site at a
  time, per LLP 0059 §7.
- **Exact 2 forbids platform-suffixed route files and has no React tier**
  (`rules/NOT-DOING.md` there). LLP 0065 §8's `--platform` served a convention
  the target bans and was deleted the same evening, with `MessageChannel`,
  whose only call site was React's renderer.
  `WebAssembly` and `requestAnimationFrame` are no longer requirements of the
  JS tier.
- ESM and TypeScript remain required: whatever JavaScript Exact 2 does run
  will be written that way.

*The decision as first recorded on 2026-08-28, superseded above:*

**Ibex 2 targets Exact.** It is the runtime Exact moves to,
not a smaller runtime for new work alongside an ibex 1 that keeps Exact.

This was implicit and is now explicit, because the whole corpus assumed it
without recording it: LLP 0059 decides the v1 API surface by measuring *Exact's*
boot graph, and §7 admits its own inventory is a floor derived from that graph.
A document set that scopes itself by one application's measured usage has
already answered which application it is for.

Three consequences follow immediately, and the first is expensive:

- **ESM is required.** Exact is 4,350 ESM files against 79 CommonJS ones. The
  loader built for Ibex 2 is CommonJS, which cannot load a single Exact module.
  This is the largest remaining piece of work in the program and it precedes
  anything that depends on the module format's wrapper shape. LLP 0026 and
  LLP 0027 are the prior art to read rather than reinvent.
- **The API surface is bounded and already inventoried.** LLP 0059's measurement
  becomes a specification rather than a survey.
- **`WebAssembly` and `requestAnimationFrame` are requirements**, not options.
  Both are somebody else's to provide — Tier E is the engine's and Tier H is the
  host's (LLP 0059 §2, §4) — but neither may be absent.

What this does not decide is *when* Exact moves, or whether it moves all at
once. A runtime that can run some of Exact is useful before one that can run all
of it.

## 6. Open questions

**OQ1 — Node compatibility.** Port `http`, `net`, `tls`, `fs`, and
`child_process` to Rust, or delete them? An app runtime for web, macOS, iOS,
and Linux plausibly needs only `fetch`, WebSocket, timers, `crypto.subtle`,
storage, `URL`, and `TextEncoder`. Deleting is far cheaper than porting, and
this single answer sets the size of the entire program. It is a product
question, not a technical one, and it is the author's.

**OQ2 — capsec: whole, or absent.** Restated 2026-08-28 as the author's
requirement: Ibex 2 ends up with capsec either fully implemented, understood,
testable, and usable — or not present, creating no complexity and no
performance tax. Not the state it is in.

Two things carry the name today. The *mechanism* is small and whole: authority
arrives as module parameters, never on the global object; a manifest keyed by
module; three grant families (origin, path prefix, environment name) checked
at one Rust chokepoint; intrinsics frozen at boot. It fits on a page
(LLP 0060, LLP 0062 R1–R5), it is tested, and it costs a grant lookup per host
call plus the 1.7 ms freeze. The *program* around it — LLP 0058.000.001's
G1–G6, policy generations, revocation ancestry, graduation manifests, tier
definitions, five-platform receipts — is large, unbuilt, and is the shape that
produced Ibex 1's unending list. Ibex 1's list came from enforcing at
JavaScript globals, thousands of sinks needing observers and registries to
prove coverage; Ibex 2 removed that cause, and the remaining risk is
re-importing the evidence ceremony by specification.

The question that decides it is the author's: **will Exact 2 run JavaScript
its author did not write** — npm packages, agent-installed code, user
extensions?

- *Yes:* keep the mechanism, retire the program. Tombstone 0058.000.001's
  gates, add package-level grants (LLP 0065 OQ2 — without them a real
  manifest is unwritable), bound the freeze in `caps`, done.
- *No:* delete grants, manifest, freeze, and receipts. Keep only what costs
  nothing and keeps the door open the way Exact 2's own NOT-DOING keeps
  doors open: capabilities stay parameters rather than globals (§3.1).

Recommendation, given Exact 2's shape — no npm graph, no application JS
before first pixel, Contract-first: *no, door open*. Undecided; the author
decides.

**Answered, later on 2026-08-28: *in, whole.*** The author expects Exact 2 to
run JavaScript it did not write — npm dependencies, most likely — and
possibly third-party Rust (OQ4). The recommendation above was conditional on
the opposite, and it flips: the mechanism is cheaper to keep than to re-grow.
"Whole" is bounded, and `issues/20260828-capsec-made-whole.md` carries the
list:

1. **One page states the model.** Authority arrives as module parameters,
   never on the global object; grants are keyed by *package*; three families
   today (origin, path prefix, environment name) and more only with a
   measured call site; checked at the Rust boundary against the grant the
   call carries, never against who is calling; intrinsics frozen at boot;
   the global name list asserted before any module runs. Non-goals stay as
   LLP 0062 §4 has them: not a sandbox — no defense against exhaustion,
   voluntary handoff, or timing.
2. **Package-level grants** (LLP 0065 OQ2). Grants key on file paths today,
   so a real dependency manifest is unwritable. A package is a prefix of its
   canonical path — `./node_modules/react/` — which §4.1's one-file-one-name
   rule already makes exact.
3. **The freeze under `caps`**, at its measured 1.7 ms, so the tax is a
   number the build refuses to exceed rather than a fact remembered.
4. **The proof is the test suite** — grants honoured, denials, the
   adversarial fixtures that exist, R5, the closure scan — plus the artifact
   keyed to the engine receipt. No graduation manifest, no tier
   definitions, no five-platform ceremony, no policy generations, no
   revocation ancestry until something needs revoking. LLP 0058.000.001's
   G1–G6 program is tombstoned; what its §7 wanted as *tests* is kept as
   tests.

*Done 2026-08-29: LLP 0067 is the page; package grants are LLP 0065 §4.2; the
freeze budget is a `rules/RULES.md` row enforced by a test; 0058.000.001 is
tombstoned and 0058.000 superseded.*

The line that keeps it whole rather than endless: the claim is supply-chain
integrity against packages that were not granted, and the evidence is tests
that fail. The moment the ask becomes "prove no path bypasses the boundary
on five platforms," it is Ibex 1 again, and the answer is no.

**OQ3 — The event loop.** How the Rust executor and the engine's job queue
interleave, and who owns the microtask drain. Owned by LLP 0058.

**OQ4 — Third-party Rust.** Raised 2026-08-28: Exact 2 may run Rust code its
author did not write, as well as JavaScript. The JavaScript model does not
extend to native Rust: a Rust crate linked into the process has ambient
authority and no boundary to check at. Two honest shapes, and they are
different problems:

- *Rust dependencies of the runtime itself* are the ordinary supply chain —
  trusted at build time, audited with `cargo vet` / `cargo deny`, never
  loaded at run time. Not capsec.
- *Rust loaded at run time* — plugins, extensions, app data crates from a
  registry — should be **wasm modules with explicit imports**. Exact 2
  already builds its kernel for `wasm32`; a wasm module can reach only what
  its host hands it, which is the same rule as the module parameters above,
  enforced by the wasm runtime rather than by this one. One model for both:
  code you did not write gets only what it is handed — JavaScript through
  parameters, Rust through imports.

Whether Exact 2 wants the second shape is Exact 2's decision; this document
only says that native Rust is not a capability boundary and should not be
described as one.

## 7. What this does not claim

This is a re-founding of where capabilities live, not a claim that the
resulting runtime is faster by construction. The startup numbers in §1 are
measurements of today's boot path; they establish that the current design pays
a large avoidable cost, not that the proposed one hits any particular budget.
`rules/RULES.md` sets that budget at 30ms to app entry, derived from Exact's
100ms first-frame budget.

**Measured since, in LLP 0063.** The runtime floor is 4ms of the 30. The same
570-module graph loads in ~851ms from source and ~3ms from ahead-of-time
bytecode, and the reason is not the parser — Hermes parses at the same
throughput this document's 155ms figure implies. What costs is roughly 2ms of
fixed price per compile unit, paid once per module, which bytecode removes
almost entirely. The proposal's premise survives contact with a measurement;
its loader has to compile ahead of time for that to be true.
