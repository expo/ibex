# LLP 0060: Authority is carried, not inferred

**Type:** Decision
**Status:** Draft
**Systems:** CapSec, Engine, Runtime, Module Loader, Host ABI, Build
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-27
**Revised:** 2026-08-27 (initial draft)
**Related:** LLP 0057 (Ibex 2 — this discharges its OQ2 and is the precondition for its §4), LLP 0058 (the engine seam — unreachable without this decision), LLP 0059.000 (the six capabilities this decision binds), LLP 0013 (per-package capability compartments — the mechanism this retires), LLP 0039 (secure and insecure modes — the cost record this closes), LLP 0004 (module loading and builtins — the injection site), LLP 0002 (host embedding ABI)

## Summary

Ibex today determines *who is asking* for a capability by inspecting the
JavaScript stack. That single choice is the reason the Hermes fork exists:
**4,095 of its 5,725 patch lines — 72%, and every Class C interpreter
change — serve stack-derived attribution and nothing else.**

Ibex 2 makes the opposite choice. A grant is bound to the identity of the
binding a module was handed, at instantiation. Nothing is inferred from a
frame, a Domain, or a job queue. The engine is then required to provide
ordinary host functions and nothing more, and **Ibex 2 builds against
unpatched Hermes.**

This is a deletion, not a new mechanism. It removes no defense the current
threat model claims, for the reason given in §3.

## 1. The decision

**D1 — Authority is carried by the binding, not inferred from the caller.**
A capability grant is bound to the identity of a host function object when a
module is instantiated. The boundary check (LLP 0059.000 §1) reads the grant
bound to the invoked binding. There is no frame walk, no `Domain` principal,
no stack intersection, and no schedule-time principal capture.

**D2 — No capability-bearing binding is ambient.** The six capability-bearing
surfaces of LLP 0059.000 §4 — `fetch`, `WebSocket`, `fs`, `localStorage`,
`process.env`, and SQLite — reach a module only by injection at
instantiation. `globalThis` carries the ungated surface only: `console`,
timers, `URL`, `TextEncoder`, `atob`/`btoa`, `structuredClone`, `Blob`,
`EventTarget`, `crypto`, `Buffer`.

This is the property that makes D1 sound, and it is why the current design
could not adopt D1: with 46,000 lines of JavaScript standard library behind
`globalThis`, ambient authority was unavoidable and interposition was the only
answer. With the standard library in Rust the ambient surface to defend is
**six names**, not thousands of bare global references.

**D3 — Ibex 2 builds against unpatched Hermes.** Patches 0001–0008 and 0013
are not carried forward. A CI gate builds and tests ibex2 against the pinned
Hermes source with no patch series applied (§6).

<!-- @ref patches/hermes — the carried series this decision retires most of -->

**D4 — Dynamic code is closed at construction, not latched after boot.**
`EnableEval` is a stock Hermes `RuntimeConfig` knob. Patch 0014 exists only
because today's boot path itself needs `eval` — the loader calls
`new Function(body)` per module. A Rust standard library over an
ahead-of-time bytecode graph compiles no source at runtime, so
`withEnableEval(false)` at construction replaces the one-way latch.

<!-- @ref ios/Frameworks/hermes-headers/hermes/Public/RuntimeConfig.h — EnableEval is stock; the latch is not needed once boot compiles nothing -->

**D5 — Every remaining patch is a recorded decision, not a default.** The five
patches D3 does not retire (§5) must each be retired, replaced in userland, or
upstreamed before Ibex 2 v1. Carrying one is permitted; carrying one silently
is not.

## 2. Why the fork is what it is

| Patches | Lines | Purpose |
|---|---|---|
| 0001–0008, 0013 | **4,095** | Answering "which package is on the stack?" |
| 0009–0011 | 969 | Structured evaluation and REPL fidelity |
| 0012 | 445 | Zero-copy `ArrayBuffer` aliasing |
| 0014, 0015 | 216 | Post-boot eval latch; empty `HermesInternal` |

Domain principals, frame walking, per-package compartment globals, the
`eval`/`Function` compartment binding, deputy fail-closed attribution,
schedule-time principal capture, and 2,599 lines of Promise
constrained-principal carrying are all downstream of the first row. So are the
interpreter changes to `GetGlobalObject`, `CoerceThisNS`, `LoadThisNS`, and
`declareGlobalVarImpl` — the only patches `patches/hermes/README.md` classes as
meaningfully conflict-prone on a pin bump.

**Those patches are hard because JavaScript sits between the package and the
capability.** `Promise.resolve(x).then(fs.readFileSync)` needs schedule-time
capture only because `fs` is a JavaScript deputy over a native call, drained on
a microtask with no live caller frame. LLP 0057 deletes that intermediate
layer. The most expensive patches in the series are artifacts of the design
Ibex 2 removes, and retiring them is a consequence of LLP 0057 rather than an
additional risk taken on top of it.

## 3. What the threat model loses, precisely

**The claim does not change.** LLP 0013 and LLP 0057 §4 state it as
supply-chain integrity, not a sandbox, with explicit handoff out of scope.
Handle-carried authority is defeated by exactly that — a package passing
another package a binding it legitimately holds — and by nothing else. There
is no class of attack that stack attribution refused and D1 admits.

Three things do change, and each is a real cost:

**The implicit deputy disappears rather than being defended.** Today a package
calling a runtime-provided JavaScript helper that reaches a capability is
attributed correctly only because patches 0007, 0008, and 0013 reconstruct the
principal across the async boundary. Under Ibex 2 there is no
runtime-provided JavaScript helper: the module calls the Rust boundary through
its own injected binding. Third-party wrappers around an injected binding
remain, and they are the explicit-handoff class already out of scope.

**Attribution changes meaning.** "Package X performed this operation" is now a
statement about which binding was invoked, not which frames were live. A
binding passed from A to B and invoked by B attributes to **A** — the grantee
whose authority it is — where a stack walk would have named B. For audit and
telemetry this is a different fact, arguably a truer one, and it must not be
reported as though it were the old one.

**Intrinsics are shared.** Patch 0004's per-package compartment globals also
kept one package's prototype mutations off another's. v1 accepts shared
intrinsics. Disabled `eval` and an ahead-of-time bytecode graph narrow the
exposure; they do not close it. See OQ1.

## 4. What the boundary check is still for

Under D1 and D2 the binary question — *may this module reach the network at
all?* — is answered structurally: a module that was not injected `fetch` has no
expression that evaluates to one. The refusal costs nothing because there is
nothing to refuse.

The chokepoint of LLP 0059.000 §1 therefore exists for the **parameterized**
grants, and only those: `net.fetch` per origin, `fs.read`/`fs.write` per path
prefix, `env.read` per variable name, `sqlite.open` per database path. That is
the whole of the runtime policy surface — four questions asked against a grant
the caller already provably holds — against a 4.16MB generated registry and the
roughly 16,628 unresolved admission rows LLP 0039 records today.

## 5. Patch disposition

D3 covers the first row. The rest are open, with a stated leaning:

| Patch | Disposition |
|---|---|
| 0001–0008, 0013 | **Retired by D3.** No replacement. |
| 0014 | **Retired by D4.** Construction-time `withEnableEval(false)`. |
| 0009 raw-throw capture | Renegotiate in userland. The structured evaluator can catch into a slot and return the raw value without asking the engine to coerce it. Fidelity cost to be measured, not assumed. |
| 0010 completion discriminator | Renegotiate. Distinguishing an empty completion from `undefined` falls back to a syntactic heuristic in the REPL — the fidelity loss LLP 0022 accepted before the patch existed. |
| 0011 async failure provenance | The largest genuinely open one at 795 lines. Serves REPL and session diagnostics, not capsec. Candidate for upstream, and for scoping down once most of `src/bin` is gone (LLP 0057 §5). |
| 0012 keyed external ArrayBuffer | Likely unnecessary. Stock JSI already provides `MutableBuffer`, `createArrayBuffer`, and `tryGetMutableBuffer`, which is the zero-copy property LLP 0059.000 §1.4 requires. The patch's residue is keyed detach and transfer refusal — a hardening property v1 can decline. |
| 0015 empty `HermesInternal` | Hardening delta over stock `EnableHermesInternal=false`. Upstream it or accept the difference. |

<!-- @ref ios/Frameworks/hermes-headers/jsi/jsi.h — stock MutableBuffer/createArrayBuffer, the zero-copy path patch 0012 predates -->

## 6. Verification

**The vanilla gate.** Ibex 2 builds and passes its suite against the pinned
Hermes source with `scripts/apply-hermes-patches.sh` not run. Without a gate,
a patch returns the first time one is convenient, and "vanilla" degrades into
an intention. The gate is what makes D3 a fact about the build rather than a
claim in a document.

Note that the current tree already tolerates an unpatched engine: `build.rs`
probes the link artifact for `ex_hermes_vm_current_package_id` and compiles a
compatibility fallback when it is absent. That path exists to keep
Android/iOS linking, not to be secure, and it is not evidence for D3 — but it
means an unpatched build is not starting from zero.

<!-- @ref build.rs — the existing frame-attribution probe; an unpatched engine already links -->

## 7. Open questions

**OQ1 — Intrinsic integrity without compartments.** Freeze intrinsics at boot
and pay the startup cost of a userland `harden` walk (the native
`__exactDeepFreeze` primitive goes away with patch 0006), or accept shared
mutable intrinsics in v1? This is the only security property §3 gives up
without a replacement, and it should be answered by measuring the walk against
the 30ms budget in `rules/RULES.md`.

**OQ2 — The injection mechanism.** Per-module bindings supplied as wrapper
parameters in the prepared graph at build time, or as a module scope supplied
at instantiation? Build time is cheaper at runtime and composes with
ahead-of-time bytecode; instantiation time is more flexible for dynamic
imports. This is loader work and it gates the spike.

**OQ3 — What survives of the capsec apparatus.** The 4.16MB generated registry
and the 19K-line `capsec-semantics` crate exist to enforce the model D1
retires. §4 says the remaining policy is four parameterized questions. What
carries over is the grant *representation* and the admission story for
origins and path prefixes — not the decision engine.

**OQ4 — Patch disposition.** §5's five open rows, per D5.
