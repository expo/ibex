# LLP 0062: Reachable authority — what a capability model needs from the engine

**Type:** Spec
**Status:** Draft
**Systems:** CapSec, Runtime, Engine, Module Loader
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-28
**Revised:** 2026-08-28 (initial draft)
**Related:** LLP 0060 (authority is carried — the decision this specifies the mechanism for), LLP 0057 (Ibex 2 §4 — where capsec moves), LLP 0059.000 (the host-call boundary this sits above), LLP 0058 (the engine seam), LLP 0013 (per-package compartments — the retired mechanism this replaces), LLP 0023 (the virtual filesystem namespace the loader addresses)

## Summary

LLP 0060 decided that authority is carried by a binding rather than inferred
from a stack. That decision is about **permission**. It leaves a second
question untouched, and the second question is the one the retired fork
answered:

- **Permission** — may *this authority* perform *this operation*? Answered at
  the host-call boundary (LLP 0059.000 §1), in a few lines.
- **Reachability** — what authority can *this code* obtain at all? Answered by
  the shape of the scope it runs in, and by nothing else.

A chokepoint with no reachability story is a lock on a door in an open field.
The fork's compartment patches (0004–0006) existed to give each package its own
global object, because the standard library was reachable *through* globals.
This document states what replaces them, and records what was measured against
vanilla Hermes rather than assumed.

**The finding that shapes everything here: the model does not require the global
object to be unreachable. It requires the global object to be empty of
authority.** That is a far weaker property, it is achievable without patching an
engine, and it survives an escape that the stronger property would not.

## 1. Requirements

An implementation satisfies this document when all five hold.

**R1 — No capability-bearing binding is reachable from the global object.**
`globalThis` carries the ungated surface only: `console`, timers, `URL`,
`TextEncoder`, `atob`/`btoa`, `structuredClone`, `Blob`, `EventTarget`,
`crypto`, `Buffer`. The six capability-bearing surfaces of LLP 0059.000 §4
reach a module by injection or not at all.

R1 is the load-bearing requirement. Every other line in this document assumes
it, and no other mechanism compensates if it fails.

**R2 — Each module receives its bindings as parameters of its own scope.**
A module is compiled as a function of its injected bindings and invoked with
them. Two modules granted differently receive two distinct binding objects,
each closed over its own grant set. Verified: two modules in one runtime, each
reaching its own origin and denied the other's.

**R3 — Module wrappers are compiled ahead of time.** LLP 0060 D4 closes `eval`
and the Function family at construction, so the wrapper cannot be built with
`new Function(body)` at load time. It is produced by the build, which is the
same artifact the startup budget already requires (LLP 0058 §1.1).

**R4 — Intrinsics are frozen before any module code runs.** See §3.

**R5 — The set of names on the global object is fixed before any module code
runs, and is asserted.** R1 is a property of a list, and a list that nothing
checks drifts. The check belongs next to the boot path, not in a document.

## 2. The escape inventory

Measured against vanilla Hermes built with `withEnableEval(false)` and
`withMicrotaskQueue(true)`, no patches applied. `crates/ibex2` holds each of
these as a test.

| escape | result |
|---|---|
| `eval('globalThis')` | blocked |
| `(0, eval)('globalThis')` | blocked |
| `new Function('return globalThis')()` | blocked |
| `({}).constructor.constructor('return globalThis')()` | blocked |
| `[].constructor.constructor('return 1')()` | blocked |
| `(function(){}).constructor('x','return x')(1)` | blocked |
| **`({}).constructor.constructor('return this')()`** | **ALLOWED — returns the global object** |

Everything that compiles source is refused. The exception is not a mistake in
the configuration: Hermes serves that **exact literal** from a cached fast path
that compiles nothing, so the eval flag never sees it. Carried patch 0014
exists precisely to close it, and LLP 0060 D4 originally claimed the flag
retired that patch. It does not, and the claim was made without testing the
case the patch is about.

**The exception is survivable, and why is the point of §1.** A module that
obtains the global object obtains a bag of ungated utilities. Under R1 there is
nothing else on it. The capability model was never a claim that `globalThis` is
unreachable — only that it is not worth reaching.

Both halves are pinned by a test: the hole is open, and it yields nothing. If a
future engine or configuration closes it, that test fails and this section is
revisited rather than quietly rotting.

## 3. Intrinsic integrity, and what it costs

R1 keeps authority off the global object. It does nothing about *integrity*:
intrinsics are shared, so one module can replace `Array.prototype.map` and
change how another module's code behaves. That is not an authority escalation —
the attacker gains control flow, not a capability — but it is the property
per-package compartments used to provide, and LLP 0060 §3 records it as the one
thing given up without a replacement.

**The replacement is a userland freeze at boot, and it is affordable.**
Measured on vanilla Hermes (`crates/ibex2/tests/intrinsic_harden.rs`, release,
mean of 20):

| | |
|---|---|
| objects frozen | 612 — the whole global graph |
| time | **~2.1 ms** |

Against the 30 ms budget in `rules/RULES.md` that is roughly 7%: real, and
affordable. Verified effective, because a number for a freeze that does not
freeze is worthless — after it, `Object.prototype.polluted = 1` does not take,
`Array.prototype.map` cannot be replaced, and `Object.defineProperty` on a
frozen prototype throws.

The walk must have three properties, all of which the fork's native
`__exactDeepFreeze` also had: it reads property **descriptors** so getters are
not invoked, it is **iterative** so a deep graph does not hit a native stack
cap, and it tracks **visited** so cycles terminate.

**This discharges LLP 0060 OQ1.** Freeze at boot and pay ~2 ms. Patch 0006's
native deep-freeze was worth about that much wall clock — a performance
optimization, not a capability requirement.

## 4. What is not defended

Stated so that none of it is later discovered as a surprise. The threat model
is unchanged from LLP 0013 and LLP 0057 §4: **supply-chain integrity, not a
sandbox.**

- **Voluntary handoff.** A module holding a capability may pass it to any other
  module. Out of scope, and pinned by a test asserting that it works.
- **Resource exhaustion.** A module may spin, allocate, or recurse. Capabilities
  bound reach, not consumption.
- **Denial by intrinsic mutation before the freeze.** Only trusted boot code
  runs before R4, which is why R4 says *before any module code runs*.
- **Anything the platform hands back.** A platform API's defaults assume a
  browser-shaped client with ambient authority; each one is checked separately.
  The precedent is `NSURLSession`, whose default redirect-following would have
  delivered a response from an ungranted origin.

## 5. What this asks of the module loader

The loader is where R1, R2, R3, and R5 are actually enforced, and it does not
exist yet. When it is written it must:

1. Compile each module as a function of its injected bindings, at build time.
2. Resolve each module's grant set before instantiation, from a declared source.
3. Instantiate with distinct binding objects per module — never a shared one.
4. Publish nothing capability-bearing on the global object, and assert the
   global name list after boot.
5. Run the intrinsic freeze after the standard library is installed and before
   the first module executes.

Nothing above requires an engine patch.

## 6. Open questions

**OQ1 — Where do grants come from?** §5.2 says "a declared source" because the
answer is not decided. A manifest per package, a field in the build graph, or
an import-site declaration (LLP 0014 answered a version of this for Ibex 1).
This is the largest open design question in the capability model.

**OQ2 — Does the freeze belong in Rust?** ~2 ms is affordable but not free, and
a native freeze over the same graph would likely be faster. It is not needed for
correctness, so it is a startup-budget question to answer with a measurement
once there is a boot path to measure.

**OQ3 — What replaces `caps`-style enumeration for R5?** The assertion that the
global carries no authority must be mechanical. Whether that is a test, a build
step, or a runtime check at the end of boot is undecided.
