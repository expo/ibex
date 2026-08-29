# LLP 0062: Vanilla Hermes as a capability substrate, measured

**Type:** Research
**Status:** Draft
**Systems:** CapSec, Runtime, Engine, Module Loader
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-28
**Revised:** 2026-08-28 (§3: the global object is no longer frozen, only its bindings locked — running Exact showed 193 `globalThis.__exact*` anchors silently failing)
**Revised:** 2026-08-28 (Ibex 2's measured engine is `IBEX_HERMES_VANILLA_SOURCE_COMMIT` `6badada762121682b5481b6124e6c3a991ae6046`; the numbers below were taken on the previous vanilla checkout of the patched pin `e639a7ba` and should be re-read if they drift)
**Revised:** 2026-08-28 (rescoped from Spec to Research after LLP 0058.000 and 0058.000.000 landed from a dual-model review: they own the requirements normatively, and this measures the engine facts they state as conditionals. §1 now points at them rather than competing.) 2026-08-28 (initial draft)
**Related:** LLP 0058.000 (vanilla Hermes and the Rust capability boundary — **normative**; this measures what it assumes), LLP 0058.000.000 (capability-context and adapter protocol — normative for §1's requirements), LLP 0060 (superseded; the independently-derived decision), LLP 0057 (Ibex 2 §4 — where capsec moves), LLP 0059.000 (the host-call boundary this sits above), LLP 0013 (per-package compartments — the retired mechanism), LLP 0023 (the virtual filesystem namespace the loader addresses)

## Summary

**Normative authority for everything here is LLP 0058.000 and LLP 0058.000.000.**
This document measures. Those documents state, correctly and conservatively,
several things about stock Hermes as conditionals — *if* the selected pin
retains a behaviour, *if* an escape is closed — and a capability argument that
rests on a conditional is only as good as whether anyone checked. This is the
check, run against the vanilla pin (`IBEX_HERMES_VANILLA_SOURCE_COMMIT` in
`scripts/hermes-version.sh`) with a build carrying zero Ibex patches. The
absolute timings in §3 were taken on the previous vanilla checkout of
`e639a7bad8bfca844d982afa54fac786c65a8856`; the escape inventory is a
language/VM fact that a pin bump must re-assert, not a number that moves.

Three findings, in descending order of how much they matter:

1. **Every escape that compiles source is closed by construction-time
   configuration — except one.** Hermes serves the exact literal
   `Function("return this")` from a cached fast path that compiles nothing, so
   `withEnableEval(false)` does not gate it. LLP 0058.000 §5 and §8.1 treat that
   as a conditional; on the current pin it is a fact. §2.
2. **It does not matter, and why is the whole argument.** The model never
   required the global object to be *unreachable*, only *empty of authority* —
   LLP 0058.000 D4. Reaching `globalThis` buys nothing when nothing
   capability-bearing is on it, which is a far weaker property and one vanilla
   Hermes can hold.
3. **Intrinsic integrity costs about 2 ms.** A userland freeze of the whole
   global graph is 612 objects and ~2.1 ms, verified effective. That prices
   LLP 0058.000 D8's integrity contract on the one-trust-domain tier, and it
   means retired patch 0006's native deep-freeze was worth roughly 2 ms of wall
   clock rather than a capability property. §3.

## 1. What the measurements are against

The requirements are **LLP 0058.000.000's**, not this document's: §6 owns module
binding, globals, and bootstrap; §8 owns tasks, microtasks, timers, and
callbacks; §11 owns the conformance suite. An earlier revision of this document
stated its own R1–R5, written before that spec existed and independently
convergent with it. They are removed rather than restated, because two documents
stating the same requirement in different words is how a corpus starts
contradicting itself.

What the measurements below bear on, in that spec's terms:

- **§2** tests the escape surface that D4's "shared global carries no authority"
  has to survive, and prices the one escape that remains open.
- **§3** prices D8's integrity contract on the one-trust-domain tier.
- **§4** restates the adversary limits so a reader of the numbers does not
  over-read them; D8 and §3.2 of LLP 0058.000 are the normative statement.

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

**The global object itself is not frozen** (2026-08-28). The first freeze walked
from `globalThis` and froze it along with everything under it. Running Exact
showed what that costs: its runtime anchors shared state on the global object
under 193 distinct `__exact*` names, plus `process`, `window`, `self`,
`global`, and `navigator`, and with the object frozen every one of those
writes silently did nothing — the symptom was a `TypeError` three modules
later, reading a registry that had never been created. The freeze now locks
each existing global binding (non-writable, non-configurable, so `Array`
cannot be pointed elsewhere) and freezes everything reachable from them, but
leaves the object extensible. That is the SES lockdown shape — shared
intrinsics immutable, the global object a compartment's own — and it gives up
nothing R1 or this section claims: a property an application adds is state,
not authority. What it does give up is a channel: two modules can now
communicate through a global they both name. §4 already declines to defend
against voluntary handoff, and this is that with an extra step.
`crates/ibex2/tests/harden.rs` pins both halves.

## 3.1 A language conformance gap that reaches ordinary code

Found while lowering ES modules, and recorded here because it is the same kind
of fact as §2: something a design may reasonably assume, which this engine does
not provide.

**`for (const x of …)` does not create a per-iteration binding.** Closures made
inside the loop all capture the last value:

```js
const fs = [];
for (const n of ['a', 'b']) fs.push(() => n);
fs.map(f => f()).join(',')   // 'b,b'  — the spec says 'a,b'
```

`forEach` is correct, because each element gets its own function invocation, and
that is the workaround `__ibex2_export_all` uses. Without it, `export * from`
republishes one value under every name — which is how this was found.

LLP 0058 §2 puts Hermes at roughly 55% of Test262 and argues the gap is
survivable because Ibex 2 moves the standard library out of JavaScript, so less
of the language is load-bearing. That argument holds, and this is the shape of
its cost: the failure is silent, produces plausible values rather than an error,
and appears in a pattern application code writes constantly.

It also sharpens LLP 0058 OQ3. A conformance floor "expressed as a suite over
the application tier" needs to include closure capture in loops, because a
runtime that gets this wrong miscomputes rather than refuses.

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

Nothing, now. LLP 0058.000 §6 (M0–M6) owns the migration plan and
LLP 0058.000.001 owns the greenfield topology. An earlier revision listed five
loader obligations here; they are covered by those documents and are removed
rather than duplicated.

The one measured input the loader should carry forward: the freeze in §3 must
run **after** the standard library is installed and **before** the first module
executes, and it costs ~2 ms wherever it is placed.

## 6. Open questions

**OQ1 — Where do grants come from?** Not decided. A manifest per package, a
field in the build graph, or an import-site declaration (LLP 0014 answered a
version of this for Ibex 1). The implementation in `crates/ibex2` uses a
per-module manifest provisionally. This remains the largest open design question
in the capability model and is not answered by the 0058.000 family.

Package resolution has since made one part of it concrete rather than
hypothetical: grants key on a resolved file path, so granting a package means
naming internals that are not the author's to know and that change on upgrade.
LLP 0065 OQ2 carries that narrower question.

**OQ2 — Does the freeze belong in Rust?** ~2 ms is affordable but not free, and
a native freeze over the same graph would likely be faster. It is not needed for
correctness, so it is a startup-budget question to answer with a measurement
once there is a boot path to measure.

**OQ3 — What replaces `caps`-style enumeration for R5?** The assertion that the
global carries no authority must be mechanical. Whether that is a test, a build
step, or a runtime check at the end of boot is undecided.
