# LLP 0045: Network Terminal-Provenance Program

**Type:** Plan
**Status:** Draft
**Systems:** Security, Conformance, Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-08-01
**Related:** LLP 0044 §9 (the measurement that scoped this program; this is
the "Lane B terminal-provenance program" it defers network to); LLP 0036
(advertisement completion plan); LLP 0021 (conformance program); LLP 0037
(D1–D4 attribution rulings); LLP 0039 (secure/insecure modes — the
de-patching decision touches both);
issues/20260801-network-terminal-provenance-program.md (umbrella ticket);
llp/evidence/0044-scope-measurement-09e6aeceb938aa0a945f5f94c2901dfcc84c66ed509d986f32d05f284dfaea18.json

## Summary

The LLP 0044 §9 measurement found that 64% of `network`-family coverage
cells (373 of 580 seed-pure network cells) cannot be certified by any
amount of probe authoring: their rows carry
`no-static-enforcement-terminal` — the static builtin call-graph walker
finds **no path from the public surface to any typed enforcement gate**.
Without a source-derived terminal there is nothing to validate an
observed run against, and accepting the run alone would be the dynamic
route witnessing LLP 0044 §6 rejects.

Crucially, the walker's refusal is **correct, not conservative**. The
network builtins' enforcement routes genuinely are dynamic today, in two
distinct ways:

1. **Patchable method dispatch.** The capability path hops through
   prototype methods (`this._writePendingRequest()`,
   `socket.setTimeout()`), and nothing freezes those prototypes —
   `src/builtins/http.js` contains zero `Object.freeze` calls. A runtime
   prototype write really can reroute the path to the enforcement gate.
2. **Assigned-identifier hook aliases.** Native terminals are called
   through feature-detection aliases
   (`var _x = typeof __exactHook === 'function' ? __exactHook : null;
   … _x(...)`). `_x` is an assigned identifier, so the walker refuses to
   resolve it — soundly, since assignment is mutation.

This plan makes those routes *actually static* — an enforcement-hardening
change in its own right — which converts network's Lane B poison into
ordinary Lane A authoring work. It deliberately does **not** author
network probes, change HTTP behavior semantics, or advertise anything.

## Measured problem shape (2026-07-31 catalog `sha256-XcvN5FFF…`)

Poisoned network cells by module, with the distinct dynamic-receiver
methods behind them:

| module | poisoned cells | distinct `dynamic-call-receiver` methods |
| --- | ---: | ---: |
| node.http | 162 | 63 |
| node.net | 78 | 25 |
| node.dns | 32 | **0** |
| node.tls | 30 | **0** |
| node.http2 | 18 | 9 |
| ws.* | ~13 | ~9 |
| node.https | 4 | 22 (largely shared with http) |
| node.dgram | 1 | 2 |

Ambiguity kinds across those rows: `unresolved-call` dominates at 3,226
row-occurrences (and is the **entire** poison for dns and tls);
`dynamic-call-receiver` spans 75 distinct method names across modules;
`cross-source-export-projection` 370; `computed-call` is marginal. Call
sites to touch for de-virtualization: `src/builtins/http.js` has 117
`this._internal()` sites across 62 prototype-internal method
definitions (of 196 total `this.method()` sites); `net.js` has 20 sites
across 14 definitions; the remaining modules are each a fraction of
that.

Re-derivation: generate the recipe catalog
(`generate-capsec-conformance-recipes.mjs --target aarch64-apple-darwin`),
select rows with `no-static-enforcement-terminal` and a `network:*`
action, and aggregate `route.ambiguousCallees` by the edge's module
segments. The counts above are retained in the LLP 0044 evidence files.

## The plan

### Step 0 — SSA-alias analyzer extension (spike first; may halve the program)

Extend the walker (`capsec-surface-inventory.mjs`, `routeForCallable`)
with **single-static-assignment alias resolution**: a direct call through
identifier `_x` resolves to native hook `__exactHook` iff every one of
these holds, statically:

- `_x` is module-local (never exported, never a parameter, never
  captured for mutation);
- `_x` is assigned **exactly once**, at module top level, and its
  initializer is a reference to a proven native hook — either bare
  (`var _x = __exactHook`) or the typeof-guarded conditional alias
  (`typeof __exactHook === 'function' ? __exactHook : <inert>`), in
  which case the resolved route records the guard as a conditional
  shape;
- no other write to `_x` exists anywhere in the module (including
  `delete`, compound assignment, or aliasing `_x` itself into a mutable
  location).

Anything short of all three keeps today's `unresolved-call` refusal.
This widens what static analysis accepts, so the rule itself gets a
security review before the regenerated inventory is trusted (register
item 2). **Gate:** regenerate the inventory and catalog; measure the
per-module poisoned-cell delta. Expected on the measured data: dns and
tls clear entirely or nearly so, and every module's `unresolved-call`
share drops, before any builtin code changes.

### Step 1 — Enforcement-trunk extraction in `http.js` (pattern-proving module)

De-virtualize **only the capability-path hops**: each internal method on
a route that should reach a native terminal becomes a module-local
function (`this._x()` → `_x(self)`), with the prototype method retained
as a thin wrapper delegating to it so the public/compat method surface
is unchanged. Internal call sites call the free function directly, which
the walker already follows. Feature-detected hook calls on those routes
are normalized to whatever shape step 0's accepted rule resolves.

Consequence, stated plainly: **the enforcement path becomes
non-patchable.** Userland that overwrites `ClientRequest.prototype._x`
still changes the method, but internal routing no longer flows through
the patched slot. For a capability-security runtime this is hardening —
an enforcement route that prototype pollution can reroute is a
vulnerability shape, not a compat feature — but it is an observable
behavior change for code that patches underscore-internals, and it
applies in **both** secure and insecure modes (one shared implementation;
mode-divergent routing would be worse). That is register item 1.

Per-iteration loop: transform a route cluster → rebuild the bundle and
run the generated-artifact regen chain (fingerprints, surface inventory,
identity restamps) → run the HTTP compat/streaming/agent suites →
regenerate the catalog → confirm the poisoned-cell count fell and no
route regressed. Compat tests that deliberately patch internals get
explicit dispositions, not silent accommodation.

### Step 2 — Remaining modules on the proven pattern

net, http2, https, dgram, ws in parallel streams once http.js validates
the transform and its test/disposition pattern. Each is a fraction of
http's volume (table above). dns/tls only if step 0 left residue.

### Step 3 — Verification and hand-off

Full catalog regeneration; success metric: network poisoned cells
**373 → ~0** (any irreducible residue gets an explicit per-cell
disposition and a named reason). Security review of every changed
enforcement path (these edits are enforcement-adjacent by definition).
Then network's cells enter the ordinary LLP 0036 step-2 / LLP 0044
Lane A authoring program — **which is not this plan's scope**: finishing
this plan makes network *authorable*, not *certified*.

## Estimates

Day 1: step-0 spike + measurement. Days 2–5: http.js. Days 5–8:
remaining modules in 2–3 parallel streams. Days 8–10: review + full
regeneration. Roughly **two weeks single-threaded, 1–1.5 weeks
parallelized; low-single-digit thousands of dollars in tokens.** The
drag is the per-iteration regen chain and test surface, not the edits.
These numbers are estimates, not measurements; the step-0 gate produces
the first measured revision of them.

## Author-decision register

1. **De-patching enforcement internals** (blocks step 1): accept that
   internal capability-path routing stops flowing through patchable
   prototype slots, in both modes, with thin wrappers preserving the
   method surface. Recommended: yes — enforcement routes should not be
   reroutable by prototype writes.
2. **The SSA-alias resolution rule** (blocks trusting step-0 output):
   the exact soundness conditions above, reviewed as a widening of what
   static analysis accepts.
3. **Sequencing** (blocks staffing): recommended to run *after or beside*
   the LLP 0044 fs+env+process v1.1 push without blocking it — this
   program feeds a later network milestone, per LLP 0044 §9 option (a).

## Non-goals

- No rewrite of HTTP/net behavior semantics; the transform is
  route-shape-preserving with the single documented patching exception.
- No dynamic route witnessing, no evidence-bar change, no adapter
  credit — Lane B rows clear only because source provenance now supplies
  their terminals.
- No network probe authoring, no advertisement, no scope change: this
  plan ends where Lane A begins.
