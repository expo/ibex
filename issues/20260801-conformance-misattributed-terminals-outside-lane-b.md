# Conformance route evidence can record the wrong terminal, outside Lane B

**Status:** Open
**Severity:** P1
**Systems:** Security, Conformance
**Author:** Claude (Opus 5), directed by Charlie Cheever
**Date:** 2026-08-01
**Related:** LLP 0046 §3.3 (where this was found); LLP 0045 §3 (the evidence
bar this violates); issues/20260801-network-terminal-provenance-program.md

## The defect

`net.Socket.connect`'s recorded route evidence names the wrong terminal:

```
edgeId:              surface.builtin.export.node.net.socket.connect.*
terminalObservedKey: builtin:export:node_net:Socket.connect
alternatives:        ["native-op:__exactTcpClose"]      <- the socket CLOSE path
residualReasons:     ambiguous-static-enforcement-route,
                     public-surface-invocation-not-authored
```

The actual connect syscalls — `__exactUnixConnect` (src/builtins/net.js:2727)
and `__exactTcpConnect` (:2814) — sit inside a `setTimeout` callback.
`walkDirectFunctionBody` (packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs:3873)
never walks a function passed as an argument, so the walk reaches neither. The
only terminal it does find is on the cleanup path
(`Socket.connect → _resetSocketForConnect → _cancelPendingConnect →
__exactTcpClose`).

## Why this is worse than a Lane B cell

Note the residual reason that is **absent**: `no-static-enforcement-terminal`.

This cell is **not in Lane B**. It reads as a cell that has a static enforcement
terminal — it just has the wrong one. LLP 0045 was scoped entirely to the
walker's honest refusals (the 338 cells that admit they have no terminal). This
is the opposite failure: a **confident misattribution**, and nothing currently
measures that class.

A probe authored against this evidence would validate `__exactTcpClose` and
report the connect route as covered.

## Scope is unknown

One instance is confirmed by direct measurement. The generating condition —
a capability call inside a callback argument, with some *other* terminal
reachable directly — is not specific to `net.Socket.connect`. Sibling sites are
known to exist (`ws.js:948` `setTimeout(acceptLoop, 0)` reaching
`__exactTcpAccept`; `ws.js:457` reaching `__exactTcpRead`), though whether those
cells also record a competing wrong terminal has not been checked.

**No measurement of this class exists.** That is the substance of this ticket.

## What to do

1. **Measure the class.** For every cell with a recorded terminal, determine
   whether any capability call is reachable only through an unwalked callback
   argument. Cells where such a call exists *and* a different terminal was
   recorded are misattributions; cells where none was recorded are the ordinary
   Lane B case.
2. **Land callback-argument attribution** (same walker site, :3873). Measured to
   give 11 Lane B cells a real terminal with 0 going silent, and it is the fix
   for this defect too.
3. **Do not admit timers as non-terminal before (2).** `unresolved-call:setTimeout`
   is currently the *only* marker that a route defers into unanalyzed code.
   Admitting it alone clears 0 Lane B cells and turns 6 into routes claiming to
   have been fully analyzed with no gate — three of which demonstrably contain
   one. See LLP 0046 §3.3.
4. Consider whether the evidence schema should distinguish "terminal found, walk
   complete" from "terminal found, walk incomplete" — the latter is what every
   route containing an unwalked callback actually has.

## Reproduction

```
bun packages/ibex-devtools/src/scripts/generate-capsec-conformance-recipes.mjs \
  --target aarch64-apple-darwin --output /tmp/catalog.json
node -e '
const c=require("/tmp/catalog.json");
for (const r of c.recipes.filter(r=>(r.edgeIds||[]).some(e=>/node\.net\.socket\.connect\b/.test(e))))
  console.log(JSON.stringify({alts:r.route.alternatives, res:r.residualReasons}));
'
```

**Done when:** the class is measured, callback attribution has landed, and any
remaining misattributed cells carry an explicit disposition rather than a
confident wrong terminal.
