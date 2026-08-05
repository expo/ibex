# Conformance route evidence can record the wrong terminal, outside Lane B

**Status:** Resolved
**Severity:** P1
**Systems:** Security, Conformance
**Author:** Claude (Opus 5), directed by Charlie Cheever
**Date:** 2026-08-01
**Related:** LLP 0046 §3.3 (where this was found); LLP 0045 §3 (the evidence
bar this violates); issues/20260801-network-terminal-provenance-program.md

## Resolution (2026-08-05)

Callback-argument attribution now walks inline callbacks plus uniquely resolved
local and module-level functions passed to calls. The direct route is frozen
before deferred edges are added, so the change cannot erase a previously
recorded terminal; callback-derived proof paths are bounded to one deterministic
witness per terminal/dependency.

An exact edge-cell comparison of catalogs generated before and after the change
measured **46 pre-fix misattributions repository-wide**: 32 in `node_fs`, 5 in
`node_child_process`, 4 in `node_net`, 3 in `node_tls`, and 1 each in
`exact_http` and `node_https`. Nine of those 46 were network-action cells. All
46 now include the callback-only terminal alternatives; **0 previously
recorded terminals were removed** and **0 measured misattributions remain**.

A further **15 cells had no recorded terminal before the change**. Thirteen
carried `no-static-enforcement-terminal` and now clear it (11 network, plus
`node_fs.glob` and `node_perf_hooks.timerify`). The other two
(`node_fs.mkdtempDisposable` and `node_fs.rm`) had no action classification and
therefore did not carry the formal Lane B residual, despite having an empty
terminal set. In the network-program scope, the original **11 Lane B** estimate
was exact.

Measurement catalogs:

- before: `sha256-FNMK1tLlsukgqktcaro3d9yASLSAWPFUfb0Uxj4CoOE`
- after: `sha256-pFBdy33-86VRMMPknRZapaThurvcb84oeBHSubNCA1k`

The comparison grouped recipes by exact `edgeId`, unioned each cell's recorded
`route.alternatives[].terminalObservedKey` set, and classified newly reachable
callback terminals against the untouched baseline. This also verified all
recorded-terminal cells rather than limiting measurement to the network Lane B
set.

`unresolved-call:setTimeout` was deliberately **not** admitted and remains on
the `net.Socket.connect` route. The optional evidence-schema distinction
between "terminal found, walk complete" and "terminal found, walk incomplete"
was not added; that remains a follow-up for the wider provenance program.

Regenerating the catalog with the reproduction below produced 12
`net.Socket.connect` recipes. Every one now records `__exactTcpClose`,
`__exactUnixConnect`, `__exactTcpConnect`, `__exactTcpConnectStart`, and
`__exactTcpConnectPoll`. They retain `ambiguous-static-enforcement-route`,
`argument-selected-terminal-alternatives-not-authored`, and
`public-surface-invocation-not-authored` (plus the scenario-specific branch
residual where applicable), but no longer carry a missing-terminal residual.

## The defect

`net.Socket.connect`'s recorded route evidence names the wrong terminal:

```
edgeId:              surface.builtin.export.node.net.socket.connect.*
terminalObservedKey: builtin:export:node_net:Socket.connect
alternatives:        ["native-op:__exactTcpClose"]      <- the socket CLOSE path
residualReasons:     ambiguous-static-enforcement-route,
                     public-surface-invocation-not-authored
```

The actual connect syscalls — `__exactUnixConnect` (currently
src/builtins/net.js:2730) and `__exactTcpConnect` (:3000, plus the async
`:2964`/`:1288` start/poll pair) — are reached through work entered by the
`setTimeout` callback currently beginning at :3026. The ticket's original
`:2814` pointer is now only the unsupported-TCP fallback timer; source moved
after the ticket was written.
At the time of the report, `walkDirectFunctionBody` began at
packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs:3873 and never
walked a function passed as an argument, so the walk reached neither. The only
terminal it found was on the cleanup path
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

## Original scope was unknown

One instance is confirmed by direct measurement. The generating condition —
a capability call inside a callback argument, with some *other* terminal
reachable directly — is not specific to `net.Socket.connect`. Sibling sites are
known to exist (`ws.js:948` `setTimeout(acceptLoop, 0)` reaching
`__exactTcpAccept`; `ws.js:457` reaching `__exactTcpRead`), though whether those
cells also record a competing wrong terminal has not been checked.

The resolution above supplies the missing measurement.

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
confident wrong terminal. **Met 2026-08-05:** all 46 measured misattributions
now carry their callback terminals; none remain in this measured class.
