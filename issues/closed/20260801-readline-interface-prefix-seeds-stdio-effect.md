# node_readline: `/^interface(?:\.|$)/` seeds a stdio effect on pure members

**Status:** Open
**Severity:** P3
**Systems:** Conformance
**Author:** Claude (Opus 5), directed by Charlie Cheever
**Date:** 2026-08-01
**Related:** LLP 0046 §2 (the network instance of this shape and its cost);
issues/20260801-network-terminal-provenance-program.md

## The defect

`builtinExportClassification`
(packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs:9587) classifies
by **receiver-class prefix**:

```js
/^interface(?:\.|$)/ → readlineOperationEffectSpec()
```

That seeds a `stdio` effect on all 51 `Interface.*` surfaces, including members
that perform no I/O at all — e.g. `_wordLeftIndex` (src/builtins/readline.js:849),
`_wordRightIndex` (:866), `getPrompt` (:1372), `_getPromptText` (:739),
`_pushUndoSnapshot` (:759), `_rememberKill` (:768). These are in-memory string
and buffer operations.

## Why it matters

Seeding a capability a member does not have inflates that family's coverage
denominator with cells that can never be certified by proving a route, because
there is no route. In the network family the identical shape accounted for **90
of 338 cells** and helped invalidate an entire program plan (LLP 0046).

## Scope: bounded, one instance

The `/^receiverclass(?:\.|$)/ → effect spec` shape occurs at exactly 12 sites in
`capsec-coverage-model.mjs`. Eleven are network (:9210, :9222, :9228, :9250,
:9257, :9278, :9284, :9311, :9352, :9392, :9665), plus a harmless non-effect
`blocklist.` at :9399. **`node_readline` (:9587) is the only non-network
instance.**

By contrast `node_fs` (:8975–9080), `exact_process`, `node_child_process`,
`exact_sqlite`, and `exact_crypto` all **enumerate members** — fs tests
`/^readstream\.(?:_read|open)$/`, not `/^readstream(?:\.|$)/`. So this is not a
systemic modelling failure; a full cross-family audit is **not** warranted.

## Fix

Follow the existing member carve-out pattern (:9207/:9216/:9219): place an
exact-string member set for the pure `Interface.*` members *before* the class
prefix. Prefer an exact `Set` over widening the regex — a widened regex silently
absorbs future members, which is how the network instance arose.

Gate the change through the LLP 0045 §3 paired allow-list
(`scripts/llp0045-route-evidence-diff.mjs --scope all`) so the residual removals
are individually declared rather than booked as a falling count.

**Done when:** `Interface.*` members that perform no stdio carry a non-capability
disposition, and the readline family's denominator reflects only members that can
actually reach a gate.

## Resolution (2026-08-06)

Fixed as part of the LLP 0049 §4.1 seeding fixes (uncommitted at the time of
this note; lands with that change set). `NODE_READLINE_INTERFACE_PURE_MEMBER_APIS`
in `packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs` is an
exact-string member set ordered before the `/^interface(?:\.|$)/` prefix. Nine
members were re-derived from `src/builtins/readline.js` as pure in-memory and
now carry `non-capability(pure-in-memory-compute)`: `_addHistory` (:968),
`_getPromptText` (:739), `_pushUndoSnapshot` (:759), `_rememberKill` (:768),
`_resetHistorySearch` (:775), `_wordLeftIndex` (:849), `_wordRightIndex`
(:866), `getPrompt` (:1372), `setPrompt` (:1368).

Deliberately left on the class prefix after source verification (all reach the
input/output streams or were judged borderline and kept conservative):
every `_delete*`/`_refreshLine`/`_yank*`/completion/prompt/question/write
member (they reach `_writeToOutput` → `output.write`, readline.js:732), the
terminal-size readers `_getColumns`/`_getDisplayPos`/`getCursorPos`
(readline.js:679-684 read `output.columns`/`input.columns`), and
`_normalWrite` (in-memory decode/buffer but it is the non-TTY line-delivery
path; kept seeded conservatively).

Gated through the LLP 0045 §3 paired allow-list as prescribed:
`llp/evidence/0049-allow-list-phase0-seeding.json` (strict mode, declared
before candidate generation; gate PASS, 0 unexplained, 0 stale).
