# `MessagePort.postMessage` passes a reference instead of cloning

**Status:** Closed
**Resolved:** 2026-08-28
**Impact:** 2
**Urgency:** 2
**Ease:** 3
**Confidence:** 5
**Severity:** P3
**Systems:** Runtime
**Author:** Claude (Opus 5), directed by Charlie Cheever
**Date:** 2026-08-28
**Related:** LLP 0059.000 §3.8.1, LLP 0059 §3

`crates/ibex2/src/bindings/message_channel.js` delivers the argument to
`postMessage` by reference. The platform structured-clones it, so a receiver
cannot observe mutation the sender makes afterwards, and non-cloneable values
(functions, DOM nodes) throw `DataCloneError` rather than arriving.

Stated rather than faked: `structuredClone` is a v1 Tier I item that does not
exist yet, and a hand-rolled deep copy would diverge from the real algorithm in
ways harder to reason about than a documented reference pass.

Nothing needs it today. React's renderer — the reason `MessageChannel` exists
here at all — posts `null`, so the divergence is unobservable in the case that
motivated the API.

Two consequences to fix together:

1. Clone via `structuredClone` once it lands.
2. Throw `DataCloneError` for values that cannot be cloned, instead of
   delivering them.

**Done when:** a message whose payload the sender mutates after `postMessage`
arrives with the value as it was at post time, and a function payload throws.

## Resolution (2026-08-28)

Retired, not fixed. `MessageChannel` was in Tier I for one reason — React's
renderer — and LLP 0057 §5.2 moved the target to Exact 2, which has no React
tier. LLP 0059 §7's rule (no measured call site, no API) took the binding out
the same evening, and this ticket with it. If a `MessageChannel` ever returns
it should clone from the start; the divergence recorded here is the reason.

