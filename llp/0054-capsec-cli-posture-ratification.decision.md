# LLP 0054: CapSec CLI Posture — Enforce-Only Ordinary Execution, Ratified

**Type:** Decision
**Status:** Accepted
**Systems:** CLI, CapSec, Security, Build, Product
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-23
**Revised:** 2026-08-25 (r2 — ACCEPTED by Charlie Cheever, 2026-08-25, decision relayed via orchestrator exact-9e (register batch item 1), together with the Exact capability posture matrix (`docs/capability-posture-matrix.md`, ratified in the same decision). D1–D4 are in force; D3's watch-child residue removal is executed with this acceptance. r1 2026-08-23: initial draft, authored as the ibex counterpart Exact RFC 0499 C-2 names, on the cross-repo pattern of LLP 0052 ↔ Exact RFC 0476.)
**Related:** LLP 0021 (typed CapSec effect model, armed snapshot — the enforce-only workflow this ratifies), LLP 0038 (unadvertised dev arming — the compile-time dev-arming escape), LLP 0039 (secure and insecure modes — insecure behavior is selected at compile time, never at runtime), LLP 0042 (prepared-graph independent commitment — the commitment machinery behind armed startup), LLP 0052 (durable authority mint/verify — the cross-repo counterpart precedent), LLP 0053 (carrier-bearing ingress coordination — the sibling Exact-carrier ask; deliberately NOT this document), `runtime-surface.json` (the ENG-22429 CLI-surface authority), Exact RFC 0499 §4.3/§5 C-2 (the posture-matrix requirement this answers), Exact LLP 0506 D1(c) (the freeze conjunct the matrix serves), Exact `docs/capability-posture-matrix.md` (row 10 consumes this document's claim)

## Context

Exact RFC 0499 C-2 asks for an ibex counterpart LLP making the CLI's
`--capsec permissive` default an explicit dev flag. That ask was
written against an earlier tree. **Verified against today's tree, the
flip has already happened** — what remains is to ratify the posture as
a recorded, citable claim, and to disposition two pieces of legacy
vocabulary residue. Verified current state (all in `src/bin/ibex/`):

1. `--capsec` defaults to **`auto`** — "Generate and authenticate the
   enforce-only armed execution snapshot" (`cli.rs`,
   `default_value = "auto"`). The doc line on the field reads
   "ordinary execution is enforce-only."
2. Ordinary secure-build execution **refuses** `permissive` and
   `audit`: `validate_runtime_inputs` bails with "production
   capability enforcement rejects legacy allow/deny, environment
   endowment widening, and advisory-attribution overrides"
   (`runtime.rs`), and the armed startup path independently refuses
   any mode outside `Auto | Enforce`.
3. The legacy values remain **parseable but hidden**
   (`PossibleValue::new("permissive").hide(true)`) so validation can
   issue a precise refusal instead of a clap parse error; foreground
   audit is the separately named `ibex capsec audit` command.
4. Dev escapes are **compile-time Cargo features, never runtime
   flags**: `insecure` (LLP 0039 — selected at compile time;
   `Host::new_armed_insecure`) and `unadvertised-dev-arming`
   (LLP 0038 — off by default, never in a shipped build).
5. `Host::default_legacy()` (SecurityMode::Permissive) survives
   **only in `#[cfg(test)]` code** — engine, host ABI, and hermes
   test modules; no production call site remains.
6. **Residue:** `watch_child_args` (`main.rs`) still reconstructs and
   forwards `--capsec permissive` / `--capsec audit` verbatim to
   watch children. Harmless in effect — the child refuses — but our
   own tooling synthesizes a value ordinary execution refuses.

## Decision (accepted 2026-08-25)

- **D1 — Ratify the posture.** Ordinary `ibex` execution is
  **enforce-only**: `--capsec` defaults to `auto`, secure builds
  refuse `permissive`/`audit`, and the only dev escapes are the
  compile-time features of LLP 0038/0039. No runtime flag may weaken
  capsec. This is the recorded claim Exact's capability posture
  matrix (row 10, "ibex CLI") consumes; Exact cites this document
  plus the conformance assertions below, never the stale RFC 0499
  premise ("the CLI defaults to `--capsec permissive`" — true when
  0499 r1 was written, stale now).
- **D2 — Legacy value vocabulary.** `permissive` and `audit` stay
  parseable-but-hidden **solely to produce precise refusals**. They
  are removed from the parse surface only at the next deliberate
  CLI-surface break, with `runtime-surface.json` updated in the same
  change (ENG-22429 authority). Until then their only lawful behavior
  is refusal in secure builds.
- **D3 — Remove the watch-child residue.** `watch_child_args` stops
  synthesizing `--capsec permissive` / `--capsec audit` for watch
  children: `auto` forwards nothing (already true), `enforce`
  forwards `--capsec enforce` (already true), and the two refused
  values forward nothing — the parent has either already refused or
  is an insecure build whose child inherits the same compile-time
  posture. A refused value must never be manufactured by our own
  tooling on a shipping path.
- **D4 — Posture stability.** Any future change to the default, the
  refusal set, or the compile-time escape features is a **posture
  event**: it requires an Exact-side re-verification of posture
  matrix row 10 before the submodule pointer advances (the Exact
  matrix records its verification SHA per row).

## Out of scope, named

- The three missing capsec **resource types** Exact RFC 0499 C-2 also
  tracks (shared memory — Exact LLP 0411; per-realm extension
  bindings — Exact LLP 0410; sandboxed-producer IPC — Exact LLP 0421
  OQ1/OQ5) are separate asks with their own sizing; this Decision
  deliberately does not carry them.
- The carrier asks I1–I4 are LLP 0053's.

## Verification

- Conformance assertions (register with this corpus's existing test
  conventions): the `--capsec` default remains `auto`; secure-build
  validation refuses `permissive`/`audit` with the exact message
  above; after D3, `watch_child_args` emits no `--capsec` value
  outside `enforce`.
- Exact side: `docs/capability-posture-matrix.md` row 10 cites this
  document; the Exact-side source test
  (`armed-runtime-host-consumers`) continues to pin the embedder
  consumers.
