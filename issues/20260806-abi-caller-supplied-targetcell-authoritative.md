# Caller-supplied `EffectGate.target_cell` is authoritative at the host ABI on shipping builds

**Status:** Open
**Impact:** 3
**Urgency:** 2
**Ease:** 3
**Confidence:** 5
**Score reviewed:** 2026-08-06
**Score rationale:** A real, verified property of an unconditionally
exported ABI symbol on every shipping `CompleteAdvertised` build, found
by an independent round-3 review of the LLP 0021 scoped-advertisement
amendment. It is bounded — the ABI returns a verdict and grants nothing,
and all three in-repo callers are test-gated — so it is not a live
capability escape, but it lets an embedder's enforcement point and the
typed-evidence stream be fed a caller-chosen answer, which is not what
the certification claims.
**Severity:** P2
**Systems:** Security, Host ABI, CapSec
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-08-06
**Related:** LLP 0021 §A3 ingress rule, §A9 M32, §A8 F3a;
`llp/reviews/0021-scoped-advertisement-amendment.fable.md` round-3 N8

## What is true today

`EffectGate` is a `#[derive(Deserialize)]` struct with a **public**
`target_cell: TargetCellDisposition` field
(`crates/capsec-semantics/src/decision.rs:401-407`), so a gate is fully
constructible from untrusted JSON.

`ex_host_evaluate_typed_decision` (`src/host/abi.rs:5823-5839`) is an
unconditionally exported `#[no_mangle] pub unsafe extern "C"` symbol —
no `cfg` — whose `gates` argument is a caller-owned byte buffer. It
dispatches to `Host::evaluate_typed_decision_json_with_evidence`
(`src/host/mod.rs:3963-3990`), which strict-parses the buffer,
`serde_json::from_value`s it into `Vec<EffectGate>`, and evaluates it
**unchanged**. The four `pub` Rust ingresses behave identically
(`src/host/mod.rs:3776`, `:3844`, `:3942`, `:3963`).

The Host's own authoritative projection is `fn target_cell`
(`src/host/mod.rs:956-961`):
`self.target_cells.get(edge).copied().unwrap_or(Incomplete)`. Nothing
on the ABI path consults it for a caller-supplied gate.

Two consequences on every shipping build:

1. **A caller can present `complete` for a cell the admitted map holds
   as `Closed`.** The evaluator's lifecycle/target-closure stratum
   matches on `gate.target_cell`
   (`crates/capsec-semantics/src/decision.rs:672-683`): `Closed` returns
   a hard `Deny` with `DecisionReason::TargetCellClosed`, `Complete`
   falls through. Because the byte comes from the caller, the deny at
   `:674-683` is converted into a pass simply by serializing
   `"targetCell":"complete"`.
2. **Any non-inventory `coverage_edge_id` evades the
   `unwrap_or(Incomplete)` default.** The Host would answer `Incomplete`
   (refuse) for an edge id absent from the admitted map; a caller
   presenting its own disposition never reaches that default.

## Bounded reach (stated honestly)

This is **not** a capability escape by itself. `ex_host_evaluate_typed_
decision` returns a **verdict** and grants nothing: it performs no
effect, opens no handle, and mints no authority. The exposure is:

- the **typed-evidence stream** — recorded decisions can reflect a
  caller-chosen cell disposition rather than the armed Host's;
- **embedders and native runtime extensions** that link the host ABI and
  treat the ABI's answer as *their* enforcement point. That population
  is precisely the one a target-cell certification speaks to, which is
  why this is worth a ticket rather than a shrug.

All three in-repo callers of the symbol are test-gated —
`src/bin/ibex/engine/hermes.rs:1144` (under
`#[cfg(all(test, feature = "capsec-conformance-observer"))]`),
`src/bin/ibex/engine/capsec_host_abi_output_batch.test.rs:2014`
(reachable only via the `include!` at `hermes.rs:6301` under the same
gate), and `src/host/abi.rs:13208` (below that file's `#[cfg(test)]` at
`:10476`) — so there is no production in-repo caller. The **symbol**
carries no `cfg` and is exported regardless.

## Relationship to LLP 0021's scoped-advertisement amendment

The amendment's §A3 **ingress rule** (discard the incoming `target_cell`
and recompute it from the retained `AdmittedScopedTargetCells` at every
ingress), §A9 M32, and the F3a fixture class fix exactly this channel —
but **only under `TargetArmState::ScopedAdvertised`**. F3a-5 explicitly
asserts the whole class is a no-op under `CompleteAdvertised`, so that
work leaves today's releases untouched by design. This ticket is the
`CompleteAdvertised` half, which is out of that amendment's remit.

## Options

1. **Apply recomputation unconditionally**, not only under
   `ScopedAdvertised`: every caller-supplied gate crossing a `pub`
   entry point or the C symbol has its `target_cell` discarded and
   recomputed from the armed Host's map via `fn target_cell`
   (`:956-961`). Strongest, and it makes the amendment's F3a class
   arm-state-independent. Needs a compatibility check on any embedder
   that today presents a correct disposition and relies on being able
   to observe that it did (which is not a capability anything needs —
   see §A3's argument).
2. **Equality-check instead of recompute** under `CompleteAdvertised`:
   refuse when the presented value differs from `fn target_cell`'s.
   Weaker (LLP 0021 §A3 gives three reasons recomputation beats it) but
   a smaller behavioural delta.
3. **Do nothing until `ScopedAdvertised` ships**, and document the
   property. Acceptable only if the embedder population is empty; it is
   not obviously empty, since the symbol is exported unconditionally.

Option 1 is recommended; it is the same mechanism the amendment already
specifies, with the arm-state condition removed.

**Done when:** a caller-supplied `EffectGate` cannot determine its own
`target_cell` at any evaluator ingress on a `CompleteAdvertised` build —
proved by a fixture that serializes `"targetCell":"complete"` for a cell
the armed map holds as `Closed` and asserts the deny at
`decision.rs:672-683` still fires — or the property is explicitly
accepted with the reasoning recorded in LLP 0021 and this ticket closed
against that record.
