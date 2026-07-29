# Carrier v2 cannot express a reserved loader/runtime principal as a carrier owner

**Status:** Open
**Systems:** Module Loader, CapSec, Schemas
**Author:** Claude Fable 5 (Claude Code)
**Date:** 2026-07-29

**Filed:** 2026-07-29 (Exact LLP 0413 Phase 1 arms E/F, adapter option 1 —
see the Exact repo's `issues/20260728-llp0413-phase1-carrier-tournament.md`,
"Arms E/F progress" finding 1)
**Related:** LLP 0013 (reserved runtime/module-loader principals for loader
machinery and the shared `rolldown-runtime.js` chunk redirect); LLP 0026 §9;
LLP 0027 (carrier v2); `schemas/module-carrier-v2.schema.json`;
`src/module_loader/carrier.rs`; `src/module_loader/identity.rs`

**Impact:** 2
**Urgency:** 2
**Ease:** 3
**Confidence:** 3
**Score reviewed:** 2026-07-29
**Score rationale:** No current ibex producer hits this (the loader resolves
its own chunk machinery outside the carrier wire), but any external adapter
that inherits a bundler's synthesized runtime-helper chunk as an emitted
module has no faithful carrier encoding for it; the workaround exists and is
Documented, so this is a schema-clarity question, not a blocker.

## The gap

`schemas/module-carrier-v2.schema.json` allows `definingPrincipal.kind` to be
`root | runtime | module-loader | quarantine | package`, but a
`module-loader`- or `runtime`-principal carrier is unsatisfiable for any real
entry today:

- `SourceId::file` requires a **root or package** defining principal
  (`src/module_loader/identity.rs`), so no file-backed entry can carry a
  loader/runtime owner; and
- `PreparedModuleCarrierV2::validate` admits a principal-less (builtin)
  entry only when the carrier's defining principal `is_root()`
  (`src/module_loader/carrier.rs`), so a builtin-shaped entry cannot ride in
  a loader/runtime carrier either.

Every entry shape is therefore excluded: the schema advertises an owner kind
the decoder can never accept a member for.

## Where it bites

Exact's LLP 0413 Phase 1 adapter-option-1 producer inherits Vite/rolldown's
synthesized bundler-runtime helper chunk (`\0rolldown/runtime.js` content —
`__commonJSMin`/`__exportAll`, no npm sources) as an emitted module. LLP 0013
treats exactly this artifact as loader machinery under the reserved
principal, but at the carrier wire the only admissible encoding is a builtin
record charged to the ROOT carrier (the LLP 0027 "builtin is charged to the
authenticated root initialization owner" rule). That is what the Exact
producer does (builtin domain `exact-dev-bundler`), and admission accepts it —
but it silently converts "loader-owned machinery" into "root-owned builtin",
which is an attribution statement, not just a packaging one.

## Decide one of

1. **Bless the workaround:** document (LLP 0027) that bundler-runtime helper
   code in a prepared publication is root-charged builtin content, and
   narrow the carrier v2 schema's `definingPrincipal` to the kinds a carrier
   can actually own (`root | package`), so the wire shape stops advertising
   an unsatisfiable owner.
2. **Make the reserved principal real on the wire:** allow
   `module-loader`/`runtime` carriers whose entries are builtin-shaped
   records in a matching reserved domain, with admission and frame
   attribution rules to match (LLP 0013's loader-principal trust would then
   flow through the carrier wire rather than being re-derived).

Either resolution is fine for Exact's tournament (the root-charged builtin
encoding is already recorded as option-1 tournament data); the schema/decoder
disagreement is ibex's to own.
