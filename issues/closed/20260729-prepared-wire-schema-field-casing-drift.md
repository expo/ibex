# Prepared-graph wire schemas disagree with the Rust decoders on tagged-enum field casing

**Status:** Closed
**Resolution:** Chose the uniform schema spelling. Tagged `SourceId`,
`ModulePayloadV1`, and `ProducerIdentityV1` variants now apply
`rename_all_fields = "camelCase"`, and schema/codec parity tests cover the
previous drift. LLP 0027 records the regenerable-cache migration rule.
**Systems:** Module Loader, Schemas
**Author:** Claude Fable 5 (Claude Code)
**Date:** 2026-07-29

**Filed:** 2026-07-29 (found by the Exact LLP 0413 Phase 1 arms E/F external
producer: publications written to the schema spelling validate under ajv but
are refused by the real decoders)
**Related:** LLP 0027 ("The checked-in JSON Schema is a review artifact; the
Rust decoder independently enforces the closed structure");
`schemas/module-artifact-v1.schema.json`;
`schemas/prepared-module-graph-v1.schema.json`;
`src/module_loader/artifact.rs`; `src/module_loader/identity.rs`;
Exact repo `tests` `vendor/ibex/tests/llp0413_arms_ef_admission.rs`

**Impact:** 2
**Urgency:** 2
**Ease:** 4
**Confidence:** 5
**Score reviewed:** 2026-07-29
**Score rationale:** No ibex-internal path round-trips through the schemas,
so nothing is broken in-tree; but any external producer or reviewer using
the schemas as the wire reference emits/validates the wrong field names.
Mechanical fix, decoder-verified spellings below.

## The drift

serde's `rename_all` on a tagged ENUM renames variants, not fields. ibex's
struct types consistently use struct-level `rename_all = "camelCase"` (so
`ModuleSemanticsV1`, `PreparedModuleCarrierV2`, `PreparedGraphIndexV2`,
`PreparedCarrierEntryV2` really are camelCase on the wire), and
`carrier.rs`'s `PreparedCarrierEngineBindingV2` adds explicit per-field
renames — but three tagged enums do NOT rename their fields, so their wire
form is snake_case while the checked-in schemas say camelCase:

| Type (Rust wire = authority) | Decoder accepts | Schema says |
| --- | --- | --- |
| `SourceId::Builtin` (`identity.rs`) | `source_key` | `sourceKey` (`prepared-module-graph-v1.schema.json` `$defs.sourceId`) |
| `ModulePayloadV1::Inline` (`artifact.rs`) | `factory_source` | `factorySource` (`module-artifact-v1.schema.json` `$defs.payload`) |
| `ModulePayloadV1::Carrier` | `carrier_digest`, `entry_id`, `entry_factory_digest` | `carrierDigest`, `entryId`, `entryFactoryDigest` |
| `ProducerIdentityV1::InProcess`/`Prepared` | `producer_id`, `producer_binary_digest`, `deployment_graph_digest` | `producerId`, `producerBinaryDigest`, `deploymentGraphDigest` |

Decoder-verified: a publication using the schema spellings is refused with
e.g. ``unknown field `sourceKey`, expected `domain` or `source_key` ``
(observed 2026-07-29 via the Exact arms E/F admission harness); the same
publication with snake_case fields is admitted end to end.

## Decide one of

1. **Fix the schemas** to the decoder spellings (pure review-artifact edit;
   no wire change). Cheapest and consistent with LLP 0027's authority order.
2. **Fix the decoders** to camelCase via `rename_all_fields = "camelCase"`
   (serde ≥ 1.0.190) or explicit per-field renames, making the whole wire
   uniformly camelCase — but this is a WIRE BREAK for any existing prepared
   publication and for the deterministic-publication byte-compare in
   `load_prepared_source_graph_v1`; it would need a schema-version story.

Option 1 unless there is an aesthetic-uniformity reason strong enough to pay
for a wire migration. Note the Exact adapter-1 producer and its schema
validation currently emit/patch to the DECODER spelling
(`scripts/produce-prepared-graph-publication.mjs` documents the patch); if
option 2 is ever chosen, that producer must move in lockstep.

## Resolution evidence 2026-07-29

Option 2 was selected because the checked-in schemas are the external
producer contract and every other object field is already camelCase.
Canonical round trips and a checked schema-to-codec field test prove the
schema-shaped spelling. Old snake_case prepared cache material is disposable:
it refuses and cold-rebuilds rather than creating a permanent second v1 wire
dialect.
