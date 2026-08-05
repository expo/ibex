# decode_and_admit does not bind carrier-manifest entryId spellings; the LLP 0413 harness tamper probe is positional

**Status:** Resolved
**Systems:** Module loader, Carrier admission, Verification
**Author:** Claude Fable 5 (Claude Code)
**Date:** 2026-07-29
**Related:** `tests/llp0413_arms_ef_admission.rs`, `src/module_loader/carrier.rs`
(`PreparedModuleCarrierV2::validate`, `AdmittedPreparedCarrierV2::decode_and_admit`),
Exact LLP 0413 §14, Exact LLP 0416 §D2 measurement

## What was observed

During the Exact LLP 0416 D2 adapter-2 measurement, the unchanged
`llp0413_arms_ef_admission` harness was pointed at 8 adapter-2 publications
(4 JS factory-table + 4 hermes-bytecode). All 8 ADMIT and all splice
refusals hold, but the single-byte manifest tamper probe on the contract-lab
`per-principal-hbc` publication was **admitted**: the probe flips the byte
at `manifest.len()/2`, and in that manifest the middle byte lands inside an
`entryId` digest string (offset 28 of the base64url payload). The flipped
character keeps the manifest strict-JSON/JCS-canonical and keeps entry
ordering strict, so `decode_and_admit` accepts it.

## Why (both encodings, not an HBC-only fact)

`PreparedModuleCarrierV2::validate` binds:

- carrier BYTES via `carrier_digest` recompute;
- each entry's SEMANTICS via `semantic_digest` recompute;
- ordering/uniqueness of `entry_id` and principal agreement.

It never binds the `entry_id` SPELLING to anything: for JS factory tables
the entry ids also appear inside the (digest-bound) carrier source, but
validate does not cross-check them; for hermes-bytecode carriers the table
keys are inside compiled bytecode and cannot be cross-checked at this layer
at all. `decode_and_admit` adds producer/deployment/principal equality and
authorized-semantic-digest membership — all untouched by an entryId flip.

## Why this is harness-scope, not a production admission hole (analysis)

In the committed-admission shape, entry lookups come from the VOUCHED index
(`records[].entryId`), and `carrier.entry(entry_id)` fails for a renamed
manifest entry, so a tampered entryId refuses at the index/record join —
the layer the tamper probe deliberately bypasses (it calls
`decode_and_admit` in isolation with manifest-derived expectations). The
prior adapter-1 M2/M3 runs passed the same probe only because `len()/2`
landed on digest-checked bytes there.

## Suggested dispositions (either is fine)

1. Harness: make the tamper probe assert refusal of the FULL admission join
   (decode_and_admit + index record entry lookup), or probe multiple byte
   positions / a digest-checked field deterministically.
2. Decoder (optional hardening): have `validate` require, for JS factory
   tables, that every `entry_id` appears as a table key in the digest-bound
   source (byte-level containment), documenting that hermes-bytecode
   carriers rely on the index join for entry-id binding (ibex LLP 0029
   grouped-carrier lookup territory).

Repro: run `llp0413_arms_ef_admission` with
`EXACT_LLP0413_PUBLICATION_DIR` pointing at a publication whose carrier-0
manifest has an `entryId` byte at `len()/2` (the Exact D2 contract-lab
`per-principal-hbc` publication is one).

## Resolution (2026-07-31)

Disposition 1 (harness), plus the documentation half of disposition 2.

- `tests/llp0413_arms_ef_admission.rs`: the manifest tamper probe now asserts
  refusal of the FULL admission join — `decode_and_admit` may accept a flip
  that lands inside an entryId spelling, but then at least one of the
  carrier's index records must fail `entry()`/`prepared_artifact()` lookup by
  the index's own spelling. Probes are deterministic: the historical
  middle-byte position (kept, now join-asserted), a byte inside the
  digest-checked `carrier_digest` value (must refuse at decode itself), and
  the middle byte of every carrier-0 index record's entryId spelling.
- `src/module_loader/carrier.rs`: new lib test
  `entry_id_manifest_flip_refuses_at_the_admission_join` reproduces the
  latitude self-contained (inline JS factory-table carrier, entryId byte
  flip keeps the manifest canonical) and asserts the join refuses; written to
  also accept refusal at decode so an optional future spelling-binding
  hardening does not invalidate it. Runs in ordinary `cargo test --lib`, no
  Exact publication needed.
- `PreparedModuleCarrierV2::validate` now documents what it binds and that
  entryId spellings are deliberately index-join-bound (hermes-bytecode table
  keys cannot be cross-checked at this layer).

Decoder hardening (byte-containment of entry ids in digest-bound JS factory
source) remains optional and unimplemented, per the ticket's "either is
fine" analysis.

Verification: `cargo test --lib module_loader::carrier` 4/4 green
(new test exercised for real); `cargo test --test llp0413_arms_ef_admission`
compiles and skips vacuously here — no `EXACT_LLP0413_PUBLICATION_DIR`
publication exists on this machine, so the reworked gated probes are
compile-verified and logic-mirrored by the lib test; the next Exact-side
LLP 0413 run exercises them against real publications.
