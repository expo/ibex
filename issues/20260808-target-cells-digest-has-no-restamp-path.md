# `targetCellsRawContentDigest` has no non-ceremony restamp path — any coverage-model correction reds `check:capsec-contract`

**Opened:** 2026-08-08 · **Priority:** P2 · **Owner:** CapSec conformance /
promotion chain (found while landing the host-ABI + startup seeding
correction for LLP 0049)

## Symptom

After any change that legitimately alters generated target-cell bytes —
here, withdrawing 90 source-proven false effect assertions — the full
regen chain completes for every generated artifact except one, and
`bun run check:drift` stays red:

```
bun run generate:capsec-contract
error: target advertisements do not bind the exact generated target-cell bytes
```

## Cause

`capsec/generated/target-advertisements.json` carries
`targetCellsRawContentDigest`, which binds the exact bytes of
`capsec/registry/target-cells.json`.

That field is:

- **validated** by the digest contract —
  `packages/ibex-devtools/src/scripts/capsec-contract.mjs:4403`;
- **written** only by the promotion-bundle path —
  `packages/ibex-devtools/src/scripts/capsec-portable-promotion-bundle.mjs:743`,
  `:1152-1153`, `:1219` — which runs during an actual promotion ceremony.

`generate:capsec-registry` regenerates `target-cells.json` but does **not**
rewrite the advertisement's digest; it only validates the publication
(`generate-capsec-registry.mjs:1343`, `validateTargetAdvertisementPublication`).

No promotion has ever run — `advertisements` is `[]` — so the digest was
seeded once and there is now **no non-ceremony path to restamp it**. Any
correction to the coverage model therefore reds the contract check until a
promotion runs, which is circular: a promotion cannot run while the
contract check is red.

## Why this is the predicted M18 pin-9 coupling

The LLP 0049 Phase 1 implementation review flagged that the digest contract
validates the **HEAD copy** of the foundation documents, and that this is
the pin which gates shipping (LLP 0021 amendment, M18 pin 9; A10 #2 settled
that both foundation documents move together). This ticket is that coupling
firing in practice, from the direction nobody had exercised: not a
promotion publishing new bytes, but an ordinary model correction
invalidating the frozen binding.

## What is NOT wrong

The seeding correction itself is sound and verified: with the chain run,
required fixtures drop 22,522 → 21,908 and fs+env+process goes 609 → 519
cells / 3,913 → 3,260 authorable rows / 79 → 66 template classes, with the
poisoned count unchanged at 73. Every other generated artifact regenerated
cleanly. Landed in `8f5047fcd`.

## Options

1. **Give the registry generator ownership of the digest** when
   `advertisements` is empty — i.e. an unadvertised advertisement file's
   binding is regenerated rather than frozen. Cheapest, and arguably
   correct: with nothing advertised, the digest asserts nothing about a
   published claim.
2. **A dedicated restamp command** for the pre-promotion state, with the
   reason recorded, keeping the frozen-once-advertised behaviour.
3. Decide the digest should not exist until the first promotion, and have
   the contract check skip it while `advertisements` is empty.

Option 1 or 3 should be checked against A10 #2's settled disposition
(both foundation documents move together) before implementing.

## Done when

A coverage-model correction can complete the regen chain to a green
`check:drift` without a promotion ceremony, and the chosen mechanism is
consistent with M18 pin 9 / pin 14.
