# LLP 0056 implementation slice 2 (milestone layer) — codex security delta review

**Type:** Review artifact (implementation security delta, LLP 0005 honesty rules)
**Reviewed range:** `d965d03b3..7302d8c13` (the four slice-2 milestone commits; the later clippy-hygiene commit `04fcf9960` was outside the reviewed range)
**Reviewer:** codex gpt-5.6-sol, reasoning effort xhigh, read-only sandbox, run 2026-08-24 by the 0056 legs-2/3 lane (session exact via Claude Fable 5); full transcript retained lane-side (`/tmp/l23-codex-secrev.log`, 294,422 tokens used)
**Review frame:** seven-point enforcement-surface brief (single-publication regression, fail-closed refusal routing, decode bounds, candidate-table dispatch, carrier v3/identity parity, new public surface, vendored-authority trust scope)
**Verdict:** LAND-WITH-FIXES (F1–F4, all MAJOR, none BLOCKER)

## Findings (verbatim substance)

- **F1 (MAJOR)** — `artifact.rs:258-283`, `runner_pipeline.rs:4282-4285, 4497-4500`: adding `ProducerIdentityV1::PreparedPackage` changed the landed single-publication lane's observable refusal for a crafted index carrying that identity — previously index-shape decode failure (`IBEX_PREPARED_COMMITMENT_CORRUPT ... graph index shape`), now a later untokenized producer/deployment staleness prose error. Fail-closed either way; token/position parity broken.
- **F2 (MAJOR)** — `carrier.rs:562-572`, `runner_pipeline.rs:4204-4205, 1851-1863`: composition-lane schema failures misrouted to #14 — a carrier v2 manifest is decoded as the v3 closed shape before its schema identifier is inspected; synthetic package records surface through `portable_record_display` wrapped as #14. Registry row #12 owns both classes.
- **F3 (MAJOR)** — `carrier.rs:580-708`, `runner_pipeline.rs:4151-4181`: package-local predicates do not execute in registry ordinal order (#15 before #14 completion; #21 before #17–#20; artifact #21 before record-carrier #15) — multi-fault inputs report a later ordinal than the mandatory lowest tuple.
- **F4 (MAJOR)** — `composition.rs:44-45`, `runner_pipeline.rs:4007-4013, 4083, 4188, 4242`: `packageGraphDigest` never recomputed from the §4.2 preimage (domain constant unused); admission propagates the claimed digest, so an internally-consistent forged digest earns an `AdmittedCompositionPackageV1`. Package root still prevents post-commit index substitution; the §4.2/#14 facet-derivation guarantee was absent.

## Checks that passed

Extracted LLP 0042 function body and bounded-read discipline unchanged; novel-failure default correctly #11 with no typed failure reaching it; candidate-table v1/v2 dispatch and digest-before-stamp ordering correct; UTF-8-byte/nesting/safe-integer/file-size/closed-serde bounds present; prepared/in-process identity mixing on the composition core refuses #12; carrier v3 drops none of v2's checks; no composition driver or execution entry exists; vendored authority hashes match the fixture manifest and are referenced only from tests/documentation.

## Disposition

All four findings were verified against the tree by the lane orchestrator
and fixed in commit `afe5398d3` ("fix(0056): enforce slice-2 admission invariants"), gate-verified by the lane
(F1: typed early `IBEX_PREPARED_COMMITMENT_SCHEMA` refusal on the
single-publication arm with a pinning regression test; F2: schema-
identifier-first carrier dispatch + synthetic-record routing to #12,
each with routing tests; F3: ordinal-ordered phases with sweep +
lowest-ordinal selection where landed helpers bundle predicates, pinned
by multi-fault tests; F4: the §4.2 recomputation implemented with a
documented PROVISIONAL preimage encoding pending its O-1 row, pinned by
a test vector, disagreement refusing #14). Gate results for the fixed
tree accompany the landing commit message.
