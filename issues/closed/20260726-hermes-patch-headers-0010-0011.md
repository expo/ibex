# Hermes patches 0010/0011 are missing the in-file classification header

**Status:** Resolved

**Filed:** 2026-07-26 (found during Exact LLP 0404 review; verified — 0009
and 0012 carry `# Class:` header blocks, 0010 and 0011 begin directly with
`diff --git`)

`patches/hermes/README.md` says each patch is classified in its header, and
the digest-keyed identity machinery treats the patch files as authoritative
bytes — but `0010-completion-record-discriminator.patch` and
`0011-structured-async-failure-provenance.patch` have no header comments at
all. Their README-table classifications exist, so this is governance drift,
not a semantic problem.

Fix: add the same `# LLP …` / `# Class:` / `# @ref` header block the other
patches carry. Note this changes the patch bytes and therefore
`ibex_hermes_patch_digest()` — land it as a deliberate digest-bumping commit
(artifact cache re-key), ideally batched with the next pin bump rather than
alone.

## Resolution

**Resolved:** 2026-07-26. Both patches now carry the house-style header block
(`# LLP 0024 Hermes patch NNNN — <title>` / `# Class: B (...)` / `# @ref ...`
/ prose), classified per the README table rows: 0010 refs
`LLP 0024#6-evaluation-outcomes-and-the-abi` (the anchor its own added doc
comment already cited), 0011 refs `LLP 0024#9-asynchronous-failures` (the
anchor its inline Promise-tracker comment already cited). Diff bodies are
byte-identical to the previous patch bytes — only `#` comment lines were
prepended (`diff <(grep -v '^#' new) old` is empty for both).

**Digest impact analysis (done before editing):**

- `ibex_hermes_patch_stack_digest_hex` moved
  `08e6330d9fab…d930e8c1` → `cd3dd1da3755…f1aa0329` (12-char key
  `08e6330d9fab` → `cd3dd1da3755`).
- Live/forward-looking consumers (no committed assertion, nothing to update):
  `scripts/download-hermes.sh` release identity, both source cache keys and
  `ibex_write_source_patched_profile_receipt` in `scripts/hermes-version.sh`,
  `build_support/hermes_profile_provenance.rs` (recomputes from repo files;
  `tests/hermes_profile_provenance_contract.rs` round-trips that live value),
  `.github/workflows/hermes-artifacts.yml` and
  `portable-engine-physical-promotion.yml` (compute the digest in-run).
- Committed declarative metadata that records the digest AND is enforced —
  updated in this commit: the two `patchStackDigest` literals in
  `REVIEWED_HERMES_EVALUATOR_PROFILES`
  (`packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs`, enforced
  by that package's inventory test asserting live discovery ==
  `HERMES_EVALUATOR_REVIEW_ID`) and `REVIEWED_HERMES_EVALUATOR_REVIEW_ID`
  (`packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs`, enforced by
  the semantic classifier), recomputed to
  `hermes-evaluators.7049b7fa9469481a0cd2efa914f77dc8ff58508c622d1f4a81f253cbe5aa09f2`.
- Deliberately NOT updated: the frozen attestation oracle fixtures under
  `tools/portable-engine-attestation-verifier/` — they record the subject name
  of an already-published artifact (`…-p08e6330d9fab-…`) and verify a recorded
  sigstore bundle, not the live repo digest.
- No Hermes rebuild was required for consistency: no committed check compares
  a recorded digest against rebuilt artifact bytes. Local
  `~/.cache/exact/hermes` entries and published release assets keyed with
  `p08e6330d9fab` simply miss under the new key; the next build re-keys and
  re-publishes under `pcd3dd1da3755` (the cost this ticket anticipated).

**Apply-cleanliness verification:** `git apply --stat` parses both edited
patches, and the full blob-verified series was replayed for real —
`scripts/apply-hermes-patches.sh` against a fresh clone of the pinned commit
`ac8c6e6c80ec…` (from the `~/.cache/exact/hermes/hermes-src` object cache)
verified all 12 patches and produced final tree
`a6e9b222128ab97f9b740839e354f8edd357a388`, byte-for-byte the tree the README
documents. Test parity with pristine `origin/main` (b9558cf3): the capsec
inventory and coverage-model suites show the exact same pre-existing failures
before and after this change (stale reviewed lockdown-taming digest and a
host-ABI count drift — filed separately as
`issues/20260726-capsec-reviewed-lockdown-identity-drift.md`), and no new
failures.
