# CapSec reviewed lockdown/inventory identity has drifted from the live sources

**Status:** Resolved

**Filed:** 2026-07-26 (found while landing the 0010/0011 patch-header fix;
verified against pristine `origin/main` b9558cf3 in a clean worktree — this is
pre-existing drift, not introduced by that commit)

Two committed reviewed-identity assertions no longer match live discovery:

1. **Lockdown taming digest.** The live `lockdownJS` content scanned from
   `src/engine/hermes_runtime.cc` hashes to
   `sha256-db554fcb6c9c245527ee92fc34988671b3797dfa15676ad75e72a3734ffd6c5c`,
   but the reviewed literal `REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST` is still
   `sha256-84bc50a29f721c540d8cf37b74f395d4afef63f0174df05bd40ec9b0e4486e8c`
   in both `packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs`
   and `packages/ibex-devtools/src/scripts/capsec-coverage-model.mjs`.
   Someone changed the engine lockdown script without re-reviewing the
   snapshot. Consequences on `origin/main` today:
   - `capsec-surface-inventory.test.mjs` — "reviewed lockdown content binds
     execution, targets, and taming helpers" fails (live
     `engineIdentityReviewId` ≠ the reviewed `HERMES_EVALUATOR_REVIEW_ID`,
     driven entirely by the lockdown digest; every profile identity field
     matched as of b9558cf3).
   - `capsec-coverage-model.test.mjs` — "every currently observed repository
     surface joins exactly one semantic edge" fails with
     `unclassified observed surface native-op:global:AsyncFunction` (the
     classifier deliberately fails closed on an unreviewed engine identity).

2. **Host ABI count.** The same inventory test file's "live repository
   discovery has every non-empty category and stable ordering" asserts
   `expect(first.hostAbi).toHaveLength(361)` but live discovery now finds 362
   host-ABI entries — an ABI surface was added without updating the reviewed
   count.

Fix: re-review the lockdown change, update
`REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST` in both files, recompute
`REVIEWED_HERMES_EVALUATOR_REVIEW_ID` in `capsec-coverage-model.mjs` from the
exported `HERMES_EVALUATOR_REVIEW_ID`, and update the reviewed host-ABI
length. Note the patch-header commit (this branch) already moved the reviewed
`patchStackDigest` values to
`sha256-cd3dd1da3755030de039f6c08d4b9116fd85da6a46aace96706e0fa1f1aa0329` and
the reviewed-side review id to
`hermes-evaluators.7049b7fa9469481a0cd2efa914f77dc8ff58508c622d1f4a81f253cbe5aa09f2`;
the review id must be recomputed again after the lockdown digest is fixed
(it hashes the taming digest together with the profiles).

## Resolution

The CapSec completion branch reviewed the error-prototype lockdown change,
updated both reviewed taming digests, and refreshed the host-ABI count. After
rebasing the Hermes 0010/0011 classification-header repair from main, the
combined live inventory exports and the classifier accepts
`hermes-evaluators.08bb542867d4d29fabe8e67c64eae3b78d5605fc9259dafda2e0044c41c2beae`.
The inventory/classifier tests and complete generated-drift gate pass with that
composed identity.
