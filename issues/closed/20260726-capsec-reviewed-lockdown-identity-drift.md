# CapSec reviewed lockdown/inventory identity has drifted from the live sources

**Status:** Closed
**Resolution:** Resolved
**Impact:** 5
**Urgency:** 5
**Ease:** 4
**Confidence:** 5
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “CapSec reviewed lockdown/inventory identity has drifted from the live sources” shows the issue reaches a security, correctness, release, or core product boundary; the defect is blocking or unsafe on a live path now, while the implementation is localized and has concrete acceptance witnesses, with a direct reproduction or current implementation proof.
**Score disposition:** Resolved on the CapSec completion branch; see the
resolution below.

**Filed:** 2026-07-26 (found while landing the 0010/0011 patch-header fix;
verified against pristine `origin/main` b9558cf3 in a clean worktree — this is
pre-existing drift, not introduced by that commit)
**Date:** 2026-07-26

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

## Resolution — 2026-07-26

**1. Lockdown drift reviewed and restamped.** The entire delta between the
reviewed snapshot (pinned at 9e1e5d8e) and the live `lockdownJS` is commit
`4c6ac052` ("Repair the override mistake for error prototypes under
lockdown", 2026-07-26, documented in LLP 0013 and
`issues/closed/20260726-hermes-error-prototype-name-not-writable.md`).
Review findings, affirming the change:

- The delta adds only the SES-reference override-mistake repair for the
  error-intrinsic family (`constructor`/`message`/`name` on the error
  prototypes, plus `toString` on `Error.prototype`), converting configurable
  data properties into accessor pairs before the freeze walk, plus the
  `hasOwn` capture it uses. Evaluator taming (`Function`, `GeneratorFunction`,
  `AsyncFunction`, `eval`), the `process.umask` seal, and the freeze walk are
  byte-identical to the reviewed snapshot.
- No shared mutability is reintroduced: the setter only shadows on the
  receiver (throws on the frozen prototype itself, now in sloppy mode too);
  the getter always returns the original captured value and never reassigns
  it; the accessor pair is frozen directly (literal accessors have no
  `.prototype` own property); and displaced object/function values are queued
  in `overrideValueRoots` and explicitly frozen, so the repair leaves no
  mutable intrinsic outside both freeze walks.
- Fail-closed semantics are preserved (`if (failClosed) throw` on every
  repair step), and no new globals or rendezvous names are introduced.

`REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST` is now
`sha256-db554fcb6c9c245527ee92fc34988671b3797dfa15676ad75e72a3734ffd6c5c` in
both `capsec-surface-inventory.mjs` and `capsec-coverage-model.mjs` (and the
coverage-model test's fixture copy).

**2. Evaluator review id recomputed.** Restamping also required affirming one
more profile-identity field this branch had drifted:
`sourceBuildAuthorityDigests["scripts/build-hermes-linux.sh"]` moved to
`sha256-af521ddda077302b82de42a024eba5e708b9072462d2c4e53c742d8cc473ea92` for
commit `69e28bb7` ("perf: precompile Linux runtime bundle") — reviewed: the
script change only adds the Hermes VM CLI as a built/published artifact (the
HBC-version compatibility probe for build.rs) and does not alter patch
application or the runtime library build. With both fields live-accurate the
exported `HERMES_EVALUATOR_REVIEW_ID` recomputes to
`hermes-evaluators.dbce0074a95aa698966c1d6d1b8bd465118956c7f1f66afead03d2a5356a3880`,
matching live discovery exactly; `REVIEWED_HERMES_EVALUATOR_REVIEW_ID` in
`capsec-coverage-model.mjs` is set to that value.

**3. Host-ABI count updated to 362.** The added surface is
`ex_hermes_activate_webgpu_runtime_v1` from commit `1407af0e` ("Defer WebGPU
runtime activation", 2026-07-25), which already carried its reviewed
classification (`REVIEWED_HOST_ABI_NAMES` row, coverage edge, non-capability
WP4 in the generated inventory) — only the reviewed count assertion was
missed. The companion output-catalog pins move with it, each +1 from the new
surface's `int32_t (ExactHermesRuntime*)` contract: 312 output-bearing / 50
structural-only, return channels 294, `value:scalar` returns 226, `input`
parameters 916.

**4. Startup env row completed.** The live-vs-reviewed startup-name check
also surfaced the fetch owner-race fix's `env:IBEX_TEST_RUNTIME_PRODUCER_HOLD_MS`
(registered in the runtime-environment registry but absent from
`REVIEWED_STARTUP_NAMES` / `HARNESS_STARTUP_ENVIRONMENT_CONTROLS`); both rows
added, mirroring `IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS`.

Both `capsec-surface-inventory.test.mjs` and `capsec-coverage-model.test.mjs`
pass. Item 2 of
[20260726-capsec-regen-chain-broken](../20260726-capsec-regen-chain-broken.md)
is discharged by this fix; that ticket stays open on item 3 (the
`runtime.rs#authenticated-file-ingress` range repin) before the full regen
chain can run.

### Completion-branch reconciliation

The CapSec completion branch also carries the source-built Hermes profile and
additional reviewed host ABIs. After merging the restamp above, live discovery
therefore exports
`hermes-evaluators.3e6954de6300cf7cbd32f27af9077c4a0a55dc951e106a44a991791846e9971f`
and 375 host ABIs: 325 output-bearing / 50 structural-only, with 306 return,
66 callback, and 235 out channels. The classifier pins that composed identity;
the inventory/classifier tests and complete generated-drift gate pass.
