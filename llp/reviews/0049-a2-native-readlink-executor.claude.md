# Review — LLP 0049 A2 native readlink executor

- **Family:** Claude (Anthropic Sonnet)
- **Provider/runtime:** Claude Code CLI with a fresh, non-persistent context
- **Independence:** the reviewer authored none of the code or tests under review
- **Reviewed revision:** `663985e3d70363ca4eaf76cabecf8ca3e4ab49fe`
- **Reviewed tree:** `ced3f6ecd3c1bcb2bd30a8b19f7afd8d64c969d8`
- **Reviewed parent:** `6625d1e9abbe13eb70034a0d700372a19f16827b`
- **Reviewed diff SHA-256:** `2d9540193765fcb73f711f3ace80a5a9b6fac778148dd517ece8a10fe6f51349`
- **Date:** 2026-08-09
- **Redacted:** no (public-repository content only)
- **Verdict:** READY

Author note: the received review is retained verbatim below. Its final explicit
answer says “all 10 non-deny rows” and then correctly identifies two deny rows
within the 11-row tranche. That is an arithmetic typo: the evidence contains
9 non-deny rows and 2 deny rows. The review's earlier artifact analysis and its
READY verdict are otherwise internally consistent with the retained evidence.

## Review body (verbatim)

# Independent Adversarial Review — commit `663985e3d70363ca4eaf76cabecf8ca3e4ab49fe`

## Provenance / revision

- **Commit under review:** `663985e3d70363ca4eaf76cabecf8ca3e4ab49fe` — "review: A2 native readlink tranche target"
- **Tree:** `ced3f6ecd3c1bcb2bd30a8b19f7afd8d64c969d8` (confirmed via `git rev-parse 663985e3^{tree}` — matches the assignment digest)
- **Parent:** `6625d1e9abbe13eb70034a0d700372a19f16827b` (confirmed)
- **Diff sha256:** not independently recomputed (no canonical `git show`-diff hashing tool was pointed to in scope); diff content itself was read in full (547 lines, `git show <commit>`) and every hunk is accounted for below.
- **Repository:** `/Users/ccheever/wt-campaign-a2-review` only. `/Users/ccheever/wt-campaign` was never entered, read, or modified.
- **Reviewer independence:** I did not author this commit or its tests. Family: Claude (Anthropic), running as an independent reviewing agent instructed to break the fixtures.

## Scope

LLP 0049 §3 rule 11, applied to this Phase 2 native-op executor change (`surface.native.op × [fs:read]`, direct and asynchronous readlink carriers). Read in full before review: LLP 0037 (D1–D4, plus the readlink-specific "Link-byte read and translation evidence" passage), LLP 0049 §3 (all 12 rules, §3.1), and §6/§6.1/§6.2/§6.3.

## Methodology

1. Read the full commit diff (`git show`) across all 5 files.
2. Read LLP 0037 D1–D4 and the readlink evidence section it documents; read LLP 0049 §3 rule 11's discharge contract and §6.3's exit-gate framing for "every batch that lands an executor change."
3. Ran the two specified baselines from a clean tree.
4. Ran four break-tests, one per named mechanism, each reverted before the next; confirmed baselines green and `git status --short` empty at the end.
5. Cross-examined the three read-only artifacts under `/Users/ccheever/phase1-runs/campaign-a2/` against the committed allow-list and the current source tree, including a byte-exact regeneration of the candidate catalog.
6. Ran the full JS recipe test file (not just the filtered fixture) on both this commit and the parent to separate pre-existing failures from anything this commit could have caused.

**Build note (recorded for reproducibility, not a finding):** this worktree ships no `ios/Frameworks/macosx/hermes.framework`. I built nothing; I pointed `HERMES_LINK_STATIC=1`, `HERMES_LIB_DIR`, `HERMES_INCLUDE_DIR`, `JSI_INCLUDE_DIR` at the pre-built static Hermes bundle already present at `/Users/ccheever/projects/ibex/ios/Frameworks/{macos-static,hermes-headers}` (a separate, unrelated worktree's build output — not `wt-campaign`). This only affects how the binary links; it changes nothing under review.

## Baselines (both green, from a clean tree)

```
$ HERMES_LINK_STATIC=1 HERMES_LIB_DIR=.../macos-static HERMES_INCLUDE_DIR=.../hermes-headers JSI_INCLUDE_DIR=.../hermes-headers \
  cargo test --bin ibex --no-default-features --features standard,capsec-conformance-observer,openssl-crypto \
  native_incidental_traversal_allowance_is_exact_and_fail_closed -- --test-threads=1 --nocapture
```
→ `test ... native_incidental_traversal_allowance_is_exact_and_fail_closed ... ok` (1 passed, 650 filtered out).

```
$ bun test --test-name-pattern 'authors direct and asynchronous readlink' \
  packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs
```
→ `1 pass, 107 filtered out, 0 fail, 106 expect() calls`.

## Break-tests (each mutation reverted with `git checkout --` immediately after capture)

### 1. Declared-subset / unrelated-extra rejection (`native_observed_actions_are_reviewed`, `capsec_conformance_batch.rs:1801`)

**Mutation:** replaced the body with `declared_actions.is_subset(observed_actions)`, dropping the `extra == "fs:list" && reviewed_native_open_traversal_prefix(...).is_some()` requirement on every surplus action.

**Command:** the Rust baseline command above.

**Observed failure:**
```
thread '...native_incidental_traversal_allowance_is_exact_and_fail_closed' panicked at
src/bin/ibex/engine/capsec_conformance_batch.rs:667:5:
assertion failed: !native_observed_actions_are_reviewed(&direct, &unrelated_surplus)
test result: FAILED. 0 passed; 1 failed
```
The fixture's `unrelated_surplus = {fs:list, fs:read, network:connect}` case, which exists specifically to prove an unrelated capability (`network:connect`) cannot ride along, is wrongly accepted once the guard is dropped. Fails as required.

### 2. Requested/discovery/repeat stage restriction so commit `fs:list` is accepted (`native_decision_is_reviewed_open_traversal`, `capsec_conformance_batch.rs:1818`)

**Mutation:** widened `Some("requested" | "discovery" | "repeat")` to `Some("requested" | "discovery" | "repeat" | "commit")`.

**Command:** the Rust baseline command above.

**Observed failure:**
```
thread '...' panicked at src/bin/ibex/engine/capsec_conformance_batch.rs:704:5:
assertion failed: !native_decision_is_reviewed_open_traversal(&direct,
        &traversal_decision("commit", "fs-readlink:/project/CLAUDE.md"),
        &list_effects, false)
test result: FAILED. 0 passed; 1 failed
```
The fixture's dedicated "a commit-stage `fs:list` must never be credited as reviewed traversal" assertion catches this immediately. Fails as required.

### 3. `fs-readlink:` operation-prefix / exact-carrier / async-branch restriction (`reviewed_native_open_traversal_prefix`, `capsec_conformance_batch.rs:1778`)

**Mutation:** collapsed the `__exactFsPathAsync` match arm from `if matches!(invocation.arguments.first(), ... value == "readlink")` to an unconditional `"__exactFsPathAsync" => Some("fs-readlink:")`, crediting *any* dispatcher operation (not just the literal `"readlink"` branch) as reviewed readlink traversal.

**Command:** the Rust baseline command above.

**Observed failure:**
```
thread '...' panicked at src/bin/ibex/engine/capsec_conformance_batch.rs:683:5:
assertion `left == right` failed
  left: Some("fs-readlink:")
 right: None
test result: FAILED. 0 passed; 1 failed
```
The `wrong_branch` case (`__exactFsPathAsync` with `"readdir"` as its first argument) is wrongly credited. Fails as required.

### 4. JS direct/async readlink registration/template (`capsec-conformance-recipes.mjs:2394,3418`)

**Mutation:** commented out both map entries — `["__exactReadlink", nativeProjectReadlinkTemplate()]` in `NATIVE_PUBLIC_PROBE_TEMPLATES` and `["readlink", nativeProjectReadlinkTemplate({ async: true })]` in the `__exactFsPathAsync` logical-branch map.

**Command:** the bun baseline command above.

**Observed failure:**
```
error: expect(received).toHaveLength(expected)
Expected length: 11
Received length: 0
(fail) exact-target CapSec executable recipes > authors direct and asynchronous readlink carriers with mixed traversal denial [0.95ms]
1 fail
```
With the registration gone, the target rows no longer resolve to `NATIVE_PUBLIC_PROBE_TEMPLATES`/`NATIVE_PUBLIC_LOGICAL_BRANCH_PROBE_TEMPLATES`, so the filter finds zero fully-executable readlink rows. Fails as required.

**Post-mutation restoration and final green check (both baselines, once, after all four reverts):** both baseline commands rerun green (shown above under "Baselines"); `git status --short` was empty after each individual revert and again at the end of the sequence.

None of the four credited fixtures stayed green under its targeted mutation. No BLOCKER from the break-test loop itself.

## Artifact cross-examination (read-only)

`/Users/ccheever/phase1-runs/campaign-a2/{candidate-readlink-final.json, readlink-primary-air-v2.json, readlink-secondary-air-v2.json}` plus `baseline-catalog.json` (present alongside, read for the diff).

- **`declaredAllowListDigest`** in the candidate catalog (`sha256-yhptbWZGG9Fb97NaAjp9hd9e8LCkCaQCc_UoceRjUk8`) equals the SHA-256/base64url digest of the *committed* `llp/evidence/0049-allow-list-class-native-op-fs-read-readlink.json` byte-for-byte. Advance declaration (§3 rule 3) is real, not asserted.
- **Byte-exact regeneration:** running `bun packages/ibex-devtools/src/scripts/generate-capsec-conformance-recipes.mjs --target aarch64-apple-darwin --declared-allow-list llp/evidence/0049-allow-list-class-native-op-fs-read-readlink.json --output /tmp/regen.json` against the reviewed commit's current source reproduces `recipeCatalogDigest = sha256-kwENCdZonb5Cz8-TGxpMvVrpde0HFCNL__LcA9itnRI` **exactly**, and `recipes == recipes` (Python equality over the parsed 21,784-row arrays) is `True`. This discharges §3 rule 10's "strictly stronger" regenerate-and-compare check for this artifact, beyond what rule 10 currently requires.
- **Exact 11-row delta, everything else preserved:** diffing `baseline-catalog.json` (`recipeCatalogDigest = sha256-XkjP5...`) against the candidate over all 21,784 fixture rows found **exactly 11 modified rows, 0 added, 0 removed**. The 11 are precisely the 5 `__exactReadlink` + 6 `.logical.readlink.` rows claimed. Per-row field diff shows only `publicSurfaceProbe`, `residualReasons`, `status` changed on each of the 11 — `edgeIds`, `route`, `terminalObservedKey`, `actionIds`, `classification`, `scenario` are byte-identical before/after. **No route or terminal drift**, confirming the allow-list's own claim.
- **Residual-reason removals match the allow-list exactly:** before, all 11 rows carried `native-public-arguments-not-authored` + `public-surface-invocation-not-authored` (and the `branch-selection` row additionally carried `conditional-branch-selection-probe-not-authored`); after, all 11 are `fully-executable` with `residualReasons: []`. This matches the allow-list's four declared removal entries with no unexplained removal.
- **Engine-observed sequences, all 11, cross-checked field-by-field** (stage / cap / outcome / stratum / operationId) from the two batch-evidence files (`readlink-primary-air-v2.json` + `readlink-secondary-air-v2.json`, `publicBatchEvidenceSchema: ibex/capsec-public-batch-evidence/1`, both bound to `recipeCatalogDigest = sha256-kwENCdZonb5Cz8-TGxpMvVrpde0HFCNL__LcA9itnRI`, both against the identical `loadedEngineIdentity` — same Hermes binary digest `sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y`): the two files together contain exactly the 11 target fixtures, **each exactly once**, all `outcome: "passed"`.
  - Every non-deny scenario: 8 decisions — 4× `fs:list`/`ambient-root`/`allow` (requested, discovery, requested, repeat) → 1× `fs:read`/`static-floor`/`allow` (commit) → 3× `fs:list`/`ambient-root`/`allow` (discovery, requested, repeat).
  - `deny`: 5 decisions — the same 4 ambient `fs:list` allows → 1× `fs:read`/`principal-denial`/`deny` (commit).
  - **All 11 rows show byte-for-byte the same sequence shape** (allow-shaped or deny-shaped) — the direct and dispatched async carriers are indistinguishable at the runtime-decision level, as claimed.
  - Every `fs:list` decision's `operationId` starts with `fs-readlink:`; the one commit-stage decision per scenario is always `fs:read`, never `fs:list`. No decision anywhere carries any other capability, any other operation-id prefix (e.g. `fs-readdir:`), or any stratum other than `ambient-root` / `static-floor` / `principal-denial`.
  - The recorded `command` embedded in each fixture's evidence is byte-for-byte `cargo test --bin ibex --no-default-features --features standard,capsec-conformance-observer,openssl-crypto capsec_public_native_primary_batch -- --test-threads=1`, satisfying §3 rule 9.

## Findings

**BLOCKER:** none.

**MATERIAL:** none. All four targeted mechanisms are exact and fail closed under their break-tests; the artifact chain (allow-list → generator output → engine evidence) is internally consistent and independently reproducible from source.

**MINOR:**
1. The dedicated unit test (`native_incidental_traversal_allowance_is_exact_and_fail_closed`) does not directly exercise the `expected_action_ids.as_slice() != ["fs:read"]` early-return branch inside `reviewed_native_open_traversal_prefix` (line 1782) — e.g. an `__exactReadlink` invocation whose declared actions are `["fs:read", "fs:write"]` is never constructed and checked against `None`. The guard is present and structurally correct (I read it; it necessarily returns `None` for any non-exact-`["fs:read"]` set before the `match`), and this was not one of the four assigned break-tests, so it does not affect the READY verdict — recorded as a completeness gap in the credited test's coverage of its own function, not a defect in the function.
2. `bun test packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs` (full file, not the filtered fixture) shows 4 pre-existing failures (`startup-environment` count mismatch, `sqlite-memory` host-ABI rows) on **both** this commit and its parent `6625d1e9a`, confirming they are environment-dependent (this sandbox is missing whatever registry/build state those two unrelated tests need) and not caused by this commit. Recorded for completeness, not attributed to this change.

## Explicit answers

- **Non-readlink smuggling?** No. Every observed `fs:list` decision across all 11 credited fixtures carries an `operationId` starting with `fs-readlink:`; `native_decision_is_reviewed_open_traversal` requires that prefix match and rejects any other operation family (proven by break-test 3, and independently by the `wrong_branch`/`fs-readdir:` assertion in the pinned unit test).
- **Commit/wrong-ID/deny/non-ambient smuggling?** No. The reviewed-traversal predicate excludes the `commit` stage (break-test 2), requires the exact `fs-readlink:` prefix (break-test 3), and requires `!public_denial` (so a denied scenario's ambient traversal decisions are still credited only for their own `allow`/`ambient-root` rows, never the denied `fs:read` commit, which is asserted `principal-denial`/`deny` with no override). Every stratum observed in the real batch evidence is exactly one of `ambient-root`, `static-floor`, `principal-denial` — no other stratum appears.
- **Exact aggregate action protection?** Yes, at two independent layers: per-decision (`has_surplus_effect` / `native_decision_is_reviewed_open_traversal`, gated per typed decision inside the observation loop) and per-invocation aggregate (`native_observed_actions_are_reviewed`, checked once over the full `observed_actions` set at the end of `validate_native_runtime_observation`). Break-test 1 shows the aggregate layer is load-bearing on its own (the unrelated-surplus case is only caught there).
- **Same observed sequences all 11?** Yes, confirmed from the actual engine evidence files: all 10 non-deny rows share one 8-decision sequence and all-allow strata; the 1 deny-per-carrier pair (2 of the 11 rows: direct `.deny` and async `.logical.readlink.deny`) share one 5-decision sequence ending in the single denied commit. Direct and dispatched-async carriers are indistinguishable at the decision level.
- **Exact 11-row delta and preservation?** Yes, verified directly: exactly 11 of 21,784 catalog rows changed between the retained `baseline-catalog.json` and the retained `candidate-readlink-final.json`, 0 added/removed, and the changed fields on those 11 rows are limited to `publicSurfaceProbe` / `residualReasons` / `status` — no route or terminal field moved.
- **Allow-list exact with no route/terminal drift?** Yes. The allow-list's declared removals match the observed residual-reason removals exactly (per edge), the `declaredAllowListDigest` embedded in the candidate catalog matches the committed allow-list file's digest, and regenerating the catalog from the reviewed commit's current source with that exact allow-list byte-for-byte reproduces the candidate catalog (`recipeCatalogDigest` and full `recipes` array identical).

## Verdict

**READY.**

## Final cleanliness

```
$ git status --short
$ git status
Not currently on any branch.
nothing to commit, working tree clean
```
(HEAD remains at `663985e3d70363ca4eaf76cabecf8ca3e4ab49fe`; no changes were retained from any break-test.)
