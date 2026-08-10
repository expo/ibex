# Review: LLP 0049 A2 — Native `env:read` + `fs:list` `which` bare-command executor (final)

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** Codex workspace agent, GPT-5 family
**Date:** 2026-08-09
**Redacted:** No
**Method:** Fresh independent adversarial review of the corrected exact
seven-file staged target. I authored neither the implementation nor its tests.
I read LLP 0000, LLP 0037 D1–D4, LLP 0049 §3 and §6, and the applicable
repository review instructions; inspected the staged Rust executor,
independent JavaScript consumer, recipe, allow-list, inventory, candidate, and
both physical receipts; independently regenerated the candidate; replayed the
target observations through the production consumer; and ran isolated positive
and break tests in a detached worktree. The earlier NOT READY artifact was
excluded from the reviewed diff, retained unchanged, and not treated as
evidence that the correction worked.

---

## Verdict

**READY.** I found no blocker, material issue, or unaddressed minor issue in
the reviewed A2 class.

The previous blocker is closed. Both production consumers now classify the
exact bare-command early-denial subject independently of its declared action
set and return the exact exception result before the generic action rule. A
denial therefore passes only with authored actions `env:read, fs:list`, one
observed `env:read` request, and the rest of the exact invocation/recipe
account. Narrowing the authored actions to the observed prefix is rejected by
the production JavaScript and Rust wrappers, not merely by their helper
functions.

The promoted claim remains narrow: bare `__exactWhich("ref-check")` may read
the principal PATH overlay and perform path discovery for
`project/ref-check`; successful observations return the unchanged logical
string `/project/ref-check`. The reviewed account does not authorize directory
enumeration, arbitrary environment reads, slash-containing arguments, related
global names, or alternative result strings.

## Reviewed identity

- Base commit: `52a7f61276ed1cc50921499400b29bc1892dc927`
- Base tree: `09f6e7d5835b9cc5379e29677c596aec7ce557be`
- Staged target tree: `c1ea3bdd1920253ec9199885deee674d6a535efc`
- Canonical staged diff SHA-256 (`git diff --cached | shasum -a 256`):
  `d1d21c11ca1e8b2d80a58c4ed33bd0cc2b442dfb488c25bcc85e801f706923a6`
- Diff shape: 7 files, 505 insertions, 26 deletions
- Candidate:
  `/Users/ccheever/phase1-runs/campaign-a2/candidate-env-read-fs-list-which-bare-v3.json`
- Candidate raw SHA-256:
  `4119432be2e56c607bfb4273c3336c5102d9533c9400c2fae1932e95b3ddd2d6`
- Catalog digest: `sha256-Yqenf9cBCh57flKqrJWc266ihly5w3cD-VBOYDW9RpY`
- Declared allow-list digest:
  `sha256-5A4uWaO0IEaB5xNu_1WcgLyTMpOXlryGHRbSLZuhIPY`
- Allow-list raw SHA-256:
  `e40e2e59a3b4204681e7136eff559c80bc9332939796bc861d16d22d9ba120f6`
- Loaded engine digest in both receipts:
  `sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y`
- Primary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/env-read-fs-list-which-bare-primary-v5-final.json`,
  raw SHA-256
  `628e4ce1314f063a3494d0d0218e4c4b0307199753f459f58bfc2a1cde32048f`,
  312/312 completed
- Secondary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/env-read-fs-list-which-bare-secondary-v5-final.json`,
  raw SHA-256
  `2dab4790eee403d4673c6578baf8141db5b7792f6b2c137c713f9fdfa9376add`,
  342/342 completed

The supplied
`candidate-env-read-fs-list-which-bare-final-v4.json` is byte-identical to v3.
Independent regeneration from the corrected staged source also produced
byte-identical candidate bytes and the same raw digest. The candidate reports
21,784 required fixtures, 3,982 fully executable, 3,124 internally verified,
9,985 adapter executable, and 14,678 unresolved.

The final staged file hashes, also matched byte-for-byte after restoring every
isolated mutation, are:

- inventory:
  `a94b567e8131a0be06c4c3396d351b118e4d94bd2c2328e30fb36662ee6b874f`
- allow-list:
  `e40e2e59a3b4204681e7136eff559c80bc9332939796bc861d16d22d9ba120f6`
- recipes:
  `f7b429295c83cf3dd4352ec6750b27d66ad720355f10b38a7cc04c5de07da9c5`
- recipe tests:
  `a33dc194b0743fcea9715f9c578287ad7d4ad20db93d9e40cb7e1b704c354057`
- evidence consumer:
  `bd1e99fabc0dfad1ee06dbf4320c1e12792223e800875eb37a7487a142357bcd`
- evidence tests:
  `f8029385ea16eea672444e60b7ac8baf68dfe288c16fc5f7d6d2add859ac2e26`
- Rust executor/validator:
  `23b57a0f7173c092be0d8cab951c7e9f99a5318cc63582d122acd41f193c0446`

`git diff --cached --check` passed. The staged diff digest remained the exact
value above after review. I made no implementation change in the shared tree;
this final review artifact is the only new file from this review pass, while
the earlier NOT READY artifact remains untracked and unchanged.

## Correction and fail-closed integration audit

The JavaScript consumer first recognizes the protected subject using only
fields outside the action account it is protecting: native/global invocation,
exact global `__exactWhich`, exactly one literal `ref-check` argument,
`permission-denied`, and recipe scenario `deny`. Once classified, the
production `observedActionSetMatchesReviewedAccount` returns the exact helper's
answer directly. It cannot fall through to generic declared/observed equality.
The exact helper then requires one `requested` decision, declared actions
exactly `env:read, fs:list`, and observed actions exactly `env:read`.

The Rust mirror follows the same architecture. Its classifier binds the exact
global, one bare literal argument, permission-denied result, and early
sequence independently of the declared/observed action sets. The production
wrapper returns the exact helper result for that subject; the generic rule is
available only to invocations outside it. The focused Rust unit exercises both
the helper and production wrapper against wrong global, slash argument, wrong
result, wrong stage/count, narrowed declaration, and empty, full, filesystem-
only, or unrelated observed sets.

This ordering matters: the previous implementation used
`exactException || genericRule`, so a narrowed declaration could fail the
exception and then satisfy generic equality. I independently removed the new
mandatory-subject branch in each consumer. The production JavaScript replay
then accepted the narrowed denial, and the Rust exact test failed. Restoring
the branch restored rejection, demonstrating that the correction is
load-bearing at both production integration points.

The successful-result account is also closed in both consumers. It requires
the exact global, one bare `ref-check` literal, exactly five result keys,
return/string/none result metadata, and exact logical string
`/project/ref-check`. The Rust accepted input/result pairs are limited to the
reviewed slash fixture and this bare fixture; neither prefix globals nor
alternative strings are admitted.

## Source, recipe, and D2 audit

The catalog contains exactly six bare-command fixtures: `allow`,
`branch-selection`, `deny`, `malformed`, `missing-attribution`, and
`wrong-principal`. Each invokes `__exactWhich` with exactly one literal
`ref-check`, declares exactly `env:read` and `fs:list`, seeds only the principal
PATH overlay with `/project`, requires setup `env:write PATH`, and requires the
runtime floor `env:read PATH` plus exact `fs:list project/ref-check`. The only
allowed coverage edge is `surface.native.op.exactwhich.0it66ce`.

The five non-deny fixtures pin seven typed decisions:

```text
requested, commit, requested, discovery, requested, repeat, discovery
```

They bind the exact logical result `/project/ref-check`. The denial pins one
`requested` decision and has no successful-string expectation.

The physical receipts match that account. Every non-deny observation contains
two `env:read` decisions followed by five `fs:list` decisions; the denial stops
after the refused `env:read` request. Each filesystem operation uses the
reviewed `fs-which:` identity and represents executable-path traversal or
candidate discovery. None is a readdir/directory-content operation. Thus the
observed D2 union contains no directory enumeration or other surplus
authority, and the returned value is the logical executable path rather than
a backing path.

The three allow-list entries explain exactly six public-invocation changes,
one branch-selection change, and six native-argument changes. The generated
inventory uses the intended one-based byte offsets: 43,347 points to the
recipe-catalog environment read and 43,533 points to the adapter-evidence
environment read.

## Candidate, route, and receipt audit

Independent generation:

```text
bun packages/ibex-devtools/src/scripts/generate-capsec-conformance-recipes.mjs \
  --target aarch64-apple-darwin \
  --declared-allow-list llp/evidence/0049-allow-list-class-native-op-env-read-fs-list-which-bare.json \
  --output /tmp/ibex-which-bare-final-review.dRBvS5/candidate.json

recipeCatalogDigest: sha256-Yqenf9cBCh57flKqrJWc266ihly5w3cD-VBOYDW9RpY
declaredAllowListDigest: sha256-5A4uWaO0IEaB5xNu_1WcgLyTMpOXlryGHRbSLZuhIPY
cmp against supplied v3: byte-identical
raw SHA-256: 4119432be2e56c607bfb4273c3336c5102d9533c9400c2fae1932e95b3ddd2d6
```

Paired route gate:

```text
node scripts/llp0045-route-evidence-diff.mjs \
  --baseline /Users/ccheever/phase1-runs/campaign-a2/candidate-fs-list-which-slash-final-v4.json \
  --candidate /Users/ccheever/phase1-runs/campaign-a2/candidate-env-read-fs-list-which-bare-v3.json \
  --allow-list llp/evidence/0049-allow-list-class-native-op-env-read-fs-list-which-bare.json \
  --scope all

PASS; 13 changes, 13 allow-listed, 0 unexplained, 0 stale
residual delta: public invocation -6, branch selection -1, native arguments -6
lane B/C/D unchanged at 528/1326/32
```

Terminal gate:

```text
node scripts/capsec-terminal-evidence-diff.mjs \
  --baseline /Users/ccheever/phase1-runs/campaign-a2/candidate-fs-list-which-slash-final-v4.json \
  --candidate /Users/ccheever/phase1-runs/campaign-a2/candidate-env-read-fs-list-which-bare-v3.json

PASS; 0 changed cells, 0 unexplained entries, 0 stale entries
```

The target lives on primary shard 4 (`allow`, `deny`, `malformed`,
`wrong-principal`) and secondary shard 2 (`branch-selection`,
`missing-attribution`). I loaded the production
`buildPublicFixtureEvidence` consumer and replayed all six physical target
observations. All six rebuilt executions matched the candidate byte-for-byte.
Independent production mutations reported:

```text
wrong-global: rejected — native runtime invocation descriptor drift
slash-argument: rejected — observed typed stages, actions, or gates drifted
wrong-result: rejected — public invocation did not return
narrowed-actions: rejected — observed typed stages, actions, or gates drifted
wrong-observed-actions: rejected — observed typed stages, actions, or gates drifted
wrong-stage-count: rejected — malformed runtime public observation
wrong-scenario: rejected — observed typed stages, actions, or gates drifted
```

The separate external production replay reported `6/6 byte-structural
matches` and rejected wrong denial actions, a narrowed denial declaration, and
a wrong returned string.

## Tests and adversarial break tests

Focused final tests passed in a detached worktree constructed from the base
commit plus the exact staged patch:

```text
bun test packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs \
  packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.test.mjs \
  -t 'authors bare executable lookup through the exact principal PATH overlay|admits only the observed bare-which early-denial action prefix'
2 passed, 200 filtered, 0 failed, 93 expectations

cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  'engine::hermes::tests::capsec_conformance_batch::native_which_early_denial_action_prefix_is_exact_and_fail_closed' \
  -- --exact --nocapture --test-threads=1
1 passed, 657 filtered, 0 failed

cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  'engine::hermes::tests::capsec_conformance_batch::native_which_string_result_account_is_exact_and_fail_closed' \
  -- --exact --nocapture --test-threads=1
1 passed, 657 filtered, 0 failed

./ref-check
51 documents, 2,537 references, 2,016 files, 0 errors, 1 unchecked
```

The detached worktree lacked its own Hermes compiler artifact. Its Rust tests
therefore used `EXACT_ALLOW_FALLBACK=1`, explicit Hermes library/header paths,
and the shared Cargo target directory as build plumbing. The mandated secure
feature vector remained byte-for-byte exact:
`--no-default-features --features standard,capsec-conformance-observer,openssl-crypto`.

I then changed one production constraint at a time in that isolated worktree,
leaving the corresponding assertions intact:

1. Removing the mandatory exact-subject branch from the JavaScript production
   wrapper made the real-receipt narrowed-declaration check fail with
   `Missing expected exception` (exit 1). This directly reproduced the prior
   integration defect.
2. Widening the JavaScript helper to accept declared `env:read` alone failed
   its narrowed-action negative (`Expected false`, received `true`).
3. Widening its subject classifier to accept globals beginning
   `__exactWhich` failed the wrong-global negative.
4. Widening its argument classifier to accept `/project/ref-check` failed the
   slash-argument negative.
5. Removing the mandatory exact-subject branch from the Rust production
   wrapper failed the exact positive production assertion; 0 passed, 1
   failed, 657 filtered.
6. Widening the Rust exact action helper to accept declared `env:read` alone
   failed the narrowed-declaration negative; 0 passed, 1 failed, 657 filtered.
7. Removing the bare input/result pair from the Rust string account failed the
   bare positive; 0 passed, 1 failed, 657 filtered.
8. Removing the Rust exact-string equality check failed the wrong-result
   negative; 0 passed, 1 failed, 657 filtered.
9. Widening the Rust classifier to accept global prefixes failed the
   wrong-global negative; 0 passed, 1 failed, 657 filtered.

The baseline Rust units additionally executed exact negatives for a slash
argument, wrong result, wrong stage/count, and all wrong action sets. The
production JavaScript replay independently rejected those mutations against
the physical v5 denial observation. After restoring every mutation, all seven
reviewed files matched the shared staged target hashes above.

These breaks demonstrate that exact subject classification, no-fallthrough
control flow, the full declared action set, the one-action denial prefix, and
the logical string result are each load-bearing in the independent consumers.

## Findings disposition

The prior review's **BLOCKER B1** is fixed in staged target tree
`c1ea3bdd1920253ec9199885deee674d6a535efc` / diff
`d1d21c11ca1e8b2d80a58c4ed33bd0cc2b442dfb488c25bcc85e801f706923a6`.
Its exact narrowed-action mutation now fails at both production integration
points, and removing the correction makes it fail open again.

No new finding requires disposition. This READY judgment is limited to the
reviewed Phase 2 class and its exact evidence account; it does not promote the
diagnostic matrix to Phase 3 authority or make claims about unrelated test
coverage.
