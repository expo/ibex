# Review: LLP 0049 A2 — Direct recursive `__exactMkdir` executor

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** Codex workspace agent, GPT-5 family
**Date:** 2026-08-09
**Redacted:** No
**Method:** Fresh independent adversarial review under LLP 0049 §3 rule 11. I
read LLP 0000, LLP 0037 D1–D4, LLP 0049 §3 and §6, LLP 0021 WP5/WP10, LLP
0023 §4.1, and the repository review instructions; inspected only the exact
seven-file staged target plus the unchanged native entry point it describes;
regenerated the candidate; ran the strict route and terminal comparisons;
checked the retained physical evidence through both production consumers; and
ran positive and isolated break tests. I did not author or alter the staged
implementation.

---

## Verdict

**READY.** I found no blocker, material issue, or unaddressed minor issue in
the reviewed class.

The promoted claim is exactly one synchronous native public invocation:
`__exactMkdir("target/ibex-capsec-mkdir-recursive-closed", true, -1)`. The
native entry point refuses that recursive branch with `EPERM` before path
conversion or lookup. The retained execution consequently has no completion,
actions, stages, setup, floors, typed decisions, or legacy decisions, and has
one exact four-key throw result whose message ends in `, mkdir`. Both
production consumers admit this zero-decision execution only after proving the
full exact account and result. This is physical closed-branch evidence, not a
relaxation of LLP 0037 D1–D4.

## Reviewed identity

- Base commit: `477e00697426a660a8024b600ca5d24903a33c5d`
- Base tree: `bc1290b2723bee5b8678072af13d99a785970ba0`
- Seven-file staged target tree: `4710bc5745c3718bb5cc8f07d2f69e29c9efd65e`
- Exact staged nonbinary diff SHA-256
  (`git diff --cached | shasum -a 256`):
  `fd7fd53ca6455103eeb95217642456b3aa0752dc8e747013fd7b31dc581bb51b`
- Diff shape: 7 files, 222 insertions, 48 deletions
- Final candidate:
  `/Users/ccheever/phase1-runs/campaign-a2/candidate-mkdir-recursive-v2-final.json`
- Final candidate raw SHA-256:
  `bd0094220ecf61914242e75bd0f2dde6a0485168fe3f694e89f85e458645081b`
- Catalog digest:
  `sha256-OhNVXB3-plW2v1jIh6k70SPZN5iEyUhHhVtT1BvR4GE`
- Declared allow-list digest:
  `sha256-asbbYDXh2YjJkUl-xhp3L6UQt__zvzw7oTE8nzmrplM`
- Allow-list raw SHA-256:
  `6ac6db6035e1d988c991497ec61a772fa510b7fff3bf3c3ba1313c9f39aba653`
- Loaded engine digest in both supplied receipts:
  `sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y`
- Primary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/mkdir-recursive-primary-v1.json`,
  raw SHA-256
  `646567ea4147652ff5be1cf5cd85b25b367c0eced7d36c9773d5e1abec87f725`,
  323/323 completed, including the one target execution
- Secondary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/mkdir-recursive-secondary-v1.json`,
  raw SHA-256
  `12d2e36dbd23b1d2bdaf7580d90ffc6cc59e3c2162fce03a1ca4ee2e5721fdb9`,
  348/348 completed; this shard does not own the target
- Replay program:
  `/Users/ccheever/phase1-runs/campaign-a2/replay-mkdir-recursive-evidence.mjs`,
  raw SHA-256
  `92b679aeea9c80167801340e0bb4f690f14d1994f1446d7e9866687e573ce26f`

Independent generation from the staged source produced a byte-identical
candidate at `/tmp/ibex-mkdir-review.TifzsI/candidate.json`. It has the same
raw and semantic digests and reports 21,784 required cells, 3,999 fully
executable cells, 3,124 internal-only cells, 9,985 adapter cells, and 14,661
unresolved cells. The earlier `candidate-mkdir-recursive-v1.json` is also
byte-identical to the final candidate.

Final staged file SHA-256 values were:

- inventory:
  `f510dead22250219a87af54fa08bdfa83a1fffbbd5e51760e5fcc35cfc69e27f`
- allow-list:
  `6ac6db6035e1d988c991497ec61a772fa510b7fff3bf3c3ba1313c9f39aba653`
- recipes:
  `f6d5b35dc2e42367c3444aa664a21d8c0abfc70ba28e5e25827a5f42b378e3fa`
- recipe tests:
  `6be1f63eb01f7527758771ec83ee820fe99c84630c6f0b130120e3d8b9620bdf`
- evidence consumer:
  `36c7e8966406b96ff0ce8e50f7ccafa7cda9ce02fac6834d0553f822bc357584`
- evidence tests:
  `7d3f3c678026dce6f643d4351e607dbbcc50e35aaf0b50622338d5e204f2badf`
- Rust validator:
  `63bc2e6ed45eae98890a28773a87a9f1f239d7495fc579417174e0369b825bfc`

The inventory change is offset-only. Its two one-based byte anchors move from
51,490/51,676 to 52,151/52,337, and `tail -c +<offset>` still begins at the
exact recorded `env::var(...)` call in each case. `git diff --cached --check`,
`git diff --check`, and `./ref-check` passed.

## Source, recipe, and consumer audit

The recipe generator now selects a logical-branch template before considering
the route-wide native-public template. That order is essential: only the
`recursive` logical branch receives the new closed template. Its exact account
is:

```text
global:         __exactMkdir
args:           ["target/ibex-capsec-mkdir-recursive-closed", true, -1]
completion:     absent (synchronous invocation)
classification: closed
scenario:       branch-selection
floors/setup:   [] / []
actions/stages: [] / []
decisions:      0
result:         permission-denied; fragment "EPERM: operation not permitted"
allowed edge:   surface.native.op.exactmkdir.021eaz0 only
```

The route-wide `__exactMkdir` template remains unchanged: it uses
`["target/ibex-capsec-mkdir", false, -1]`, the original list/write actions,
seven typed decisions, and its cleanup. I independently extracted all six
nonrecursive `__exactMkdir` rows from baseline and candidate; the row sets
have the same count and are byte-identical. Thus logical-template precedence
does not silently change nonrecursive behavior.

Both production consumers bind the direct-recursive account above, including
the exact three literals and the absence of a completion. They also require
the exact action list, zero decision count, empty stages/floors/setup, exact
classification/scenario/global, and the only allowed edge. The result must
have exactly these four keys and values:

```json
{
  "kind": "throw",
  "globalName": "__exactMkdir",
  "errorName": "Error",
  "errorMessage": "EPERM: operation not permitted, mkdir"
}
```

There is no typed- or legacy-decision shortcut. The zero-decision production
branch invokes the exact reviewed-account and exact-result helpers before it
admits this fixture.

The unchanged native source independently confirms the physical ordering.
`__exactMkdir(path, recursive, mode)` parses the recursive flag and mode, then
calls `refuseClosedArmedFsMutation(runtime, "mkdir")` when recursive, before
converting the path and before `exactResolveVfsPath`. The refusal helper sets
`errno = EPERM` and throws the operation-bound filesystem error. No capability
lookup, action, typed decision, worker dispatch, or completion is reached.

The allow-list is one strict catalog edge row for
`surface.native.op.exactmkdir.021eaz0`, with exactly the three residual
removals needed to author its arguments, public invocation, and closed denial
probe. It authorizes no route or terminal change.

## Candidate, gates, and physical evidence

The strict route comparison against
`candidate-closed-fs-mutations-v6-final.json` passed with 3 changes, all 3
allow-listed, 0 unexplained changes, and 0 stale entries. Lane B/C/D counts
remain 528/1,326/32. Each change is the exact `-1` removal in one of the three
declared residual classes. The strict terminal comparison passed with 0
deltas, 0 changed cells, 0 unexplained entries, and 0 stale entries.

The supplied primary receipt's target execution uses the mandated secure
command:

```text
cargo test --bin ibex --no-default-features --features standard,capsec-conformance-observer,openssl-crypto capsec_public_native_primary_batch -- --test-threads=1
```

It has the exact catalog and engine digests, exact invocation, no completion,
zero legacy decisions, an empty typed-decision list, empty actions/stages/
floors/setup, and the exact four-key result. The replay fed this execution
through the production JavaScript consumer and reported:

```text
production evidence replay: 1/1 byte-structural match
wrong path, recursive flag, mode, action, count, completion, error suffix,
global, and widened result mutations: rejected
```

I also independently reran the physical primary batch from the restored
detached target. It passed all 323 executions. The entire JSON receipt has
expected nondeterministic differences from the supplied receipt, but its one
target execution object is byte-structurally identical to the supplied target,
including its evidence digest. The reviewer receipt is
`/tmp/ibex-mkdir-review.TifzsI/review-primary.json`, raw SHA-256
`edb5712b496c917e63d027ffe1227c3cc4092a86e3b0b459d415bdbfe5999a27`.

## Positive and adversarial tests

Focused positive tests passed:

```text
bun test packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs \
  packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.test.mjs \
  -t 'physically refuses direct recursive mkdir before path lookup|admits only exact closed native filesystem mutation branches'
2 passed, 203 filtered, 0 failed, 47 expectations

cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  'engine::hermes::tests::capsec_conformance_batch::native_closed_filesystem_mutation_account_is_exact_and_fail_closed' \
  -- --exact --nocapture --test-threads=1
1 passed, 658 filtered, 0 failed

./ref-check
51 LLP documents, 2,538 references in 2,018 files, 0 errors, 1 unchecked
```

I changed one load-bearing rule at a time in detached worktree
`/tmp/ibex-mkdir-review-wt.xEMmlV`, leaving the relevant negative tests intact:

1. Putting the route-wide template lookup before logical-branch lookup made
   the recursive row unresolved with exactly its three original residuals.
2. Widening the JavaScript account admitted wrong path, recursive flag, mode,
   and a fabricated completion.
3. Removing its exact action/count checks admitted both mutations.
4. Removing its exact result-key/global/suffix checks admitted wrong global,
   wrong suffix, and widened result shape.
5. Removing its zero-decision reviewed-account gate rejected the real target
   with `absence of a typed decision is not evidence here`.
6. Widening the Rust tuple account failed the wrong-path/recursive/mode
   negative assertion.
7. Removing the Rust result suffix equality failed the wrong-syscall negative
   assertion.
8. Removing only direct recursive `__exactMkdir` from the Rust zero-decision
   admission made the physical primary batch pass executions 1–110 and fail
   exactly execution 111, the target, with `a zero-decision public invocation
   did not select a reviewed zero-effect branch`.

The exact production-batch command used for that final break was:

```text
IBEX_CAPSEC_RECIPE_CATALOG=/Users/ccheever/phase1-runs/campaign-a2/candidate-mkdir-recursive-v2-final.json \
IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT=/tmp/ibex-mkdir-review.TifzsI/review-primary.json \
HERMES_LIB_DIR=/Users/ccheever/wt-campaign/ios/Frameworks \
HERMES_INCLUDE_DIR=/Users/ccheever/wt-campaign/ios/Frameworks/hermes-headers \
JSI_INCLUDE_DIR=/Users/ccheever/wt-campaign/ios/Frameworks/hermes-headers \
EXACT_ALLOW_FALLBACK=1 \
CARGO_TARGET_DIR=/Users/ccheever/wt-campaign/target \
cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  capsec_public_native_primary_batch -- --test-threads=1
```

Result: executions 1–110 passed; execution 111 failed with the exact
zero-decision error above; Cargo reported the primary-batch test failed. After
restoring the helper, the same command passed 323/323 executions.

The isolated worktree lacks its own `hermesc`; the Rust runs therefore used
`EXACT_ALLOW_FALLBACK=1`, explicit checked-in Hermes library/header paths, and
the shared Cargo target directory as build plumbing. The security-relevant
feature vector remained exact:
`--no-default-features --features
standard,capsec-conformance-observer,openssl-crypto`.

Every mutation was restored. The detached target then had no working-tree
diff and reproduced the exact seven-file staged diff hash
`fd7fd53ca6455103eeb95217642456b3aa0752dc8e747013fd7b31dc581bb51b`.

## Findings disposition

No findings require disposition. The class stays within LLP 0049's narrow A2
promotion model: one exact logical branch, one exact synchronous invocation,
one exact physical pre-lookup refusal, one strict allow-list edge row, two
independent fail-closed consumers, and no additional authority, route,
terminal, or zero-decision claim.
