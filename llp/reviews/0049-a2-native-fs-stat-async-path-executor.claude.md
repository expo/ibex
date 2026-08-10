# A2 `__exactFsStatAsync` path executor review

Type: Review
Status: Complete
Systems: capsec-conformance-batch, capsec-conformance-recipes
Author: Claude Sonnet 4.6 (via OpenCode)
Date: 2026-08-09
Related: LLP 0037, LLP 0039, LLP 0045, LLP 0049

## Review identity

- Role: independent adversarial reviewer; the reviewer authored neither the code nor its tests.
- Model: `opencode/claude-sonnet-4-6`.
- Reviewed commit: `a162466417e3724ee5890b3592a717a34f23313a`.
- Parent: `ace5a5a3d853ea040c780aa6f5e640c451a47f9d`.
- Tree: `262bcfa2fd6c449675eaa293d3403e501890aa6d`.
- Verified diff SHA-256: `7c1bebbd3e9da7f3946f0ab7e45a2e8b703140650e1d31a5712acc6ab61ea6f3`.
- Evidence inspected read-only: baseline and candidate catalogs plus the primary and secondary physical batch envelopes under `target/a2-review-evidence/fs-stat-async/` in the review worktree.

The reviewed commit was constructed with `git commit-tree` from the exact index intended for the class. The reviewer independently verified the commit, parent, tree, and diff digest before inspecting the change.

## Scope and evidence checks

The change claims only the six `logical.path` rows for
`surface.native.op.exactfsstatasync.0b0hr8s`. The six retained-descriptor rows
remain unresolved and unclaimed.

The reviewer verified:

- the allow-list contains exactly the three expected residual-reason removals;
- the baseline-to-candidate delta closes only the six path rows;
- both catalog-diff gates pass;
- both physical shards bind catalog digest
  `sha256-_yqPRp_GvFXSjrFkfHb1NLQeSXQmV5qVGxUVh8raQnM`;
- both physical shards bind engine digest
  `sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y` on `aarch64`;
- every physical command contains the exact secure vector
  `--no-default-features --features standard,capsec-conformance-observer,openssl-crypto`;
- the six target rows appear exactly once across the two shards and pass;
- source arity `3`, the `stat` path discriminator, the null presented handle,
  and event-loop-quiescence completion match the native global;
- the descriptor sibling is mutually exclusive and was not accidentally credited.

The independently recomputed source-descriptor digest was
`sha256-JEruNsiz5RjdkiDN2JC_LFOWYB182LwDY7k9Sb3XJYo`, matching the evidence.

## Observed typed sequence

The observed non-deny sequence is:

| # | Stage | Outcome | Stratum | Capability |
|---:|---|---|---|---|
| 1 | `requested` | `allow` | `static-floor` | `fs:list` |
| 2 | `discovery` | `allow` | `ambient-root` | `fs:list` |
| 3 | `requested` | `allow` | `static-floor` | `fs:list` |
| 4 | `repeat` | `allow` | `static-floor` | `fs:list` |
| 5 | `repeat` | `allow` | `static-floor` | `fs:list` |
| 6 | `repeat` | `allow` | `static-floor` | `fs:list` |

The observed deny sequence is one `requested / deny / principal-denial /
fs:list` decision. All decisions use the claimed coverage edge and atomicity
group. There are no surplus `fs:list` decisions: `fs:list` is the direct
metadata operation's semantic floor, and no `fs:read` or `fs:write` decision
appears.

## Green baseline

The reviewer ran:

```text
cargo test --bin ibex --no-default-features --features standard,capsec-conformance-observer,openssl-crypto native_filesystem_denial_message_allowance_is_exact_and_fail_closed -- --test-threads=1
```

Result: `1 passed; 0 failed; 655 filtered out`.

The recipe file had four known count/SQLite failures in both the parent and
candidate context; the new async-stat assertion is among the passing tests.
Those known failures do not change the review disposition.

## Adversarial break-tests

All mutations were made only in the detached review worktree, then reverted.
The worktree was clean at the end.

1. Removed `__exactFsStatAsync` from
   `native_filesystem_denial_message_is_reviewed`. The focused test failed at
   the positive assertion for the exact name. Credited.
2. Widened the predicate to admit `__exactFsStatAsyncExtra` and
   `__exactFsLstatAsync`. The focused test failed at its first negative
   assertion. Credited.
3. Replaced the focused test body with an empty body. The test passed
   trivially, demonstrating that test-name execution alone cannot certify the
   security property and that the independent source review is material. The
   reviewer restored the assertions and treated their presence as a reviewed
   security condition.

## Findings and dispositions

- Blocker: none.
- Material: none.
- Minor M1: the allow-list proof cites the enclosing native-global registration
  span (`hermes_runtime_fs.cc:7901-7992`) while naming `fsStatArmedWork`, whose
  definition is earlier in the file. This is a documentation imprecision, not
  a security defect; the cited span shows the call and reviewed data flow.
- Minor M2: the known recipe count/SQLite failures weaken unrelated invariant
  coverage. They predate this class and are tracked outside this campaign.
- Observation O1: branch-selection uses the same invocation as allow because
  the row proves that this exact discriminator reaches the path branch; the
  numeric `fstat` descriptor branch is mutually exclusive.
- Observation O2: the missing-attribution scenario returns while attribution
  is validated separately by the batch harness; this is consistent with the
  evidence contract.

## Verdict

**READY.** The exact reviewed revision satisfies LLP 0049 section 3 rule 11.
The Rust change is fail-closed for both omission and near-miss widening, the
physical evidence is bound to the expected engine and secure feature vector,
and the six observed path rows match the catalog claim without crediting the
descriptor sibling.
