# Independent Adversarial Review: A2 Async Write-File Path Tranche

**Review artifact for LLP 0049 §3 rule 11**

| Field | Value |
|---|---|
| Reviewed commit | `d6c32469ed21bc6fd489dcc963fa8720734c3843` |
| Tree | `0f1c4d509058a6a54e4fc4fc78650bbc59523fd1` |
| Parent | `3bb93253d596dbfee40fd2ca3b8b73e823474bfd` |
| Diff SHA-256 | `99c8329da01223714f35946990d6aef649092714a179c4faf866db7b84ba38ee` |
| Reviewer | Claude Sonnet 4.6 (`opencode/claude-sonnet-4-6`) |
| Provider/runtime | OpenCode CLI, fresh review session |
| Date | 2026-08-09 |
| Worktree | `/Users/ccheever/phase1-runs/campaign-a2/fs-write-file-async-review-worktree-v3` (detached HEAD) |
| Redacted | no (public-repository content only) |
| Verdict | READY |

**Reviewer-independence statement.** This reviewer is a different model
instance from the authoring agent. The reviewer did not author the code under
review, its tests, or its evidence artifacts. The final review was performed
at the exact cited revision. Each adversarial mutation was reverted before the
verdict, both focused baselines ended green, and the detached worktree ended
clean.

---

## 1. Review history and disposition

The first independent pass reviewed revision
`2f9493fa3ecff6804557eaa771bc6cac97871c93` (tree
`e9d08156609151ea6fbe08a46b3c4cfd4f9c87f6`, diff SHA-256
`8d833650bdde796dfde960ad7993fd7dc69341ff2e85ff842d8380770e1de570`)
and returned **NOT READY**. It found two genuine coverage gaps:

1. the incidental-traversal fail-closed test did not exercise a wrong action
   identifier; and
2. the write-file lifecycle did not have focused break coverage for exact
   bytes, deny-state preservation, cleanup registration, and marker
   publication.

The author added those cases, then requested a new review over the resulting
exact Git tree. The first pass also treated the catalog digest and declared
allow-list digest as though they should match one another. The final review
verified their distinct roles: the catalog digest binds the generated catalog,
while the allow-list digest binds the declaration embedded in that catalog.
Both independently reproduce their retained values.

The final fresh review returned **READY** with zero blockers, zero material
findings, and three informational observations. In particular, the reviewer
confirmed that the Rust executor additions are narrow, fail closed, and
credited by focused tests; that the six catalog rows and physical executions
are exact; and that every surplus `fs:list` is traversal-stage attribution
rather than a directory-listing effect.

## 2. Baselines and exact bindings

The reviewer independently verified:

- reviewed revision, tree, parent, and diff SHA-256 shown above;
- strict regeneration of catalog digest
  `sha256-ufiaNsMFnU2Y-h0gn94cBWrg1fyGNxN9AmMK93NdpVw`;
- declared allow-list digest
  `sha256-6_wYBtPOaRIDfSaa_XVxtd1lQm-6nhtLVU_ied47mnA`;
- byte identity with the retained candidate catalog;
- primary physical evidence at 300/300 fixtures and secondary evidence at
  330/330 fixtures, with the six target scenarios occurring exactly once;
- catalog and evidence binding to engine digest
  `sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y`; and
- exact use of `--no-default-features --features
  standard,capsec-conformance-observer,openssl-crypto`.

The focused JavaScript template test and the three focused Rust executor tests
were green before mutation. They were green again after all mutations were
reverted, and `git status` was empty in the detached worktree.

## 3. Break-tests

| Break-test | Mutation | Credited failure |
|---|---|---|
| Path boundary | Widen the exact owned-path predicate so another `target/` path is accepted. | `native_incidental_traversal_allowance_is_exact_and_fail_closed` failed because the wrong path returned an allowance. |
| Argument producer | Stop requiring the exact `__exactStringToUtf8Bytes("ibex-capsec-async-write-file")` literal. | `native_async_argument_producer_is_exact_and_fail_closed` failed because the wrong literal was accepted. |
| Action binding | Remove the exact expected-action-ID guard from the traversal allowance. | `native_incidental_traversal_allowance_is_exact_and_fail_closed` failed because a wrong `fs:list` action ID returned the operation prefix. |
| Output bytes | Replace exact byte equality with a mere file-exists check. | `native_async_write_file_fixture_lifecycle_is_exact_and_fail_closed` failed with `accepted wrong bytes`. |
| Cleanup registration | Stop registering the exact owned output for cleanup. | `native_async_write_file_fixture_lifecycle_is_exact_and_fail_closed` failed because the cleanup list was empty. |

These mutations also cross-examined the class's security boundaries rather
than only its happy path. The retained lifecycle test separately proves that a
deny result fails if the file changed, that an unchanged deny publishes no
cleanup marker, that successful execution removes the exact owned file and
publishes `removed-owned-file`, and that an unowned path panics.

## 4. Attribution audit

Across all six executions, each surplus `fs:list` decision had a
`fs-write-file-async:` operation identifier and a `requested`, `discovery`, or
`repeat` stage. No surplus decision used `commit`, no directory entries were
returned, and the operation's effect was the exact file write. The reviewer
therefore agreed that these are LLP 0037 D1/D2 traversal decisions and do not
belong in the semantic required-action floor.

The observed allow sequence contains nine decisions and the observed deny
sequence contains seven. The deny terminates at the denied `fs:write`
discovery decision before commit. These sequences were pinned from the bound
engine rather than inferred.

## 5. Final verdict

**READY.** The exact reviewed Rust change has independent adversarial coverage
with five load-bearing break-tests. No blocker or material security-path
finding remains. The informational notes were: catalog and allow-list digests
are intentionally distinct; the single-file JavaScript suite retains four
pre-existing failures also present at the parent revision; and rustfmt moved a
small number of unrelated lines mechanically without changing their behavior.
