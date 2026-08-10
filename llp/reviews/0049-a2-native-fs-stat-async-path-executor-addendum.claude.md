# A2 `__exactFsStatAsync` path executor — final-target addendum review

Type: Review
Status: Complete
Systems: capsec-conformance-batch, capsec-conformance-recipes
Author: Claude Sonnet 4.6 (via OpenCode, `opencode/claude-sonnet-4-6`)
Date: 2026-08-09
Related: LLP 0037, LLP 0039, LLP 0045, LLP 0049
Prior review: `/Users/ccheever/wt-campaign/llp/reviews/0049-a2-native-fs-stat-async-path-executor.claude.md`

## Reviewer and model independence

This addendum was authored by a fresh OpenCode session (`opencode/claude-sonnet-4-6`) that received the task prompt directly from the orchestrator. The reviewer authored neither the code nor its tests, and was given no prior context from the original review session. The prior review report was read as evidence only.

## Exact final review target

| Field | Value |
|---|---|
| Commit | `6587099be4756041ba6bcf8b3321fea9fdd2f181` |
| Parent | `ace5a5a3d853ea040c780aa6f5e640c451a47f9d` |
| Tree | `a2b3101cf921e26b977d5e9ba4c32c47700a14de` |
| Diff SHA-256 (parent → target) | `9e3939fcb668c75546b635fa17f3484cd8c1ddc518232d1fa1c84ff0a3cb992e` |

All four values independently confirmed by the reviewer.

## Prior READY-reviewed target

| Field | Value |
|---|---|
| Commit | `a162466417e3724ee5890b3592a717a34f23313a` |
| Parent | `ace5a5a3d853ea040c780aa6f5e640c451a47f9d` (same parent) |
| Tree | `262bcfa2fd6c449675eaa293d3403e501890aa6d` |
| Diff SHA-256 (parent → target) | `7c1bebbd3e9da7f3946f0ab7e45a2e8b703140650e1d31a5712acc6ab61ea6f3` |

## File-by-file comparison: a162466... vs 6587099...

`git diff a162466 6587099 --stat` reports two files changed, 3 insertions, 3 deletions.

### 1. `src/bin/ibex/engine/capsec_conformance_batch.rs`

One line changed (line 2481 in the final target). The change is entirely within a comment:

```
- // @ref LLP 0049#3-construction-rules--what-counts-as-evidence
+ // @ref LLP 0049#3-construction-rules — reviewed evidence sets stay closed
```

The old fragment `#3-construction-rules--what-counts-as-evidence` did not exist in LLP 0049. The new anchor `#3-construction-rules` is valid. This is a comment-only repair; no Rust token, no `assert!`, no function signature, no data structure changed.

The file size delta between the two commits is exactly **14 bytes** (the em-dash `—` occupies 3 UTF-8 bytes vs the two hyphens `--` it replaces, plus the added gloss text).

### 2. `capsec/registry/runtime-environment-inventory.json`

Exactly 4 lines changed, all `sourceOffset` fields:

| Entry sourceRef | Old offset (a162466 inv) | New offset (6587099 inv) |
|---|---|---|
| `...#env::var:IBEX_CAPSEC_RECIPE_CATALOG:read` | 36905 | 37284 |
| `...#env::var:IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT:read` | 37091 | 37470 |

**Origin analysis.** The old offsets (36905, 37091) were generated against the `ace5a5a` (parent) Rust file (verified by byte-reading `ace5a5a:capsec_conformance_batch.rs` at those positions — both point to `nv::var("IBEX_CAPSEC_...")`). The new offsets (37284, 37470) are correct for the `6587099` Rust file (byte-verified at those positions — both point to `nv::var("IBEX_CAPSEC_...")`). The offset increase reflects the 379 bytes of campaign Rust code inserted before those `env::var` call sites. No other inventory fields changed — no `sourceRef`, no `stage`, no `scope`, no security-relevant field.

### Files confirmed unchanged between a162466 and 6587099

The following files present in the parent-to-target diff (the reviewed security surface) are byte-identical between the two commits:

- `llp/evidence/0049-allow-list-class-native-op-fs-stat-async-path.json`
- `packages/ibex-devtools/src/scripts/capsec-conformance-recipes.mjs`
- `packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs`

These were confirmed via `git diff --stat` showing zero changes in those files.

## Semantic equivalence proof

The changes between the READY-reviewed commit (`a162466`) and this final target (`6587099`) are:

1. **`@ref` comment text** (1 line, Rust): non-executable, comment-only; the `assert!` macro and all surrounding code are identical byte-for-byte.
2. **`sourceOffset` fields** (2 values, JSON): generator-owned metadata pointing to byte positions of the same `env::var` call sites in the updated Rust file; no logic or security-relevant inventory field changed.

There is no semantic Rust change, no JS change, and no allow-list change between the two commits.

## Commands and results

### ./ref-check

```
$ ./ref-check
ref-check: ok — 51 LLP docs, 2534 refs in 2010 files, 0 errors, 1 unchecked
```

The repaired `@ref LLP 0049#3-construction-rules` resolves correctly. Exit 0.

### cargo fmt --check

```
$ cargo fmt --check
(no output, exit 0)
```

### Focused secure Rust test

```
$ HERMES_LIB_DIR=/Users/ccheever/projects/ibex/ios/Frameworks \
  HERMES_INCLUDE_DIR=/Users/ccheever/projects/ibex/ios/Frameworks/hermes-headers \
  cargo test --bin ibex \
    --no-default-features \
    --features standard,capsec-conformance-observer,openssl-crypto \
    native_filesystem_denial_message_allowance_is_exact_and_fail_closed \
    -- --test-threads=1
```

Result:

```
running 1 test
test engine::hermes::tests::capsec_conformance_batch::native_filesystem_denial_message_allowance_is_exact_and_fail_closed ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 655 filtered out; finished in 0.00s
```

## Findings

- No blocker.
- No material finding.
- The prior review's Minor M1 and M2 and Observations O1 and O2 carry forward unchanged; this addendum does not revisit them.
- The `@ref` repair correctly targets an existing LLP 0049 section heading; the annotation now resolves and describes the security rationale accurately.

## Verdict

**READY.**

The final target commit `6587099be4756041ba6bcf8b3321fea9fdd2f181` differs from the READY-reviewed commit `a162466417e3724ee5890b3592a717a34f23313a` only in a comment-only `@ref` anchor repair and two generator-owned `sourceOffset` metadata values. No semantic Rust, JS, or allow-list change is present. `./ref-check` passes with 0 errors. `cargo fmt --check` exits 0. The focused security test passes: 1 passed, 0 failed. This commit satisfies LLP 0049 section 3 rule 11.
