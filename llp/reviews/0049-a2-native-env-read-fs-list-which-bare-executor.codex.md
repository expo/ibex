# Review: LLP 0049 A2 — Native `env:read` + `fs:list` `which` bare-command executor

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** Codex workspace agent, GPT-5 family
**Date:** 2026-08-09
**Redacted:** No
**Method:** Independent adversarial review of the exact staged seven-file
implementation target. I authored neither the implementation nor its tests. I
read LLP 0000, LLP 0037 D1–D4, LLP 0049 §3 and §6, and the relevant LLP 0021
scoped-completeness contract; inspected the staged Rust executor, independent
JavaScript consumer, template, allow-list, generated inventory, candidate, and
both physical receipts; regenerated the candidate; replayed the physical
observations through the production consumer; and ran isolated break tests in
a detached worktree. Only this review artifact was added to the shared tree.

---

## Verdict

**NOT READY.** One open **BLOCKER** prevents LLP 0049 §3 rule 11 discharge.

Both production consumers accept the real early-denial observation after the
recipe's declared action set is incorrectly narrowed from
`["env:read", "fs:list"]` to `["env:read"]`. Their new exact exception helpers
correctly reject that mutation, but the surrounding generic action-equality
fallback then accepts it. The focused tests exercise only the exact helper (or
deliberately omit the production assertion), so the self-authored green suite
does not catch the integration defect.

The current unmutated candidate and receipts are internally consistent, all
other reviewed neighboring mutations reject, and the D2 path-discovery account
is supported by the physical observations. Those facts do not cure the
fail-open authoring drift at the production evidence boundary.

## Reviewed identity

- Base commit: `52a7f61276ed1cc50921499400b29bc1892dc927`
- Base tree: `09f6e7d5835b9cc5379e29677c596aec7ce557be`
- Staged target tree: `6d7e94a50892bb7b937e748d4cbe7e578fabd6a2`
- Canonical staged diff SHA-256 (`git diff --cached | shasum -a 256`):
  `ad4f35d44ae6d44dbcdbbfe2d24b0374b62d2822f0d55194f44958d112529bc0`
- Diff shape: 7 files, 469 insertions, 23 deletions
- Candidate:
  `/Users/ccheever/phase1-runs/campaign-a2/candidate-env-read-fs-list-which-bare-v3.json`
- Candidate raw SHA-256:
  `4119432be2e56c607bfb4273c3336c5102d9533c9400c2fae1932e95b3ddd2d6`
- Catalog digest: `sha256-Yqenf9cBCh57flKqrJWc266ihly5w3cD-VBOYDW9RpY`
- Declared allow-list digest:
  `sha256-5A4uWaO0IEaB5xNu_1WcgLyTMpOXlryGHRbSLZuhIPY`
- Allow-list raw SHA-256:
  `e40e2e59a3b4204681e7136eff559c80bc9332939796bc861d16d22d9ba120f6`
- Primary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/env-read-fs-list-which-bare-primary-v4-final.json`,
  raw SHA-256
  `7766a5edc8e40ee578b3b3c96fff72a58e10600aefd5901484421e028932adcf`,
  312/312 passed
- Secondary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/env-read-fs-list-which-bare-secondary-v4-final.json`,
  raw SHA-256
  `5f657f3f64600ef26473901249c09dc5c78ca552a9c2b1ba90bcd1619e3b6de5`,
  342/342 passed
- Loaded engine digest in both receipts:
  `sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y`

The supplied `candidate-env-read-fs-list-which-bare-final-v4.json` is
byte-identical to v3. Independent regeneration from the staged source also
produced byte-identical bytes and the same raw digest. The candidate reports
21,784 required fixtures, 3,982 fully executable, 3,124 internally verified,
9,985 adapter executable, and 14,678 unresolved.

Final staged file hashes before isolated mutation were:

- inventory:
  `0d6c1df7a1bd744e1080d053d92653633a791999da0f217e54658e8caf46bd06`
- allow-list:
  `e40e2e59a3b4204681e7136eff559c80bc9332939796bc861d16d22d9ba120f6`
- recipes:
  `f7b429295c83cf3dd4352ec6750b27d66ad720355f10b38a7cc04c5de07da9c5`
- recipe tests:
  `a33dc194b0743fcea9715f9c578287ad7d4ad20db93d9e40cb7e1b704c354057`
- evidence consumer:
  `55c8cd4a0d587ce3d758ae62716525e8dd7dd93b280e03db889ba28890b8c89d`
- evidence tests:
  `bf2c5323238289064dac3e2dc25293aa0cbf86509973755a3be7fd1046c3b2e3`
- Rust executor/validator:
  `b90df3d3466022c0b97f914d525fa1e2e737a708f1dce3518b124e0e2dcfc457`

The detached worktree was created at the base commit and received the exact
cached patch; its cached diff digest matched `ad4f35d…`. After the break tests,
the mutated JavaScript and Rust files were restored byte-for-byte to the shared
staged hashes. `git diff --cached --check` passed, and the shared staged digest
remained unchanged.

## BLOCKER B1 — wrong declared action set bypasses the exact exception

### Evidence

The JavaScript production integration computes `actionSetMatches` as:

```text
reviewedNativeEarlyDenialActionPrefix(...) || genericActionRule
```

The new exact helper requires authored actions
`["env:read", "fs:list"]` and observed actions `["env:read"]`. With the
authored actions mutated to `["env:read"]`, that helper returns false, but the
generic non-open-then-act rule sees declared and observed actions as equal and
returns true. A driver using the real deny receipt and production
`buildPublicFixtureEvidence` produced:

```text
wrong-global: rejected — native runtime invocation descriptor drift
slash-argument: rejected — observed typed stages, actions, or gates drifted
wrong-result: rejected — public invocation did not return
wrong-declared-actions: ACCEPTED
wrong-observed-actions: rejected — observed typed stages, actions, or gates drifted
wrong-stage-count: rejected — malformed runtime public observation
wrong-scenario: rejected — observed typed stages, actions, or gates drifted
```

The command was an inline Node ESM review driver that loaded the staged
`buildPublicFixtureEvidence`, the v3 catalog, coverage registry, and real v4
deny execution; cloned the recipe/execution once per named mutation; then
called the production builder and printed acceptance or the thrown error:

```text
node --input-type=module -e '<load catalog, coverage, and real deny receipt;
  mutate global / argument / result / declared actions / observed actions /
  stage+count / scenario; call buildPublicFixtureEvidence for each>'
exit 2 because wrong-declared-actions was accepted
```

Rust has the same control-flow defect. `native_observed_actions_are_reviewed`
first calls `reviewed_native_early_denial_action_prefix`; when that returns
false it applies the general subset/equality rule. For declared
`["env:read"]` and observed `{ "env:read" }`, the general rule succeeds. The
staged Rust unit explicitly skips the production-wrapper negative for this one
nearby case with the comment that an exact env-read pair remains valid under
the general rule.

In the detached worktree I removed that skip and required every nearby
invocation, including the reduced declared action set, to be rejected by the
production wrapper. With the required secure feature vector, the test failed:

```text
cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  'engine::hermes::tests::capsec_conformance_batch::native_which_early_denial_action_prefix_is_exact_and_fail_closed' \
  -- --exact --nocapture --test-threads=1

assertion failed: !native_observed_actions_are_reviewed(&nearby, &observed_prefix)
0 passed; 1 failed; 657 filtered out; exit 101
```

This is not merely a pure-helper concern. It demonstrates that both actual
consumer integrations accept the bad declaration.

### Impact

The reviewed exception exists because the deny observation stops after the
`env:read` request and therefore cannot physically emit the later `fs:list`
action. The authored full action set is what binds that one-decision prefix to
the reviewed two-action class. Allowing it to shrink to the observed prefix
turns the exact exception into a generic self-consistent account and permits
authoring drift to erase the later path-discovery obligation on the deny row.
That contradicts the requested exact early-denial account and LLP 0049's
fail-closed evidence discipline.

### Required resolution

Classify the reviewed bare-`which` early-denial shape before applying the
generic action rule, and make that classified shape return the exact helper's
answer rather than fall through. The classifier must not depend on the field
being protected (`expectedActionIds`), or a bad action set will again evade it.
The JavaScript integration has the recipe scenario available; Rust can bind
the exact global, bare literal argument, permission-denied result, and early
sequence before requiring the full declared/observed action pair.

Add integration tests against the production wrappers—not only the pure
helpers—that prove:

- exact declared `["env:read", "fs:list"]` plus observed `["env:read"]`
  passes;
- reduced declared `["env:read"]` fails;
- widened/reordered declared actions fail;
- empty, `fs:list`-only, full two-action, and unrelated observed sets fail.

**Disposition:** open at this reviewed target. A corrected implementation has
to receive a fresh independent review under its new exact diff identity.

## Source, recipe, and D2 audit

The recipe creates exactly six bare-command fixtures. Each invokes
`__exactWhich` with one literal `ref-check`, seeds only the principal PATH
overlay with `/project`, requires setup `env:write PATH`, and requires the
runtime floor `env:read PATH` plus exact `fs:list project/ref-check`. The five
non-deny scenarios pin seven decisions:

```text
requested, commit, requested, discovery, requested, repeat, discovery
```

The deny scenario pins one `requested` decision. Non-deny results bind the
exact logical string `/project/ref-check`; deny has no success-string field.
The only allowed coverage edge is
`surface.native.op.exactwhich.0it66ce`.

The engine source confirms the branch: a slash-containing command bypasses
PATH, while the bare command authorizes and reads the principal PATH overlay,
joins `/project` with `ref-check`, and calls `exactWhichArmed`. That helper
performs a retained path walk and returns `path.virtualPath`, never the backing
spelling.

For LLP 0037 D2, all five non-deny receipts have exactly two `env:read`
decisions (`requested`, `commit`) followed by five `fs:list` decisions at
`requested`, `discovery`, `requested`, `repeat`, `discovery`. Every filesystem
operation ID starts `fs-which:` and names the candidate path/root walk. No
decision performs a readdir/directory-content operation, and the public result
is the exact logical executable path rather than directory entries. The deny
receipt stops at the refused `env:read` and emits no filesystem decision.
Thus every observed `fs:list` in this class is path discovery/traversal, not a
real directory listing.

The generated inventory offsets are correct under its one-based convention:
43,478 points to `env::var("IBEX_CAPSEC_RECIPE_CATALOG")` and 43,664 points to
`env::var("IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT")`.

## Candidate, gate, and receipt results

Independent generation:

```text
bun packages/ibex-devtools/src/scripts/generate-capsec-conformance-recipes.mjs \
  --target aarch64-apple-darwin \
  --declared-allow-list llp/evidence/0049-allow-list-class-native-op-env-read-fs-list-which-bare.json \
  --output /tmp/ibex-which-bare-review.whAjil/candidate.json

recipeCatalogDigest: sha256-Yqenf9cBCh57flKqrJWc266ihly5w3cD-VBOYDW9RpY
declaredAllowListDigest: sha256-5A4uWaO0IEaB5xNu_1WcgLyTMpOXlryGHRbSLZuhIPY
cmp against supplied v3: byte-identical
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

PASS; 0 deltas on 0 cells, 0 unexplained, 0 stale
```

Production receipt replay:

```text
node /Users/ccheever/phase1-runs/campaign-a2/replay-which-bare-evidence.mjs

production evidence replay: 6/6 byte-structural matches
wrong deny action mutation: rejected
wrong string mutation: rejected
```

## Green and other break-test results

The unmutated focused tests passed:

```text
bun test packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs \
  packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.test.mjs \
  -t 'authors bare executable lookup through the exact principal PATH overlay|admits only the observed bare-which early-denial action prefix'

2 passed; 200 filtered; 0 failed; 83 expectations

cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  'engine::hermes::tests::capsec_conformance_batch::native_which_early_denial_action_prefix_is_exact_and_fail_closed' \
  -- --exact --nocapture --test-threads=1
1 passed; 657 filtered; 0 failed

cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  'engine::hermes::tests::capsec_conformance_batch::native_which_string_result_account_is_exact_and_fail_closed' \
  -- --exact --nocapture --test-threads=1
1 passed; 657 filtered; 0 failed

./ref-check
51 documents; 2,537 references; 2,016 files; 0 errors; 1 unchecked
```

The detached worktree lacked a local Hermes compiler artifact. Rust tests used
`EXACT_ALLOW_FALLBACK=1`, explicit Hermes library/header paths, and the shared
Cargo target directory as build plumbing only. Every Cargo invocation retained
the exact promotion feature vector:
`--no-default-features --features standard,capsec-conformance-observer,openssl-crypto`.

Additional isolated breaks:

1. Removing the JavaScript production call to the exact exception and replaying
   the real deny execution failed with `observed typed stages, actions, or
   gates drifted`. This proves the production integration—not only the helper—
   depends on the exception.
2. Widening the JavaScript helper's global comparison to prefix matching made
   `__exactWhichExtra` pass; the focused test failed (`Expected: false`,
   `Received: true`).
3. Widening its argument account to include `/project/ref-check` made the slash
   near-miss pass; the focused test failed at the third expectation.
4. Production mutation replay rejected wrong global, slash argument, public
   result, observed action, stage/count, scenario, and backing-path string.
5. The same production replay accepted the reduced declared action set, and
   the added Rust integration assertion failed as documented in B1.

These results show that the branch, global, argument, result, stage/count,
scenario, observed-action, and exact-string checks are otherwise load-bearing.
They also isolate the one unsafe fallthrough rather than attributing the
failure to the exact helper itself.

## Findings disposition and residual risk

- **B1 — BLOCKER, open:** wrong declared action set bypasses the exact early-
  denial helper through the generic production fallback in both Rust and
  JavaScript. Required resolution and re-review are above.

No other blocker, material, or minor finding was found in this exact target.
Residual risk remains bounded by the diagnostic nature of Phase 2 receipts:
they are not the later authoritative Phase 3 ceremony, and this focused review
did not run every unrelated repository test. More importantly, no green count
or valid current receipt should be interpreted as closing B1; the reviewed
implementation is **NOT READY** until both production consumers reject the
reduced declaration and that correction receives a fresh independent review.
