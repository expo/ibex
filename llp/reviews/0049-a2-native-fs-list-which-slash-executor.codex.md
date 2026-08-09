# Review: LLP 0049 A2 — `__exactWhich` slash-containing command

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** Codex workspace agent, GPT-5 family
**Date:** 2026-08-09
**Redacted:** No
**Method:** Independent adversarial source, recipe, catalog, receipt, and
production-consumer review against LLP 0049 §3 rule 11 and LLP 0037. I
authored neither the implementation nor its tests. I inspected the exact staged
target, regenerated its catalog, ran the paired gates and focused tests, replayed
the retained physical observation through the production JavaScript consumer,
and ran the two requested Rust mutation tests in an isolated detached worktree.
No content was sent to an external provider.

---

## Verdict

**NOT READY.** The Rust producer's denial-message set is exact and both required
mutation tests are load-bearing, but the independent JavaScript promotion
consumer rejects the new `__exactWhich` recipe descriptor. The staged target
updates only the Rust closed set; the JavaScript closed set still omits
`__exactWhich`. The class therefore cannot survive the independent evidence
consumer and does not discharge LLP 0049 §3 rule 11.

Two further material gaps remain: the successful native result is asserted only
as a generic return, not the exact virtual path, and no retained per-batch
evidence envelope exists for this class.

## Reviewer independence and exact target

- Reviewer: OpenAI GPT-5-family Codex workspace agent.
- Independence: I authored neither the reviewed code, its recipe tests, the
  allow-list, candidate, nor physical receipts.
- Base commit:
  `c4d9dfd9521ef73d4cdd42ce408c2c2308e04a35`.
- Base tree: `5824346bc893e19227f43486f49235cc26696c51`.
- Staged target tree: `8688e6a81a69290b91f5fe83796c885da16b11d0`.
- Canonical staged diff command: `git diff --cached --binary | shasum -a 256`.
- Canonical staged diff SHA-256:
  `06758fe3d93833b17977c21dbdb028964e20ba0ce6026d6aa68bb15d3c00cb24`.
- Diff shape: five files, 119 insertions and 2 deletions.

Reviewed file hashes:

- `capsec/registry/runtime-environment-inventory.json`:
  `d8eef22f51f122b0da7943199e2d26f9edbf1a74c3982330d16220006ae66cd8`
- `llp/evidence/0049-allow-list-class-native-op-fs-list-which-slash.json`:
  `5b94eb61a1add93a1f4199ce7d7da6ef983eeab3799faec8b69ae0fbe79fb5a8`
- `packages/ibex-devtools/src/scripts/capsec-conformance-recipes.mjs`:
  `c64165eeba07e72f2ee6b22cef531b7ba128e86899a0102ee39d7c847a8a8472`
- `packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs`:
  `f6891fbf1ca054bd6ec258bd756711da5070ecff172d26c71b1a2c481f5f89fc`
- `src/bin/ibex/engine/capsec_conformance_batch.rs`:
  `c0d03e22ced10bfcad736a1bec5af97c166ccc182292501367715ab92e9b9c6b`

## Scope, source, and recipe audit

The intended claim is correctly narrow in the recipe source. Exactly six
`logical.slash-containing-command` rows become `fully-executable`: `allow`,
`branch-selection`, `deny`, `malformed`, `missing-attribution`, and
`wrong-principal`. Every row invokes the exact global `__exactWhich` with one
literal argument, `/project/ref-check`; declares only `fs:list`; binds the exact
path selector `project/ref-check`; permits only
`surface.native.op.exactwhich.0it66ce`; and uses the exact secure command vector.

The six `logical.bare-command` siblings remain unresolved and continue to
declare `env:read + fs:list`; the staged template does not claim them. This
matches the secure C++ branch: a command containing `/` calls
`exactWhichArmed` directly, while only a bare command authorizes and reads the
principal `PATH` overlay. `exactWhichArmed` walks and retains the virtual path,
checks executable metadata, rechecks retained identity, and returns the virtual
spelling rather than the backing path.

The recipe test passed:

```text
bun test packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs \
  -t 'authors direct executable-path lookup without reading PATH'

1 pass, 112 filtered, 0 fail, 49 expectations
```

`git diff --cached --check` passed. `./ref-check` passed with 51 LLP documents,
2,535 references in 2,014 files, zero errors, and one unchecked external
reference.

The two generated inventory offsets are correct byte offsets in the staged Rust
source:

- `IBEX_CAPSEC_RECIPE_CATALOG`: 37,505, pointing at
  `env::var("IBEX_CAPSEC_RECIPE_CATALOG")`.
- `IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT`: 37,691, pointing at
  `env::var("IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT")`.

## Candidate and paired-gate audit

Candidate:
`/Users/ccheever/phase1-runs/campaign-a2/candidate-fs-list-which-slash-final.json`.

- Raw SHA-256:
  `80a1a5a5f5875659a8a9d7903d46703e64383b3306c6f07779aa38ee1038a13a`.
- Catalog digest:
  `sha256-bF7OtC-jbCcPLi6fPIzQvplyxIrYpL_GWyLaksIfw6Q`.
- Declared allow-list digest:
  `sha256-W5TrYaGt2TofQZnOfX2m75g-6rN5n67Itprg--eftag`.

Regenerating from the staged source and declared allow-list produced a
byte-identical candidate with the same raw and semantic digests: 21,784 required
fixtures, 3,976 fully executable, 3,124 internally verified, 9,985 adapter
executable, and 14,684 unresolved.

The strict paired route gate was run against
`candidate-fs-path-async-access-read-final-stable.json`:

```text
node scripts/llp0045-route-evidence-diff.mjs \
  --baseline <access-read-final-stable> \
  --candidate <which-slash-final> --scope all \
  --allow-list llp/evidence/0049-allow-list-class-native-op-fs-list-which-slash.json
```

Result: **PASS** — 13 changes, 13 explained, zero unexplained, zero stale.
The whole-catalog delta is exactly six removals of
`native-public-arguments-not-authored`, six removals of
`public-surface-invocation-not-authored`, and one removal of
`conditional-branch-selection-probe-not-authored`. Lane counts remain B 528 /
C 1,326 / D 32.

The terminal gate also passed:

```text
node scripts/capsec-terminal-evidence-diff.mjs \
  --baseline <access-read-final-stable> --candidate <which-slash-final>
```

Result: **PASS** — zero deltas on zero cells, zero unexplained, zero stale.

The allow-list source spans resolve to the exact staged template and logical
branch registration. It declares no route or terminal-set change and cannot
clear the unresolved bare-command sibling.

## Physical receipt and LLP 0037 audit

Receipts:

- Primary:
  `/Users/ccheever/phase1-runs/campaign-a2/fs-list-which-slash-primary-v2.json`
  — raw SHA-256
  `0e37325ec1c69d24f9bff9adc2ea4bac146692b004a8b34109d225c0cdf082d2`.
- Secondary:
  `/Users/ccheever/phase1-runs/campaign-a2/fs-list-which-slash-secondary-v2.json`
  — raw SHA-256
  `b2ce6a5cc5242fcece539cb4b36f426ced3c0db27bcd9c5a4814190dd55318b7`.

Both bind the candidate digest above and the same loaded engine digest,
`sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y`. The primary receipt is
308/308 passed and the secondary is 340/340 passed. The six target scenarios
occur exactly once across the two shards; all six report `passed`, bind their
candidate plan digest, use `native-op:__exactWhich` as both public carrier and
terminal, and carry the exact secure feature vector.

The five non-deny observations pin the bound-engine sequence required by LLP
0037 D3:

```text
requested, discovery, requested, repeat, discovery
```

Their authority strata are:

```text
static-floor, ambient-root, static-floor, static-floor, static-floor
```

The one deny observation contains only the first `requested` decision, with
`deny / principal-denial`, and returns the expected EACCES error containing
`filesystem policy denied` for `/project/ref-check`.

Every typed decision carries exactly the declared `fs:list` effect, the
`fs-which:` operation prefix, the exact
`surface.native.op.exactwhich.0it66ce` gate, and its corresponding atomicity
group. LLP 0037 D2's surplus-action relaxation is therefore **not engaged**:
there is no surplus capability. The root `discovery` decision is the proper
empty-path prefix of the exact project floor and correctly uses ambient-root
authority; the final target `discovery` remains on the exact static floor. It
would be incorrect to characterize the complete sequence as an undeclared
incidental traversal.

The six evidence digests are:

- allow: `sha256-9rgHb_0ratw8DFl8itkl550fuuE4BgJC0mKG2ZYpHlg`
- branch-selection:
  `sha256-FBVWWVCOC5G8p0TF3pj0AiB6JN56zPqKwfRHbEpGkrc`
- deny: `sha256-WEITMVubigiPw2kHvMn6vQmuNeux2cxMqTmfmTxnYd4`
- malformed: `sha256-hG-3uwG10qXzZbWNrawZJjeKhuX5Do9Q8pl7JkyNmBo`
- missing-attribution:
  `sha256-xSMiBUlUfaBmZ1SA1rkGE_IuJHx1m9ybTBWpClIxiOw`
- wrong-principal:
  `sha256-yLzjoorc5qnykgRVNdHOFUUPuQxuYaXamdWQXzbgBho`

These receipts prove that the Rust batch executed the intended source-bound
branch on the stated engine. They do not overcome the independent-consumer
blocker below.

## Exact Rust allow-list and required break-tests

The restored final Rust test passed under the mandated vector:

```text
cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  'engine::hermes::tests::capsec_conformance_batch::native_filesystem_denial_message_allowance_is_exact_and_fail_closed' \
  -- --exact --nocapture --test-threads=1

1 passed, 0 failed, 655 filtered out
```

The isolated detached worktree was created at base `c4d9dfd95`, then the exact
staged diff was applied. Its applied diff hash was independently confirmed as
`06758fe3d93833b17977c21dbdb028964e20ba0ce6026d6aa68bb15d3c00cb24`.
The isolated Cargo runs used explicit Hermes include/library paths,
`EXACT_ALLOW_FALLBACK=1`, and the shared Cargo target directory only as build
plumbing; the exact secure feature vector above was unchanged.

Break-test 1 — remove `__exactWhich` from the production Rust `matches!` set,
leaving the positive assertion intact:

```text
thread '...native_filesystem_denial_message_allowance_is_exact_and_fail_closed'
panicked at capsec_conformance_batch.rs:959:5:
assertion failed: native_filesystem_denial_message_is_reviewed("__exactWhich")

FAILED. 0 passed; 1 failed; 655 filtered out
```

Break-test 2 — widen the production Rust set with `__exactWhichExtra`, leaving
the negative assertion intact:

```text
thread '...native_filesystem_denial_message_allowance_is_exact_and_fail_closed'
panicked at capsec_conformance_batch.rs:960:5:
assertion failed: !native_filesystem_denial_message_is_reviewed("__exactWhichExtra")

FAILED. 0 passed; 1 failed; 655 filtered out
```

Each mutation was reversed with an explicit patch. After both reversions, the
isolated Rust file hash again equaled the shared reviewed target
(`c0d03e22...e9b9c6b`), the isolated staged diff hash again equaled
`06758fe3...cb24`, and the focused Rust test passed 1/1. All five reviewed file
hashes matched between the restored isolated worktree and the shared target.
The independent-consumer diagnostic mutation described below was likewise
reversed; its JavaScript file hash returned to
`c81d8dedff6d859474cbc0b1a5ba09b422571d6002d49cd180cdfb0d3d49dbbf`.

An initial short-name Rust command combined with `--exact` selected zero tests;
it is not credited. The fully-qualified command and the two observed failures
above are the credited runs.

## Findings and dispositions

### BLOCKER B1 — the independent JavaScript consumer rejects the class

`packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.mjs` has a
separate closed `NATIVE_FILESYSTEM_DENIAL_GLOBALS` set at lines 1174–1189. At
the reviewed target it omits `__exactWhich`. Every new recipe carries the
top-level exact fragment `filesystem policy denied`, so
`validateRuntimeInvocation` calls
`validateNativeFilesystemDenialRecipeDescriptor`; the closed-set lookup fails
and `buildPublicFixtureEvidence` throws:

```text
enforcement.src.engine.hermes.runtime.process.cc.exactwhich.15y11vy.logical.slash-containing-command.allow:
unreviewed native denial expectation
```

The same descriptor predicate applies to all six scenarios, so none can enter
the promotion evidence path. This is precisely the cross-authority defect rule
11 requires an independent replay to catch: the Rust producer and its new
positive/near-miss test pass while the independent consumer disagrees.

As a diagnostic only, in the isolated worktree I added the single missing
`__exactWhich` JavaScript set entry without changing any receipt. All six real
observations then replayed byte-for-byte through `buildPublicFixtureEvidence`
(6/6), confirming this closed-set disagreement is the immediate rejection
cause. That diagnostic mutation was fully restored and is not part of the
reviewed target.

**Disposition: OPEN; blocks landing.** Add `__exactWhich` to the independent
JavaScript closed set, add its own positive and `__exactWhichExtra` near-miss
tests, replay all six retained observations through the production consumer,
and obtain a fresh independent review of the corrected exact diff.

### MATERIAL M1 — successful `which` output is not asserted at true strength

The recipe asserts only `expectedResult: "return"`. The synchronous native
harness records `kind`, `globalName`, `valueType`, and `cleanup`, but not the
returned string. The Rust validator accepts any returning value for this global,
and the JavaScript consumer requires only that `valueType` and `cleanup` are
strings. Therefore the physical receipt does not prove the source/allow-list
claim that the result is exactly `/project/ref-check` or even that it remains a
string on a future run.

After applying only the isolated B1 diagnostic entry, changing the real allow
observation's recorded `valueType` from `string` to `null` was accepted by
`buildPublicFixtureEvidence` as a passing execution. A wrong string or a leaked
backing path is even less detectable because the actual string value is absent
from the evidence schema.

**Disposition: OPEN; material.** Bind the exact expected virtual string in the
recipe, transport it in the synchronous native result evidence, and assert it
independently in both Rust and JavaScript. Add a break-test that substitutes a
wrong string and must fail. This is consistent with LLP 0037's exact returned-
value treatment for path-disclosing operations such as `readlinkSync`.

### MATERIAL M2 — the retained per-batch evidence envelope is absent

The reviewed staged change contains the rule-3 allow-list but no
`llp/evidence/0049-batch-native-op-fs-list-which-slash-<digest>.json` envelope.
The candidate and physical receipts outside the repository are useful inputs to
this review, but they do not replace LLP 0049 §6/§6.3's retained per-batch
envelope binding source revision, candidate, allow-list, commands, paired gates,
physical receipts, and review disposition.

**Disposition: OPEN; material to the Phase 2 exit gate.** Retain the envelope
for the corrected final target and index/bind this NOT READY review plus the
fresh corrected review honestly; do not relabel this artifact after the target
changes.

## Final assessment

The source-selected slash branch, six-row scope, paired allow-list, catalog
digest, physical engine binding, typed decisions, LLP 0037 D2/D3 treatment, and
Rust exact-name allow-list are sound at the strength tested. They are
insufficient for landing because the independent production consumer rejects
the descriptor, the return-value assertion is too weak for the class's path
claim, and the retained batch envelope is absent.

**Final verdict: NOT READY.**
