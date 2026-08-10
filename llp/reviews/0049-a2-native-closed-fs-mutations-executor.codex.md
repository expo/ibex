# Review: LLP 0049 A2 — Native closed filesystem mutations executor

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** Codex workspace agent, GPT-5 family
**Date:** 2026-08-09
**Redacted:** No
**Method:** Fresh independent adversarial review under LLP 0049 §3 rule 11. I
read LLP 0000, LLP 0037 D1–D4, LLP 0049 §3 and §6, LLP 0021 WP5/WP10, LLP
0023 §4.1, and the repository review instructions; inspected the seven-file
staged target plus the engine entry points it records; regenerated the
candidate independently; compared route and terminal evidence; replayed both
physical receipts through the production JavaScript consumer; and ran positive
and isolated break tests. I did not edit the primary implementation.

---

## Verdict

**READY.** I found no blocker, material issue, or unaddressed minor issue in
the reviewed class.

The promoted claim is deliberately narrow. Sixteen closed filesystem mutation
operations are refused synchronously at the native public dispatcher with
`EPERM` before path lookup, descriptor ownership work, capability work, or
worker dispatch. Accordingly, their retained observations have exactly zero
typed decisions, zero legacy decisions, no stages, gates, setup, floors, or
actions, and exactly one four-key throw result. This is physical zero-effect
evidence, not a relaxation of LLP 0037 D1–D4.

## Reviewed identity

- Base commit: `bc6b20f613ccd7a741a9f4679297800ab78f21ec`
- Base tree: `7f02df12f7e390cd2a44e3c78361e9d8f5ad85db`
- Seven-file staged target tree: `706e65f2359100bcbee2c4f8e109650e97a3f7ec`
- Canonical staged binary diff SHA-256
  (`git diff --cached --binary | shasum -a 256`):
  `b1888a42cfa5cf00d2e6a1927f5668ca33204c34db6134223a47d241b3a5d0c3`
- Diff shape: 7 files, 1,276 insertions, 25 deletions
- Candidate:
  `/Users/ccheever/phase1-runs/campaign-a2/candidate-closed-fs-mutations-v6-final.json`
- Candidate raw SHA-256:
  `b5c5b424fe740517e9e9b438819107c3a1f594fad9a106e941b507e7ecd9be3d`
- Catalog digest:
  `sha256-HgfaOHXr8RcI_aVAsI1PynCogv3mjR0gfGp2DRGz3G0`
- Allow-list digest:
  `sha256-N-58JXvaHByM9FvvqgV-fpuInr8y-wPjyvLt2Hs0Hcw`
- Allow-list raw SHA-256:
  `37ee7c257bda1c1c8cf45befaa057e7e9b889ebf32fb03e3caf2edd87b341dcc`
- Loaded engine digest in both receipts:
  `sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y`
- Primary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/closed-fs-mutations-primary-v5-final.json`,
  raw SHA-256
  `e38e4663b5e80b0cc9f716a028f58484364b9fd5bf9b5d13db0085fa2fe136d2`,
  322/322 completed, including 10 target executions
- Secondary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/closed-fs-mutations-secondary-v5-final.json`,
  raw SHA-256
  `04a9dde784bca8451c8504adf22d485345cfd5adf2f0aae0c9715445eabfc3ac`,
  348/348 completed, including 6 target executions
- Replay program:
  `/Users/ccheever/phase1-runs/campaign-a2/replay-closed-fs-mutations-evidence.mjs`,
  raw SHA-256
  `cf0aec09930c0fd945570f3d527d8524dd9e941dd75da10d9c25aa10e84f2616`

Independent candidate generation from the staged source produced a
byte-identical file with the same raw digest. The candidate reports 21,784
required cells, 3,998 fully executable cells, 3,124 internal-only cells,
9,985 adapter cells, and 14,662 unresolved cells.

The final staged file hashes, also matched byte-for-byte after restoring the
detached mutation worktree, are:

- inventory:
  `1d9ade14833fb7d9bf4829df07127eaea5ecf26f76e9f6675d302df955332129`
- allow-list:
  `37ee7c257bda1c1c8cf45befaa057e7e9b889ebf32fb03e3caf2edd87b341dcc`
- recipes:
  `df172071d2db3f7c9a3b8c4e21552fd0c73489e92e3e8dfbe3273ea2c411abd2`
- recipe tests:
  `affdbdd4c655f12cd370031dc19ccbc27065aa9ab6915166915c9a65630a5d55`
- evidence consumer:
  `a5a066133286fc649c2c8683007f16fbc6cca488b230e5d41863ba0bb15277af`
- evidence tests:
  `66afa6601d4952e8977093ab3252a8d004aa3f76583cefa325e87e75b57a7181`
- Rust validator:
  `194211844c66064d77d66abd965f9f99c518e45c3946fa797ca6064ddb899a73`

The runtime-inventory anchors are exact: one-based byte offset 51,490 points
at `env::var("IBEX_CAPSEC_RECIPE_CATALOG")`, and 51,676 points at
`env::var("IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT")`. `git diff --cached
--check` passed, and the implementation binary-diff digest remained exact
after review.

## Source, recipe, and validator audit

The catalog contains exactly three descriptor mutations and thirteen path
mutations:

- `fchmod(42, 384)`, `fchown(42, 0, 0)`, and `futimes(42, 0, 0)` through
  `__exactFsFdAsync`
- `chown`, `copyfile`, `copyfile_excl`, `lchmod`, `lchown`, `link`, `lutime`,
  recursive `mkdir`, `mkdtemp`, `rename`, `rmdir`, `symlink`, and `unlink`
  through `__exactFsPathAsync`, each with its exact authored logical path slots
  and option arguments

Every target recipe is `closed`, `branch-selection`, and fully executable.
Each has an empty floor, setup, stage list, and expected action list; expected
typed-decision count zero; exact `permission-denied` completion; and denial
fragment `EPERM: operation not permitted`. The only allowed edge is the
corresponding public dispatcher edge:
`surface.native.op.exactfsfdasync.1iinzl8` or
`surface.native.op.exactfspathasync.10cb78b`.

The Rust security consumer and independent JavaScript promotion consumer each
bind the full exact account: classification, scenario, global, operation,
argument arity and literal values, all six logical path slots, empty floors,
setup, stages and actions, zero decisions, completion, and allowed edge. Each
accepts a result only when its object has exactly these four keys and values:

```json
{
  "kind": "throw",
  "globalName": "<exact dispatcher>",
  "errorName": "Error",
  "errorMessage": "EPERM: operation not permitted, <exact operation>"
}
```

There is no typed or legacy admission shortcut and no gate evidence. The
zero-decision branch is admitted only after both consumers prove the full
reviewed account and exact throw result. A wrong global, operation, argument,
path, descriptor, suffix, result shape, action, or decision count is rejected.

The engine implementation independently supports the physical interpretation.
`__exactFsPathAsync` recognizes a closed mutation and calls the refusal helper
before converting or resolving the path and before capability or async-worker
dispatch. `__exactFsFdAsync` refuses the three closed descriptor operations
before descriptor conversion, ownership/capability work, duplication, or
worker dispatch. The refusal helper sets `EPERM` and throws the operation-bound
filesystem error.

Recursive `mkdir` is especially important. Although an allowed open execution
can reach the `__exactMkdir` worker, this closed invocation stops at
`__exactFsPathAsync`. Both consumers exclude the worker auxiliary terminal for
this exact closed account, and the recipe permits only the dispatcher edge.
The implementation therefore cannot borrow `__exactMkdir` worker evidence to
promote this fixture.

The allow-list has six exact source-span entries explaining 48 residual
removals: 16 native-public-argument residuals, 16 public-surface-invocation
residuals, and 16 closed-surface-denial-probe residuals. It does not authorize
a route or terminal change.

## Candidate, route, and receipt audit

The strict route comparison against
`candidate-env-read-fs-list-which-bare-final-v4.json` passed with 48 changed
entries, all 48 explained, 0 unexplained entries, and 0 stale allow-list
entries. Lane B/C/D counts remain 528/1,326/32. The only residual deltas are
-16 in each of the three authored residual classes above. The strict terminal
comparison passed with 0 changed cells, 0 unexplained entries, and 0 stale
entries.

The two receipt target sets are disjoint, their union contains exactly the 16
catalog targets, and all 16 use `ibex-native-public-surface-harness` with the
mandated secure Cargo feature vector. Every target execution has zero typed
decisions, zero legacy decisions, empty actions, floors, setup and stages,
count zero, only the dispatcher terminal, and the exact four-key result. There
is no target missing from the receipts and no duplicate physical execution.

The supplied replay rebuilt all 16 target executions through the production
JavaScript evidence consumer and matched each retained execution structurally:

```text
production evidence replay: 16/16 byte-structural matches
wrong syscall, widened result, wrong global, legacy observation, descriptor,
path, action, and count mutations: rejected
```

I separately changed the authored operation of the retained `fchmod` recipe to
`fchown`; the production evidence consumer rejected that wrong-operation
mutation as well.

## Tests and adversarial break tests

Focused final tests passed:

```text
bun test packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs \
  packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.test.mjs \
  -t 'executes async retained durability without overclaiming metadata|physically refuses every closed async path-mutation branch before lookup|admits only exact closed native filesystem mutation branches'
3 passed, 201 filtered, 0 failed, 186 expectations

cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  'engine::hermes::tests::capsec_conformance_batch::native_closed_filesystem_mutation_account_is_exact_and_fail_closed' \
  -- --exact --nocapture --test-threads=1
1 passed, 658 filtered, 0 failed

./ref-check
51 LLP documents, 2,538 references in 2,018 files, 0 errors, 1 unchecked
```

The detached worktree lacked its own Hermes compiler artifact. Its Rust tests
therefore used `EXACT_ALLOW_FALLBACK=1`, explicit Hermes library/header paths,
and the shared Cargo target directory as build plumbing. The security-relevant
feature vector was not changed:
`--no-default-features --features
standard,capsec-conformance-observer,openssl-crypto`.

I changed one production admission or evidence constraint at a time in the
detached worktree, leaving its relevant positive and negative tests intact:

1. Removing the closed-mutation branch from the JavaScript denial descriptor
   validator made an actual positive descriptor fail with `unreviewed native
   denial expectation`.
2. Removing the JavaScript zero-decision admission made the retained `fchmod`
   execution fail with `absence of a typed decision is not evidence here`.
3. Bypassing the JavaScript exact-result helper caused the wrong-syscall and
   extra-result-key rejection assertions to fail because those mutations were
   admitted.
4. Widening the JavaScript exact account to admit descriptor 43 failed the
   explicit descriptor near-miss assertion.
5. Widening the Rust exact account's global comparison failed the explicit
   wrong-global assertion.
6. Removing the Rust zero-decision exact-result admission made the physical
   primary batch fail on its retained `fchmod` target with `a zero-decision
   public invocation did not select a reviewed zero-effect branch`.
7. Removing the Rust closed-worker exclusion made the physical secondary
   batch fail on recursive `mkdir` because its account improperly expected the
   `__exactMkdir` worker edge in addition to the dispatcher edge.
8. Removing the Rust syscall-suffix equality failed the exact-result unit's
   wrong-syscall negative assertion.

All mutations were restored. The detached implementation then had no working
tree diff, reproduced the canonical seven-file binary-diff digest, and passed
the exact secure Rust test again. These breaks show that zero-decision
admission, the independent JavaScript descriptor, result exactness, and the
recursive-worker exclusion are load-bearing rather than documentary checks.

## Findings disposition

No findings require disposition. The class remains within LLP 0049's narrow
A2 promotion model: exact authored operations, exact physical public-entry
refusals, independent fail-closed consumers, no borrowed worker evidence, and
no additional authority, gate, route, or terminal claim.
