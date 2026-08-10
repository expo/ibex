# A2 `__exactFsPathAsync` access-read executor review

**Type:** Review
**Status:** Complete
**Systems:** Security, Conformance, Runtime, Devtools
**Author:** Codex (OpenAI GPT-5 family)
**Date:** 2026-08-09
**Related:** LLP 0021, LLP 0037, LLP 0049

## Review identity and exact target

- Role: independent adversarial reviewer. This reviewer authored neither the
  implementation, its tests, nor the allow-list/evidence under review.
- Family / provider/runtime: OpenAI GPT-5 family / Codex.
- Method: local source review, retained-artifact inspection, focused secure
  tests, production-consumer replay, and paired-diff checks. No content was
  sent to an external provider.
- Redacted: no.
- Reviewed base and `HEAD`:
  `52abebaed00852bdda31a805e17b9faac0e9b6f3` (tree
  `b3c53b2d65dfc5954887ed6532dfa5b869ff97dd`, parent
  `ace5a5a3d853ea040c780aa6f5e640c451a47f9d`).
- Reviewed target: the uncommitted four-file change over that `HEAD`, before
  any correction prompted by this review:
  `packages/ibex-devtools/src/scripts/capsec-conformance-recipes.mjs`,
  `packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs`,
  `src/bin/ibex/engine/capsec_conformance_batch.rs`, and
  `llp/evidence/0049-allow-list-class-native-op-fs-path-async-access-read.json`.
- Exact reviewed four-file diff SHA-256:
  `f8a7356c53fa4a60639b3e67fe39e5e391361a184d161b0c0ceee022263c2fe1`.
  This was computed from `git diff --binary HEAD -- <the four paths>` with a
  temporary index containing an intent-to-add entry for the otherwise
  untracked JSON file. The repository index was not changed. Without that
  temporary intent-to-add, Git silently omits the untracked fourth file; that
  three-file byte stream hashes to
  `34f470bb44ef58fe21eaae37214522cb5b239e06caec845944195e268ccd99e4`
  and is not the reviewed four-file digest.
- Raw allow-list SHA-256:
  `074ff3e1e7fb6310420ecffad9e2ae007238bee1037b85c49e70faa2d8090a39`.

The digest was produced with a temporary index as follows:

```text
task_index=$(mktemp)
GIT_INDEX_FILE="$task_index" git read-tree HEAD
GIT_INDEX_FILE="$task_index" git add -N -- llp/evidence/0049-allow-list-class-native-op-fs-path-async-access-read.json
GIT_INDEX_FILE="$task_index" git diff --binary HEAD -- packages/ibex-devtools/src/scripts/capsec-conformance-recipes.mjs packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs src/bin/ibex/engine/capsec_conformance_batch.rs llp/evidence/0049-allow-list-class-native-op-fs-path-async-access-read.json | shasum -a 256
```

Result: `f8a7356c53fa4a60639b3e67fe39e5e391361a184d161b0c0ceee022263c2fe1`.

This artifact intentionally does not review the correction that appeared in
the shared worktree after the finding was reported. That correction requires a
fresh review and a new exact diff digest.

## Governing constraints

The review applied LLP 0049 §3 rules 3, 6, 7, 9, and 11 and §6/§6.3. In
particular, a catalog delta needs symmetric allow-list and terminal-diff gates,
physical execution under the exact secure feature vector, and an independent
implementation review that attempts to break the fixtures. LLP 0037 D3 requires
typed sequences to be pinned from a bound-engine run. LLP 0021 WP10 requires
fixture-specific, source-bound public evidence that survives the independent
promotion consumer.

## Scope and positive evidence

The intended class is narrow and the Rust producer is locally fail-closed:

- exactly six `logical.access-read` rows become `fully-executable`;
- all six invoke `__exactFsPathAsync` with exact first argument `"access"`,
  exact project path `Cargo.toml`, null unused second path, and mode `0` (`F_OK`);
- all six require only `fs:list` over the exact project path;
- the `access-write` sibling remains unresolved in all six scenarios;
- the Rust closed map admits `access -> native-op:__exactAccess` only for the
  `__exactFsPathAsync` global and rejects `mkdtemp`, another global, and a null
  operation;
- the C++ source branch at `hermes_runtime_fs.cc:7661-7678` uses mode `0` to
  keep `needsRead` and `needsWrite` false, then dispatches to
  `fsAccessArmedWork`; and
- the retained physical decisions carry only `fs:list` on
  `surface.native.op.exactaccess.1a12cmn`. No `fs:read` or `fs:write` content
  authority appears.

The paired route gate passes in strict all-scope mode: 13 residual-reason
removals, 13 explained, zero unexplained, zero stale. The terminal-diff gate
passes with zero terminal changes on zero cells.

## Physical evidence inspected

| artifact | raw SHA-256 | binding / target rows |
| --- | --- | --- |
| `candidate-fs-path-async-access-read-v2.json` | `f6978ed72d9bbaf23aad86827a8e355dd576edfb9cb3d3c22cb2f88c40880895` | catalog `sha256-cY2t5jerfrwBMazy0ZwfRgXgR1eRWxrrOCToaSoeOxg`; declared allow-list `sha256-B0_z4ef7YxBCDs_62eKuAHI4vuEDe4XEnnD6otgJCjk` |
| `fs-path-async-access-read-primary-air-v3.json` | `42fecec041fe69ee6bad925ddb427e299b2ccd1c696b16e694d4d58dedc95edc` | same catalog; engine `sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y`; 3 target rows |
| `fs-path-async-access-read-secondary-air-v1.json` | `4009b38f399e69cea555e33349f79e3c74f8a39887cf6ac9a9e2d00f60dc1cd8` | same catalog and engine; 3 target rows |

The six scenarios occur exactly once across the two shards: `allow`,
`branch-selection`, `deny`, `malformed`, `missing-attribution`, and
`wrong-principal`. All report `passed`, all embed
`--no-default-features --features
standard,capsec-conformance-observer,openssl-crypto`, and all retain the carrier
as `native-op:__exactFsPathAsync` while every typed gate uses only the exact
access worker edge.

The five non-deny rows have stages
`requested, discovery, requested, repeat, repeat, repeat`, all allowed. The deny
row has one `requested / fs:list / deny / principal-denial` decision and returns
the expected filesystem-policy denial.

## Commands and results

### Focused Rust closed-map unit

```text
cargo test --bin ibex --no-default-features --features standard,capsec-conformance-observer,openssl-crypto 'engine::hermes::tests::capsec_conformance_batch::native_async_worker_terminal_account_is_exact' -- --exact --nocapture
```

Result: PASS — `1 passed; 0 failed; 655 filtered out`.

### Focused recipe test

```text
bun test packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs -t 'authors async access existence checks without claiming content authority'
```

Result: PASS — `1 pass; 0 fail; 111 filtered out`, 43 expectations.

### Paired catalog gates

```text
node scripts/llp0045-route-evidence-diff.mjs --baseline /Users/ccheever/phase1-runs/campaign-a2/candidate-fs-stat-async-path-final.json --candidate /Users/ccheever/phase1-runs/campaign-a2/candidate-fs-path-async-access-read-v2.json --scope all --allow-list llp/evidence/0049-allow-list-class-native-op-fs-path-async-access-read.json
node scripts/capsec-terminal-evidence-diff.mjs --baseline /Users/ccheever/phase1-runs/campaign-a2/candidate-fs-stat-async-path-final.json --candidate /Users/ccheever/phase1-runs/campaign-a2/candidate-fs-path-async-access-read-v2.json
```

Result: PASS / PASS — route changes `13/13` explained, zero unexplained and
zero stale; terminal deltas `0` on `0` cells.

### Independent JavaScript closed-map test

```text
bun test packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.test.mjs -t 'keeps the native async worker-terminal account exact'
```

Result: PASS — `1 pass; 0 fail; 86 filtered out`, 27 expectations. This is
not a positive result for this class: the test's supposedly exact expected map
omits `access`, so it passes while the producer and consumer disagree.

### Production-consumer replay break-test

The review loaded candidate v2, selected all six `logical.access-read` recipes,
joined their exact retained runtime observations from the two physical shards,
constructed the bound two-edge coverage slice
(`surface.native.op.exactfspathasync.10cb78b` and
`surface.native.op.exactaccess.1a12cmn`), and called the production-exported
`buildPublicFixtureEvidence` for every row. The same replay also called the
production-exported `nativeAsyncWorkerTerminal` on the authored invocation.

Result: FAIL as a promotion path, reproduced on all six rows. Worker lookup
returned `null`; `buildPublicFixtureEvidence` rejected `6/6` with:

```text
runtime-derived terminal is outside the bound route
```

This is the load-bearing adversarial break-test. It uses the real candidate
recipe, real physical runtime observations, and the independent production
consumer, rather than a hand-built facsimile of the decision sequence.

### Physical-artifact audit

An independent read-only Bun assertion pass over candidate v2 plus both shards
checked exact scenario set, unique six-row coverage, catalog/engine binding,
secure command tokens, exact invocation arguments, typed stages, action set,
worker edge, and carrier terminal.

Result: PASS — 6 recipes, 6 unique physical executions (3 + 3), only
`fs:list`, only `surface.native.op.exactaccess.1a12cmn`, and no observed content
authority.

### Static checks

```text
git diff --check HEAD -- packages/ibex-devtools/src/scripts/capsec-conformance-recipes.mjs packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs src/bin/ibex/engine/capsec_conformance_batch.rs
./ref-check
```

Result: PASS; `ref-check` reported 51 LLP documents, 2,535 references in 2,012
files, zero errors, one unchecked external reference.

## Findings and required dispositions

### BLOCKER B1 — the independent promotion consumer rejects all six receipts

At the reviewed pre-fix state,
`packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.mjs:1193-1199`
contained a separate closed `NATIVE_ASYNC_WORKER_TERMINALS` map with only five
operations and no `access`. Its production validator calls that map at line
8697. Because the lookup returns `null`, lines 9485-9491 reinterpret the real
`native-op:__exactAccess` worker as the route terminal, and lines 9534-9544
reject it because the statically bound route correctly names the public
`native-op:__exactFsPathAsync` carrier.

The Rust producer's new seven-entry map and its test therefore pass, and the
physical harness produces good observations, but the independent promotion
consumer cannot accept any of them. The six rows are marked
`fully-executable` before their evidence can survive the required consumer.
This blocks the class.

The independent JS test at
`capsec-public-surface-evidence.test.mjs:9884-10014` compounds the defect: its
hard-coded expected map omits `access` (and already omitted the Rust map's
`readlink` entry), so the test advertises exactness while allowing cross-table
drift. A disposition must reconcile the production consumer and its positive
and negative tests with the Rust closed map, then replay all six retained
receipts through `buildPublicFixtureEvidence`. The correction is not reviewed
by this artifact.

Disposition: **OPEN; blocks landing.**

### MATERIAL M1 — no retained per-batch evidence envelope is in the reviewed change

The reviewed scope contains the strict allow-list but no
`llp/evidence/0049-batch-native-op-fs-path-async-access-read-<digest>.json`.
The two physical files under `/Users/ccheever/phase1-runs/` are useful raw
receipts, but they are not the retained per-batch envelope required by LLP 0049
§6/§6.3 and do not by themselves create a repository-stable source-revision,
command, gate, physical-artifact, and review binding.

Disposition: **OPEN.** Retain the batch envelope after the corrected final diff
and fresh independent review are known; bind its digests and verdict to that
final target rather than to this rejected pre-fix target.

### MINOR M2 — stale worker-map comment

`src/bin/ibex/engine/capsec_conformance_batch.rs:2493-2498` still calls the
account an "exact reviewed five-operation worker map" although the reviewed
Rust constant has seven entries. This does not widen execution, but it is
source documentation drift in the security-sensitive validation path.

Disposition: **OPEN.** Correct against the actual final closed set.

## Verdict

**NOT READY.** The Rust producer and physical execution are narrow and locally
sound, but the independent production evidence consumer rejects every one of
the six new receipts. BLOCKER B1 must be corrected and reviewed in a fresh pass;
this pre-fix artifact must not be re-labeled READY after the fact. The retained
batch envelope and stale comment also remain open.
