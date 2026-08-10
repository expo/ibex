# Independent Adversarial Review: A2 On-Disk SQLite Open Tranche

**Review artifact for LLP 0049 §3 rule 11**

| Field | Value |
|---|---|
| Reviewed commit | `e920a678ee5d3ed07c2fcb32d5739108d678d25b` |
| Tree | `752c2f0c48e5d14580a441fcfdc564d0405494e8` |
| Parent | `6edef70e1a1fce0334fa489e40e1bee75e581dd7` |
| Diff SHA-256 | `6221f9aefeab151ba5be3939ba066bd945bc9b97728bac97cbd73a370b852ff4` |
| Reviewer | Claude Sonnet 4.6 (`opencode/claude-sonnet-4-6`) |
| Provider/runtime | OpenCode CLI, fresh review session |
| Date | 2026-08-09 |
| Worktree | `/Users/ccheever/phase1-runs/campaign-a2/sqlite-open-review-worktree` (detached HEAD) |
| Redacted | no (public-repository content only) |
| Verdict | READY |

**Reviewer-independence statement.** This reviewer is a different model
instance from the authoring agent. The reviewer did not author the code under
review, its tests, or its evidence artifacts. The review was performed at the
exact cited revision with read-only access to evidence outside the detached
review worktree; all adversarial mutations were reverted before the verdict.

Author note: the received review is retained verbatim below, apart from the
provider/runtime and redaction fields added above for repository provenance.

---

## 1. Methodology

1. Read LLP 0037 (D1–D4 authorization attribution rulings) and LLP 0049 (§3 construction rules, §6 Phase 2 executor campaign) to orient.
2. Read the complete diff at the reviewed commit.
3. Read the relevant Rust executor source (`capsec_conformance_batch.rs`, `hermes_runtime_sqlite.cc`, `hermes_runtime_fs.cc`) and JS template source (`capsec-conformance-recipes.mjs`, `capsec-conformance-recipes.test.mjs`).
4. Read-only cross-examination of `candidate-sqlite-open-v1.json`, `sqlite-open-primary-v2.json`, `sqlite-open-secondary-v2.json`, and `candidate-readlink-final.json` (baseline).
5. Ran both commanded baselines and recorded outputs.
6. Ran four independent break-tests, one mutation at a time, restoring between each, confirming each fails a credited test.
7. Verified diff SHA-256, catalog digest strict regeneration, allow-list digest, 12-row delta, decision sequences, and cleanup contract against the evidence.
8. Re-ran both baselines green and confirmed `git status` clean.

---

## 2. Baseline Outputs

### Baseline 1: bun test

**Command:**

```
bun test packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs \
  --test-name-pattern 'on-disk SQLite open branches'
```

**Output:**

```
bun test v1.3.14 (0d9b296a)

 1 pass
 108 filtered out
 0 fail
 8 expect() calls
Ran 1 test across 1 file. [10.04s]
```

Result: **GREEN**

### Baseline 2: cargo test

**Command:**

```
cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  native_sqlite_file_setup_ -- --test-threads=1 --nocapture
```

**Output:**

```
running 2 tests
test engine::hermes::tests::capsec_conformance_batch::native_sqlite_file_setup_binding_is_exact ... ok
test engine::hermes::tests::capsec_conformance_batch::native_sqlite_file_setup_is_real_and_bounded ...
thread '...' panicked at src/bin/ibex/engine/capsec_conformance_batch.rs:1217:5:
SQLite setup escaped its exact harness-owned paths
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 651 filtered out; finished in 0.01s
```

Result: **GREEN**. The `panicked` line is expected — the test uses
`std::panic::catch_unwind` to confirm that
`create_native_sqlite_file_fixture("target/ibex-capsec-sqlite-escaped.sqlite")`
panics (path not in the exact two-path allowlist), and
`assert!(escaped.is_err())` passes.

---

## 3. Break-Tests

### Break-test (a): Empty/non-SQLite fixture instead of real seeded database

**Mutation (`capsec_conformance_batch.rs`):** Replaced the
`rusqlite::Connection::open` + `execute_batch` seeding block with
`std::fs::write(path, b"")` (empty file, not a valid SQLite database).

**Command:** (same as Baseline 2)

**Observed failure:**

```
test engine::hermes::tests::capsec_conformance_batch::native_sqlite_file_setup_is_real_and_bounded ...
thread '...' panicked at src/bin/ibex/engine/capsec_conformance_batch.rs:549:10:
read seeded SQLite setup row: SqliteFailure(Error { code: Unknown, extended_code: 1 },
  Some("no such table: ibex_capsec_probe"))
FAILED

test result: FAILED. 1 passed; 1 failed; ...
```

**Analysis:** The test opens the fixture read-only with rusqlite and queries
`SELECT value FROM ibex_capsec_probe`. An empty file is not a valid SQLite
database and has no such table. The credit therefore cannot be earned by a
fixture that is not a genuine initialized SQLite database.

**Restoration:** Reverted to the original `rusqlite::Connection::open` +
`execute_batch` block.

**Baseline re-verified after restoration:** GREEN (both tests pass).

---

### Break-test (b): Widened exact two-path setup allowlist

**Mutation (`capsec_conformance_batch.rs`):** Replaced the two-path exact
`matches!` in `create_native_sqlite_file_fixture` with
`path.starts_with("target/") && path.ends_with(".sqlite")`, accepting any
`target/*.sqlite` path.

**Command:** (same as Baseline 2)

**Observed failure:**

```
test engine::hermes::tests::capsec_conformance_batch::native_sqlite_file_setup_is_real_and_bounded ...
thread '...' panicked at src/bin/ibex/engine/capsec_conformance_batch.rs:556:5:
SQLite setup accepted an unowned path
FAILED

test result: FAILED. 1 passed; 1 failed; ...
```

**Analysis:** The test calls
`create_native_sqlite_file_fixture("target/ibex-capsec-sqlite-escaped.sqlite")`
inside `catch_unwind`. With the original exact two-path allowlist, this panics
and `escaped.is_err()` is true. With the widened predicate, the escaped path is
accepted without panic, `catch_unwind` returns `Ok`, and
`assert!(escaped.is_err())` fails. The exact two-path constraint is therefore
load-bearing.

**Restoration:** Reverted to the original two-path `matches!` expression.

**Baseline re-verified after restoration:** GREEN.

---

### Break-test (c): Weakened `__exactSqliteOpen` / exact-argument setup binding

**Mutation (`capsec_conformance_batch.rs`):** Changed
`native_sqlite_file_setup_is_bound` to only check
`invocation.global_name == "__exactSqliteOpen"` without checking that
`invocation.arguments.first()` is the exact `path` string.

**Command:** (same as Baseline 2)

**Observed failure:**

```
test engine::hermes::tests::capsec_conformance_batch::native_sqlite_file_setup_binding_is_exact ...
thread '...' panicked at src/bin/ibex/engine/capsec_conformance_batch.rs:591:5:
assertion failed: !native_sqlite_file_setup_is_bound(
  &invocation("__exactSqliteOpen", serde_json::json!("target/another.sqlite")), path)
FAILED

test result: FAILED. 1 passed; 1 failed; ...
```

**Analysis:** The binding predicate test explicitly asserts that
`native_sqlite_file_setup_is_bound` returns `false` when the first argument is
a different path (`"target/another.sqlite"` versus the expected
`"target/ibex-capsec-sqlite-open-read.sqlite"`). Removing the path check allows
a mismatched invocation to pass the binding check. The path-argument binding is
therefore load-bearing and prevents setup credit from leaking to a different
invocation's path.

**Restoration:** Reverted to the full two-predicate implementation.

**Baseline re-verified after restoration:** GREEN.

---

### Break-test (d): Changed JS cleanup contract

**Mutation (`capsec-conformance-recipes.mjs`):** Changed
`expectedCleanup: "closed-sqlite-db-removed-owned-file"` to
`expectedCleanup: "closed-sqlite-db"` in `nativeProjectSqliteOpenTemplate`.

**Command:**

```
bun test packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs \
  --test-name-pattern 'on-disk SQLite open branches'
```

**Observed failure:**

```
packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs:
8261 |           recipe.publicSurfaceProbe.invocation.expectedCleanup ===
8262 |             "closed-sqlite-db-removed-owned-file",
...
error: expect(received).toBe(expected)
Expected: true
Received: false

(fail) exact-target CapSec executable recipes > authors exact on-disk SQLite open branches with owned setup

 0 pass / 1 fail
```

**Analysis:** The JS test hard-asserts that `expectedCleanup` is exactly
`"closed-sqlite-db-removed-owned-file"`. Weakening it to
`"closed-sqlite-db"` (the raw marker the JS harness stamps before the Rust
harness removes the file and upgrades the marker) breaks the JS test. The
combined cleanup contract — `__exactSqliteClose` closes the DB
(`closed-sqlite-db`), then Rust removes the fixture and upgrades to
`closed-sqlite-db-removed-owned-file` — is therefore fully validated
end-to-end.

**Restoration:** Reverted to `"closed-sqlite-db-removed-owned-file"`.

**Baseline re-verified after restoration:** GREEN.

---

## 4. Artifact Cross-Examination

### 4.1 Diff SHA-256

The SHA-256 of
`git diff 6edef70e1a1fce0334fa489e40e1bee75e581dd7 e920a678ee5d3ed07c2fcb32d5739108d678d25b`
is:

```
6221f9aefeab151ba5be3939ba066bd945bc9b97728bac97cbd73a370b852ff4
```

This matches the stated reviewed diff SHA-256. **VERIFIED.**

### 4.2 Catalog digest strict regeneration

Command:

```
bun packages/ibex-devtools/src/scripts/generate-capsec-conformance-recipes.mjs \
  --target aarch64-apple-darwin \
  --declared-allow-list llp/evidence/0049-allow-list-class-native-op-sqlite-open-file.json \
  --output <tmp>
```

Output digest:
`sha256-PtfRaTT3gcL8sQG33ZJJKurCwxPs1wsh17L7ZvXbypk`

Expected (from `candidate-sqlite-open-v1.json`):
`sha256-PtfRaTT3gcL8sQG33ZJJKurCwxPs1wsh17L7ZvXbypk`

**EXACT MATCH.** Strict regeneration at the reviewed commit with the committed
allow-list reproduces the candidate digest. Content verification (recipe-level
comparison of all 21,784 rows) confirms no content differences between
regenerated and candidate.

### 4.3 Allow-list digest

SHA-256 of
`llp/evidence/0049-allow-list-class-native-op-sqlite-open-file.json` (raw file,
URL-safe base64):

```
sha256-WIiMoo18xGbpR7eb913aDoUV6yczwpfCJuiZHgPzNcM
```

Matches the `declaredAllowListDigest` field in
`candidate-sqlite-open-v1.json`. **VERIFIED.** The allow-list was authored
before the candidate was generated (§3 rule 3 advance-declaration
requirement).

### 4.4 Exact 12-row delta

Baseline (`candidate-readlink-final.json`, digest
`sha256-kwENCdZonb5Cz8-TGxpMvVrpde0HFCNL__LcA9itnRI`):

- `__exactSqliteOpen` file-read/file-read-write rows: 12, all
  `status: unresolved`

Candidate (`candidate-sqlite-open-v1.json`, digest
`sha256-PtfRaTT3gcL8sQG33ZJJKurCwxPs1wsh17L7ZvXbypk`):

- `__exactSqliteOpen` file-read/file-read-write rows: 12, all
  `status: fully-executable`
- Fully-executable count baseline: 3,940; candidate: 3,952; delta: +12.
  **EXACT.**

Non-target rows: zero status changes outside the 12 target rows. **VERIFIED.**

Routes, terminals (`terminalObservedKey`), action sets (`actionIds`), and
classifications are identical between baseline and candidate for all 12 rows.
**VERIFIED** (byte-level comparison of these fields).

### 4.5 Evidence envelopes bind candidate and engine

Both `sqlite-open-primary-v2.json` and `sqlite-open-secondary-v2.json` contain:

- `publicBatchEvidenceSchema: "ibex/capsec-public-batch-evidence/1"`
- `recipeCatalogDigest: "sha256-PtfRaTT3gcL8sQG33ZJJKurCwxPs1wsh17L7ZvXbypk"`
  (matches candidate)
- `loadedEngineIdentity.binaryDigest: "sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y"`
- `loadedEngineIdentity.targetArchitecture: "aarch64"`
- `loadedEngineIdentity.structuralFeatures: ["hermes-frame-attribution",
  "native-compartments", "native-lockdown"]`

**VERIFIED.**

### 4.6 All 12 target executions exist exactly once and pass

| fixtureId suffix | evidence file | outcome |
|---|---|---|
| `file-read.allow` | primary-v2 | passed |
| `file-read.branch-selection` | primary-v2 | passed |
| `file-read.malformed` | primary-v2 | passed |
| `file-read-write.malformed` | primary-v2 | passed |
| `file-read-write.allow` | secondary-v2 | passed |
| `file-read-write.branch-selection` | secondary-v2 | passed |
| `file-read-write.deny` | secondary-v2 | passed |
| `file-read-write.missing-attribution` | secondary-v2 | passed |
| `file-read-write.wrong-principal` | secondary-v2 | passed |
| `file-read.deny` | secondary-v2 | passed |
| `file-read.missing-attribution` | secondary-v2 | passed |
| `file-read.wrong-principal` | secondary-v2 | passed |

Primary/secondary overlap: **none**. Total: **12 / 12**. All passed.
**VERIFIED.**

### 4.7 Observed stage/action/outcome/authority sequences match source

**file-read allow scenario (7 decisions from primary-v2):**

| # | stage | cap | outcome | stratum | sourceId |
|---|---|---|---|---|---|
| 0 | requested | fs:list | allow | static-floor | principal.000000.floor.000000 |
| 1 | discovery | fs:list | allow | ambient-root | null |
| 2 | requested | fs:list | allow | ambient-root | null |
| 3 | repeat | fs:list | allow | ambient-root | null |
| 4 | requested | fs:list | allow | static-floor | principal.000000.floor.000000 |
| 5 | repeat | fs:list | allow | static-floor | principal.000000.floor.000000 |
| 6 | commit | fs:read | allow | static-floor | principal.000000.floor.000001 |

**file-read-write allow scenario (7 decisions from secondary-v2):**

Same 6 traversal stages, then commit with `[fs:read, fs:write]` both at
static-floor (sourceIds `.000001`, `.000002`). **Verified.**

**file-read deny scenario (1 decision from secondary-v2):**

| # | stage | cap | outcome | stratum | sourceId |
|---|---|---|---|---|---|
| 0 | requested | fs:list | deny | principal-denial | principal.000000.denial.000000 |

result: `throw`, errorMessage:
`"EACCES: filesystem policy denied, open '/project/target/ibex-capsec-sqlite-open-read.sqlite'"`

**file-read-write deny (1 decision from secondary-v2):** identical pattern on
`ibex-capsec-sqlite-open-read-write.sqlite`.

These sequences match the pinned `expectedTypedStages` in the recipes:

- non-deny: `["requested", "discovery", "requested", "repeat",
  "requested", "repeat", "commit"]`
- deny: `["requested"]`

**VERIFIED.** The sequences match source
(`NATIVE_EXISTING_PROJECT_CHILD_STAGES` + `"commit"` from
`nativeEffectStages`).

### 4.8 All fs:list decisions are open traversal, not directory enumeration

All 6 pre-commit decisions in the allow scenario have
`operationId: "sqlite-open:0:{\"root\":\"project\",\"components\":[{\"encoding\":\"utf8\",\"value\":\"target\"},{...}]}"`.
All carry `cap: fs:list` at `requested`, `discovery`, or `repeat` stages — the
three traversal stages of an armed path open. None is a `commit`-stage
`fs:list` (which would indicate a directory listing). The deny scenario's
single decision also has the same `sqlite-open:0:{...}` operationId, confirming
it is an open-traversal refusal, not a directory enumeration denial.

**VERIFIED.** All `fs:list` decisions are traversal for the open. LLP 0037 D2
per-family authoring gate: satisfied.

### 4.9 Cleanup/result proves the checked-fd SQLite body actually returned

The JS harness (line ~1811 of `capsec_conformance_batch.rs`) closes the returned
handle via `__exactSqliteClose(value)` and records
`cleanup: "closed-sqlite-db"`. The Rust harness then:

1. Removes the on-disk fixture via `std::fs::remove_file`.
2. Asserts `invocation_result["cleanup"] == "closed-sqlite-db"` (line 3337).
3. Upgrades to `"closed-sqlite-db-removed-owned-file"` (line 3339).

The evidence shows `cleanup: "closed-sqlite-db-removed-owned-file"` in all
non-deny return results, confirming the body entered, opened the SQLite
database, returned a valid handle, and the harness closed it. Break-test (d)
confirms this is not a formality.

**VERIFIED.**

### 4.10 Embedded command spells the exact secure feature vector

Both evidence files record the invocation command as:

```
["cargo", "test", "--bin", "ibex", "--no-default-features",
 "--features", "standard,capsec-conformance-observer,openssl-crypto",
 "capsec_public_native_primary_batch", "--", "--test-threads=1"]
```

(Secondary uses `capsec_public_native_secondary_batch`.)

`--no-default-features` plus
`standard,capsec-conformance-observer,openssl-crypto` is the exact secure
feature vector required by LLP 0049 §3 rule 9. **VERIFIED.**

---

## 5. Security Questions

### Q1: Does raw rusqlite setup permit false credit?

No. The `create_native_sqlite_file_fixture` function creates a genuine on-disk
SQLite database and seeds it with a table `ibex_capsec_probe` containing the row
`"file-backed"`. The Rust test `native_sqlite_file_setup_is_real_and_bounded`
reopens this file read-only with rusqlite and queries the seeded row, asserting
`value == "file-backed"`. Break-test (a) proves an empty file (or any non-SQLite
fixture) fails this assertion. The `__exactSqliteOpen` body in the armed
execution opens this real database through `exactOpenArmedSqliteFile` →
`openArmedPathTarget` → `ex_host_authorize_typed_fs_open`, producing the
observed seven typed decisions.

### Q2: Does path cleanup permit false credit or enforcement bypass?

No. The cleanup is two-staged: the JS harness closes the handle and records
`closed-sqlite-db`; the Rust harness then removes the fixture file and asserts
the JS marker before upgrading it. The `assert_eq` ensures the upgrade cannot
happen unless the body actually completed and closed the handle. If the fixture
file does not exist at cleanup, `expect("remove on-disk SQLite setup fixture")`
would panic and fail the test. The two exact paths
(`target/ibex-capsec-sqlite-open-read.sqlite`,
`target/ibex-capsec-sqlite-open-read-write.sqlite`) are bounded by the
`matches!` guard in `create_native_sqlite_file_fixture`, break-tested by (b).

### Q3: Does denial ordering admit an enforcement-model contradiction?

No. The deny scenario produces exactly one `requested`-stage `fs:list`
decision at `stratum: principal-denial`. This is consistent with the floor
arming an explicit denial entry (`principal.000000.denial.000000`) that fires
at the first traversal request. This is the correct behavior for the deny
scenario in the native-op executor: the principal's floor carries a denial that
stops the first path request. The deny does **not** allow traversal decisions
first (unlike the LLP 0037 D4 mixed allow-traversal / deny-operation shape for
`readFileSync`); here `fs:list` is the traversal capability being denied, not a
separate operation capability — the floor denies at the traversal layer
itself. The `expectedActionIds: ["fs:list"]` for deny (versus
`["fs:list", "fs:read"]` for allow) correctly reflects this: only `fs:list` is
observed, not `fs:read`.

This is consistent with how other `existingProjectChildStages` native-op deny
scenarios behave in the batch (for example `__exactReadlink`,
`__exactReadFile`, and `__exactFsOpen`).

### Q4: Does source/catalog binding permit credit leakage across surfaces?

No. The `native_sqlite_file_setup_is_bound` function enforces two conditions
simultaneously: (1) `global_name == "__exactSqliteOpen"`, preventing any other
native global from triggering SQLite file setup; and (2) the first argument
must be the exact `path` string, preventing cross-branch reuse (the two branches
use distinct paths `ibex-capsec-sqlite-open-read.sqlite` versus
`ibex-capsec-sqlite-open-read-write.sqlite`). The
`allowed_coverage_edge_ids` field in each recipe is
`["surface.native.op.exactsqliteopen.0a20llh"]`, binding credit to this specific
edge. Break-test (c) confirms the path check is load-bearing.

---

## 6. Findings

### BLOCKERS

None.

### MATERIAL

None.

### MINOR

**MINOR-1 (documentation gap):** The `NativeProbeSetup::SqliteFile` variant
does not carry a `serde(deny_unknown_fields)` annotation. Since the enum uses
`#[serde(tag = "kind", rename_all = "kebab-case")]` and the variant has a
single `path: String` field, any unknown JSON fields would be silently ignored.
This is consistent with other variants in the enum (none have
`deny_unknown_fields` individually) and is test harness code only, not
production security enforcement. No functional impact identified.

**MINOR-2 (observed stage split across shards):** The 12 executions are split
4/8 between primary and secondary shards. No shard contains all 12; verifying
coverage requires examining both files. This is operational rather than a
defect, but an evidence envelope summary that states the complete 12/12 pass
count from a merged view would simplify future re-verification.

---

## 7. Final Cleanliness

After all break-tests and restorations:

```
Not currently on any branch.
nothing to commit, working tree clean
```

Both baselines re-run and confirmed GREEN.

---

## 8. Verdict

**READY**

All 12 claimed `__exactSqliteOpen` logical file-read and file-read-write cells
move from `unresolved` to `fully-executable` under:

- A genuine on-disk SQLite database seeded with rusqlite and confirmed readable
- A two-path exact allowlist preventing fixture escape
- An exact-argument binding tying setup to the specific observed invocation
- A two-stage cleanup contract proving the body entered and closed the returned handle
- Seven typed decisions (non-deny) / one typed decision (deny), all matching the pinned sequence
- All six pre-commit decisions confirmed as open-path traversal, not directory enumeration
- Strict catalog regeneration reproducing the candidate digest
- Allow-list authored before candidate generation
- Secure feature vector `--no-default-features --features standard,capsec-conformance-observer,openssl-crypto` throughout
- Zero unexplained route, terminal, action, or classification changes

No BLOCKER or MATERIAL findings. The enforcement model is internally
consistent with LLP 0037 D1–D4 and LLP 0049 §3 rules 1–12.
