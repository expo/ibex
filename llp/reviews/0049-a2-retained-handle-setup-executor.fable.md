# Independent Adversarial Review: A2 Retained-Handle Setup Authority (Executor)

**Review artifact for LLP 0049 §3 rule 11**

| Field | Value |
|---|---|
| Reviewed commit | `157a23f6fb4e6d9948725cc9327db93bfc843174` |
| Tree | `2cb76e350831d130479aff9e33fe34abfafbe099` |
| Parent | `cc80b6e863b0b373894469d381c4e1933be46743` |
| Base | `0ed858db53f5a733eb86e93c3ab27bd35f899804` |
| Full diff SHA-256 (`0ed858db5..157a23f6f`) | `5d705bb8aca891ca0a419152a09564d8b7b28b38e6c29e32d2143f5f3095faee` |
| Author-declared implementation diff SHA-256 (`0ed858db5..cc80b6e86`) | `8a1a603085a8d3257edf26b71775c05982bd8b4a104ddf2c3d84328751554bd6` — **reproduced** |
| Reviewer | Claude Opus 5 (`claude-opus-5`), Claude Code |
| Provider/runtime | Fresh review session, no authoring context |
| Date | 2026-08-10 |
| Review worktree | `/Users/ccheever/phase1-runs/retained-handle/fable-review-wt` (detached HEAD, Mac Air fleet runner `100.70.173.122`) |
| Feature vector | `--no-default-features --features standard,capsec-conformance-observer,openssl-crypto` |
| Bound engine | `sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y` |
| Redacted | no (public-repository content only) |
| **Verdict** | **NOT READY** |

**Reviewer-independence statement.** This reviewer is a different model family
from the authoring agent. The reviewer did not author the code under review,
its tests, its recipe templates, or its evidence artifacts, and had no part in
the authoring session. All work was performed at the exact cited revision in a
detached review worktree created by the reviewer. Every adversarial mutation
was applied one at a time and reverted before the next; `git status` was
verified empty after each. Physical evidence outside the worktree was read
only, never written.

---

## 1. Methodology

1. Read the author's memo (`~/phase1-runs/retained-handle-memo.md` on the Air)
   and treated every claim in it as a hypothesis to be falsified, not as input.
2. Read the complete diff at the reviewed revision: the executor
   (`capsec_conformance_batch.rs`), the observer-only C ABI seam
   (`hermes_runtime.cc`, `hermes_runtime_internal.h`, `hermes_structured.rs`),
   the Host projection (`host/mod.rs`, `host/abi.rs`), the recipe templates
   (`capsec-conformance-recipes.mjs` + tests), the ingress obligations, and the
   LLP 0049 / evidence / allow-list artifacts.
3. Traced the enforcement path that the property actually rests on, end to end:
   `requireFdList` → `requireOwnedFd` → `ex_host_authorize_typed_fs_open` →
   `exactCollectTypedPrincipalStack` → `ex_host_authorize_typed_fs_stack` →
   `authorize_typed_fs_open_stage`.
4. Reproduced the artifacts independently rather than accepting them: raw
   SHA-256 of both evidence files, the implementation diff digest, and a
   from-source regeneration of the candidate recipe catalog.
5. Executed the proof class myself from a reviewer-built focus catalog and read
   the raw decision evidence, rather than reading the author's envelopes.
6. Ran eight adversarial mutations, one at a time, restoring between each.
7. Baseline-compared the known-red devtools suite against the base commit.
8. Re-ran everything green and confirmed a clean tree.

---

## 2. Independent reproduction of the author's artifacts

| Claim | Result |
|---|---|
| Batch evidence raw SHA-256 `64a79dba…683854` | **reproduced** |
| Allow-list raw SHA-256 `79244b21…9d75` | **reproduced** |
| Implementation diff SHA-256 `8a1a6030…4bd6` (base → `cc80b6e86`) | **reproduced** |
| Candidate catalog digest `sha256-9YEpHm_6-e24FK2Q9Q_VSr7wy6hkKyN_qRmf8cHXnwI` | **reproduced from source** by re-running the generator with `--declared-allow-list llp/evidence/0049-allow-list-class-native-op-fstat-retained.json` |
| Catalog delta `3,999 → 4,000` fully executable, `14,661 → 14,660` unresolved | **reproduced** (4,000 / 14,660 at tip) |
| `./ref-check` | **reproduced**: 51 docs, 2,548 refs, 0 errors, 1 unchecked |
| `bun run check:drift` | **reproduced**: exit 0, "Generated artifacts are up to date" |
| `cargo test --lib` | 737 passed / 0 failed / 4 ignored under the exact secure vector (memo says 723; see MINOR-6) |
| Devtools recipe suite red baseline | **reproduced and baseline-compared**: the same four failures at `0ed858db5` and at `157a23f6f`, byte-identical names; no regression |

The observed typed sequence was verified against the raw decision, not the
memo. Reviewer-executed evidence for the deny row:

```
operationId            fs-open:0:{"root":"project","components":[{"encoding":"utf8","value":"cargo.toml"}]}
atomicityGroup         surface.native.op.exactfsopen.05ao6wa.decision
combination            conjunction
stage                  repeat
actor                  root/project-root
effectOwner            root/project-root
constrainedPrincipals  [root/project-root, package/image-lib@2.4.1]
effects                [fs:list], finalObjectGeneration "retained-descriptor-v1", retainedHandle "fd:13"
outcome                deny
evidence               exactly 1 row: principal image-lib@2.4.1, stratum principal-denial,
                       sourceId principal.000001.denial.000000
result                 Error: EACCES: filesystem policy denied, fstat '/project/Cargo.toml'
```

and for the three allow-like rows, exactly two rows per effect:
`principal.000000.floor.000000` (root) and `principal.000001.floor.000000`
(`image-lib@2.4.1`), both `static-floor`. Every claim in the memo's "Proof
class" section is confirmed against the runtime, including the
`retained-descriptor-v1` generation and the `fd:*` retained handle — these are
produced by the real `Stage::Repeat` branch in
`ex_host_authorize_typed_fs_stack`, not by the harness.

---

## 3. The authority-separation property

This is the property the review exists for, so it is stated precisely and then
attacked.

**Mechanism, as built.** `install_native_public_test_host` detects a
retained-handle recipe (`native_uses_retained_handle_authority`) and then:
principal 0 (project root) receives the setup floor and is explicitly stripped
of denials; principal 1 (`image-lib@2.4.1`) receives the probe floor, an empty
escalation ceiling, and — on a deny row — the denial. Setup and cleanup use
`eval_immediate`, which is the ordinary authenticated path and puts only the
root actor on the stack. Only the probe uses `eval_probe_immediate`, which
routes through `evaluate_authenticated_with_constrained_principals` →
`ibex_private_test_eval_lowered_session_with_principals` → a one-shot
`ScopedTypedPrincipalStack`. `exactCollectTypedPrincipalStack` **unions** that
scoped set with the live frame-attribution principals, and
`ex_host_authorize_typed_fs_stack` canonicalizes the whole set and evaluates a
**conjunction** (verified in the emitted decision:
`"combination": "conjunction"`). Adding principal 1 can therefore only
*narrow*; it can never widen.

**The three leak paths the brief names, checked:**

- *Shared principal.* `conformance_observer_principal_id` delegates to
  `Host::module_runner_principal_id`, which bails unless the principal is
  already an exact member of `typed_imports` (the immutable armed snapshot). It
  assigns a runtime-local numeric projection; it cannot mint a principal or a
  grant. `assert_ne!(package_id, 0)` forbids aliasing the root owner, and
  `evaluate_authenticated_with_constrained_principals` rejects any non-strictly-
  increasing or empty set before admission (covered by the author's new unit
  test, which I ran).
- *Inherited floor.* The retained branch replaces, not merges,
  `principals[1]["floor"]`. The setup floor is additionally pinned to be
  *identical* to the probe floor by `assert_eq!(required_setup_floor,
  required_floor)`, so setup can never be granted anything the probe is not
  also constrained by. Break-test F confirms this guard fires.
- *Retained handle carrying its own capability.* It does not. `requireOwnedFd`
  authenticates the runtime nonce and `entry.owner` (still principal 0, so
  ownership passes), and then `requireFdList` performs a **fresh** repeat-stage
  typed authorization over the full collected principal set. The handle
  authorizes identity, not authority. Break-test A demonstrates this directly.
- *Ordering / one-shot lifetime.* The constrained set is consumed by
  `ex_hermes_eval_lowered_session` immediately after the drive guard (which has
  already cleared the thread-local stack to `nullptr`, so `previous_` is null
  and there is nothing to restore into), and the private wrapper clears it
  again on the refused-drive path. Verified empirically in break-test G.

**Verdict on the property: it holds.** Break-tests A, B, E, G and H each
attack it from a different direction and each behaves correctly. I could not
construct a path by which setup authority satisfies the probe decision.

Break-test A is the decisive one and deserves to be quoted: with the probe
downgraded to root-only — i.e. exactly the "setup authority carries the probe"
failure — the **deny row returns instead of throwing**. That proves the
retained handle plus principal 0's floor genuinely *would* allow the operation,
that the refusal is attributable solely to principal 1's presence at probe
time, and that the harness catches the leak. That is the correct shape of
proof, and it is the strongest single result in this review.

Break-test B is the mirror: forcing setup to run under `[0, 1]` makes
`__exactFsOpen` fail closed with `EACCES: filesystem policy denied, open
'/project/Cargo.toml'`. The setup principal is genuinely narrower than the
probe stack; the split is not cosmetic.

---

## 4. Findings

### BLOCKER-1 — The SQLite "real file-backed handle" proof is not a proof

`retained_sqlite_setup_creates_a_real_file_backed_native_handle`
(`src/bin/ibex/engine/capsec_conformance_batch.rs:573`) is the *only* evidence
offered for the file-backed SQLite constructor. It does not test file-backing.

Two mutations, each applied alone and reverted:

- **D** — substitute `":memory:"` for the on-disk path in the argument passed
  to the loaded `__exactSqliteOpen`, leaving everything else intact: **the test
  still passes.**
- **D2** — additionally delete the `create_native_sqlite_file_fixture(path)`
  call so that *no file exists on disk at any point*: **the test still
  passes**, and `issues/.ibex-capsec-sqlite-retained-test.sqlite` is confirmed
  absent afterwards.

The reason is structural. The test's only file-related assertion is
`assert_eq!(setup.sqlite_file_path.as_deref(), Some(path))`, and
`state.sqlite_file_path` is set from the *declared* `path` field, never from
anything the runtime reports about the opened database. `native_sqlite_file_path_is_owned(path)`
likewise checks the declared string. Nothing in the setup path or the test
correlates the returned registry handle with a file.

This matters for three compounding reasons:

1. The memo states as fact: *"It does not substitute `:memory:`."* As written
   that is a property of the constructor's **declared arguments**, not of what
   is proven; a reader will take it as the latter.
2. The batch evidence envelope
   (`llp/evidence/0049-batch-native-op-fstat-retained-9YEp…json`,
   `independentAdversarialReview.requiredBreakTests[3]`) names this exact
   attack — *"Replace the SQLite file setup with a memory database and prove
   the file-backed setup test fails"* — as a required break-test. **It does not
   fail.** An attestation artifact that lists a break-test which does not break
   is worse than one that omits it.
3. Memory-backed SQLite substitutes were explicitly refused by the prior A2
   campaign. This is that substitute, re-admitted by omission.

No campaign row is miscertified today — no SQLite row is claimed closed — so
this is not a false green on a certified cell. It is a false *proof*, and under
§3 rule 11 the artifact cannot be accepted while it asserts one.

**Minimal flip:** either (a) make the test observe file-backing from the
runtime — e.g. assert that opening a deliberately absent owned path fails, and
assert the seeded row is readable through `__exactSqliteGet`/`__exactSqliteAll`
on the returned handle, or read the database file list back through the loaded
globals — or (b) withdraw the "real file-backed" claim from the memo, the
evidence envelope, and LLP 0049 §6, and mark the SQLite mechanism unproven.
(a) is preferred and is a small change.

### MATERIAL-2 — The entire SQLite half of the change is unreachable code

`sqliteFileHandleSetup`
(`packages/ibex-devtools/src/scripts/capsec-conformance-recipes.mjs:787`) has
**no caller**. Consequently:

- `sqlite-file-database` and `sqlite-file-statement` never appear in the
  generated catalog. I confirmed this against a from-source regeneration: the
  only occurrences of those strings in the repository are the constructor
  itself and the `bindNativeSetupSources` allow-list at line 4557.
- `NativeProbeSetup::SqliteFileStatement` is never constructed by any recipe.
- The `retained_sqlite_operation` cleanup block
  (`capsec_conformance_batch.rs:4636`) and the new
  `"finalized-sqlite-statement-closed-db"` expected-cleanup mapping are never
  exercised.
- Eight of the eleven entries in `native_sqlite_file_path_is_owned`
  (`target/ibex-capsec-sqlite-retained-*.sqlite`) are unreferenced.

The memo and LLP 0049 §6 both state that the change "structurally unblocks …
48 retained-SQLite rows". I verified the 48 figure itself — the candidate
catalog contains exactly 48 non-fully-executable `exactsqlite*` rows, all
carrying `native-public-arguments-not-authored` — so the *count* is honest.
What is not demonstrated is that this executor unblocks them, because no code
path from a recipe to `SqliteFileDatabase` exists and the one constructor test
that does run proves less than claimed (BLOCKER-1).

There is also a concrete, foreseeable obstacle the author did not hit: the
eight anticipatory fixture paths all live under `target/`, and the author's own
environment note records that `target/` resolves *outside* the VFS mount in the
standard worktree layout — which is precisely why the constructor test had to
place its fixture in `issues/` instead. I reproduced that layout (worktree
`target` symlinked to the shared build directory) and it is the normal case,
not an accident. Whichever of those 48 rows is authored first will hit
`ERR_IBEX_OUTSIDE_MOUNT` before it hits anything interesting.

**Minimal flip:** either author one file-backed SQLite recipe end to end
(one row, through `execute_native_public_recipe` and
`validate_native_runtime_observation`, with real evidence), or restate the
claim as "36 retained-FD rows structurally unblocked and demonstrated; the
SQLite constructor is landed but unexercised, and 48 SQLite rows remain
blocked pending a first authored row." Also move the anticipatory fixture
paths out of `target/`.

### MATERIAL-3 — The 36-row FD figure is not derivable from the catalog

I could reproduce the 48 exactly. I could not reproduce 36. Counting
non-fully-executable rows in the regenerated candidate catalog: 96 across all
`exactfs*`/`exactsqlite*` native surfaces, of which 48 are SQLite, leaving 48
filesystem rows — of which only 18 fall on the retained-descriptor globals
named by `auxiliary_allowed_terminal`, and only 12 of those carry
`native-public-deny-scenario-not-authored`. 36 may well be correct under the
author's A2 cell definition, but nothing in the repository lets a reviewer
derive it, and §3 rule 1 discipline applies to executor-capability counts as
much as to measurements.

**Minimal flip:** record the derivation (the query or the enumerated edge ids)
alongside the 36 in the evidence envelope, or drop to the number that is
derivable.

### MATERIAL-4 — The deny row's decisive principal is installed by a test hook, not by attribution

In production nothing puts `image-lib@2.4.1` on the evaluation stack for a
root-submitted `ibex:eval`. The package principal is placed there by
`ibex_private_test_eval_lowered_session_with_principals`, an observer-only
entrypoint. The row therefore certifies two real things — that the evaluator
conjoins over the constrained principal set, and that the retained-handle
repeat-stage decision consults it rather than the handle's recorded owner — but
it does not certify the frame-attribution path that would put a package
principal on the stack in a real call. That path is exercised elsewhere; it is
not exercised here.

This is disclosed in the memo and in the envelope's `authoritySeparation.probe`
field, and I judge the substitution legitimate — denying principal 0 makes
setup impossible, which is the whole structural gap. But the LLP 0049 §6 text
added by this change does not say it, and the row is counted in the same
`3,999 → 4,000` counter as rows whose denial lands on the acting principal. A
later reader will take the retained deny rows as like-for-like with the other
70 closed A2 rows. They are not.

**Minimal flip:** one sentence in the new LLP 0049 §6 paragraph stating that
the constrained-principal set is installed by an observer-only hook standing in
for frame attribution, and that retained deny rows certify evaluator
conjunction rather than the attribution path.

### MINOR-5 — Test fixture written into a tracked source directory

`issues/.ibex-capsec-sqlite-retained-test.sqlite` is not matched by
`.gitignore` (`git check-ignore` exits 1). `NativePublicFixtureCleanup::drop`
removes it on the panic path, so it is unlikely to be left behind, but the
harness's own invariant — *"SQLite setup escaped its exact harness-owned
paths"* — previously meant "under `target/`". Prefer a gitignored location, or
add the path to `.gitignore`.

### MINOR-6 — One pre-existing assertion was loosened

`execute_native_public_recipe` previously did
`std::fs::remove_file(path).expect("remove on-disk SQLite setup fixture")`; it
now iterates the four owned paths and tolerates `NotFound` on every one,
including the main database file. Extending cleanup to the journal/WAL/SHM
sidecars is a clear improvement, but tolerating a missing *primary* file is a
loosening of an existing check that previously would have caught an on-disk
SQLite probe whose file never existed. Suggest keeping `NotFound` tolerance for
the three sidecars and requiring the main file.

Apart from this, I found **no other weakened assertion or selector**. The
recipe-test change from `expect(rows).toHaveLength(4)` to an exact five-element
scenario-set comparison is a strengthening; `cleanup.files.push` →
`extend(native_sqlite_owned_paths(...))` is a strengthening; the
`uses_project_path` change to `floor.iter().chain(deniable_floor.iter())`
exactly preserves the previous behaviour now that `floor` no longer includes
the deniable floor in retained mode; and adding `__exactFsFstatSync` to
`native_filesystem_denial_message_is_reviewed` is required and correct — the
`EACCES: filesystem policy denied` text is the genuine
`throwTypedFsAuthorizationError` message, confirmed in the executed evidence.

### MINOR-7 — Bookkeeping

- `Host::conformance_observer_principal_id` is `pub` while the function it
  delegates to is `pub(crate)`. It is `#[cfg(feature = "capsec-conformance-observer")]`
  and therefore absent from every shipped vector, so this is not a real
  exposure, but `pub(crate)` would match the delegate and the surrounding
  convention.
- The LLP 0049 ledger row *"per-class paired allow-lists (rule 3, strict
  mode)"* still lists only the `env-read` and `fs-list` allow-lists;
  `llp/evidence/0049-allow-list-class-native-op-fstat-retained.json` was not
  added to it, although the per-batch-envelope row above it was updated.
- The memo reports `cargo test --lib`: 723 passed. Under the exact secure
  feature vector at the reviewed tip I measure **737 passed / 0 failed / 4
  ignored**. Presumably a different feature vector; state which one.

---

## 5. Break-test table

Each mutation was applied alone to the pristine reviewed tree and reverted
before the next (`git status --porcelain` empty between every row).

| # | Mutation | Target property | Expected | Observed | Verdict |
|---|---|---|---|---|---|
| A | `eval_probe_immediate` downgraded to the unconstrained scope — the probe runs under setup authority alone | authority separation | deny row must stop denying; allow rows must lose a floor row | **deny row returned instead of throwing** (`capsec_conformance_batch.rs:3819`, `left: "return", right: "throw"`); allow / malformed / wrong-principal failed at `:4071` with `retained-handle allow must prove both owner and probe authority for every effect: left 1, right 2`, evidence showing only `principal.000000.floor.000000` | **PASS** |
| B | `eval_immediate` upgraded to the constrained scope — setup runs under `[0, 1]` | setup authority is genuinely narrower | setup must be refused | `native public setup __exactFsOpen failed: EACCES: filesystem policy denied, open '/project/Cargo.toml'` at `:2254`, on both shards | **PASS** |
| C | Real `__exactFsOpen` descriptor replaced by a raw host fd from `std::fs::File::open("Cargo.toml").into_raw_fd()` | proof class requires a genuine Hermes `FdEntry` | probe must be refused on ownership, not authority | probe result `{"kind":"throw","errorMessage":"fstat: bad file descriptor"}` — `requireOwnedFd` refused before any typed authorization; batch failed at `:4611` | **PASS** |
| D | `":memory:"` substituted for the on-disk path in the SQLite constructor | SQLite handle is file-backed | `retained_sqlite_setup_creates_a_real_file_backed_native_handle` must fail | **test passed** | **FAIL — see BLOCKER-1** |
| D2 | As D, plus removal of `create_native_sqlite_file_fixture` so no file exists at all | SQLite handle is file-backed | test must fail | **test passed**; fixture path confirmed absent afterwards | **FAIL — see BLOCKER-1** |
| E | Retained-allow validation weakened from `== effects.len() * 2` to `>= effects.len()`, **combined with** mutation A | the exact-count assertion is load-bearing | the leaked run must now pass green, proving the assertion is what carries the property | **passed green**; captured evidence shows `constrainedPrincipals: ["project-root"]` and a single `principal.000000.floor.000000` row — a certified-looking allow that certifies nothing | **PASS** (assertion confirmed necessary and sufficient) |
| F | `requiredSetupFloor` widened with a sibling `fs:list` on `Cargo.lock` | setup floor cannot exceed probe floor | both authoring and executor guards must fire | bun: `(fail) reads retained descriptor metadata and closes its source-bound setup`; Rust: `a retained-handle setup floor must exactly match the probe floor` at `:1902` | **PASS** |
| G | Diagnostic: an unconstrained `__exactFsOpen("Cargo.toml","r")` submitted immediately after the denied probe | one-shot constraint does not leak into a later submission | must succeed | `{"kind":"return","globalName":"__exactFsOpen","value":15}` — principal 1 is not still on the stack | **PASS** |
| H | Retained-deny expected source prefix flipped to `principal.000000.denial.` | the deny assertion reads real evidence | deny row must fail | `retained-handle denial escaped the probe principal` at `:4055`, printing the real row `principal.000001.denial.000000` | **PASS** |

Seven of nine mutations produced the required failure. Two — D and D2, the
mutation the author's own evidence envelope names as required — did not.

**Post-restore state:** tree clean at `157a23f6f`; primary shard 1/1 ok,
secondary shard 4/4 ok, `retained_sqlite_setup_*` ok, focused bun recipe
assertion 1 pass / 0 fail.

---

## 6. Verdict

**NOT READY.**

The property this review exists to defend — that setup authority cannot leak
into probe authority — **holds**, and holds under direct attack. The
constrained-principal mechanism narrows and cannot widen; the retained handle
authorizes identity and not authority; the exact-count evidence assertions are
non-vacuous and are precisely what carries the guarantee (break-test E shows
that relaxing them alone converts a leaked run into a green one); the one-shot
override does not survive its submission; and the retained-fstat deny row is a
genuine probe-time denial attributable solely to the constrained package
principal, reproduced by this reviewer from an independently regenerated
catalog. The FD half of this change is sound work and I would accept it on its
own.

What blocks acceptance is the SQLite half. Its single test does not test what
it is named for, what the memo says it does, or what the evidence envelope
lists as a required break-test — and the 48 rows it is credited with unblocking
have no code path reaching them. That is an attestation-integrity problem
rather than an enforcement problem, which is why the flip set is small.

### Minimal flip set

1. **BLOCKER-1** — Make `retained_sqlite_setup_creates_a_real_file_backed_native_handle`
   fail under a `:memory:` substitution: assert file-backing from the runtime
   (a deliberately-absent owned path must fail to open, and the seeded row must
   be readable through the returned handle). Alternatively withdraw the "real
   file-backed" claim from the memo, the envelope, and LLP 0049 §6.
2. **MATERIAL-2** — Either author one end-to-end file-backed SQLite row, or
   restate the unblock claim as "36 FD rows demonstrated; SQLite constructor
   landed but unexercised", and move the anticipatory fixture paths out of
   `target/`.
3. **MATERIAL-3** — Record the derivation of the 36-row FD figure, or reduce it
   to the derivable count.
4. **MATERIAL-4** — One sentence in LLP 0049 §6 recording that the
   constrained-principal set is installed by an observer-only hook standing in
   for frame attribution.

MINOR-5 through MINOR-7 are not blocking and may be folded into the same
commit or deferred.

The single closed row (retained `__exactFsFstatSync` deny) is, on this
reviewer's independent execution, correctly proven; I would have no objection
to it landing once the claims around it are made accurate.
