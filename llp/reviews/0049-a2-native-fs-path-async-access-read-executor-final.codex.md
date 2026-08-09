# Review: LLP 0049 A2 — Native FsPathAsync access-read executor

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** Codex workspace agent, GPT-5 family
**Date:** 2026-08-09
**Redacted:** No
**Method:** Independent adversarial review of the final uncommitted seven-file
change against base `52abebaed00852bdda31a805e17b9faac0e9b6f3`. I read the
governing LLP 0049 plan, LLP 0037 attribution decision, and the relevant LLP
0021 WP10/native-filesystem sections; inspected the implementation, generated
catalog, allow-list, candidate, and both physical receipts; replayed all six
observations through the production verifier; and ran positive and isolated
mutation tests in a detached worktree. I did not rely on the prior NOT READY
review or its conclusions.

---

## Verdict

**READY.** I found no blocker, material issue, or unaddressed minor issue in
the reviewed A2 access-read class.

The reviewed claim is narrow and symmetric: only a literal first argument
`"access"` on the native global `__exactFsPathAsync` selects
`native-op:__exactAccess`. The Rust execution validator and independent
JavaScript promotion-evidence validator both implement that rule. The closed
account rejects `access-read`, unrelated operations, wrong globals (including
direct `__exactAccess` in the JavaScript negative), null/non-string literals,
and non-literal argument kinds. The authored recipe declares only `fs:list`.

## Reviewed identity

- Base: `52abebaed00852bdda31a805e17b9faac0e9b6f3`
- Canonical seven-file review diff SHA-256:
  `f508e5f58753bb7ac7a8a1c4c7714ba74c3d40ce5a3d0b310e59ff4f8d5c7177`
- Diff shape: 7 files, 162 insertions, 4 deletions; 280 lines and 13,308
  bytes in the canonical `git diff --binary HEAD -- <seven paths>` stream.
- Candidate:
  `/Users/ccheever/phase1-runs/campaign-a2/candidate-fs-path-async-access-read-v3.json`
- Candidate digest:
  `sha256-cY2t5jerfrwBMazy0ZwfRgXgR1eRWxrrOCToaSoeOxg`
- Primary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/fs-path-async-access-read-primary-air-v4-final.json`
- Secondary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/fs-path-async-access-read-secondary-air-v2-final.json`
- Loaded engine digest in both receipts:
  `sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y`
- Allow-list digest:
  `sha256-B0_z4ef7YxBCDs_62eKuAHI4vuEDe4XEnnD6otgJCjk`

The canonical diff digest includes the untracked allow-list via a temporary
index and excludes review artifacts. An earlier local calculation used
`--full-index`, which changes the patch serialization by expanding blob IDs;
that alternate serialization is not the reviewed digest. Regenerating the
canonical stream independently produced the value above.

The final file hashes were also compared between the shared tree and the
restored detached mutation worktree:

- inventory: `a86db05a67c6074278da7c05edb5eee16173db1f5450f2df813e70c237293593`
- recipes: `5181888fe04d9d8f075a5db16de6da827dcc192f83dbf13a93ac64ee073eb21d`
- recipe tests: `8a4506b5b08842ec06221c1dc7e78b494df6346a803c39141bc693574d6c502b`
- evidence verifier: `c81d8dedff6d859474cbc0b1a5ba09b422571d6002d49cd180cdfb0d3d49dbbf`
- evidence tests: `b7efe203ea41c347dcf8f934e17185325b4d44f43444aee6b0cd41d635fcec27`
- Rust validator: `ccc29448a8fbf1cc33118a5a088f3dda430019c5ac7d8b05caa04cfb66ae1851`
- allow-list: `074ff3e1e7fb6310420ecffad9e2ae007238bee1037b85c49e70faa2d8090a39`

## Source and recipe audit

The recipe catalog contains exactly six new logical fixtures:
`allow`, `branch-selection`, `deny`, `malformed`, `missing-attribution`, and
`wrong-principal`. Every fixture invokes `__exactFsPathAsync` with literal
arguments `("access", "Cargo.toml", null, 0, 0, 0)`, declares only
`fs:list`, allows exactly the dispatcher and `__exactAccess` coverage edges,
and uses the expected six typed stages except for the one-decision deny case.
The completion contract is quiescence with a one-second timeout.

The C++ source span cited by the allow-list contains the access dispatch. With
mode `0`, the branch selects neither read nor write authority, calls the armed
list-target path, and schedules the access worker. The three allow-list entries
explain only the exact residual removals for the reviewed dispatcher edge:
six public-invocation residuals, one conditional-branch residual, and six
native-argument residuals.

Inventory anchors were checked against the generated recipe source:
`IBEX_CAPSEC_RECIPE_CATALOG` is at byte 37,335 and
`IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT` at byte 37,521, exactly matching the
inventory. No stale offset was found.

## Candidate and receipt audit

The route-evidence diff from
`candidate-fs-stat-async-path-final.json` to the reviewed candidate passed with
13 changes, 13 explained, 0 unexplained, and 0 stale. The terminal-evidence
diff passed with 0 changed cells, 0 unexplained entries, and 0 stale entries.
Lane counts were unchanged. A structural comparison found changes in exactly
the six access-read recipes and only in `publicSurfaceProbe`, `status`, and
`residualReasons`, plus the expected top-level catalog/digest/summary fields.

I independently loaded the real `buildPublicFixtureEvidence` and
`computeRecipeCatalogDigest` exports, the candidate catalog, coverage-edge
registry, and both physical receipts. All six receipt observations rebuilt
byte-for-byte equal to their recorded candidate executions (6/6). Their
evidence digests were:

- branch-selection: `sha256-KmbzrkjPesG4AX9VaEL9ZFHLSDHlsCcl77HN-GdKkAo`
- deny: `sha256-n81ZxCHh1zF_Rju9_9TerFgB1biXCGOgqoGN8Hdq1BA`
- malformed: `sha256-w-bgRQ59ErSABsvA2L6lKOXgm3tPQAEICcTs8Ve3IF4`
- allow: `sha256-FCCJ7KQFtzsfdA91eCjzcy_AoFXKSEmmHN35nYY6Nuo`
- missing-attribution: `sha256-qaEG-1Pi2uEk6HdeEUaqo0qS9o4l6GfR0ceLW5Vc5sQ`
- wrong-principal: `sha256-XExuLDTjPDMHLL6BtjnrzE793z_rclkAG94x0E603Oc`

For every execution, the batch candidate digest, recipe plan digest, engine
digest, public probe, and terminal observation agreed. The public surface was
always `native-op:__exactFsPathAsync`; the observed worker/gate was only
`native-op:__exactAccess` / `surface.native.op.exactaccess.1a12cmn`; atomicity
groups were the access edge; operation IDs used the `fs-access:` prefix; and
completion was quiescent. The observed action union was exactly `fs:list`, so
there is no LLP 0037 D2 surplus. I found no route laundering, authority
widening, engine mismatch, digest mismatch, assertion weakening, or stale
allow-list entry.

## Tests and adversarial break tests

The restored final target passed:

```text
bun test <recipe-test> <evidence-test> --test-name-pattern
  'async access existence|worker-terminal account exact'
2 passed, 197 filtered, 0 failed, 73 expectations

cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  native_async_worker_terminal_account_is_exact -- --test-threads=1
1 passed, 655 filtered, 0 failed
```

The detached worktree lacked its own Hermes compiler artifact, so the isolated
Rust mutation builds used `EXACT_ALLOW_FALLBACK=1`, explicit Hermes/JSI include
paths, and the shared Cargo target directory. This was build plumbing only;
the exact secure feature vector above remained enabled, and the unit exercises
the pure closed-map selector.

I then changed one production authority at a time, never the shared tree:

1. Removing `("access", "native-op:__exactAccess")` from the Rust map while
   leaving the closed-account test intact failed compilation because the
   six-entry implementation could not equal the expected seven-entry account.
2. Removing `["access", "native-op:__exactAccess"]` from the independent
   JavaScript map failed the focused test: expected `native-op:__exactAccess`,
   received `null`.
3. Adding the near-miss `access-read` to the JavaScript map failed the explicit
   negative: expected null, received `native-op:__exactAccess`.
4. Adding the near-miss `access-read` to the Rust map failed the exact closed
   account (eight implementation entries versus seven expected).
5. Widening the JavaScript global guard to accept direct `__exactAccess`
   failed the explicit direct-global negative.
6. Widening the Rust global guard to accept `__exactMkdir` failed the wrong-
   global assertion: received `Some("native-op:__exactMkdir")`, expected None.

After restoring each mutation, all seven reviewed file hashes again matched
the final shared target, and the focused green tests above passed. These
failures demonstrate that both independent authorities are load-bearing and
that the near-miss/wrong-global negatives defend the closed claim.

## Findings disposition

No findings require disposition. The scope is the requested logical access
existence class only; content-read authority is neither declared nor inferred,
and no additional operation or terminal is promoted.
