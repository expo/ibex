# Review: LLP 0049 A2 — Native `fs:list` `which` slash executor (final)

**Reviewer family:** OpenAI (Codex)
**Provider / runtime:** Codex workspace agent, GPT-5 family
**Date:** 2026-08-09
**Redacted:** No
**Method:** Fresh independent adversarial review of the corrected seven-file
staged target. I read LLP 0000, LLP 0037 (especially D1–D4), LLP 0049 §3 and
§6, and the applicable repository review instructions; inspected the staged
implementation, recipe, allow-list, inventory, candidate, and both physical
receipts; independently regenerated the candidate; replayed every target
receipt through the production JavaScript evidence consumer; and ran isolated
positive and break tests. The earlier NOT READY artifact was excluded from the
reviewed diff, was not modified, and was not used as review evidence.

---

## Verdict

**READY.** I found no blocker, material issue, or unaddressed minor issue in
the reviewed A2 class.

The promoted claim is narrow: `__exactWhich("/project/ref-check")` may emit
only `fs:list` for the exact logical path `project/ref-check`, and successful
public observations must return the unchanged logical string
`/project/ref-check`. The recipe, Rust execution validator, and independent
JavaScript evidence consumer all bind that exact global, one exact literal
argument, exact floor, exact result shape, and exact string. Denials are
accepted only for a closed set that now includes `__exactWhich`; the explicit
`__exactWhichExtra` near-miss remains rejected in both validators.

## Reviewed identity

- Base commit: `c4d9dfd9521ef73d4cdd42ce408c2c2308e04a35`
- Base tree: `5824346bc893e19227f43486f49235cc26696c51`
- Staged target tree: `cde67590f637dca3f306d9ab37d4fa0a07427169`
- Canonical staged diff SHA-256 (`git diff --cached | shasum -a 256`):
  `276d27be7d5945d726902f20fdf5e7beeca3fabec0a04ec7024f0c8c0d6188cd`
- Diff shape: 7 files, 279 insertions, 23 deletions
- Candidate:
  `/Users/ccheever/phase1-runs/campaign-a2/candidate-fs-list-which-slash-final-v4.json`
- Candidate raw SHA-256:
  `c4c20c3681368596fdea67352cd0cb56dd1b2f85a82ea11b4a9d536023645339`
- Catalog digest: `sha256--zHoPIkgplAuRKPVWDmzbmLClmE4tEL02MjD4PWNpqI`
- Allow-list digest: `sha256-wR22LSNvWMnTpwjGoz9ulPIBxntPkO1md6wiT2BxiP8`
- Allow-list raw SHA-256:
  `c11db62d236f58c9d3a708c6a33f6e94f201c67b4f90ed6677ac224f607188ff`
- Loaded engine digest in both receipts:
  `sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y`
- Primary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/fs-list-which-slash-primary-v3-final.json`,
  raw SHA-256
  `59c93203cc13ff465c171f170d4d614e5d3088c223ffa6138957dfada4677949`,
  308/308 completed
- Secondary receipt:
  `/Users/ccheever/phase1-runs/campaign-a2/fs-list-which-slash-secondary-v3-final.json`,
  raw SHA-256
  `7c11c45b5493b19a0d6d00c0ffdec9cf08421ed91b3bc85fa47ddfa15cbbd76a`,
  340/340 completed

`candidate-fs-list-which-slash-final-v4.json` is byte-identical to the supplied
`candidate-fs-list-which-slash-v3.json`. Independent regeneration from the
staged source produced a byte-identical candidate with the same raw digest.
The candidate reports 21,784 required cells, 3,976 fully executable cells,
3,124 internal-only cells, 9,985 adapter cells, and 14,684 unresolved cells.

The final staged file hashes, also matched byte-for-byte after restoring the
detached mutation worktree, are:

- inventory:
  `eeb78a0b9ca5335e74f653de4f960bfdf8b4b9a27f9bc122743f185963fa71e4`
- allow-list:
  `c11db62d236f58c9d3a708c6a33f6e94f201c67b4f90ed6677ac224f607188ff`
- recipes:
  `219d2fcd1062fdd67e825678c4e8bdd2689accfc9319610f7c480a6619800c3b`
- recipe tests:
  `300527f7134c5a4d3fb944d504abe245ffd08057877231a387ee48e94271b2c5`
- evidence consumer:
  `c51f294171411bb00de28ed6f1702b29c09b8faa0ccf1711c54e769d6fb33dd2`
- evidence tests:
  `0881f1c341e3df0300c356d8dbeef67b19171a59c3aa5189ba63f01d00bfc37c`
- Rust validator:
  `7bf826545fb3b0e99c90b209d806fa157ea2bc349f9c85b6804caacfd5ed486d`

`git diff --cached --check` passed. The staged diff digest remained the exact
value above after review. The only pre-existing untracked review artifact was
the earlier NOT READY report; this final report is the only file I created.

## Source, recipe, and validator audit

The catalog contains exactly six slash-containing-command fixtures: `allow`,
`branch-selection`, `deny`, `malformed`, `missing-attribution`, and
`wrong-principal`. Every fixture calls `__exactWhich` with exactly one
JSON-literal argument, `/project/ref-check`, declares only `fs:list`, and uses
the exact `path-exact` floor rooted at `project` with component `ref-check`.
The only allowed coverage edge is
`surface.native.op.exactwhich.0it66ce`, and operation IDs use the `fs-which:`
prefix.

The five non-deny recipes require typed stages
`requested, discovery, requested, repeat, discovery` and exact returned
`stringValue: "/project/ref-check"`; the deny recipe requires only
`requested` and deliberately has no successful-string expectation. The
observed strata were the expected static-floor/ambient-root sequence for
non-deny cases and principal-denial for deny. The literal slash path means the
fixture does not consult or depend on `PATH`.

The Rust account captures `stringValue` only when an expected string is
authored, then requires exactly five result keys: `kind`, `globalName`,
`valueType`, `cleanup`, and `stringValue`. It additionally requires return
kind, global `__exactWhich`, string type, cleanup `none`, exact logical result,
one literal argument equal to the expected result, and the fixed reviewed
value `/project/ref-check`. The independent JavaScript consumer enforces the
same closed account and does not accept a backing/private path in place of the
logical path.

The denial-message allow-lists in Rust and JavaScript contain exact
`__exactWhich`. Both have explicit `__exactWhichExtra` negative coverage, so
neither a prefix match nor an accidentally widened family is accepted.

I checked the allow-list source spans against the reviewed source and the two
generated-recipe inventory anchors. Byte offsets 39,046
(`IBEX_CAPSEC_RECIPE_CATALOG`) and 39,232
(`IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT`) point at the intended source bytes.

## Candidate, route, and receipt audit

The strict route-evidence comparison against
`candidate-fs-path-async-access-read-final-stable.json` passed with 13 changed
entries, 13 explained, 0 unexplained, and 0 stale. The residual delta is
exactly six public-invocation residuals, one branch-selection residual, and six
native-argument residuals. Lane B/C/D counts remain 528/1,326/32. The terminal
comparison passed with 0 changed cells, 0 unexplained entries, and 0 stale
entries.

I loaded the actual `buildPublicFixtureEvidence` and
`computeRecipeCatalogDigest` exports and replayed the six target observations
from both physical receipts. Every rebuilt execution was byte-for-byte equal
to its candidate execution (6/6). The scenario evidence digests were:

- allow: `sha256-9P9eMywDEZ2MYBKxHhJ1xYFy_xqghHICZ0Fr1OwhADc`
- branch-selection: `sha256-fCwwX1asiq81LJVqfofdCr5ekQ3EEXASMhY5p0_Y1Ek`
- deny: `sha256-WEITMVubigiPw2kHvMn6vQmuNeux2cxMqTmfmTxnYd4`
- malformed: `sha256-txU8FNYGjZv_VmYZVhSi-9VInVhOWM9CkIH65azJaw0`
- missing-attribution: `sha256-EMMlWAjLX9JX0oialRwEwYglMPm9ihm7YoX90yo7g7Y`
- wrong-principal: `sha256-ZJLS_OGzMD2bHMoJch8iAB7zFmQixYiec1XydOywb2g`

Every successful observation reported `valueType: "string"` and
`stringValue: "/project/ref-check"`. All executions used only `fs:list`, the
reviewed `fs-which:` operation identity, and the one reviewed coverage edge.
Thus the observation union has no LLP 0037 D2 surplus, and the class does not
launder a physical/backing path into the logical result or add ambient
authority.

Independent replay mutations were all rejected:

- runtime `stringValue: "/backing/private/ref-check"`
- runtime `valueType: "null"` with null `stringValue`
- authored global `__exactWhichExtra`
- authored literal argument `/project/other`
- authored expected result `/project/other`

## Tests and adversarial break tests

Focused final tests passed:

```text
bun test packages/ibex-devtools/src/scripts/capsec-conformance-recipes.test.mjs \
  packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.test.mjs \
  -t 'authors direct executable-path lookup without reading PATH|keeps native filesystem denial expectations on the reviewed globals'
2 passed, 198 filtered, 0 failed, 73 expectations

cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  'engine::hermes::tests::capsec_conformance_batch::native_filesystem_denial_message_allowance_is_exact_and_fail_closed' \
  -- --exact --nocapture --test-threads=1
1 passed, 656 filtered, 0 failed

cargo test --bin ibex --no-default-features \
  --features standard,capsec-conformance-observer,openssl-crypto \
  'engine::hermes::tests::capsec_conformance_batch::native_which_string_result_account_is_exact_and_fail_closed' \
  -- --exact --nocapture --test-threads=1
1 passed, 656 filtered, 0 failed

./ref-check
51 documents, 2,535 references, 2,014 files, 0 errors, 1 unchecked
```

The detached worktree lacked its own Hermes compiler artifact. Its Rust tests
therefore used `EXACT_ALLOW_FALLBACK=1`, explicit Hermes library/header paths,
and the shared Cargo target directory as build plumbing. The mandated secure
feature vector remained exact:
`--no-default-features --features standard,capsec-conformance-observer,openssl-crypto`.

I changed one production or recorded authority at a time in the detached
worktree, leaving the tests/validators intact:

1. Removing `__exactWhich` from the JavaScript denial set failed its positive
   assertion with `unreviewed native denial expectation`.
2. Adding `__exactWhichExtra` to that set failed the explicit near-miss
   negative because the descriptor was accepted.
3. Removing `__exactWhich` from the Rust denial set failed its positive
   assertion.
4. Adding `__exactWhichExtra` to that set failed the explicit near-miss
   negative.
5. Changing the Rust positive fixture's recorded `stringValue` to
   `/backing/project/ref-check` failed the exact-result positive assertion.
6. Changing its recorded `valueType` from `string` to `null` failed the same
   positive assertion.

The JavaScript production replay independently rejected the analogous wrong
backing-string and null-result mutations. After restoring all mutations, the
seven reviewed files matched the shared staged target byte-for-byte and all
four focused final tests passed. These breaks demonstrate that the closed
denial accounts and exact logical string result are load-bearing in both
independent consumers.

## Findings disposition

No findings require disposition. The corrected target closes the previously
observed independent-consumer omission and makes the returned logical string
part of the retained, fail-closed account; the exact-prefix negatives prevent
silent widening. No unrelated class, terminal, operation, or capability is
promoted.
