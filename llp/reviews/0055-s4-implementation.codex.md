# Review: LLP 0055 S4 implementation — codex (code round 1 + confirm + micro-confirmation)

**Reviewer:** codex gpt-5.6-sol, effort xhigh, `codex exec -s read-only`, full repository access, same commissioning prompt as the grok round (mutually blind).
**Date:** 2026-08-25. **Requested by:** the LLP 0055 S4 lane (dual-family code round).
**Round 1 target:** commit a70c8cd6a on cd9a40d5c. **Verdict:** NOT READY — 6 materials (payload-semantics binding; receipt finalization outside the fence; pending bypassing single-flight/capacity; pending different-bytes answered busy; restart-family misclassification; missing Cargo.lock ring edge), 3 minors. All addressed in fix round eeb07d472 (5 fixed; material 1 partial + accepted-text disposition citing §13.1/OQ1, which this reviewer's confirm round ACCEPTED).
**Confirm target:** eeb07d472. **Verdict:** NOT READY — 1 new material (digest-before-begin ordering), 1 minor (§10 busy class). Both adopted in the confirm-round fix commit.
**Micro-confirmation target:** the confirm-round fix (HEAD). **Verdict: READY — no findings.**

Final cross-family state: codex READY (micro-confirmation), grok READY x2 (round 1 + delta), security delta resolved to NEUTRAL.

---

## Round 1 (verbatim)

## Verdict
NOT READY

## Material Findings

1. The authenticated payload is not tied to the update that is applied. Admission verifies only the payload digest, then discards the payload; `begin_admitted` accepts an independent invalidation vector, and staging accepts independent records. The happy-path fixture signs `{"replacements":[]}` while invalidating and staging a real replacement. A signature for payload A can therefore authorize application B. This violates LLP 0055 §6’s canonical-body enumeration and “verify before staging” requirements. [hot_update.rs:439](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:439), [hot_update.rs:461](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:461), [hot_update.rs:772](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:772), [hot_update.rs:1001](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:1001), [LLP 0055 §6:734](/Users/ccheever/projects/ibex-wt/s4h-lane/llp/0055-hot-revision-intra-generation-updates.spec.md:734), [LLP 0055 §6:742](/Users/ccheever/projects/ibex-wt/s4h-lane/llp/0055-hot-revision-intra-generation-updates.spec.md:742).

2. Commit receipt finalization is outside the commit fence. `HotRevisionSurfaceV1::commit` returns before the separate `settle_committed` call; during that gap an exact retransmit sees `Pending` and answers busy, not the committed receipt. This violates LLP 0055 §5.3 step 7 and §6’s guarantee that the terminal receipt is finalized in-fence. [hot_revision.rs:126](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_revision.rs:126), [hot_update.rs:573](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:573), [hot_update.rs:1021](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:1021), [LLP 0055 §5.3:692](/Users/ccheever/projects/ibex-wt/s4h-lane/llp/0055-hot-revision-intra-generation-updates.spec.md:692), [LLP 0055 §6:771](/Users/ccheever/projects/ibex-wt/s4h-lane/llp/0055-hot-revision-intra-generation-updates.spec.md:771).

3. Pending reservations bypass single-flight and the 4096-entry bound. `admit` checks only `surface.is_in_flight()`, but the surface does not become in-flight until the later `begin` call. One owner thread can therefore retain arbitrarily many different admitted handles, all reserving pending rows; those reservations can subsequently terminalize past capacity because the gate counts only existing terminals. This creates unbounded replay-table growth and violates LLP 0055 §5.2’s busy gate and §6’s capacity law. [hot_update.rs:328](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:328), [hot_update.rs:339](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:339), [hot_update.rs:347](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:347), [hot_update.rs:673](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:673), [hot_revision.rs:109](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_revision.rs:109), [LLP 0055 §5.2:565](/Users/ccheever/projects/ibex-wt/s4h-lane/llp/0055-hot-revision-intra-generation-updates.spec.md:565), [LLP 0055 §6:786](/Users/ccheever/projects/ibex-wt/s4h-lane/llp/0055-hot-revision-intra-generation-updates.spec.md:786).

4. A pending same-`updateId` envelope with different bytes answers busy rather than `update-identity-conflict`: the pending branch ignores its stored digest. This contradicts LLP 0055 §5.2 check 2 and §6’s content-binding law. [hot_update.rs:306](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:306), [hot_update.rs:317](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:317), [LLP 0055 §5.2:557](/Users/ccheever/projects/ibex-wt/s4h-lane/llp/0055-hot-revision-intra-generation-updates.spec.md:557), [LLP 0055 §6:781](/Users/ccheever/projects/ibex-wt/s4h-lane/llp/0055-hot-revision-intra-generation-updates.spec.md:781).

5. Check-3 authority/restart refusals are misclassified. `begin_revision` can report authority drift or a builtin/synthetic source requiring restart, but `begin_admitted` maps every unrecognized algebra error to `FullReloadCurrentAuthority`. LLP 0055 §10 requires `regenerate-policy-and-restart-runtime`/restart-family recovery for these cases. [generation.rs:1143](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/generation.rs:1143), [generation.rs:1164](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/generation.rs:1164), [hot_update.rs:538](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:538), [hot_update.rs:545](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:545), [LLP 0055 §10:914](/Users/ccheever/projects/ibex-wt/s4h-lane/llp/0055-hot-revision-intra-generation-updates.spec.md:914).

6. HEAD’s lockfile is incomplete. `Cargo.toml` adds `ring` as a direct dependency, but `HEAD:Cargo.lock` omits it from the `ibex-runtime` dependency list; the uncommitted worktree change adds exactly that missing row. Consequently the repository’s `--locked` build gate cannot consume the reviewed commit, preventing LLP 0055 §11’s required exit fixtures from being reproducible. [Cargo.toml:124](/Users/ccheever/projects/ibex-wt/s4h-lane/Cargo.toml:124), `HEAD:Cargo.lock:1054,1092–1094`, [portable-engine-physical-promotion.yml:295](/Users/ccheever/projects/ibex-wt/s4h-lane/.github/workflows/portable-engine-physical-promotion.yml:295).

## Minor Findings

1. F9 does not explicitly assert the `keep-last-good` class for capacity or identity-conflict responses: those admission variants carry only diagnostics, and the capacity fixture asserts only the variant/message. LLP 0055 §11 F9 explicitly names the class. [hot_update.rs:679](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:679), [hot_update.rs:1499](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:1499), [LLP 0055 §11:993](/Users/ccheever/projects/ibex-wt/s4h-lane/llp/0055-hot-revision-intra-generation-updates.spec.md:993).

2. Admitted/settlement handles are session-bound only by `debug_assert!`. Pairing a handle with the wrong consumer session in release mode can strand the original pending row without poisoning its session because settlement marks the handle settled before confirming replacement. [hot_update.rs:469](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:469), [hot_update.rs:578](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:578), [hot_update.rs:583](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:583).

3. The repository ticket still marks S4 incomplete even though this commit claims to be the final slice; repository policy also calls for resolving and closing completed filesystem tickets. [20260824 issue:20](/Users/ccheever/projects/ibex-wt/s4h-lane/issues/20260824-llp0055-hot-revision-h1-surface.md:20).

## Judgment Calls

(a) AGREE. Coordinate currency must precede graph-digest currency after ask 2: a post-race envelope commonly has both old coordinates and an old digest, and the coordinate row must win with `keep-last-good` plus committed coordinates. Matching coordinates isolate graph desynchronization.

(b) AGREE. With exclusive `&mut` access and the immediately preceding equality proof, passing `live` is algebraically equivalent to passing the claimed base; `begin_revision` remains a valid invariant backstop. [hot_update.rs:490](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:490), [hot_update.rs:508](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:508).

(c) AGREE. SHA-256 and Ed25519 are distinct primitive domains, and their framing also differs (`NUL` in `digest_bytes`, newline in the signed message). Reusing the public protocol identifier is cryptographically unambiguous, though a separate named constant could improve readability. [artifact.rs:713](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/artifact.rs:713), [hot_update.rs:750](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:750), [hot_update.rs:754](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:754).

## Verified Claims

1. FINDINGS 1, 3, and 4.

2. VERIFIED — check-1 failures return before any insertion, and the adversarial helper asserts an empty table followed by legitimate admission. [hot_update.rs:285](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:285), [hot_update.rs:347](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:347), [hot_update.rs:887](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:887).

3. VERIFIED for ordinary check-3 refusals; busy and quarantine take their specified non-terminal exceptions. [hot_update.rs:474](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:474), [hot_update.rs:610](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:610), [hot_update.rs:936](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:936).

4. FINDING 2.

5. VERIFIED — the three actual busy paths add no row or terminal outcome. [hot_update.rs:306](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:306), [hot_update.rs:326](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:326), [hot_update.rs:1368](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:1368).

6. FINDING 3.

7. VERIFIED — quarantine/drop poison the shared rotation latch, the rotation gate precedes lookup, and a fresh session starts with an empty table. [hot_update.rs:290](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:290), [hot_update.rs:603](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:603), [hot_update.rs:715](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:715), [hot_update.rs:739](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:739).

8. VERIFIED — private material is confined to the non-serializable signing session, Debug redacts it, verifier construction copies only public bytes, and signing is domain-prefixed. [hot_update.rs:93](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:93), [hot_update.rs:104](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:104), [hot_update.rs:130](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:130), [hot_update.rs:754](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:754).

9. FINDING 1 — the raw 64-KiB/16-MiB limits and absence of clock comparison are correct, but the 512 limit is applied to an independent caller vector rather than authenticated payload records. [hot_update.rs:368](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:368), [hot_update.rs:482](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:482).

10. VERIFIED — stale coordinates yield ask-2 `keep-last-good` with committed coordinates; a matching-coordinate graph mismatch yields full reload. [hot_update.rs:490](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:490), [hot_update.rs:553](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:553).

11. VERIFIED — replay ownership is a separate host session object, keyed by `updateId` and storing the full envelope digest, independent of `HotRevisionSurfaceV1`. [hot_update.rs:217](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:217), [hot_update.rs:228](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:228).

12. VERIFIED — `begin` is exclusive, TLA-bearing staged records require both evaluation and TLA receipts, and the exact diff removes no pre-existing assertion or changes an existing refusal string. [hot_revision.rs:90](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_revision.rs:90), [hot_revision.rs:212](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_revision.rs:212), [generation.rs:1439](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/generation.rs:1439).

13. FINDINGS 1, 3, and 4; MINOR FINDING 1. No pre-existing assertion was weakened or deleted.
---

## Confirm round (verbatim, post-fix eeb07d472)

## Verdict
NOT READY

## Material Findings
1. [src/module_loader/hot_update.rs:540](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:540), LLP 0055 §5.2 check 3 / §6 — `surface.begin` runs before the live base-graph digest comparison at line 588. Consequently, a current-coordinate envelope with a stale graph digest and an empty invalidation set terminalizes `KeepLastGood` instead of the required graph-desync `FullReloadCurrentAuthority`. This changes recovery and the session-lifetime replay receipt. Compare the digest before `begin_revision` and add a compound F9 fixture.

## Minor Findings
1. [src/module_loader/hot_update.rs:789](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:789), LLP 0055 §5.2 / §10 — `Busy` remains classless despite both clauses explicitly assigning surface busy to `keep-last-good`. Its occupancy-nack status controls replay recording, not refusal classification; capacity and rotation are likewise occupancy nacks and now carry the class. `Duplicate` is correctly classless because it is not a refusal.
2. [issues/20260824-llp0055-hot-revision-h1-surface.md:20](/Users/ccheever/projects/ibex-wt/s4h-lane/issues/20260824-llp0055-hot-revision-h1-surface.md:20) — the S4 checkbox, H2 payload-derivation obligation, and close-out evidence have not landed yet.

## Resolution Check
1. Payload semantics — DISPOSITION-ACCEPTED. [hot_update.rs:361](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:361) retains the exact authenticated bytes and [hot_update.rs:833](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:833) exposes them immutably. Section 6 requires end-to-end derivation before staging but does not require the S4 Ibex library itself to own decoding; §13.1 fixes the v1 record form, while the Exact consumer is explicitly H2-owned. The H2 obligation must still be recorded during close-out.
2. Receipt finalization — RESOLVED. [hot_update.rs:612](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:612) commits and terminalizes in one owner-thread call frame; backstop errors poison the origin at line 634, and unwind invokes the settlement drop backstop at line 867.
3. Pending single-flight/capacity — RESOLVED. [hot_update.rs:341](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:341) gates on `pending_update`; reservation sets it at line 369 and ordinary removal/terminalization clears it at lines 723/745. Quarantine deliberately strands both row and marker behind the earlier rotation gate. `Pending(None)` exists only during the contiguous `take`→overwrite operations at lines 734–745 and 759–774, with no observable call boundary.
4. Pending different bytes — RESOLVED. [hot_update.rs:309](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:309) distinguishes the bound digest: exact pending duplicates are busy, while different bytes return `IdentityConflict` without mutating the row.
5. Restart-family classification — RESOLVED. [hot_update.rs:568](/Users/ccheever/projects/ibex-wt/s4h-lane/src/module_loader/hot_update.rs:568) maps current restart-family begin errors to `RegeneratePolicyAndRestartRuntime`; the authority-drift fixture verifies terminal replay.
6. Cargo lock edge — RESOLVED. `Cargo.lock` contains the direct `ring` edge, and `cargo tree --locked` resolves the vendored `ring` dependency.
7. Prior minor 1, admission classes — NOT RESOLVED. Rotation, identity conflict, and capacity now carry `KeepLastGood`; duplicate is correctly classless, but busy remains classless as described in Minor Finding 1.
8. Prior minor 2, session binding — RESOLVED. Real `Rc::ptr_eq` checks guard admitted and settlement handles at lines 490, 619, 658, and 679. Foreign early returns mutate neither receiving session nor surface; dropping the owned handle poisons only its origin, while dropping a foreign `ready` releases its flight guard without applying its activation token.
9. Prior minor 3, ticket close-out — NOT RESOLVED. It is explicitly deferred to the post-review close-out commit.

`cargo test --locked --lib`: 817 passed, 4 ignored; focused S4 tests: 22 passed. Formatting and `ref-check` also pass.
---

## Micro-confirmation round (verbatim, post-confirm-fix)

## Verdict
READY
## Findings
None.