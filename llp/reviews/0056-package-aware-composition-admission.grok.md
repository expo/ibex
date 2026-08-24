# Review: LLP 0056 — Package-Aware Composition Admission (grok family)

**Reviewer family:** grok
**Model:** grok-4.6, effort xhigh, headless (`--output-format plain`)
**Mode:** full text of LLP 0056 r1 + Exact LLP 0413.001 r6 inlined in the prompt; no repository access (code claims routed as verification requests); blind to the sibling codex review
**Rounds:**
- Round 1 (2026-08-24): reviewed r1 (`fa7b5ed0d`). Verdict: NOT READY.

## Round 1 (r1, verbatim)

I'll start by reading the full review prompt and the LLP review skill so the assessment follows the required process.The governing spec continues past the first chunk; I'll read the rest so the conformance check is against the full r6 text.## Overall Assessment

This is a strong, implementable ibex leg: fail-closed, vocabulary-correct on composition role vs `Principal`, and aimed at the right seams (`admit_package_v1` extract, carrier v3, `prepared-package` identity, multi-root link, evaluate-then-invoke). The three-channel split and the per-package graph digest are the right answers to the identity guarantee and to anti-replay.

It is **not yet a drop-in implementation of Exact LLP 0413.001 r6**. The nine-step *narrative* tracks §4, but the load-bearing registry machinery does not: §6.2 has no ordinals, step-3 predicate order does not match r6 ordinals, two different “defaults” compete at step 3, `ibex:target-profile-mismatch` is moved from step 3 to step 2, and §10 reinterprets `cross-principal-denied` as a composition-role check. Those are not wording nits. Predicate order, fallback eligibility, and unique reachability *are* the spec.

The 6→11 imported-row expansion is the right *engineering* move and is in the spirit of O-2’s “enumerate the landed tokens.” It is **not** a strict one-for-one substitution of r6’s six placeholder slots, and the covering map is not total on its own terms.

---

## Conformance Findings (MATERIAL/MINOR, cite section numbers)

### MATERIAL

**C1. O-2 covering map has no ordinals, so it cannot implement “predicate order = ordinal order.”**  
0413.001 §4.1: ordinal order *is* within-step predicate order; lowest ordinal wins. 0056 §5 restates that, then §6.2 proposes eleven imported rows with Step and Class only — no `#` column, no full replacement table for rows 10–33. §5’s step-3 prose order (root → schema/role → inventory → carriers → HBC preflight → artifacts → alias → *then* `generation-splice`) is **not** r6’s ordinal order (`package-root-mismatch` #10, `carrier-integrity` #11, `generation-splice` #12, `alias-conflict` #13, then the `ibex:` rows). Multi-fault fixture 38 is undefined until ordinals exist. O-2’s gate (parity against §4.1) cannot pass. 0056 §6.3’s “§4.1 plus this section’s imported rows” also creates a **second registry authority** until a coupled 0413.001 amendment lands.

**C2. Dual totality defaults at step 3.**  
0413.001 §4.1 totality: step 3 → `package-root-mismatch`. 0056 §5: “undecidable remainder defaults to `ibex:prepared-commitment-corrupt`, **and** step 3’s registry default stays `package-root-mismatch`.” Two catch-alls is a defect, not fail-closed. An outcome outside a unique row must have exactly one code.

**C3. `ibex:target-profile-mismatch` moved from step 3 to step 2 without an ordinal home (0056 §5/§6.2 vs 0413.001 §4.1 #17).**  
r6 places it at step 3 (environment, imported). 0056 runs it in 2b after policy-stale. That changes multi-fault results: wrong-target + tampered packages is `(2, target-profile-mismatch)` under 0056 and `(3, package-root-mismatch)` under r6 (#10 beats #17). Authentication-first is a good *reason* to move it, but it is an r6 contradiction until §4.1 is amended with a new step-2 ordinal.

**C4. §6.2 is only partly inside O-2’s license.**  
O-2: enumerate landed tokens; **replace the six placeholder rows one-for-one**; one §7 reachability row per imported code. 0056 §6.2 replaces #14–18 and #20 with **eleven** rows, changes **class** of `encoding-incompatible` and `compiler-fingerprint-mismatch` (environment → producer-defect), changes **step** of `target-profile-mismatch`, and **drops** `ibex:engine-binary-digest-mismatch` with no named disposition. The expansion is justified (r5 names were invented; untokenized `bail!` sites are real). Cardinality change, step/class edits, and a dropped placeholder are a **coupled 0413.001 §4.1 amendment**, not a silent O-2 swap. “New imports after O-2 are spec amendments” (r6 §4.1) applies here.

**C5. Covering map is not total and not injective on its own terms (0056 §6.1–§6.2).**  
Overlaps / splits without unique predicates:

- `carrier-integrity` (#11) vs `ibex:prepared-commitment-corrupt`: §5 sends “tamper-shaped byte/digest” to `carrier-integrity`; §6.2 also puts “carrier/artifact canonicality prose sites” under corrupt.
- `_DEPLOYMENT` “dissolved” into `carrier-integrity` **and** corrupt/schema — one landed token, three composition codes.
- Untokenized `decode_and_admit` / `verify_for_admission` classes named in §6.1 (stale entry semantic digest, deployment-set membership, semantic-digest membership, carrier/entry binding, `SourceId`/integrity disagreement) have no unique §6.2 row and would fall into the illegal dual default (C2).

A covering map that cannot say “this failure → exactly one code” does not discharge O-2.

**C6. §10 reinterprets `cross-principal-denied` as a composition-role rule, contradicting r6 and 0056’s own §2.**  
0413.001 §4 step 6: “**cross-defining-principal** authorization.” 0056 §2: a package is never a principal; no token may use “principal” for composition role. §5 step 6 cites “the cross-defining-principal authorization rule (§10),” then §10 defines: external ref authorized iff agent package + `externalRole: "app"` + app-owned target + declaration includes `agent`. That is a **role** check already implied by steps 5–6 (`app-references-agent`, `local-agreement-disagreement`, `external-owner-mismatch`, 2b role-set). Under that reading, registry #29 and fixture 33 are unreachable — O-6 requires demonstrated reachability. The v1 honesty about EXECUTION collapsing to root must not delete admission-time **defining-principal** authorization on the `security.rs` seam.

**C7. 0413.001 §3.3 authorized-linker requirement is not specified.**  
r6: composition admission uses the **authorized linker path**, never the non-authorized dev shortcut. 0056 §7–§10 describe `link_prepared_composition`, root-principal EXECUTION attribution, and a structural role rule. It never names the authorized vs shortcut path. Silence here is a contradiction, not a deferral of the armed posture.

**C8. Collection-bound enforcement site is wrong (0056 §3.1 vs 0413.001 §3.1).**  
r6 bounds: records ≤ 65 536 **per package**, declared edges ≤ 1 048 576, external refs ≤ 4 096, etc. 0056: “enforced **at envelope decode**,” including records-per-package. Records, bindings, and `externalRole` rows live in **package** indexes (§4.3–§4.5), not in `composition.json`. Unless the envelope inlines those collections (it should not), limit/limit+1 fixtures will test the wrong surface and oversize package indexes can pass step 1.

**C9. Host-held commitment duplicates envelope facts with no 2a equality checks (0056 §3.2, §5).**  
Commitment carries `declaredRoles`, `target`, and `producer`; the envelope already binds declaration, target/engine/encoding, and producer via `compositionRootDigest`. Step 0 checks commitment.target vs embedder; 2b checks envelope vs embedder / `expectedRoles`. Nothing requires `commitment.declaredRoles == envelope.declaration` or `commitment.producer == envelope.producer`. That is a parity pair that can drift — the failure mode §4.4 correctly refuses for role-in-carrier. A stale authentic envelope under a commitment whose `declaredRoles` lie is 2a-inconsistent and should be `composition-commitment-mismatch`.

**C10. §9.2 will bake a stale governing fixture.**  
0413.001 §7 row 35: order/cardinality/**missing-export** → `(7, entry-plan-mismatch)`. r6 §4 step 7 (and 0056 §5 step 7) moved missing named export to `entry-descriptor-invalid`. Adopting “D: 30–38” as written implements the bug. Ibex-side row 35 must split: recomputation inequality → `entry-plan-mismatch`; missing export / unknown action / malformed descriptor → `entry-descriptor-invalid`.

**C11. Report schema is not a function of outcome (0056 §8 vs 0413.001 §5).**  
`failureStage: <1..9>` and `reasonCode: "<registry code>"` are drawn as always-present. Success has no refusal code. Step 9 is **admitted** (return code 2) and the registry **ends at step 8** (`link-failure`). A step-9 report must not mint a registry `reasonCode`. Field presence for `(admitted, rc=0)` / `(refused, rc=1)` / `(admitted, rc=2)` is part of O-1 totality, not an implementation detail.

### MINOR

**c1.** Authority generation is mandatory in 0413.001 §3.1 item 8, but 2b prose only names nonce/expiry/resolver-generation for `composition-replayed`. Folding it into `composition-replayed` (0056 §5 2b) is reasonable; say so as an r6 clarification, not a silent extra conjunct.

**c2.** Class flips (`encoding-incompatible`, `compiler-fingerprint-mismatch`: environment → producer-defect) are substantively better and must be listed as §4.1 amendment deltas, not “the same imported rows.”

**c3.** `ibex:engine-binary-digest-mismatch` (#15) needs an explicit disposition: “never a landed identifier; replaced by `engine-unavailable` / `engine-binding-mismatch`.”

**c4.** §4.1 “nothing inside a package’s bytes may name a fact outside that package’s own graph” overstates §4.2: the agent graph digest **must** include ordered typed-external-reference rows (app `SourceId`s). Restate: app bytes are a pure function of the app graph; agent bytes may name app `SourceId`s only in `externalRole` rows, never target bytes/digests.

**c5.** §5 step 7 puts “root not owned by its role’s package” under `entry-descriptor-invalid`; r6 puts “wrong roots” under `entry-plan-mismatch` (recompute inequality). Split: committed plan ≠ expected plan (including root ids) → mismatch; well-formed committed descriptor whose root is not in that role’s admitted records → invalid.

**c6.** Recomputation domains from r6 (`ibex:prepared-partition:1`, `…union-table:1`, `…boundary-inventory:1`, `…alias-table:1`, `…entry-plan:1`) are not restated. 0056 adds `ibex:prepared-package-graph:1` (good) but should pin the seven r6 literals it hashes under, or explicitly defer them to O-1 with a “same strings” clause.

**c7.** `externalRole` omitted vs `null` under JCS/`deny_unknown_fields` is unspecified (0056 §4.5).

**c8.** 0056 §8 extras (`fingerprintPosture`, timings, `attribution`) are compatible with OQ2 if Exact’s §5 projection is defined as a subset. State that.

---

## Design Concerns (MATERIAL)

**D1. Four input channels, not three.**  
Served / host-held commitment / verifier-held expectations is the right trust split, and `nowUnixMs` as an input is the right test hook. But 2b’s target/engine/encoding check is against “this embedder,” which is **not** a field of `ibex/composition-verifier-expectations/1`. Target also appears on the commitment. That is a fourth, implicit channel. Put `target` / engine / encoding on the expectations object (every 2b comparison has one verifier-held struct), and stop copying them onto the commitment — or define embedder-intrinsic inputs explicitly. As written, step 0 and 2b can disagree about the same session (C9).

**D2. `aliasId` vs `SourceId` namespace disjointness is unspecified (§4.7, §5 steps 3–4).**  
Resolution: “a target id that is not owned by any package but appears as an `aliasId`” maps to the representative. If some packed record’s `SourceId` equals an `aliasId`, owned-record vs alias is ambiguous. Require `aliasId ∩ owned SourceId = ∅` at step 3 or 4, with `alias-conflict` (or a named default). Also specify that alias verification is **composition-wide** over the union of admitted records (representative may live in either package) *before* step-4 partition recompute, so “exists in its owning package” is well-defined.

**D3. Moving HBC preflight into step 3 vs “landed single-publication behavior unchanged.”**  
§5 moves `preflight_hermes_bytecode` from post-admission into step 3 (correct for composition: compatibility is admission, fallback-eligible). §11 extracts `admit_package_v1` as the shared core and claims the single-publication entries keep today’s behavior. If preflight sits inside the shared extract, today’s post-admission / `DuringEvaluation` phase for HBC failures changes on the **non-composition** path. Parameterize it, or keep preflight composition-only. Do not silently change `ibex_dev_unarmed_committed_prepared_startup_v1`.

**D4. App-byte purity is sound only with a tighter theorem than §4.1 states.**  
No-circularity **is** sound: package graph digest binds `(SourceId, semanticDigest)` + ordered edges, *not* carrier/index bytes — same role as today’s `deploymentGraphDigest`. Identity **is** sound for `app` **if** session shape is not an input to app bytes: no `entry` in the package (§4.3), `role` is the constant `"app"`, host-bridged reasons are local (§2.5 locality), agent `SourceId`s do not appear in app bindings. The agent digest **should** change when the ordered external-ref set changes, and **should not** change when app *payload* bytes change. Say that as the purity theorem; the current “no fact outside this graph” sentence fights §4.5.

**D5. `cross-principal-denied` needs a defining-principal predicate that is not implied by steps 5–6.**  
v1 may collapse EXECUTION attribution to root and still refuse, at union closure, an otherwise-legal typed external ref that the landed `ModuleGraphAuthorizer` would deny (defining-principal A → B). Fixture 33 should be that craft, not a role-cut duplicate. Name the v1 authorizer input (record `definingPrincipal` fields + declaration) so #29 is uniquely reachable.

---

## Design Concerns (MINOR)

**d1.** `invoke_named_export` ignoring the return value matches the template; a bootstrap that returns a Promise is “synchronous completion” without finished setup. One sentence of honesty now saves a later incident.

**d2.** OQ-C: prefer counts (`agentEvaluatedRecordCount` / `appEvaluatedRecordCount` / shared count) over naming SourceIds. Enough for fixture 1 without breaking OQ2.

**d3.** Combining HBC header parse and engine preflight under one `ibex:bytecode-preflight` buries “bytes aren’t HBC” vs “engine rejected this HBC.” Acceptable for v1 if fixtures distinguish them in diagnostic detail.

**d4.** `principal-grouping` as producer-defect: a carrier that merges two defining principals can also be tamper. Attacker vs producer-defect is a class call; worth one line.

**d5.** Expiry is only envelope vs `nowUnixMs`. A producer-chosen far-future expiry is a policy-digest problem; say that so nobody adds a second lifetime channel later.

**d6.** Implementation plan is good (corpus green before admission logic; nothing real-admits until leg 3). Make Exact §4.1 fold a **peer blocker** of 0056 acceptance, not “step 4 after we ship.”

---

## Verification Requests (code claims to check)

Cannot confirm against `94c85abab`; these are load-bearing — check, don’t take on faith:

1. **`IBEX_PREPARED_COMMITMENT_CORRUPT` “18 sites”** at the listed `runner_pipeline.rs` lines, and that line 3825 is the repeated-`SourceId` predicate being relocated.
2. **`admit_committed_publication_v1` at `:3532`**, bounded read at `:3240`, principal grouping at `:3631–3650`, index type at `:224`, binding row at `:246–250`.
3. **`PreparedModuleCarrierV2.deployment_graph_digest` at `carrier.rs:101`**; `decode_and_admit` `:245–345`; engine-claim `:327`; engine-binding `:339`; HBC header `:51–63`; principal crossing `:170/281/307`.
4. **`ProducerIdentityV1::Prepared { deployment_graph_digest }` at `artifact.rs:270–275`**; `DigestBoundPrepared` `:296–308`; `verify_for_admission` `:461–623`; fingerprint `:571`.
5. **`PreparedGraphCommitmentV1.deployment_graph_digest` at `arming.rs:53`.**
6. **HBC preflight at `module_runner.rs:459–469` is post-admission today**; generation uniformity `:3606–3608`; sticky `evaluation_outcome` `:4012–4059`.
7. **Root-principal EXECUTION collapse at `runner_pipeline.rs:6119–6131`** — and whether the **authorized linker** is already used on the committed-prepared path or the shortcut is.
8. **Dev channel tokens** (`IBEX_DEV_COMMITTED_*` at ~5996 / 6305–6324) and that `_MISSING`/`_AUTHORITY` (3443/3446) are armed-wrapper only.
9. **`verify_current_transform_fingerprint_v1` does not run under the v1 dev posture.**
10. **Landed C-ABI writes a report only on success** (0056 §8 contrast).
11. **Linked graph exposes only `namespace_json`** — no invoke export — so §7.3 is truly new.
12. **`ModuleSemanticsV1` / `semanticDigest` preimage does not include `deploymentGraphDigest`** (else §4.2 circularity).
13. **`native-startup-bootstrap.template.js` actually evaluate-then-invokes `installExactNativeAgentBootstrap()`** before app evaluation (r5 catch).
14. **Untokenized `bail!`/`anyhow!` set in §6.1 is complete** on `admit_committed_publication_v1` + `decode_and_admit` + `verify_for_admission` + preflight; missing sites are covering holes.

---

## Answers to the Standard Review Questions

**What do I think? Is it a good idea?**  
Yes. Package-aware admission cannot live only on the Exact side; ibex owns decode, carrier admission, link, and evaluate. Generalizing LLP 0042’s committed publication rather than forking a second loader is the right plan. Per-package roots are the only honest way to keep app bytes stable when `agent` joins. Evaluate-then-invoke is the r5 template catch, correctly promoted to an engine primitive.

**Do we have a good plan?**  
§11’s four legs are right: schema/corpus → admission/refusals → link/evaluate/C-ABI → Exact fold. Extracting `admit_package_v1` behind existing single-publication tests is the correct risk control. The plan **understates** the Exact amendment: 0056 cannot be Accepted as O-2-complete while 0413.001 §4.1 still has six placeholders with different steps/classes/ordinals.

**What would I change?**

1. **Publish a full replacement §4.1 table** (ordinal, code, step, class, unique predicate, landed sites covered). Keep the eleven distinctions; do not compress back to six. Assign ordinals so §5’s evaluation order *is* that table. Coupled Exact amendment in the same acceptance window.
2. **One remainder rule per step** — r6 defaults only. Map every known landed/un-tokenized class to a specific row.
3. **Slim the commitment** to `{schema, workflow, compositionRootDigest}` (plus whatever channel precheck still needs). Put live target/roles/clock/freshness only in expectations. 2a = digest + internal envelope consistency; 2b = envelope vs expectations in ordinal order.
4. **Restore defining-principal authorization** as the #29 predicate; keep the role cut at steps 5–6. State authorized-linker use in v1.
5. **Fix bound sites, alias disjointness, report field presence, fixture 35, HBC-preflight parameterization.**
6. **Machine-check the covering map:** `(file, line, landed token or bail string) → registry code`, grepped against the pin, so the 18-site CORRUPT enumeration cannot rot when the extract moves lines.

**Take away / don’t add.**  
Don’t add roles, armed posture, `parseFree`, or a second runtime. Don’t put `entry` back in the package. Don’t emit `unavailable-*` from ibex. Don’t invent the O-3 import-site algorithm here.

**Definitely or possibly wrongheaded?**  
Not the architecture. Wrongheaded *if shipped as written*: (1) remainder → corrupt **and** default → `package-root-mismatch`; (2) §10’s role-shaped “cross-principal” rule (reintroduces the round-1 principal/role bug under the inherited token name); (3) treating 6→11 + step/class edits as a pure O-2 substitution; (4) envelope-only enforcement of per-package bounds.

**Novel / non-standard improvements.**

- **Commitment is only a digest.** Everything else verifier-held. Kills C9 by construction.
- **Property-based multi-fault:** random conjunctions of injected faults, assert lowest ordinal — fixture 38 as a generator, not one row.
- **Later:** export descriptors carry `callable: true` so non-callable agent bootstrap becomes step-7 `entry-descriptor-invalid` instead of an admitted-lane boom. Out of v1 if descriptors stay untyped.
- **Merkle of per-record semantic digests** inside the package graph digest would make incremental app produce cheaper. Not needed for v1 correctness.

**Key open questions to refine.**

1. The full ordinalized replacement table (blocks everything else).
2. Unique predicate for every §6.1 class, especially `_DEPLOYMENT`, semantic-digest membership, and carrier vs artifact canonicality vs `carrier-integrity`.
3. Is v1 `cross-principal-denied` defining-principal (correct) or composition-role (redundant)? How does that sit on the authorized linker with EXECUTION collapsed to root?
4. AliasId ∩ SourceId; representative ownership before partition.
5. Report field-presence function for rc=0/1/2.
6. Does `semanticDigest` include any graph/commitment digest? (circularity)
7. Preflight in shared extract vs composition-only.
8. Should expectations include target/engine/encoding?
9. OQ-B (reuse `namespace_json` vs new Hermes invoke) can stay implementation-time **after** the §7.3 contract is frozen.
10. Promise-returning bootstrap: document as template-parity, or fail step 9 if the export returns a thenable?

---

## Recommended Next Step

Stay **Draft**. Revise r2 with: (1) a complete ordinalized covering table and named dispositions of all six r6 placeholders; (2) one default per step; (3) §10 rewritten around defining principals + an explicit authorized-linker sentence; (4) commitment/expectations field discipline; (5) alias disjointness, bound sites, report presence, fixture 35, preflight parameterization. Couple acceptance to a 0413.001 §4.1 amendment — do not claim O-2 discharged until both halves pin the same generated registry bytes. Then another dual-family round focused on the covering table and §10; the architecture does not need a new LLP.

---

## Verdict

Verdict: NOT READY — the architecture is right, but the O-2 map lacks ordinals and unique predicates, and several r6 rules (step of `target-profile-mismatch`, step-3 totality, defining-principal authorization, authorized linker, receipt field presence) would be implemented incorrectly as written.
