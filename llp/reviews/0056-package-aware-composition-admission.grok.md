# Review: LLP 0056 — Package-Aware Composition Admission (grok family)

**Reviewer family:** grok
**Model:** grok-4.6, effort xhigh, headless (`--output-format plain`)
**Mode:** full text of LLP 0056 r1 + Exact LLP 0413.001 r6 inlined in the prompt; no repository access (code claims routed as verification requests); blind to the sibling codex review
**Rounds:**
- Round 1 (2026-08-24): reviewed r1 (`fa7b5ed0d`). Verdict: NOT READY.
- Round 2 (2026-08-24): reviewed r3 (`54d142d78`), fresh headless session, mutually blind to the sibling codex round; full text inlined (0056 r3, 0413.001 r7 @246f959cc, both round-1 artifacts, dark-lane TS excerpts). Verdict: READY (0 MATERIAL; independently byte-verified the 38-row/defaults lockstep).

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


## Round 2 (r3, verbatim)

I'll start by reading the full review prompt and the LLP review skill so I can judge 0056 independently from the inlined documents.The full prompt is large, so I’ll read it in sections and pull the LLP review skill so the review follows that process.I’ll keep reading the inlined documents in chunks so the lockstep, fold, and pin checks rest on the actual text.I’ll keep going through the remaining inlined documents so the registry, envelope, and pin checks can be compared directly.DOC 1 and DOC 2 are in. Next I’ll read the round-1 reviews and the dark-implementation excerpts.The prompt file’s structure looks inconsistent in the first chunk, so I’ll re-read the missing middle of DOC 1 and the rest of DOC 6.I’ll extract the two registry tables and envelope sections so the lockstep and envelope-shape checks are exact, not visual.I have the full inlined corpus and a byte-level table compare. Next I’ll write the independent READY/NOT READY review from those checks, not from the round-1 artifacts.## Overall Assessment

This is a strong, implementable ibex leg of Exact LLP 0413.001 §6. Per-package content roots, a digest-only host-held commitment, a complete verifier-held expectations struct, envelope-side generation attestation, an ordinalized 38-row registry with one default per step, defining-principal authorization on the authorized linker, and tagged report shapes are the right architecture for fail-closed package-aware admission.

r3 does the two things a lockstep spec must do after r2: it records that Exact Amendment A1 adopted §6.2, and it pins the two dark-lane discoveries instead of leaving them as competing authorities. I independently confirmed the 38 registry rows and the Defaults paragraph are byte-identical across the two documents. Envelope shapes in §3.2, §3.3, and §4.8 match what 0413.001 r7 adopted.

No remaining issue changes admission outcomes, unique reachability, or the identity guarantee. Residual problems are wording traps and Exact-side note gaps. They should be polished; they do not block acceptance of this document.

## Conformance Findings (MATERIAL/MINOR, cite section numbers)

**MATERIAL:** none.

**MINOR**

- **§6 / §11 stale acceptance conjunction.** §11 still states, as a normative sentence, that the spec does not reach `Accepted` and O-2 is not discharged until A1 *and* generated-halves parity. The next sentence (“Resolved at r3”) retracts the peer blocker and keeps only the implementation gate. §6 has the same two-layer wording (“discharged when … generated registry byte-matches … and F-i …”; then “discharged at the document level”). Operative intent is clear; an acceptor should not have to rank two adjacent sentences.
- **§6.2 “0056-relative in both repositories” is not actually declared on the Exact side.** The shared table bytes contain `§4.4` / `§4.8` / `§10` (#17, #22, #34). 0056 correctly defines those as 0056-relative. 0413.001 §4.1’s surrounding prose does not. In Exact, §10 is Obligations, not the authorized-linker policy. The unique predicates remain readable in English, so this is a footgun, not a semantic fork.
- **§9.1 last paragraph is stale versus r3.** It still says “Until the O-1 package lands … leg 1 starts only against the landed O-1 schemas,” while Summary / §11 record that a seed *has* landed and leg 1 *holds* until it is r7-shaped.
- **#11 predicate still says committed `(role, packageRoot)`** after item 2 became triples. The digest check is still against `packageRoot`; generation is #22. Harmless, slightly stale.
- **0413.001 §4 step-2b narrative (peer, not 0056) omits #5 and authority-generation.** 0056 §5 2b names both. Exact’s table and “predicate order = ordinals” rule win; the Exact step list is incomplete relative to the amended table.

## Fold Verification (r1 -> r2/r3: held / not held, per finding)

Mandatory set:

| Finding | Result |
| --- | --- |
| Full ordinalized 38-row registry; one precedence tuple `(step, ordinal, roleOrder)`; one default per step (r1 dual-default at step 3 gone) | **Held** — §5, §6.2, Defaults `1→#1 … 8→#38` |
| Covering map total and injective on its own terms | **Held** — §6.1 classes each have a §6.4 disposition; splits (`_CORRUPT`→#14/#25, `_ENTRY`→#35/#36, `DEV_COMMITTED_*`→channel/#5) are unique-predicate splits, not overlapping live codes; `_DEPLOYMENT` is only #21 (r1 three-way split is gone); `carrier.rs:170` is producer-side, not on the map |
| Defining-principal `cross-principal-denied` on the authorized linker | **Held** — §2, §5 step 6, §7.2, §10; v1 generalizes `link_authorized_prepared`, never `link_prepared`; fixture F is a defining-principal craft, not a role-cut duplicate |
| Decidable generation attestation (§4.8) | **Held** — envelope `(role, packageRoot, producerGeneration)`; package bytes generation-free |
| Complete verifier inputs (§3.2/#3.3, slim commitment) | **Held** — commitment is `{schema, workflow, compositionRootDigest}`; expectations carry `expectedTarget`, `expectedRoles`, freshness, `resolverInventoryDigest`, `nowUnixMs`; engine identity is a named runtime query |
| Bounds split by enforcement surface | **Held** — §3.1 envelope vs package-index; limit/limit+1 at both surfaces |
| Tagged report shapes (§8) as a function of outcome | **Held** — `channel-error` / `refused` / `admitted` / `admitted-startup-error`; step 9 never mints a registry `reasonCode` |
| Fixture 35a/35b | **Held** — §5 D8, §9.2, and Exact §7 |
| Alias disjointness | **Held** — §4.7 `aliasId ∩ owned SourceId = ∅` → `alias-conflict`; composition-wide, before step 4 |
| HBC preflight composition-only | **Held** — §5 step 3, §11 extract “behind parameters” |
| Purity theorem restated | **Held** — §4.1: app bytes are a pure function of the app graph; agent may name app `SourceId`s only in typed external rows, never app bytes/digests |

Other r1 folds, briefly: encoding sniff #17 **held** (§4.4); D3 fingerprint drop **held**; untokenized I/O/facet/candidate/dev-wrapper sites **held** (§6.1/§6.4); tagged `local`/`external` bindings **held** (§4.5); `mainRoot = app` + monotonic executor + `CompositionSessionV1` **held** (§7.2–§7.5); step-7 order-guarantee **held**; I-JSON **held**; domain literals **held**; thenable honesty **held** (§7.3); OQ-C counts **held**; Exact projection as subset **held** (§8); generated enum from vendored registry **held** (§6.3); D1–D9 **held**.

**Not held (minor only):** grok d5’s explicit “far-future expiry is a policy-digest problem, do not add a second lifetime channel” sentence is not in r3. Expiry vs `nowUnixMs` is specified; the policy note is not.

## Lockstep Verification (6.2 vs 4.1; envelope shapes)

**Tables and Defaults.** Extracted the 38 `| # | … |` rows and the Defaults paragraph from both documents and compared them as printed. **The 38 rows are byte-identical. The Defaults paragraph is byte-identical** (`1→#1, 2a→#2, 2b→#10, 3→#11, 4→#24, 5→#28, 6→#29, 7→#35, 8→#38` plus the totality sentence). No table drift.

**Surrounding prose, consistent where it matters:**

- Precedence tuple `(step, ordinal, roleOrder)`, app before agent: both documents.
- Within-step order is ordinal order: both documents.
- D1–D9: 0056 states them; Exact’s O-2-status paragraph points at 0056 D1–D9 and restates D1, D2, D3, D4, the encoding sniff, and D6. D5/D7/D8/D9 are realized in the shared table and in Exact’s 35a/35b split. Not silent substitution.
- Environment codes stay outside the registry on Exact (`composition-unproducible`, `producer-refused-composition`, `agent-composition-unavailable`, `composition-admission-unimplemented`). 0056 correctly never emits `unavailable-*`. Channel tokens `IBEX_DEV_COMPOSITION_CORRUPT` / `_SCHEMA` / `_ARMED_CONTEXT` match.

**Envelope shapes (task c) — semantic match, no MATERIAL mismatch:**

| Surface | 0056 | 0413.001 r7 | Match |
| --- | --- | --- | --- |
| Commitment | §3.2 `ibex/prepared-composition-commitment/1`: `schema`, `workflow`, `compositionRootDigest` only | §3.3 dev-unarmed: digest-only host-held record of that schema, “no envelope fact duplicated” | Yes |
| Expectations | §3.3 `ibex/composition-verifier-expectations/1`, every field mandatory: `expectedTarget`, `expectedRoles`, `sessionNonce`, `authorityGeneration`, `resolverGeneration`, `policyDigest`, `resolverInventoryDigest`, `nowUnixMs`; I-JSON `0..=2^53-1` | §3.3 lists the same fields, all mandatory, I-JSON integers; `resolverInventoryDigest` structurally discharges O-3’s verifier-input half | Yes |
| Attestation | §4.8 `(role, packageRoot, producerGeneration)` | §3.1 item 2, same triple; package bytes generation-free; else `generation-splice` | Yes |

DOC 6’s dark `PreparedCompositionV1.packages` is still `(role, packageRoot)` without `producerGeneration`. That is the r6-shaped seed 0056 already flags; it is not a spec-level fork between 0056 and r7.

## Dark-Impl Pin Assessment (d1, d2)

**(d1) Blessing the two-member reason mapping — right call, precise enough.**

DOC 2 §2.5 is a closed two-member enum plus a locality rule: a reason must be derivable from the owning package’s own graph facts and must not reference the other package. DOC 5’s `bindEdge` maps both “specifier resolves to nothing” and “resolves to a record this package does not publish” (boot-core termination; app target outside the external universe) to `"target is not a bundle module"`.

Minting a third member would be wrong. Step-6 #30 must recompute from package-local facts. Distinguishing unresolvable vs resolvable-but-excluded requires the other package or whole-project resolver state, which §2.5 forbids. A third member that named “the other package” would also break §2.1 app-byte identity: the computed bootstrap seam is an app-package host-bridged row, and its reason must not change when `agent` joins.

The blessing text is implementable: it defines the *reason value* on inventory rows, not inventory membership (membership stays 0413.001 §2.4: bound iff local published record, or agent typed-external to `app`). v1 composition produce never applies lowering fallback, so the second member is reserved; any other string, or any set/reason divergence, is #30. One clarifying sentence would help: this reason is only for unbound literal-dynamic inventory rows, never for typed external references. Not required for implementability if §2.4 and §2.5 are read with §4.3.

**(d2) Envelope triple as the only serialized generation carrier — correct and complete.**

`PreparedPackageDeliveryV1` (DOC 6) puts `produceGeneration` beside package bytes. That value sits outside the package root (index bytes only) and outside the composition root (envelope only), so it would be an unauthenticated input to #22 and a second serialized carrier of one fact — the defect class r2 killed by slimming the commitment.

Pinning the envelope triple as the only *serialized* carrier, allowing a producer-internal in-memory ferry, and forbidding O-1 to define a wire sidecar is the right split. Admission must not consume a wrapper if one appears; extra files fall to #13 inventory. Completeness is adequate for admission. Alignment should demote `PreparedPackageDeliveryV1` in `prepared-composition-schema.ts` to a non-exported in-memory type so O-1 cannot grow it into a wire schema.

## Design Concerns (MATERIAL)

None. The r3 pins do not reopen unique reachability, fallback eligibility, or the identity guarantee.

## Design Concerns (MINOR)

- **Step 3 evaluation order vs `admit_package_v1`.** §5’s authority is `(step, ordinal, roleOrder)` and “the table IS the evaluation order.” Step 3’s “`admit_package_v1`, app then agent, in ordinal order #11–#24” is easy to implement as *full app, then full agent*. That would make `(3, #12, app)` beat `(3, #11, agent)`. One sentence that both packages’ #11 run before either package’s #12 would remove the trap. Fixture 38’s property-based lowest-tuple generator is the backstop.
- **Authorize at both step 6 and step 8.** §5 step 6 runs defining-principal authorization → #34. §7.2’s constructor also authorizes, and step 8 maps any failure to #38. Say that step 8 consumes receipts already decided at step 6 (idempotent), so policy denial cannot migrate to `link-failure`.
- **`*_for_roots` argument order.** Fixture 1 requires shared app-owned records to evaluate in the agent segment. Pin that `linkage_order_for_roots` / `synchronous_evaluation_order_for_roots` take entry-plan order (agent then app).
- **d1 identity-guarantee rationale** is implied, not stated. Worth one clause: a third reason member that mentioned the other package would change app inventory bytes when `agent` joins.
- **g5 expiry/policy note** still absent (fold miss).
- **Clean §11** to a single current acceptance sentence; drop the exhausted peer-blocker condition.
- **Ask Exact** to add, *outside* the shared table bytes, the 0056-relative section-ref note.

## Verification Requests (code claims to check)

I did not treat these as defects. They are load-bearing 0056 citations I cannot re-verify from inlined material:

1. §6.1 landed-token sites and the 18-site `_CORRUPT` list at `runner_pipeline.rs` (incl. 3825 = repeated `SourceId`).
2. `runner_pipeline.rs:3765` / `3734-3738` — fingerprint expectation tautological in dev; independent currency check skipped (D3).
3. `runner_pipeline.rs:3676-3685` peek making `carrier.rs:327` unreachable; `carrier.rs:339` engine-binding prose.
4. `carrier.rs:170` producer-side only; admission grouping at `281`/`307`.
5. `runner_pipeline.rs:6187` `link_prepared` as the unauthorized shortcut r6 forbids for compositions.
6. Whether landed candidate tables embed a generation field inside package bytes (would fight §4.3 generation-free purity; not introduced by d2).
7. `ModuleSemanticsV1` / `semanticDigest` preimage does not include a graph-level digest (§4.2 no-circularity).
8. HBC preflight at `module_runner.rs:459-469` is post-admission on the single-publication lane today (composition-only parameterization claim).
9. Covering-map completeness of remaining `bail!`/`anyhow!` sites on `admit_committed_publication_v1` + `decode_and_admit` + `verify_for_admission` after the r2 additions.

## Answers to the Standard Review Questions

**What do you think of this proposal? Is it a good idea?**  
Yes. Whole-publication `deploymentGraphDigest` cannot keep app bytes stable when an agent package joins. Per-package roots plus a composition envelope is the only honest schema. Fail-closed nine-step admission, with ibex owning decode/carrier/link/evaluate, is the right split of 0413.001 §6.

**Do we have a good plan?**  
Yes. Four legs (schema/corpus → admission/refusals → link/evaluate/C-ABI → Exact host fold), extract `admit_package_v1` behind existing single-publication tests, generate the refusal enum from a vendored registry, and do not admit for real until leg 3. Holding leg 1 until O-1 is r7-shaped is the correct response to the live parity miss.

**How would you change it?**  
Polish only: one current §11 sentence; ordinal-outer wording at step 3; step-6 vs step-8 authorization idempotence; entry-plan order for `*_for_roots`; Exact-side 0056-relative note; d1 identity-guarantee clause; demote `PreparedPackageDeliveryV1` to in-memory on alignment.

**Add / take away?**  
Do not add a third host-bridged reason, a serialized delivery sidecar, roles, armed posture, `parseFree`, a second runtime, or ibex-emitted `unavailable-*`. Do not put `entry` or generation back into package bytes. Optional extra fixture: committed inventory with a third reason member → `(6, boundary-inventory-mismatch)`.

**Definitely or possibly wrongheaded?**  
Not the architecture. Overloading `"target is not a bundle module"` is linguistically slightly dishonest and semantically forced; a third member would be the wrongheaded move. Treating generated-JSON parity as a spec-acceptance peer blocker after A1 would also have been wrongheaded — it would couple this document’s `Accepted` to an implementation artifact 0413.001 itself did not wait for.

**Novel / non-standard improvements (out of v1, not blockers):**  
Name one package-local “published-record resolution” helper in O-3 and use it at both produce classification and #30, so those cannot drift. Later, optional `callable: true` on descriptors could move non-callable bootstrap from admitted-lane boom to step 7 (0056 already correctly leaves callability to runtime for v1). Merkle of per-record semantic digests inside the package graph digest would cheapen incremental app produce; not needed for correctness.

**Key open questions to refine (implementation, not spec holes):**  
OQ-A (inline vs digest-referenced artifacts), OQ-B (native invoke shape), OQ-D (thenable bootstrap). Plus Exact-side: delete or un-export `PreparedPackageDeliveryV1` as wire; add `producerGeneration` to envelope `packages[]` in the r7-shaped O-1 seed.

## Recommended Next Step

Author may accept. Optional r4 polish of the MINOR wording items in the same commit is worthwhile and not required for the admission semantics to be frozen. Implementation leg 1 stays blocked on the exact-side r7-shaped O-1 alignment report; do not decode against the r6-shaped seed.

Verdict: READY
