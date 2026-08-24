# LLP 0053 — grok family review artifact

## Round 1 (2026-08-24)
Reviewer: grok CLI, grok-4.6 @ xhigh (headless; terminal ban). Target: LLP 0053 r2 (sha256 032e0710be81393ca700c38063f54e2be1285c54d4d34c5ac8c139be7da1d06d, ibex revision 58899c284). Capsule: git-archive of origin/main; mutually blind. Orchestrator: Claude Fable 5 (author-side reviser, session exact-1d).

### Verbatim body

I'll start by reading the LLP review skill and the RFC itself, then check the cited code and schemas in this tree.The RFC is loaded. Next I’ll pull the cited code, schemas, and related LLPs so the review can check the r2 claims against the tree, not the document’s citations.I’ll now read the cited ABI, arming, and snapshot surfaces plus a prior review artifact so the line-level claims can be checked against this tree.The ABI cites look real so far. Next I’ll open the setter, snapshot schema, and authorization paths that the fail-closed matrix depends on.The cited setter and schema lines match. I’ll now check frame attribution, principal stacks, and the remaining strict-ingestion and surface-inventory claims.A few citations already look tight; I’m now checking principal/root identity, schema evolution, and the fail-closed setter matrix for holes.I’m now checking Principal identity, snapshot additionalProperties, digest defs, and the authorize/setter exclusivity rules the matrix depends on.I’ve confirmed several citations; next I’ll check ingestion (JSON Schema vs serde), producer ordering, ArrayBuffer extraction, and the I4 session-semantics surface.I have enough tree evidence. Next I’ll write the review artifact with verified line claims, the fail-closed holes, and a READY/NOT READY verdict.Adversarial soundness review of LLP 0053 r2 against this tree. Provenance is in `llp/reviews/0053-carrier-bearing-ingress-coordination.grok.md` (family grok, 2026-08-24). Binds RFC sha256 `032e0710be81393ca700c38063f54e2be1285c54d4d34c5ac8c139be7da1d06d` at ibex revision `58899c284`. This session did not author the draft.

The skeleton is right: one JS entry point, a sibling C setter, an engine-filled attribution struct, one `/2` snapshot addition, and “absence is never an ibex refusal.” It is not implementation-ready. The fail-closed matrix is a table, not a set of invariants on the authorize/latch/serde machinery that actually exists.

## File:line claims

Almost all of the cited lines are real. Two are not.

| Cite | Result |
| --- | --- |
| `hermes_runtime.cc:16828-16831` throws unless arity is 2 | True (bundled with type checks). |
| `root_global_disposition.generated.h:1029` `exact.invokeHostAsync` | True — conditional live-sweep row, not the main table. |
| `exact_runtime.h:1966-1967` callback inline on owner thread | True. Invoked from the Promise executor at `hermes_runtime.cc:16905-16911`. |
| AsyncFailureEvent / principal-status / “missing ≠ root” (`:1397-1432`) | True. |
| `ExactEmbedderContext` `:247-251`; nonce+principal `:585-593`; v1 setter `:1972`; producer `:2111-2117` | True. Zero is a legitimate **root** principal. |
| `Host::authorizes_exact_endowment` `src/host/mod.rs:2606-2630` | True; function continues through `:2635`. **It does not read `binding.schema`.** |
| `armed-snapshot.schema.json:75-95` optional `exactEmbedder`, const `/1` | True. |
| `arming.rs:293-298` `deny_unknown_fields`; `:1829-1831` refuses non-`/1` | True. |
| Frame-attribution VM pointer `hermes_runtime_internal.h:745-749` | True. |
| Principal stacks at `hermes_runtime_internal.h:65-107` | **False for Fetch.** `TimerEntry` / `NextTickEntry` have `principalStack`. `FetchCallbackEntry` has only `uint64_t principal`. |
| Stage enum `:598-608` | True, but it is the **runtime-extension operation** fragment, not a session-semantics presentation record. |

JSON Schema is not an ingest path. `ArmedSnapshot::load` walks a `Value`; the operational gate for this field is `ExactEmbedderBinding` serde plus `validate_exact_embedder_binding`. Nesting `carrierBinding` inside `exactEmbedder` is the only old-engine-loud place.

## Four r1 corrections

The RFC claims four and labels three.

1. **`runtime-surface.json` is the CLI surface.** Sound. `exact.invokeHostAsync` lives on the disposition row and `capsec/generated/surface-inventory.md`.
2. **I3 depends on I2.** Sound for ATTRIBUTED Exact `root_id` strings (`Principal` has no Exact rootId). Overstated for the rest of the struct, which can be delivered unarmed as `UNAVAILABLE`.
3. **“real-input/no-user principal carriers” names nothing here.** Sound. Live names are `currentPrincipalId`, `ScopedNativePrincipal`, `principalStack`, `ExHermesAsyncFailurePrincipalStatus`.
4. **Not listed.** The FetchCallbackEntry stack claim is a new miss, not a correction of r1.

## Callback thread and non-app-suppliable attribution

The callback **does** run inline on the runtime owner thread. Capturing engine truth at that call is sound if and only if the struct is **filled before** the embedder callback runs, then borrowed for that invocation only.

The proposed struct is not app-suppliable at the ABI: there is no JS field for it, the third argument is only carrier bytes, and the pointer is engine-owned `const*`. Keep it that way.

Do not treat it as live TLS. Do not borrow JS `ArrayBuffer` memory for the carrier (payload is already copied into a C++ vector first). Map `kNoUserPrincipalId` (`0xFFFFFFFE`) to `principal_status=UNAVAILABLE`; do not confuse it with root principal `0`.

## Fail-closed matrix holes

Stated table:

- generic armed → both setters `-8` (matches today: no `exactEmbedder` ⇒ authorize false)
- `/1` → v1 allowed, v2 `-8`
- `/2` → v1 `-8`, v2 allowed
- unarmed diagnostic → both allowed
- at most one of v1/v2 per runtime

Holes against this tree:

**v1 on `/2`.** Today’s `authorizes_exact_endowment` matches digest + endowment set only. A `/2` snapshot with the same vectors would authorize the **existing** v1 setter. “Via a sibling v2 hook” does not close that. The v1 path itself must refuse `schema == …/2`.

**v1/v2 latch.** One-shot, rollback, `begin_embedder_capabilities_v1`, and finalize all key off the **v1-typed** `exact_host_call_async_fn`. The v2 callback has extra parameters; stuffing it into that slot is a calling-convention bug. A second slot that is not on the same latch lets both install.

**I2 ingest shape.** New engine + `/1` must still arm. A required `carrierBinding` on the current single struct would refuse `/1`. An `Option` would accept `/1` *with* pins. The RFC never writes `/1` ⇒ field absent, `/2` ⇒ field present. `validate_exact_embedder_binding` is still hard-`/1`. `additionalProperties: false` on a `rootId` map forbids every key; that sketch is unimplementable as written.

**I3 zero pins.** ATTRIBUTED = exactly one pin for this context; multiple = AMBIGUOUS; unarmed = UNAVAILABLE. Zero matching pins on an armed `/2` runtime is unspecified. App and agent endowments must both be nonempty; `rootGrantSets` is 1..=256 **total**, not per context.

## I3-requires-I2

The dependency is true for ATTRIBUTED Exact `root_id` strings: those IDs are not ibex `Principal`s, so they have to enter under authentication. I2 `rootGrantSets` keys are that introduction.

It is not true that I3 “rides frame attribution with no parallel channel.” `principal_id` rides the live frame walk. `root_id` is a lookup of I2 pins against the runtime’s setter `ExactEmbedderContext` — runtime-granularity, not “which JS frame issued the call.” If one app Hermes runtime hosts multiple Exact roots, v1 I3 is always AMBIGUOUS.

The matrix also couples **I1 v2** to I2: v2 is refused on `/1`, so the carrier-bearing ABI cannot be used on armed Exact until I2 lands.

## I4

One record with a stage tag is a fine shape. The join point is wrong in the same way r1’s `runtime-surface.json` cite was wrong: `capsec/session-semantics/` is the LLP 0024 **evaluation-session** generator, not CapSec stage facts. Those already live on `capsec/schema/effect.schema.json` (`requested|discovery|candidate|commit|delivery|repeat|cleanup`). LLP 0052 has no “no-row-collapse” rule.

## Definitely / possibly wrongheaded

**Definitely:** enforcing `/2`⇒v1-refuse only on a new hook; a second callback slot without the existing latch; `additionalProperties: false` on a dictionary; describing Exact `root_id` as frame attribution with no parallel channel; parking I4 on `capsec/session-semantics/`.

**Possibly:** unique-pin-per-context as 0510 §6.1 step 3 if production is multi-root per app runtime; refusing v2 on `/1` (fail-closed, but it serializes I1-v2 behind I2).

**Not wrongheaded:** sibling C setter; one JS method with optional third arg (the arity throw is real); engine-filled struct; opaque 1..=64 carrier; one `/2` addition; pins as inputs not authority; delivering `CARRIER_ABSENT` rather than ibex-refusing.

## Open questions before implementation

1. One Hermes app runtime = one Exact root, or many?
2. Dual `/1`/`/2` serde shape (internally tagged enum).
3. Zero pins for this context: arming refusal, fourth status, or UNAVAILABLE?
4. Must every endowed context have ≥1 pin at arming?
5. Unified ingress latch + v1 authorize MUST refuse `/2`.
6. `root_id` lifetime; `kNoUserPrincipalId` mapping.
7. I4’s real schema home; what “no-row-collapse” names.
8. Host-task-ingress-inventory row for the v2 setter.

**VERDICT 0053: NOT READY** — MATERIAL: v1 can still authorize on a `/2` snapshot if only a sibling hook is added; v1/v2 callback-slot/latch torn state; `/1`/`/2` ingest shape unspecified (map `additionalProperties` unimplementable as written); I3 zero-pin status unspecified and “no parallel channel” false for `root_id`.

---

## Round 2 (2026-08-24) — punch-list delta
Target: LLP 0053 r3 (sha256 75b47d7c9c183ab6c9a629d13371917b46b15ed6f5397561bf12ef322eedc44c, ibex revision 268d35607). Per-family capsules, own punch list only.

### Verbatim body

I'll run this as a punch-list delta review: read the LLP 0053 skill and materials first, then verify each disposition against the r3 bytes without using the shell.Punch list is loaded. Next I’ll read LLP 0053 and the related RFCs so I can check each r3 disposition against the actual text.I’ll verify the r3 claims against the cited code, schemas, and related LLPs rather than taking the punch-list wording at face value.I’ll read the cited surfaces next and check whether the r3 line numbers and mechanisms still match the tree.The per-context pin rule may clash with a rootId-keyed dictionary. I’ll check LLP 0002 topology and the 0052/I2 shapes next.Checking one I4 join-point detail and whether the always-both-endowed tree actually collides with the r3 pin rule.**VERDICT 0053: READY**

No MATERIAL concerns. Bind: sha256 `75b47d7c9c183ab6c9a629d13371917b46b15ed6f5397561bf12ef322eedc44c` (ibex revision `268d35607`). Status remains Draft; this is a punch-list delta, not an accept.

The r3 folds land as real design changes, not wording. Tree cites I re-read check out. Leftover r1 problem-statement text and implementation join points stay below the altitude line.

---

## Disposition check (round-1 grok → r3)

| ID | Claimed fold | Against the bytes | Result |
|---|---|---|---|
| **M1** | Schema-aware authorize on **both** paths; existing v1 hook refuses `/2` | r2 §I1 matrix + enforcement paragraph. Today `authorizes_exact_endowment` (`src/host/mod.rs:2611-2635`) matches digest/context/ops only and never reads `binding.schema`. `ex_host_authorize_exact_endowment` is a boolean C hook (`src/host/abi.rs:4407-4439`). Refusing `/2` inside the existing v1 path, with a sibling `_v2` hook carrying the carrier-capable ask, closes the r2 hole without pretending a second setter is enough. Finalize asserting latch tag vs armed schema is required: `authorizes_embedder_capability_set` still has a single `EXACT_INGRESS` bit (`mod.rs:2637-2648`). | **Folded, sound** |
| **M2** | One owner-thread tagged latch `None \| V1(fn) \| V2(fn)`; all helpers on it | Current state is one v1 function pointer (`hermes_runtime_internal.h:965-970`). Every named helper actually touches it: one-shot (`hermes_runtime.cc:16779`), begin (`16688`), finalize installed-bit (`16723`), JS dispatch (`16828`, `16905`), rollback (`4637`), seal (`4644`), disposition activation (`8369`). v1 and v2 callbacks are different C types, so separately typed slots are required. | **Folded, sound** |
| **M3** | Internally tagged serde enum; `patternProperties` + `additionalProperties: false`; min/max TOTAL | Today `ExactEmbedderBinding` is a struct with `schema: String` + `deny_unknown_fields` (`arming.rs:292-298`) and `validate_exact_embedder_binding` hard-requires `/1` (`1829-1831`). `V1 {…no carrierBinding…} / V2 {…required…}` is the type-level version of “`/1` ⇒ field absent, `/2` ⇒ field present.” `patternProperties` + `additionalProperties: false` is the 2020-12 dictionary idiom this corpus’s schemas already use (`common.schema.json` `$schema`). A bare closed object cannot carry dynamic `rootId` keys. | **Folded, sound** |
| **M4** | Per-context ≥1-pin arming; zero-pin unreachable; 1..=256 TOTAL | Specified at r2 §I2 and consumed at §I3 (zero matching pins on armed `/2` → unreachable, else `UNAVAILABLE` + host fails closed). JSON Schema cannot cheaply say “≥1 pin per `context` value”; putting that at arming is the right layer. `maxProperties` 256 as a **total** dictionary bound is stated as such. | **Folded, sound** |
| **M5** | Root fields are a second authenticated-snapshot channel; r2 “no parallel channel” withdrawn | §I3 now splits principal fields (frame attribution) from root fields (pin lookup vs installed `ExactEmbedderContext`). Multi-root in one app runtime is permanently `AMBIGUOUS` in v1; growth is LLP 0052 execution-scope carriers. LLP 0052 §1 does say no `Principal` variant carries root/view/scope identity (`model.rs:306-324` is `Package/Root/Runtime/ModuleLoader/Quarantine`). | **Folded, sound** |

Non-material punch-list items are present, not cosmetic substitutes:

- I1-v2 serialized behind I2 is named as a chosen coupling (§I3).
- I4 Decision re-homes to `DecisionSet`/`DecisionContext` (`model.rs:1678-1706`; stage vocabulary on `capsec/schema/effect.schema.json`). `capsec/session-semantics/` is LLP 0024’s evaluation-session generator (`manifest.json` model source `session-semantics-model.mjs`).
- The withdrawn “LLP 0052 no-row-collapse” cite was a miscitation: 0052:319 is about durable-upload provenance rows, not I4 selector encoding. 0053 now requires full typed rows directly.
- Fetch correction matches the tree: `TimerEntry`/`NextTickEntry` have `principalStack`; `FetchCallbackEntry` has a single `uint64_t principal` (`hermes_runtime_internal.h:65-107`; store at `hermes_runtime_fetch.cc:304-310`).
- `kNoUserPrincipalId` is `0xFFFFFFFEu` (`hermes_runtime_internal.h:1644`); mapping to `UNAVAILABLE` and not to root principal 0 is the right status discipline.
- Host-task-ingress-inventory already has the v1 setter row (`host-task-ingress-inventory.json:1025-1036`); a v2 sibling row is the existing generator’s shape.
- Open questions 1–4 are decided in the r2 Decision headers; r3 also freezes `root_id_len` + no-NUL grammar, capture-before-observable, issuance-time replay defuse, candidate `presentationDigest`, and selector encoding. Remaining calendar/token/pattern items are explicitly assigned in “What this design does NOT decide.”

---

## r3 vs the tree (soundness)

Load-bearing cites are in the right neighborhood:

- JS arity-2 throw: `hermes_runtime.cc:16828-16831`.
- `extractArrayBufferView` does `hasProperty`/`getProperty` on `buffer`/`byteOffset`/`byteLength` (`hermes_runtime_internal.h:2355-2413`) — observable.
- Dispatch takes `Promise` from the mutable global (`hermes_runtime.cc:16864-16865`).
- Callback is owner-thread, inline (`exact_runtime.h:1960-1967`).
- Three Exact-bearing producers: `ex_host_prepare_exact_armed_embedder_artifacts`, `ex_host_build_exact_armed_embedder_artifacts`, `ex_host_build_exact_runtime_extension_armed_embedder_artifacts` (`exact_runtime.h:2094-2135`). Binding is written, then `freshen_document` (`embedder_artifacts.rs:1239` / `1430` then `1448`) — “embed before nonce freshening” is the actual order.
- `exact_embedder_binding()` returns an owned clone (`arming.rs:665-672`). Authorize hooks return `i32` 0/1 and transfer no projection.
- `exactEmbedder` is optional, const `/1`, `additionalProperties: false` (`armed-snapshot.schema.json:75-95`).
- Disposition row `exact.invokeHostAsync` is at `root_global_disposition.generated.h:1029`. `capsec/generated/surface-inventory.md` is generated review output (file header says so).
- App and agent-isolate endowments are both required nonempty; UI worklet must stay empty (`arming.rs:1852-1857`). Pin contexts `"app"|"agentIsolate"` match that closed pair.

The installation-time copied projection is the right consequence of the boolean-hook gap: I3 root lookup has to run in C++ at JS-call time against pins the setter already authorized. Capture-before-observable + immediate carrier copy + bootstrap Promise is the right order relative to today’s executor-mediated dispatch.

Replay-at-issuance (not at ibex install) respects 0510 §6.4: pins are authenticated inputs to Exact mint, not ibex authority.

---

## Non-blocking notes (not READY-gating)

1. **r1 problem statement is still r1.** Summary still says the RFC “deliberately does not design” the asks; Need/Related still point I4 at `capsec/session-semantics/` and still name `surface-inventory.md` as a JS-global authority. r2/r3 Decisions override this. Hygiene, not a second join point.
2. **Original “Open questions 1–4” section is still listed as open.** Answers live in the r2 Decision headers. Do not treat that leftover list as undecided.
3. **Per-context ≥1 pin + unique `rootId` keys + always-both-endowed snapshots.** A legal `/2` snapshot needs ≥1 `app` pin and ≥1 `agentIsolate` pin, hence ≥2 dictionary keys. That is compatible with “exactly one matching pin **for the installed context** ⇒ ATTRIBUTED.” It is not a demand that Exact’s deployment-manifest use one `rootId` for both isolates. If Exact’s mint wants one root identity in both contexts, the dict would have to become a list or a composite key — that is an Exact-join detail, not an ibex hole in the stated shape.
4. **LLP 0002 “single bundled root”** (`0002:754`) is the artifact producer’s one project root, not Exact `rootId` cardinality. Harmless as topology color; the operative I3 rule is the per-context pin count.
5. **I4 remaining field list is still a sketch** (leasePredicate members, `selectorSet` name vs “full typed rows”). Join point, candidate↔commit digest, and selector equality are decided. Schema combinator, DecisionSet version bump, and the C++ projection-copy API may finalize at implementation.
6. **Revised header** claims review artifacts under `llp/reviews/`; this tree has no `0053-*.md` reviews. Provenance nit, not a design defect.

---

**MATERIAL concerns:** none.

**VERDICT 0053: READY**

---

## Round 4 (2026-08-24) — grok delta on r5 — CONVERGENCE
Target: r5 (sha256 d0e206f3… @5b3eaa5ab) after two corrections-only revisions past grok's r3 READY. Verdict: READY, zero material; the LLP 0052 rows-never-collapse refutation of grok's own round-1 claim explicitly ACCEPTED on byte evidence. Same hash as the codex final — dual convergence.

### Verbatim body

I'll start with PUNCHLIST.txt and the review materials, then check the r3→r5 delta against the document bytes. No shell commands.PUNCHLIST is loaded. Next I’ll read 0053, the 0052 rows-never-collapse passage, and prior grok review artifacts so the delta can be checked against the bytes.The 0052 quote is in the file. I’ll check the restored citation’s surrounding rule, the surface-inventory header, and whether the r4/r5 edits left any live contradictions.Round 4 is a delta check of r3→r5 against the bytes in this checkout. I was READY at r3; this pass only re-opens what the punch list names, plus any **MATERIAL** contradiction the corrections themselves introduced.

I did not run a shell (so I did not recompute the hash). The verdict binds to the digest and revision the prompt supplied, after reading `llp/0053-carrier-bearing-ingress-coordination.rfc.md` and `llp/0052-durable-authority-mint-and-verify.rfc.md` in this tree.

---

### Punch-list item 1 — `grantSetId` grammar and complete-pin replay

**Landed.**

- `grantSetId` is specified as UTF-8, `1..=256` bytes, no embedded NUL (I2, the parenthetical on the `rootGrantSets` value object).
- Issuance replay now requires the **complete** pin: `grantSetId` **and** `grantSetDigest` per root, plus mapping digest and commitment digest — not ids alone.

That matches the r4 header and the punch list.

### Punch-list item 2 — three SUPERSEDED ask-site corrections

**Landed.**

| Site | Bytes |
|---|---|
| I1 surface authority (line 33, cleaned at r5) | ONE authority: the root-global disposition **generator**. `capsec/generated/surface-inventory.md` is generated review output, never an authority. The r4-mislabeled-as-r3 / plural-authorities tail is gone. |
| Related (inventory) | Same demotion: inventory is review output per its own header, not a second authority. |
| I3 ask | r1 “real-input/no-user carriers” is SUPERSEDED; mechanisms named as frame attribution, principal stacks, `currentPrincipalId`; root fields on the authenticated-snapshot channel. |
| I4 ask | r1 `capsec/session-semantics/` placement is SUPERSEDED; record joins DecisionSet/DecisionContext. |

The inventory file’s own header confirms the demotion: it is `@generated` “review output”; JSON registries and the observed source-surface manifest are what it treats as authoritative. That is compatible with 0053’s claim that it is not an authority for the JS `exact.*` global surface.

### Punch-list item 3 — LLP 0052 rows-never-collapse refutation

**I accept the refutation. I do not contest it.**

My r1 claim that 0052 has no no-row-collapse rule was **false**. In this checkout, 0052 line 319 ends:

> rows from distinct scope/grant identities never collapse.

That is the verbatim sentence 0053 now quotes (I4, restored at r4, citing 0052 lines 314–320). The surrounding paragraph is the constructible-provenance-witness rule: each `(effectIndex, principal)` row carries its own complete four-layer witness and execution-scope binding; distinct scope/grant identities do not collapse. Applying that to I4’s full-typed-row selector encoding (canonical equality; digests do not compose across distinct scope/grant identities) is a fair use of the same rule, not a new contradiction.

The r3 withdrawal on my unverified no-such-rule claim was the error. r4’s restore is correct. Lesson accepted: reviewer claims fold only after byte verification, in both directions.

---

### Delta-created MATERIAL contradictions

None.

The r3→r5 edits are corrections-only and internally consistent with the r3 design I already marked READY: complete-pin replay does not walk back the three pin classes; the SUPERSEDED ask sentences now match the r3 design; the restored 0052 citation matches 0052’s bytes.

I noticed a leftover round-label at the I1 **design** surface-deltas sentence (“r3 tightens r2’s phrasing” for the same inventory demotion that r5 retagged as an r4 edit on line 33). Same substantive claim, wrong round number. Not MATERIAL; r5 scoped the label fix to the ask sentence.

---

VERDICT 0053: READY. MATERIAL concerns: none.

Binds to sha256 `d0e206f3e1121176731eae2166d190a1b7bdfe3d281cddba76d07b3678fdef39` (ibex revision `5b3eaa5ab`).
