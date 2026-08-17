# Review artifact: ibex LLP 0052 — Durable Authority Mint & Verify (family: grok)

Super-refine loop artifact. Reviews recorded verbatim per round.

## Round 1 — 2026-08-17

**Round record (persisted before launch):**

- Target: `vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md` r1 (     332 lines) — the ibex-corpus mechanism LLP that Exact LLP 0476 (Accepted 2026-08-17) delegates its byte-exact crypto / protected-object / mint-verify / WP6 work to.
- Target sha256: `984d69f5da2f8df89f6ea3140e7e729054c6276f3b89f4d7bd591f73cc6f47ae`
- Instruction (shared prompt) sha256: `a9bdc329106eb65c483bb085f09bbe912c22cfbbc6212e47635dd861061c7b7c`
- Topology (author-directed, Charlie Cheever, 2026-08-17 — same method as LLP 0475 and 0476): reviewers codex `gpt-5.6-sol` @ xhigh + grok `grok-4.6` @ xhigh; editor codex `gpt-5.6-sol` @ xhigh; late Claude (fable) final review once both families READY/nitpicking. Orchestrating Claude neither reviews nor revises.
- Capsule: read-only checkout; blindness instruction-fenced (self-attested) — forbidden vendor/ibex/llp/reviews/, llp/reviews/, scratchpad/tmp, non-target 0052* files, and the 0476 review artifacts; no network. Reviews sealed in orchestrator scratchpad on receipt, copied here once both round reviews land.
- Runner: grok headless, grok-4.6 @ xhigh, plan mode

**Receipt:** completed 2026-08-17; grok-4.6 @ xhigh headless; body sha256 `8581ac162684d54f78a38efb7ae219f355bed61078703a1613364d5126095a7f`; binds r1 sha256 `984d69f5…`. Verbatim below (leading narration part of capture).

---

I'll review the ibex durable-authority RFC as an independent security reviewer: first the target in full, then the governing 0013/0021/0476 context, then the load-bearing code claims. I will not read any 0052/0476 review artifacts or scratchpads.The RFC is in. Next I’ll read the 0013/0021/0476 context and open the cited host, CapSec, fetch, and Secure Store files to check the load-bearing claims.I have 0476 and the 0013 handle. Next I’ll open the cited host, CapSec, fetch, and Secure Store implementations and the WP6 section of 0021.The Cargo and handle-mint claims look solid. I’ll now check CapSec types, the armed-fetch closure, Secure Store’s JS reachability, and the module trampoline.0472’s title doesn’t match the four-layer intersection this RFC cites. I’ll open that document and confirm the generation-tuple and cache-identity facts.I have enough to judge the design. One load-bearing witness is weaker than the 0021/0476 identity it claims to extend; the rest of the claims checked out against the code.

## Overall Assessment

This is the right LLP: Exact 0476 correctly parked the native trust-domain mechanism here, and r1 extends 0013/0021 instead of inventing a second policy engine. The key-facility isolation story, the “sign exact TLV bytes, not canonical JSON” choice, the no-raw-path staging rule, the write-once theorem (including the Apple `fromFile:` honesty), the Keychain-is-not-monotonic caveat, and the WP6/armed-closed stance are all the right shape.

It is not ready. The mint/verify witness this document specifies is strictly weaker than the 0021 decision-cache identity and the 0476 §2/§3 obligation it is supposed to implement. Durable upload always has at least two authority edges (source handle + `network:fetch`). Collapsing those edges — and 0021’s `{policy, negative, dynamic, handle}` generations — into one grant identifier and one generation (grounded on `mint_typed_handle`’s handle counter) is a missed-revocation design, not a missing implementation note. A second delegated hole: the JS-dead registry never says it will ingest Exact 0472 four-layer publications, so an OS or view-broker revocation after mint is invisible to verify.

Every load-bearing “today’s code” claim I was asked to check is true, with one citation nit (`ProtectedObjectGuard` lives in `decision.rs`, not `model.rs`).

## Material Findings

1. **Mint/verify witness is singular; 0021/0476 identity is a set-plus-tuple. That is a missed-revocation race.**
   - **Claim:** §4 step 5 compare-and-commits “the typed authority generation,” grounded on “the atomic generation advance of `mint_typed_handle`.” The certificate carries “the authority-source/grant identifier” and “a mint generation,” plus a singular “typed network selector” (§4 last paragraph).
   - **Evidence:**
     - 0021’s live cache identity is `armed_snapshot_digest` + `policy_digest` + `GenerationSet { negative, dynamic, handle }` + `PositiveAuthorityContext { handle_ids, dynamic_grant_ids, operation_lease_ids, … }` (`vendor/ibex/crates/capsec-semantics/src/cache.rs:19–27, 40–44, 57–73`). Snapshot generations also include `policy` (`vendor/ibex/crates/capsec-semantics/src/arming.rs:301–305`).
     - `mint_typed_handle` advances **only** `generations.handle` (`vendor/ibex/src/host/mod.rs:4340–4374`).
     - `revoke_typed_dynamic` advances `negative` and `dynamic`, **not** `handle` (`vendor/ibex/src/host/mod.rs:4149–4168`). A matching test asserts handle is unchanged after dynamic grant/revoke (`vendor/ibex/src/host/mod.rs:13669–13685`).
     - Exact 0476 already froze the required witness: `authoritySources: canonical nonempty [{ sourceId, grantId, mintGeneration }]` and “`mintGeneration` is the authenticated ibex policy/negative/dynamic/handle generation tuple” (`llp/0476-durable-capability-capsules.rfc.md:94–96, 116`). Commit “compares the armed snapshot, every authority source/grant id, and mint generation” (`0476:262–267`).
   - **Severity:** MATERIAL.
   - **Why it blocks:** The first consumer (durable upload) always uses **two** edges — authenticated source handle and typed `network:fetch`. A singular grant id can record only one. A singular generation, especially if implementers follow the `mint_typed_handle` pointer, does not move when a dynamic grant or 0472-published permission is revoked. Trajectory: evaluate source+network → start staging → revoke the *other* edge or a dynamic/0472 grant → handle generation unchanged → compare-and-commit succeeds → a receipt is published for authority that already linearized as revoked. That is exactly the race 0476 assigned this LLP to close. Fix: the sealed witness is the full 0021 cache identity (snapshot + policy digest + `{negative, dynamic, handle}` + every `sourceId`/`grantId`/`handleId`), and compare-and-commit is equality of that whole tuple under the same lock revoke uses, from the after-read through journal publication.

2. **JS-dead revocation registry does not ingest 0472 four-layer publications, and verify does not re-check OS ∩ view-broker.**
   - **Claim:** §6 records “a live grant revocation” as a native authority generation so verify can see “policy replacement or grant revocation.” Verify §5 steps 1–5 never re-evaluate OS permission or view-broker grant.
   - **Evidence:** Exact 0476 requires the ibex registry to receive “authenticated ibex **and LLP 0472 four-layer** generation publications,” queryable with JS dead (`0476:272–274`, restated at `0476:701–704`). 0472’s four-layer model is real (`llp/0472-web-standards-first-runtime-apis.rfc.md:287–288, 806–818`). Ibex 0013 already says OS grants mutate behind the runtime and must be checked live, not cached (`vendor/ibex/llp/0013-per-package-capability-compartments.rfc.md:527–531`). `GenerationSet` has no OS/view-broker slot (`cache.rs:40–44`).
   - **Severity:** MATERIAL.
   - **Why it blocks:** After mint, the user can revoke Photos/network in Settings, or the view broker can drop the grant, with no ibex handle/dynamic generation change. JS-dead URLSession resume then verifies a still-valid MAC, a matching digest, and an unchanged ibex generation, and sends. 0476 explicitly put the 0472 publication ingress on this LLP; omitting it is a missed-revocation class, not altitude. Fix: specify a native, authenticated Exact→ibex publication of the four-layer generation vector into the same registry; verify fails closed on missing/stale 0472 state; do not treat 0021 handle generation as a proxy for OS/broker.

## Minor Findings and Nits

1. **`alg` inside the MAC does not, by itself, close algorithm confusion.** §3 says putting `alg`/`kid`/`iss`/`aud` in the authenticated header “covers” downgrade and audience confusion. Authenticated `alg` only stops *undetected modification*. The JWT-class bug is the verifier *selecting* HMAC vs ECDSA from the message, including HMAC-with-the-ES256-public-key. The actual close is the §2 pin (“SE-minted install refuses HMAC”) plus “verify with the pinned key’s algorithm; refuse `alg` mismatch; never use public-key bytes as an HMAC key.” State that as the rule. `iss`/`aud` stop cross-domain replay; they do **not** make a portable envelope “execute once” (0476 §7 still needs the `(issuer, aud, operationId)` lease). No kind ships, so this is not today’s send hole.

2. **“ASN.1 or fixed r‖s” must become one encoding.** Two legal ES256 encodings are a confused-verifier footgun the moment any later binding hashes signature bytes (lease `certificateHash`, kid rotation). Pin one (prefer fixed low-S `r‖s`) and reject the other.

3. **`ProtectedObjectGuard` is not in `model.rs`.** It exists at `vendor/ibex/crates/capsec-semantics/src/decision.rs:124–132`. Principals (`model.rs:306–324`) and `NetworkRequest` scheme/host/port (`model.rs:1233–1243`) are where the RFC says they are. Related-header citation should move.

4. **Related-line “0476 §14/§16” is the wrong pair.** In the Accepted 0476 I read, §14 is the platform matrix; the MUSTs this LLP owns are §6–§8 plus §16.1. §17’s four questions do match §11.

5. **`currentPrincipalId()` is a `uint64`, not a tagged `Principal`.** §1’s shorthand is slightly loose. Capture must be the same walk `checkCapabilityWithFsMode` uses — actor, effect owner, and the constrained set (`vendor/ibex/src/engine/hermes_runtime_internal.h:1735–1745, 1801–1819`) — then mapped through the armed snapshot. Numeric id alone cannot represent Root vs package integrity.

6. **Certificate list vs 0476 `DurableUploadCertificate`.** Even aside from Finding 1, the informal carry-list omits sealed `kind`, `byteCeiling`, `sourceAuthoritySelector`, and the nonempty `networkSelectors` set. 0476 §2 required this LLP to freeze that schema for the native-held receipt (not only for a future portable kind). After Finding 1 is fixed, freeze the TLV schema rather than paraphrasing it.

## Answers to the Standard Questions

**Good idea?** Yes. Persistable, JS-dead, unforgeable carriage of an *already evaluated* typed grant is the only honest way to do background native work under 0013/0021. Putting it in ibex, as an extension of handle mint rather than a new capability namespace, is correct.

**Good plan?** The skeleton is good: sibling key facility → exact-byte envelope → capture-then-evaluate-then-stage-then-digest-then-compare-and-commit → constructed write-once → external epoch → WP6-closed adapter → fail-closed platform matrix → no portable kind in this cut. The plan becomes a good *security* plan only after the witness and the 0472 registry ingress are specified at 0021/0476 fidelity.

**Add / remove / change?**
- **Change** the certificate and compare-and-commit to the full 0021 identity (Finding 1).
- **Add** the Exact→ibex 0472 generation publication and a verify check of it (Finding 2).
- **Change** §3: verifier uses the pinned key algorithm; `aud` ≠ once-execution; pin one ES256 encoding; reject duplicate TLV tags (sign exact bytes, never re-encode before verify).
- **Add** to §2: the algorithm pin is an observation of the live key’s token/class (or lives only in the sibling facility), not a JS-reachable flag; HMAC keys are `ThisDeviceOnly` / non-sync, never `kSecClassGenericPassword` in the default access group.
- **Do not add** a portable kind, a second policy engine, or a mint-time peer attestation.

**Definitely / possibly wrongheaded?**
- Definitely: singular grant + singular generation as the revocation theorem.
- Definitely: “`iss`/`aud` ⇒ execute once.”
- Possibly: “authenticated `alg` covers confusion” if implementers take it as the complete rule.
- Not wrongheaded: HMAC-verifier-is-an-issuer; SE-refuse-HMAC; fail-closed on transient SE failure; digest-recheck-is-not-the-theorem; Keychain-is-not-monotonic; deferring the portable kind; keeping armed background closed.

**Key open questions?** 0476 §17 / this §11 Q1–Q4 are the right remaining *selection* questions. After the two findings are closed, the ones that still matter are: which Apple write-once construction survives `fromFile:`; which epoch construction is actually monotonic across restore; whether URLSession can ever emit WP6 peer/candidate facts; and (this document’s Q5) handle+receipt vs a first-class typed inbox resource.

## Novel Ideas

- **Derive the algorithm pin from the live key object** (`kSecAttrTokenIDSecureEnclave` present ⇒ refuse HMAC), rather than storing a mutable “we are an SE install” flag. That is the only airtight no-downgrade I can see.
- **Treat the 0021 `DecisionCacheKey` (minus stage-specific resource bytes) as the mint witness type.** Do not invent a parallel generation. Export it as the “authenticated mint witness” 0476 asked for.
- **Custom `URLProtocol` / stream over an fd-only inode** is the only way I see to keep the strong write-once theorem and Apple background upload; named-file + `UF_IMMUTABLE` should stay a documented unavailability, not a hoped-for theorem.
- **Epoch: Secure Element counter or it is not an anchor.** Do not spend design time making a Keychain item “feel” monotonic.

## Implementation-Phase Notes

These do not drive NOT READY once Findings 1–2 are specified.

- TLV: versioned tag table, big-endian lengths, unique tags, reject duplicates and unknown tags, bounded timestamps; MAC over the exact received header+claims bytes; never JCS-roundtrip before verify.
- Hold the 0021 decision-context write lock (or the SQLite guard 0476 names) from the post-staging generation/snapshot re-read through receipt+lease+task publication. Staging itself must not hold that lock.
- JSI hook: capture in `ex_hermes_set_module_dispatch_callback` / `ex_hermes_set_module_sync_callback` (`vendor/ibex/src/engine/hermes_runtime_ios.cc:392–426, 451–513`) *before* the embedder callback. Today those host functions forward bytes and capture nothing. `ModuleBridge.handleAction` may then hop `DispatchQueue.main.async` (`ios/ExactApp/ExactApp/Modules/ModuleBridge.swift:74–82`). A read-at-entry then async work is compatible with Exact LLP 0297; it is not a cross-thread sync module call. Register the callback-affinity row.
- Sibling key module: no `ModuleRegistry` name; `kSecClassKey` (not GenericPassword); no access group that `com.exact.securestore` can name (its `baseQuery` is class + service + account only, `packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:298–303`). Negative tests against real reserved identifiers *and* guessed ones.
- AES-GCM receipt AAD as 0476 specified; journal key in the same sibling facility.
- Register `durable-authority-signed-required` plus the transfers module/resource selectors 0476 §10 said this LLP owns.
- `byteCeiling`, adapter id/version, redirect leak acceptance stay inside the sealed certificate, not only in verify prose.
- Per-install boot salt: generate when the sibling facility has no key; store this-device-only, not next to the rollbackable journal. Real value against cross-install container restore; theater if it restores with the journal.
- Direct `ring` dependency when Rust first signs/AEAD; do not call through the rustls-transitive edge (`vendor/ibex/Cargo.toml:85–86, 123, 309–315`).

### Load-bearing claim audit (all opened)

| Claim | Verdict | Cite |
|---|---|---|
| 1. `ArmedSessionToken` 32-byte OS-random nonce, snapshot-bound, wipe-on-drop, pointer identity, non-portable | **Holds** | `evaluation.rs:196, 213, 236–239, 254–256, 274–276`; `mod.rs:2362–2445` |
| 2. `check_handle_mint` explicit grant, no Root ambient; `mint_typed_handle` binds snapshot + actor-in-stack | **Holds** | `capability.rs:705–728` vs ambient Root at `697–698`; `mod.rs:4305–4335, 4363` |
| 3. `digest_authenticated_projection` = `domain ‖ u64_be(len) ‖ payload`; TLV extends, does not reuse | **Holds** | `mod.rs:448–456` |
| 4. Tagged principals; fetch scheme/host/port; `ProtectedObjectGuard` exists | **Holds** (guard is in `decision.rs`, not `model.rs`) | `model.rs:306–324, 1233–1243`; `decision.rs:124–132` |
| 5. Secure Store `getItem` any service/account; authenticated path unimplemented; no sign/verify | **Holds** | `api.ts:10–16, 94–98`; `SecureStoreModuleImpl.swift:111, 198–199, 221–241, 298–303` |
| 6. Armed typed fetch closed; WP6 requires actual peer; mint cannot attest future peer | **Holds** | `hermes_runtime_fetch.cc:188–214, 552–555`; 0021 WP6 `1789–1805` |
| 7. `hmac`/`sha2` direct; `ring` vendored/transitive, not a root dep; CryptoKit present on Swift | **Holds** | `Cargo.toml:85–86, 123, 309–315`; CryptoKit imports under `ios/ExactApp/` |

### Design evaluation (a–f)

**(a) Key facility.** Sufficient **if** the sibling module has no JS surface and the HMAC material is not a default-group GenericPassword. Current Secure Store cannot read `kSecClassKey` / SE keys (no access group, no key class). Residual JS routes if someone “implements” HMAC as `kSecClassGenericPassword` under a guessable service — the RFC already forbids that and demands negative tests. The SE-refuses-HMAC pin is airtight only if it is a live key-class observation (or lives only in the sibling facility). A JS-reachable pin flag is a forced-fallback oracle. iCloud/sync of an HMAC key would also quietly violate single-domain; require ThisDeviceOnly. No current sign/verify oracle on Secure Store.

**(b) TLV + algorithm rule.** Length-prefixed exact-byte MAC + unknown-field reject is the right root. HS256-verifier-is-an-issuer is correctly reasoned; ES256-mandatory across domains is correct. Residual: alg-from-message selection (Minor 1), dual ES256 encodings (Minor 2), duplicate TLV tags if a parser re-encodes, and the false “execute once” claim. Native-held receipts have no `aud` replay theorem; they need the lease, which 0476 owns.

**(c) Mint ordering.** The order (sync capture → 4-layer+typed authority **before** copy → authenticated handle only → native digest of the **transport** artifact → compare-and-commit) is the right order and closes the confused-deputy raw-path hole. It is not race-free until Finding 1’s witness is the full tuple under the revoke lock. Sync capture at JSI entry **does** work: the live frame is still on the stack in `dispatchModule`/`callModuleSync`; the bug is that those functions currently capture nothing, and the Swift action path may hop to main before the handler. Capture-then-async is 0297-legal.

**(d) Verify + write-once.** §5 **states** the construction (atomic seal or fd-unreachability; `O_EXCL` insufficient; `UF_IMMUTABLE` same-UID-clearable; existing-descriptor and seal-clear in the theorem; unavailable > weakened). It does not pick a mechanism; that is honest, not a hand-wave. Digest-recheck-as-defense-in-depth is correct. Apple `fromFile:` vs fd-only is a real blocker and is treated as one. Verify, as written, needs nothing from live JS — key, registry, epoch, inbox, sealed receipt are all native — **once Findings 1–2 are in the registry check**.

**(e) Epoch + revocation.** Anti-rollback construction is sound and honest that a mutable Keychain item is not a counter. Residual mode = server-idempotency only. The JS-dead registry is the right idea and matches 0021’s generation clocks **only** if it stores the full tuple (Finding 1) and 0472 publications (Finding 2). Per-install boot salt is real defense-in-depth if it does not restore with the journal; otherwise theater.

**(f) Coherence + altitude.** Correctly does **not** re-own 0021 transport or 0013 policy. Covers 0476’s delegated surface (key, envelope, mint/verify, inbox/journal, epoch, registry, WP6 adapter, module gate, conformance) with the two holes above. Deferring the portable kind is the right altitude. WP6/armed-closed is honest: `hermes_runtime_fetch.cc` really throws on armed fetch, and 0021 WP6 really keeps live fetch closed until the adapter reports the connected peer. Unarmed mint unavailable matches 0476. Do not let the simulator loopback carve-out (`hermes_runtime_fetch.cc:197–209`) become a mint oracle — §7 already says this.

## Verdict

NOT READY. The mint/verify witness and JS-dead registry, as written, cannot see a revocation of the unrecorded authority edge or of 0472 OS/view-broker state, which is a missed-revocation hole in the exact mechanism 0476 delegated here.

VERDICT: NOT READY — mint/verify’s singular grant+generation witness cannot implement 0021/0476 revocation linearization.

## Round 2 — 2026-08-17

**Round record:** target r2 (480 lines) sha256 `5ad9b44aee67799c7b671cdf70cfd7a93459e7a3864753ff13d8d64fac522fb2`; instruction sha256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`; editor codex gpt-5.6-sol @ xhigh closed r1's convergent central finding (singular authority-generation witness → complete authorityLineage set matching 0476 §4 / ibex GenerationSet{policy,negative,dynamic,handle}) + four-layer revocation ingestion/verify re-check + atomic key+pin fail-closed + byte-exact replay-safe envelope with receiver consumption. Fence verified. Topology/capsule/blindness unchanged from Round 1.- Runner: grok headless, grok-4.6 @ xhigh (fresh)

**Receipt:** completed 2026-08-17; grok-4.6 @ xhigh headless; body sha256 `44c210814a5679391153891db954ccc57495c817bed681c57394954c2627eec0`; binds r2 sha256 `5ad9b44a…`; VERDICT READY. Verbatim below (leading narration part of capture). (An earlier launch of this round errored on an empty prompt and was voided; this is the valid run.)

---

I'll review ibex LLP 0052 independently against the RFC, its governing capability LLPs, and the live mint/verify code — starting with a full read of the target.The RFC is in. Next I’ll read the governing capability LLPs and Exact 0476’s delegated obligations, then check the mint/verify claims against the actual ibex code.I have the RFC structure and citation map. Next I’ll open the cited mint, envelope, and registry implementations and the WP6 / 0476 obligation sections.Armed production closes ambient `dispatchModule`, so I’m checking whether mint would actually enter through that path or through the typed host-call ingress.The r1 revocation hole is closed against the live generation split, and the seven code claims hold. I’ll write the review to that bar.## Overall Assessment

This is a good security RFC, and r2 actually closes the r1 hole. Binding a **complete** `authoritySources` set plus the full `{policy, negative, dynamic, handle}` tuple, then compare-and-committing that set under one guard that every ibex mutation and LLP 0472 publication must share, matches the live generation split: `mint_typed_handle` ticks only `handle`, `revoke_typed_dynamic` ticks `negative`/`dynamic` and leaves `handle` unchanged. A handle-only witness would still commit after a dynamic revoke; this one would not.

The seven load-bearing code claims are true. The document extends LLP 0013/0021 rather than forking a second policy engine, covers what Accepted Exact LLP 0476 delegates in §6–§8 and §16.1, and stays honest that Apple write-once, atomic key+pin, monotonic epoch, and WP6 background facts are unproven premises, not shipped capabilities. Residual sharpness (global generation exact-match is coarse, the registry must retain the full published positive set, the capture hook must sit on the armed mint ingress) does not reopen unforgeability, downgrade, key-reachability, or a missed-revocation race.

## Material Findings

None. The r1 singular-authority-witness revocation flaw is closed against the current ibex generation/registry code. No remaining unforgeability hole, unclosed TOCTOU, JS key-reachability path, algorithm-downgrade/confused-verifier path, or missed-revocation race is specified as a shipped capability; where a platform primitive is missing, the feature is unavailable.

## Minor Findings and Nits

1. **`mint_typed_handle` constrained-stack check is only on the root-mint branch.** The no-parent path at `vendor/ibex/src/host/mod.rs:4305-4335` requires the actor in the constrained stack and coverage for every principal. The parent-handle re-attenuation branch (`4230-4298`) only requires `parent.holder == actor` plus containment. Durable mint must not treat the parent path as the mint oracle. Citation imprecision, not a durable-authority hole.

2. **`ProtectedObjectGuard` lives in `decision.rs`, not `model.rs`.** `vendor/ibex/crates/capsec-semantics/src/decision.rs:124-132`. The Related line already cites `decision.rs`; §5’s “in `crates/capsec-semantics`” is fine.

3. **Global `GenerationSet` exact-match is coarser than “this source is still valid.”** Unrelated `mint_typed_handle` (`4340-4374`) or `grant_typed_dynamic` ticks a process-global clock and would exact-mismatch every receipt. Fail-closed, not an allow-after-revoke. Per-grant `published_dynamic_generation` / `published_handle_generation` already exist and would distinguish “this edge was replaced” from “the global clock ticked.”

4. **0476 names `intendedAudience`; 0052 names `audience`.** Same singular receiving-domain meaning. 0052 owns the envelope bytes.

5. **0476 §10’s transfer control selectors** (start/pause/resume/cancel/delete/reconcile/janitor/listing) are “owned by the ibex LLP.” §8 registers the mint/verify obligation plus inbox/journal, not those control-plane selectors. Defense-in-depth coverage gap, not a mint/verify defect.

6. **Registry wording retains “high-water generations and revocation tombstones”** more clearly than the full positive `(sourceId, grantId, selectorBytes)` map verify must recompute with JS dead. The publication list implies those records are stored; say so in one sentence so implementers cannot treat the registry as a live in-process mirror that resets on restart.

7. **`kind` is in the certificate (tag 2), not the header.** Lookup-before-verify on untrusted `kind` is acceptable because `U` is MAC’d and the trust record is then equality-checked. Worth one explicit sentence next to the header table.

## Answers to the Standard Questions

**Good idea?** Yes. Durable background work needs authority a native engine can verify with JS dead, and JS must never hold the signing capability or the certificate. That is the right repair of the unsigned 0475 capsule, and it belongs in the ibex capability corpus.

**Good plan?** Yes. Persistable, JS-dead verifiability is the durable analogue of `ArmedSessionToken`; mint is at least as strict as `check_handle_mint` / `mint_typed_handle`; the envelope is TLV with protected `alg`/`kid`/`iss`/`aud`; HMAC is single-domain because a verifier with the key is an issuer; ES256 is mandatory across domains; write-once is constructed, not assumed; WP6 stays closed; no portable kind ships. Fail-closed unavailability is the right product stance.

**Add / remove / change?**
- Add one sentence that the durable registry retains the **full published positive set and selector mapping** across process death, and that ibex must restore generations from that store rather than republish zeros.
- Add that mint’s compare-and-commit re-reads the **0472 four-layer vector** (not only the ibex tuple) under the same guard. Verify’s live 0472 check already fail-closes use; mint would then fail-close commit too.
- Change global-tuple exact-match to per-source published generations if receipts must survive unrelated handle/dynamic activity; keep exact-match plus presence if coarseness is intended.
- Do not add a second policy engine, a JS sign/verify method, a portable kind, or a runtime HMAC fallback.

**Definitely / possibly wrongheaded?** The core is not. Using process-global cache clocks as “this edge still authorizes” is possibly over-strict, not unsafe. Specifying the full portable envelope while shipping no kind is the altitude 0476 §7 asked for, not premature crypto.

**Key open questions?** The five in §11 are the right implementation-selection questions. The ones that can keep the first consumer unavailable on Apple are OQ1 (named-file vs fd-only write-once) and OQ4 (WP6 facts from a background adapter). OQ2 (atomic key+pin and a real monotonic epoch) is the other hard gate. Do not weaken any of them.

## Novel Ideas

1. **Treat first-launch as “no facility state and no journal,” never “pin absent.”** Missing pin plus any journal/receipt/continuity residue is terminal. That is the cleanest distinction between fresh install and “delete SE key, plant HMAC.”
2. **Keep the isolated Keychain access group off the entitlement default.** `com.exact.securestore` queries `kSecClassGenericPassword` with no `kSecAttrAccessGroup` (`packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:298-303`), so it hits the default group. A secondary entitled group is invisible; making that group first in entitlements would reopen JS `getItem`.
3. **Put the sync capture hook on the armed mint JSI entry**, not on ambient `exact.dispatchModule`. Production armed runtimes leave that ambient channel uninstalled (`ios/ExactApp/ExactApp/Hermes/ExactRuntimeEngine.swift:7471-7481`). Capture still works: `currentPrincipalId()` and the `checkCapabilityWithFsMode` walk are valid in the JSI host function before any `enqueueCapability` hop (`ExactNativeHostSession.swift:16763-16801`).
4. **Apple background without weakening write-once:** a custom `URLProtocol` or stream over an fd-only inode, or background unavailable while foreground uses the unlinked inode. That is already the decision §5 names; it is the one to prove, not `UF_IMMUTABLE` on a guessed path.
5. **Bind 0472 `(sourceId, grantId, selectorBytes, per-layer generation)` into the lineage** in addition to the live OS/broker re-check, so JS-dead verify is not solely a current-granted snapshot against an API that cannot see revoke-then-regrant while dead.

## Implementation-Phase Notes

These do not drive the verdict.

- Direct `ring` dependency before any Rust ES256/AEAD use (`vendor/ibex/Cargo.toml` has `hmac`/`sha2` direct; `ring` only via `rustls` `features = ["ring"]` at lines 85-86 and 123).
- Register the capture-hook callback affinity (`docs/callback-affinity.md`) when the hook lands.
- Wire the new durable-authority guard through **existing** `revoke_typed_dynamic` / `revoke_typed_handle` / `grant_typed_dynamic` / `mint_typed_handle` / policy publication, without deadlocking the decision-context write lock.
- Persist/restore `GenerationSet` from the registry on boot so JS-dead verify is not bricked by in-memory clocks resetting to zero.
- Negative tests already listed in §8 are the evidence, not extra design.
- Native-held receipt AES-GCM AAD in §5.1 is the receipt; the fuller lease binding `(certificateHash, operationId, taskId, revocationGeneration, mintGeneration, leaseEpoch)` remains Exact LLP 0476’s consumer object.
- `requestPlanHash` / `serviceIdentity` / adapter identity are in the v1 schema; the consumer lease still has to bind the exact outbound request.

**Claim verification (all hold):**

1. **ArmedSessionToken.** `mint_armed_session_token` (`vendor/ibex/src/host/mod.rs:2362-2446`) requires an armed snapshot and calls `ArmedSessionToken::from_authenticated_snapshot`, which fills a 32-byte `getrandom` nonce (`vendor/ibex/src/engine/evaluation.rs:254-260`), stores `snapshot_digest` (`206, 262`), wipes the nonce on drop (`236-239`, `volatile_wipe` at `1510-1515`), and compares by `Arc::ptr_eq` (`274-276`). Possession-based and non-portable. Accurate.

2. **`check_handle_mint` / `mint_typed_handle`.** `check_handle_mint` (`vendor/ibex/src/host/capability.rs:705-728`) requires an explicit policy grant and has no Root ambient early-return (contrast `decide` at `698-699`). `mint_typed_handle` binds `armed_snapshot_digest` (`4363`) and, on the root path, requires the actor in the constrained stack plus coverage for every constrained principal (`4305-4335`). Accurate as the durable-mint floor.

3. **`digest_authenticated_projection`.** `vendor/ibex/src/host/mod.rs:448-456` is `domain || u64_be(len) || payload`. The §3 preimage adds a version token (`ASCII("IBEX-DURABLE-AUTHORITY") || 0x00 || ASCII("V1") || 0x00 || u64_be(len(U)) || U`). Extension, not a verbatim reuse. Accurate.

4. **Typed model.** `Principal` is tagged `Package`/`Root`/`Runtime`/`ModuleLoader`/`Quarantine` (`vendor/ibex/crates/capsec-semantics/src/model.rs:306-324`). `NetworkRequest::FetchEndpoint` carries `scheme`/`host`/`port` (`1233-1238`); selector `FetchEndpoint` the same (`1057-1062`). `ProtectedObjectGuard` exists (`decision.rs:124-132`). Accurate.

5. **`com.exact.securestore`.** JS `getItem`/`setItem`/`deleteItem` take caller-chosen `keychainService` (`packages/exact-secure-store/src/api.ts:34-43, 94-114`). Native queries `kSecClassGenericPassword` by service/account and returns UTF-8 bytes (`SecureStoreModuleImpl.swift:221-241, 298-303`). `requireAuthentication` throws `authenticationRequiredUnsupported` (`222-224`). No sign/verify surface. No `kSecAttrAccessGroup` anywhere under `packages/`. This facility cannot hold a JS-unreachable signing key. Accurate.

6. **Armed fetch / WP6.** Armed `__nativeFetch` throws “typed network:fetch transport is unavailable” unless the simulator loopback carve-out (`vendor/ibex/src/engine/hermes_runtime_fetch.cc:188-214`); the Windows sync bridge is closed with no carve-out (`552-556`). LLP 0021 WP6 (`vendor/ibex/llp/0021-capsec-effect-model-migration.plan.md:1789-1805`) keeps live fetch closed until the adapter reports and rechecks the connected peer. A mint-time signature cannot attest a future peer. Accurate. §7 correctly forbids the string oracle and the simulator carve-out as a mint path.

7. **Crypto resources.** Direct `hmac` and `sha2` (`vendor/ibex/Cargo.toml:85-86`). `ring` is not a root `[dependencies]` entry; rustls enables it (`123`). CryptoKit is already used on the Swift host. Accurate.

**(a) Key facility.** Sufficient against the stated attacker (JS plus same-sandbox files, not arbitrary native code). SE `kSecClassKey` is unreachable from generic-password `getItem`. HMAC in a **non-default** access group (or a helper) is unreachable from the current module. Post-provision pin is the algorithm authority, so a transient SE failure cannot force HMAC, and a planted HMAC+public flag cannot replace a deleted enclave identity. Residual route only if implementers put HMAC in the default access group or make the isolated group the entitlement default — both forbidden here.

**(b) TLV + algorithm rule.** Length-prefixed TLV, strictly increasing unique tags, unknown/duplicate/trailing rejection, JCS inner typed values that must round-trip, `alg`/`kid`/`iss`/`aud` inside MAC’d `U`, record-selected algorithm (never from the message), low-S ECDSA, constant-time HMAC compare, and `(issuer, audience, operationId)` consumption close canonicalization, alg-confusion, and same-audience replay. HS256-as-issuer is correctly reasoned. Cross-audience replay dies on audience equality. No portable kind ships until key distribution exists.

**(c) Mint ordering.** Capture → typed+0472 decision **before** copy → authenticated-handle staging → native digest of the exact transport artifact → guard-held re-read of the complete set+tuple through epoch+commit is the right order and is race-free **if** every mutation takes that guard. A revocation that linearizes first wins; a later one invalidates the lease and does not grandfather in-flight work. No raw path closes the 0475 confused deputy. Sync capture at the **true** JSI entry is workable (`currentPrincipalId` + the constrained-stack walk in `hermes_runtime_internal.h:1735-1892`) and is compatible with LLP 0297 (read ambient, then async). Today’s async trampoline really captures nothing.

**(d) Verify + write-once.** Sole-writer is required as a platform construction (`O_CREAT|O_EXCL` insufficient; `UF_IMMUTABLE` same-UID-clearable), not assumed. Digest recheck is correctly labeled defense-in-depth. The Apple `fromFile:` named-file tension is an honest blocker, not a hand-wave; background stays unavailable until one of the two named mechanisms is proven. Verify is specified to need nothing from live JS.

**(e) Epoch + revocation.** Hardware counter or named server-idempotency residual; a mutable Keychain item is correctly refused as a counter. The JS-dead registry plus four-layer publication is coherent with LLP 0021’s generation clocks (and cites the right `cache.rs` / `arming.rs` lines: `GenerationSet` at `40-44`, `SnapshotGenerations` at `301-305`, `DecisionCacheKey` at `57-73`; handle-only unsafety at `mod.rs:4340-4374`, `4149-4168`, test `13669-13685`). Boot salt is real defense-in-depth for journal-copied-without-facility, and they forbid a resurrection claim if salt restores with the journal.

**(f) Coherence + altitude.** Extends 0013/0021; does not re-own typed transport or the policy engine. Covers 0476’s blocking ibex obligations (typed mint witness/compare-and-commit, source ownership, mandatory inbox/journal, key/epoch/revocation, sole signed envelope, WP6 adapter, module gate, conformance) without contradicting the Accepted consumer (native-held receipt first, portable deferred, HS256 single-domain, ES256 cross-domain, unarmed mint unavailable, armed background closed, write-once constructed). Deferring the portable kind is the right altitude. The WP6/armed-closed stance is honest.

## Verdict

VERDICT: READY — r2’s complete set-plus-tuple witness and shared-guard compare-and-commit close the r1 revocation hole against the live ibex generation split, and the remaining items are fail-closed unavailability or implementation selection, not unforgeability holes.

## Round 3 — 2026-08-17

**Round record:** target r3 (551 lines) sha256 `b21a90f5724c977091f1b54d840988f5f00e99195dbf36718a43d0d76a0aa32a`; instruction sha256 `3d66802cd008c869f0decb796ad9ad2c822bb8542e3265121c91a8bf2044c827`; editor codex gpt-5.6-sol @ xhigh closed codex-r2's 4 findings (constructible (sourceId,grantId) provenance witness against the real DecisionEvidence model; frozen misuse-resistant AEAD lease record incl. nonce-uniqueness/AES-GCM-SIV; observation-linearized external revocation with 0476 pre-observation residual; corrected handle-mint precedent re Permissive/no-parent branch). Fence verified. r2: grok READY, codex NOT READY (4). Topology/capsule/blindness unchanged.
- Runner: grok headless, grok-4.6 @ xhigh (fresh)

**Receipt:** completed 2026-08-17; grok-4.6 @ xhigh headless; body sha256 `bf1173016784c0aaf1a2f1cb65c5e3aa97fe8c84a726aed2afbb477caa0ee825`; binds r3 sha256 `b21a90f5…`; READY (2nd consecutive). Verbatim below (leading narration part of capture).

---

I'll review LLP 0052 independently from the RFC and the governing ibex/Exact sources, starting with the target document in full and then checking the load-bearing claims against code.The RFC is in hand. Next I’ll read the capability-model authorities and check the load-bearing claims against the cited ibex and Exact sources.I have the citation map. Next I’ll open the cited implementations and the Exact 0476 sections this RFC is supposed to cover.The 0476 obligations and mint/token citations check out so far. I’ll now verify the remaining load-bearing claims in secure-store, armed fetch, WP6, and the module trampoline.I have enough primary-source evidence to score the r3 claims and the security questions. The review below is from the target RFC plus the cited ibex/Exact sources only.

## Overall Assessment

This is a strong, correctly-altituded security RFC. It does the job Exact LLP 0476 accepted and delegated: define the native trust-domain mechanism (key facility, byte-exact envelope, mint/verify, write-once objects, JS-dead revocation/epoch, WP6 adapter contract, module-gate capture) as an **extension** of ibex LLP 0013/0021, not a second policy engine.

r3’s four advertised repairs are real and load-bearing, not cosmetic:

- **Constructible provenance.** Today’s `DecisionEvidence.source_id` really does flatten static `source_id` / dynamic `grant_id` / handle `handle_id` into one optional string. Requiring `DurableDecisionEvidence` before that flattening, with a deterministic stratum-then-lex-min choice, is the right theorem.
- **Misuse-resistant native record.** Resolving 0476’s generic “AES-GCM” to AES-256-GCM-SIV, putting role/ids/nonce/install-binding in AAD, and treating nonce uniqueness as mandatory with GCM-SIV as defense-in-depth, is the right specialization.
- **External revocation.** Naming Settings as observation-linearized, with “bytes already disclosed cannot be recalled,” is honest. A zero-gap claim is correctly refused.
- **Handle-mint precedent.** The code really does **not** require the constrained stack on parent re-attenuation. r3 stops citing the no-parent branch as if it were the whole function, and durable mint refuses parent-handle re-attenuation as an oracle.

I re-checked the seven load-bearing code claims. **None is contradicted.** I also cross-checked 0476 §6–§8, §14, §16.1, and §17: this document covers what 0476 delegated and does not weaken it. Remaining gaps are implementation-selection items the RFC already fail-closes, or tightenings that do not identify a defective decision.

## Material Findings

None.

Every candidate I treated as a possible unforgeability / TOCTOU / key-reachability / downgrade / missed-revocation hole is either closed by a stated construction or explicitly fail-closed as “feature unavailable” until a named premise is proven.

## Minor Findings and Nits

1. **Simulator carve-out name.** §7 says `IBEX_CAPSEC_SIMULATOR`. The live armed branch is `IBEX_CAPSEC_SIMULATOR_PERFORMANCE_OBSERVER` (`vendor/ibex/src/engine/hermes_runtime_fetch.cc:197-214`). The rule (“never a mint oracle”) is right; the identifier is not.

2. **Legacy `check_handle_mint` vs armed host.** The cited manager path (`capability.rs:705-728` plus `gate_and_record` at `557-559`) is accurate **for the unarmed string manager**. On an armed host, `Host::check_handle_mint` hard-denies whenever `decision_context.is_some()` (`src/host/mod.rs:4646-4648`). Durable mint is always armed, so the live precedent is `mint_typed_handle` / typed evaluation, not the string function. r3 already treats durable mint as independent; one sentence would stop a reader from implementing the wrong oracle.

3. **HMAC isolation is query-shaped, not process-shaped.** §2 correctly says an entitlement is not in-process module isolation, then qualifies an access group only against “the fixed public query (generic-password plus service/account, with no access-group selector).” That matches today’s `baseQuery` (`packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:298-303`), which cannot set `kSecAttrAccessGroup` or query `kSecClassKey`. HMAC key **bytes** remain extractable by any future JS-callable native module that grows an access-group selector. Worth an explicit registry-wide prohibition (see Implementation-Phase Notes). Not a current JS route, and not a forced-fallback path.

4. **0476 schema shorthand vs this freeze.** 0476’s certificate still writes `authoritySources: [{ sourceId, grantId, mintGeneration }]`. This LLP’s tagged provenance + `policyDigest` + `fourLayerWitness` is a compatible total resolution, as claimed. Exact’s consumer doc will need a mechanical schema update at implementation; that is 0476 maintenance, not a 0052 contradiction.

5. **Mint step 5 re-reads the published four-layer vector**, not necessarily a live OS query. A Settings revoke during staging can still commit; the first send/verify live check is what catches it. That is consistent with §6’s observation residual. A live OS/broker re-query **under the commit guard** would shrink a window in which a lease exists but must not send. Hardening, not a missed-revocation of disclosed bytes.

## Answers to the Standard Questions

**Good idea?** Yes. Durable native work needs authority a dead JS runtime cannot forge or withhold. Pushing that into ibex’s existing principal/grant/generation model, with JS holding only an opaque task handle, is the correct split. 0476 already accepted the consumer shape; this is the mechanism that makes that acceptance honest.

**Good plan?** Yes. The plan is fail-closed and ordered: no key+pin proof → no authority; no write-once primitive → no durable inbox; no monotonic anchor → no local anti-rollback (server evidence never waives the AEAD nonce allocator); no WP6 adapter → armed durable upload stays closed; no portable kind’s threat model → no portable kind ships. That is how you specify a security boundary without pretending Apple’s background `fromFile:` stack is already solved.

**Add / remove / change?** I would add three sentences, not new machinery:

- Under §2: no JS-reachable module, present or future, may accept an access-group selector or a `kSecClassKey` lookup; HMAC remains a last-resort, no-enclave path.
- Under §4 step 5: while the commit guard is held, re-query live OS permission and view-broker state, not only the last published four-layer vector.
- Under §5 verify: require `lease.certificateHash == SHA-256(receipt certificate bytes)` after both AEAD opens, in addition to AAD `operationId`/`taskId` binding.

I would **not** add a portable kind, a second policy engine, a signed-JSON fallback, an HMAC-on-SE fallback, or a “background URLSession is close enough” waiver.

**Definitely / possibly wrongheaded?** Nothing definitely. Two conservative choices are slightly expensive and still right:

- Sealing the **global** `{policy, negative, dynamic, handle}` tuple on every `authoritySources` item will abort mints and invalidate leases on unrelated authority churn. That is an availability cost they name. A per-source clock would be a later schema, not a v1 hole.
- Mandating AES-256-GCM-SIV (and refusing plain GCM) may make the native receipt unavailable until an audited implementation is a **direct** dependency. Given there is no `aes-gcm-siv` symbol in the ibex tree today, that is a real gating cost. Prefer unavailable over nonce-fragile GCM.

**Novel ideas?** The valuable ones are already in the document: persistable analogue of a possession token rather than “sign a JSON capsule and hope”; constructible provenance instead of flattened `source_id`; GCM-SIV as misuse-resistance rather than permission to reuse nonces; observation-linearized external revocation instead of a fake zero-gap. I would not invent a parallel capability namespace.

**Key open questions?** The five in §11 are the right ones, and they match 0476 §17. The ones that actually decide whether anything ships on Apple are OQ1 (write-once vs `fromFile:`), OQ2 (atomic pin + monotonic epoch), and OQ4 (WP6 facts from a background adapter). OQ3 is correctly deferred. OQ5 is a typed-model representation choice with a containment invariant, not a security-waiver.

## Novel Ideas

- **Facility provision generation.** Beside `(algorithm, keyId, class)`, seal a monotonic facility-provision counter that only advances on a successful atomic provision. Rollback-to-empty-pin with leftover journal residue is already refused; a provision generation makes “this is not a fresh install” a first-class authenticated fact rather than an inference from residue.
- **One SE key, HKDF-separated roles.** If Apple proves SE P-256, derive journal/epoch/MAC keys via HKDF from a single non-exportable identity rather than several Keychain items. Fewer items to isolate; the pin remains the live SE key identity.
- **Foreground durable as a separately advertised mode.** The RFC already allows background to stay unavailable. Product-wise, prove fd-only foreground first and keep `backgroundCapable: false` until `fromFile:` or a custom `URLProtocol` is actually shown. That prevents one unproven Apple path from holding the whole facility hostage.
- **Registry-wide Keychain negative suite.** Not just “guess `com.exact.securestore.transfers` / `journal-envelope-key-v1`.” Enumerate every JS-callable module that can touch SecItem and assert none of them can name the facility’s class/group/tag.

## Implementation-Phase Notes

These do not drive NOT READY.

- **Hook placement.** `exact.dispatchModule` is a JSI host function that invokes the Swift callback **on the JS stack** (`vendor/ibex/src/engine/hermes_runtime_ios.cc:392-408`). The loss happens later, when Exact enqueues onto `engineExecutor` (`ios/ExactApp/ExactApp/Engine/ExactNativeHostSession.swift:16790-16801`). Capture in that JSI/Swift entry, attach the snapshot to the work item, and never re-read ambient principal on the queue. `exactCollectTypedPrincipalStack()` (`hermes_runtime_fs.cc:371-418`) is the walk to snapshot; after the hop, `g_vm_runtime` is the wrong time. This is compatible with Exact LLP 0297: read, then async work; no cross-thread sync module call.
- **Common guard retrofit.** Today `mint_typed_handle` / `revoke_typed_dynamic` / `revoke_typed_handle` only take `decision_context.write()`. The new durable-authority guard must be acquired on **those paths too**, with a documented lock order against the context lock, or the compare-and-commit theorem is fiction. Handle revoke already advances `negative` and `handle` (`mod.rs:4450-4468`); dynamic revoke still leaves `handle` unchanged (`4149-4168`) — the full tuple is mandatory.
- **Direct `ring` (or other audited AEAD).** `hmac` and `sha2` are direct (`vendor/ibex/Cargo.toml:85-86`). `ring` is only a `patch.crates-io` path used transitively via `rustls` features `["ring"]` (`123`, `315`). §3 already requires a direct dependency for signing/AEAD. Confirm the vendored ring actually offers AES-256-GCM-SIV, or vendor an audited implementation; CryptoKit is used in Exact Swift for hashing, not as a GCM-SIV provider.
- **Secure Store as it exists cannot hold a JS-unreachable signing key.** `getItem` returns UTF-8 of a caller-chosen `(service, account)` generic-password (`api.ts:94-98`, `SecureStoreModuleImpl.swift:111, 221-241, 298-303`). `requireAuthentication` throws “Authenticated secure-store items are not implemented in Exact yet.” (`198-199, 222-224`). Methods are only `isAvailable` / `canUseBiometricAuthentication` / `getItem` / `setItem` / `deleteItem`. That claim holds.
- **Conformance list in §8 is the right test plan.** Implement the planted-HMAC, role-swap, dynamic-revoke-with-unchanged-handle-generation, and same-UID seal-clearing cases as blockers, not as documentation.

### Load-bearing claim verification

| Claim | Verdict | Evidence |
|---|---|---|
| `ArmedSessionToken` is a 32-byte OS-random nonce, bound to the armed-snapshot digest, wiped on drop, pointer-identity compared, possession-based / non-portable | Holds | `evaluation.rs:213, 236-239, 254-260, 274-276` (`getrandom`, `volatile_wipe`, `Arc::ptr_eq`); `host/mod.rs:2427-2438` binds `snapshot.digest()` |
| `check_handle_mint` needs an explicit grant and skips Root ambient; `mint_typed_handle` binds the snapshot; only the no-parent branch requires the actor on the constrained stack | Holds | `capability.rs:557-559, 705-727`; `mod.rs:4263-4312, 4363`. Parent path is holder + containment only. Armed `Host::check_handle_mint` additionally hard-denies (`4646-4648`) — see minor #2 |
| `digest_authenticated_projection` is `domain ‖ u64_be(len) ‖ payload`; the envelope **extends** that framing | Holds | `host/mod.rs:448-456`. Envelope preimage adds `IBEX-DURABLE-AUTHORITY` / `V1` labels; not a verbatim reuse, as stated |
| Typed principals are tagged variants; fetch endpoints carry scheme/host/port; `ProtectedObjectGuard` exists | Holds | `model.rs:306-324` (also `ModuleLoader` / `Quarantine`, covered by “…”); `1489-1493`; `decision.rs:124-132` |
| `com.exact.securestore` returns key bytes to JS via `getItem` under any caller-chosen service/account; authenticated-item path unimplemented; no sign/verify | Holds | `api.ts:10-16, 35, 94-107`; `SecureStoreModuleImpl.swift:111, 198-199, 221-241, 244-295, 298-303` |
| Armed typed `network:fetch` transport is closed; WP6 requires rechecking actual peer/candidates/redirects; a mint-time signature cannot attest future peer | Holds | `hermes_runtime_fetch.cc:188-214`; LLP 0021 WP6 at `1789-1805` (“Live fetch remains closed until the transport adapter can report and recheck the actual connected peer”) |
| Crypto is resourced: `hmac`+`sha2` direct; `ring` vendored/transitive, not a direct root dep | Holds | `Cargo.toml:85-86, 119-123, 310-315` |

### Evaluation of the sharp questions

**(a) Key facility.** Sufficient against the stated JS attacker. Current Secure Store cannot name a `kSecClassKey` SE item or a non-default access group. SE keys are non-exportable and there is no JS sign oracle; mint is the only signing entry and it authors the certificate natively. HMAC-on-SE forced fallback is closed: the verifier uses the facility-owned pin/live-key identity, a missing pin with residue is key loss not bootstrap, and “probe failed” is not “no enclave.” Residual worth remembering: HMAC bytes are just generic-password data to any **future** in-process module that can set `kSecAttrAccessGroup`. That is why HMAC is confined to no-enclave devices and why a helper boundary is the stronger option.

**(b) TLV + algorithm rule.** This closes the usual JOSE failures. Unknown/duplicate/out-of-order/trailing rejected **before** signature acceptance; v1 has no optional fields; alg/kid/iss/aud sit in the protected header; the receiver may parse those fields only to locate a trust record, then requires exact equality and verifies with the **record’s** algorithm; it never selects HMAC from the message and never treats ES256 public-key bytes as an HMAC key. `kind` in the certificate (not the header) is slightly less tidy than 0476’s “protected header” wording, but `U` includes tags 1 and 2, so `kind` is authenticated; post-verify equality-check prevents a confused-verifier swap. HS256 ⇒ every key holder is an issuer is correctly reasoned; ES256 across domains is mandatory for that reason. Cross-audience replay is blocked by singular `intendedAudience` plus consume-once `(issuer, intendedAudience, operationId)` with a rollback-resistant tombstone.

**(c) Mint ordering.** The order is correct and race-free **against in-process ibex/0472 mutations**, provided those mutations actually take the new guard. Eval-before-staging prevents unauthorized inbox fill. Authenticated-handle staging (no raw path) closes 0475’s confused deputy. Compare-and-commit under one guard from last read through epoch advance and SQLite commit is the right linearization; a before/after pair would not be. A revocation that linearizes first wins; a mint that commits first is immediately subject to the next revocation (no grandfathering). The JSI-entry capture requirement is implementable: the trampoline diagnosis is accurate, and the live stack is still present in the `dispatchModule` host function. Do not capture on the worker.

**(d) Verify + write-once.** §5 constructs the sole-writer property (exclusive create is not enough; `UF_IMMUTABLE` is same-UID-clearable; need atomic verify-to-seal or fd-unreachability; existing descriptors and seal-clears are in the theorem). Digest recheck is correctly labeled defense-in-depth / check-then-use. The Apple `fromFile:` named-file tension is an honest blocker, not a hand-wave; until one of the two named mechanisms is proven, that target reports background durable unavailable. Verify is specified to need nothing from live JS (AEAD/signature, digest, registry, live OS/broker, epoch).

**(e) Epoch + revocation.** Sound and honest. A mutable Keychain item is not a monotonic counter. Server evidence may replace only the operation-replay theorem, never §5’s nonce allocator. The JS-dead registry consuming 0013/0021 generations plus 0472 four-layer vectors, restoring high-water marks instead of republishing zero, matches `GenerationSet` / `SnapshotGenerations` / `DecisionCacheKey` (`cache.rs:19-73`, `arming.rs:301-305`). The per-install boot salt is real against journal-only copy and correctly refuses a resurrection claim if it restores **with** the journal.

**(f) Coherence + altitude.** This extends 0013 (principals, grants, authority-bearing mint) and obeys 0021 WP6 without re-owning the typed transport or the policy engine. It covers 0476 §16.1 (mint witness, source ownership, inbox/journal, key/epoch/registry, sole envelope, WP6 adapter, module gate, conformance) and §6–§8’s isolation/envelope/callback-affinity obligations. Deferring “no kind ships here” while freezing the envelope is the right altitude. The WP6/armed-closed stance is honest and matches both 0021 and the armed fetch code.

## Verdict

r3 closed the remaining security-relevant gaps (constructible provenance, misuse-resistant lease AEAD, honest external-revocation residual, corrected handle-mint precedent). The load-bearing code claims hold. What is left is fail-closed implementation selection, not an unforgeability or TOCTOU defect in the RFC.

VERDICT: READY — r3 is a sound, fail-closed native-trust-domain design that covers 0476’s delegation without an unclosed crypto, key-reachability, or revocation hole.

## Round 4 — 2026-08-17

**Round record:** target r4 (544 lines) sha256 `c38d5f50dc4a0ed2140c6339fe70e33ac55085db9984587a71ce7dfcc65ff97f`; instruction sha256 `948c849cc271c8d6275071beefa3867a900d5811b4200091c0cc445f6ceefbb8`; editor codex gpt-5.6-sol @ xhigh closed codex-r3's 3 findings (stable durable-authority projection digest excluding ephemeral run/session fields vs the per-run recomputed armedSnapshotDigest; per-effect four-layer witness so two selectors with differing OS/broker state cannot collapse; self-consistent TLV depth bound). Fence verified. r3: grok READY (2nd), codex NOT READY (3). Topology/capsule/blindness unchanged.
- Runner: grok headless, grok-4.6 @ xhigh (fresh)

**Receipt:** completed 2026-08-17; grok-4.6 @ xhigh headless; body sha256 `7a9366bea9f72e5fe532ac3b6be58b182e7c1517848d534d50cd2d014ca213f2`; binds r4 sha256 `c38d5f50…`; READY (3rd consecutive: r2/r3/r4). Verbatim below (leading narration part of capture).

---

I'll review the r4 RFC independently: first the target and governing LLPs, then the load-bearing code claims. I will not read prior review artifacts.The RFC is in. Next I’ll read the governing LLPs and open the cited implementation sites to check the load-bearing claims.I have the map of citations. Next I’ll open the exact implementations and the delegated 0476/0021 sections.The cited implementations match so far. I’ll now check 0476’s delegated obligations and the mint/principal-capture path.I’m checking the snapshot field list, principal-capture trampoline, and the cited DecisionEvidence flattening next — those are the remaining places a real hole could hide.I opened the RFC, the governing LLPs, and the cited implementations. The load-bearing code claims hold; the remaining comments are altitude or inventory, not unforgeability holes.

## Overall Assessment

This is a good security RFC at the right altitude. It does the job Exact LLP 0476 assigned it: it extends ibex LLP 0013/0021 with a persistable, JS-dead-verifiable witness instead of inventing a second policy engine or a portable token for the first consumer.

The r4 changes are the right ones. Binding a stable durable-authority projection instead of the per-run `armedSnapshotDigest` is what makes restart survivable without treating a fresh `runNonce`/`channelEpoch` as revocation. Giving each `(effectIndex, principal)` its own four-layer witness, and forbidding collapsed evidence, is the only way the 0472 intersection stays meaningful when source and `network:fetch` rows do not share a vector. The depth-6 TLV bound matches the deepest required path.

I re-checked the seven load-bearing code claims against the files. They hold. The design questions that matter for this corpus — key reachability, downgrade/confused-verifier, mint TOCTOU, write-once theorem vs Apple `fromFile:`, epoch honesty, 0013/0021/0476 coherence — are decided, not waved. Residuals that the platform cannot close are named as unavailability, not as “good enough.”

## Material Findings

None. I did not find an unforgeability hole, an unclosed mint/verify TOCTOU, a JS key-reachability path the isolation rules fail to close, a downgrade or confused-verifier path, or a revocation race the compare-and-commit plus live re-query leaves unspecified.

## Minor Findings and Nits

1. **Projection field inventory vs the live loader.** The classified include-list matches `vendor/ibex/capsec/schema/armed-snapshot.schema.json` (required fields minus the three excluded run/session fields, plus `devServedProjectRoot` / `exactEmbedder` / `runtimeExtensions` iff present). `ArmedSnapshot::load` also accepts `preparedGraphs` (`vendor/ibex/crates/capsec-semantics/src/arming.rs:448-454, 1108-1133`), which is absent from that schema (`additionalProperties: false`) and from the classified include/exclude sets. The RFC’s “unclassified field ⇒ mint/verify unavailable” rule fail-closes, so this is not a silent-omit hole. Name `preparedGraphs` explicitly (include it; it is independently mutable from `packageGraph`) so an implementer does not “helpfully” drop it.

2. **JS-reachable Keychain queriers beyond `com.exact.securestore`.** Isolation against Secure Store is correctly motivated (`packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:221-241, 298-303`; `src/api.ts:94-98`). The same process also exposes `desktop.secureStorage.get/set/delete` (`ios/ExactApp/ExactApp/Hermes/ExactRuntimeEngine.swift:3822-3878` → `ExactDesktopSecureStorageBridge.swift:66-72`: generic-password, caller-chosen account, default group, no access-group selector) and a native embedded store at service `com.exact.native.embedded.host-resources.v1` with its own access group (`ExactNativeEmbeddedResourceCallbackProvider.swift:1614-1651`). Neither punches the RFC’s “non-default group / class the public generic-password query cannot satisfy” rule if that rule is actually proven. The isolation inventory and negative tests should name these routes, not only Secure Store. The “no future JS module may take an access-group selector” standing rule should also cover host-call Keychain surfaces.

3. **Domain string vs existing NUL-terminated convention.** `digest_authenticated_projection` hashes `domain || u64_be(len) || payload` (`vendor/ibex/src/host/mod.rs:448-456`) and today’s callers pass NUL-terminated domains (`b"ibex/authenticated-file-kind/1\0"` at line 480). The durable projection domain is written as `ASCII("ibex:durable-authority-projection:1")` with no terminator. v1 has a single constant domain, so this is not a collision. Follow the existing terminator so a later prefixing domain cannot be introduced by accident.

4. **Related-line obligation map is slightly short.** The body covers what 0476 delegates. The Related line cites 0476 §6–§8 and §16.1; the same obligations also live in 0476 §3 (mint/witness), §4 (write-once), §7 (envelope), §10 (module selectors), and §14/§15. Cosmetic.

5. **Trust-store `keyId` uniqueness is implied, not stated.** Lookup is `(issuer, intendedAudience, kind, keyId) → (alg, key)`, then post-auth equality. Cross-kind reuse of one `keyId` would make an authorized issuer for kind A able to produce a kind-B envelope that verifies if a second record shares that key. Pin: a `keyId` maps to at most one `(algorithm, key, kind, issuer)` in the out-of-band store.

6. **`ProtectedObjectGuard` lives in `decision.rs`, not `model.rs`.** The RFC Related line already says this; the user’s checklist bundled it with `model.rs`. Not an RFC error.

## Answers to the Standard Questions

**Good idea?** Yes. Durable background work needs a native witness that JS never holds. Treating that as persistable, cross-process 0013 mint semantics — not as a new capability namespace, and not as a portable bearer for the first consumer — is the correct architecture. 0476 already accepted the consumer shape; this is the mechanism it cannot honestly own.

**Good plan?** Yes. The order is the one that closes the holes 0475 actually demonstrated: capture at JSI entry, evaluate before copy, refuse raw paths, hash the bytes the transport will send, compare-and-commit under a guard every authority mutation must take, verify with JS dead against a complete positive set plus live OS/broker state. Crypto is TLV with protected header fields, unknown-field rejection, and out-of-band algorithm selection. Platform rows stay pending until proofs exist.

**Add / remove / change?** Add the three nits above (`preparedGraphs` classification, Keychain-route inventory, `keyId` uniqueness). Do not add a portable kind. Do not reopen armed fetch with a mint-time signature. Do not weaken HMAC-as-issuer. Do not replace the write-once theorem with a pre-send digest. Do not treat a Keychain item as a monotonic counter.

**Definitely / possibly wrongheaded?** Nothing definitely. The one place that looks tempting to weaken — “named file + `UF_IMMUTABLE` is probably fine on iOS” — is correctly refused. The other temptation — bind raw `armedSnapshotDigest` so the projection cannot drift — is what made durable authority die on every restart; r4’s allowlist-plus-unclassified-refuse is the better decision.

**Key open questions?** The five already listed are the right ones, and they are implementation-selection questions with fail-closed defaults, not permission to ship a weaker v1. I would not add a sixth design question. I would add an implementation checklist item: lock identity of the “common mutation guard” versus today’s `decision_context` `RwLock` (`vendor/ibex/src/host/mod.rs:4249-4251, 4138-4140`), so implementers wrap or replace that lock rather than adding a second one.

## Novel Ideas

- Generate the durable-projection allowlist from `armed-snapshot.schema.json` (required properties minus the three excluded names, optional properties as “include iff present”), and refuse on any other key. That makes field drift a schema change, not a prose edit.
- Prefer a helper or `kSecClassKey` (even if the journal/HMAC secret is wrapped) over generic-password-plus-access-group. Generic password is the class every present JS-reachable querier already uses; a different class is isolation that does not depend on entitlement order.
- Put `certificateHash`, `operationId`, `taskId`, and `columnRole` in the native-record AAD *and* require the consumer lease plaintext to carry `revocationGeneration`, `mintGeneration`, and `leaseEpoch` by name. 0476 already wanted those in the AEAD binding; 0052 currently leaves them inside “consumer-owned lease object.” Naming them here costs nothing and prevents a thin lease.
- For Apple background, treat custom `URLProtocol`/stream over an fd-only inode as the *preferred* attempt, and named-file+`UF_IMMUTABLE` as the fallback that must defeat same-UID clear. The RFC leaves them as equal options; the theorem is stronger on the fd-only path.

## Implementation-Phase Notes

These do not drive NOT READY.

- Retrofit every `mint_typed_handle` / `revoke_typed_dynamic` / grant / 0472 publication site onto the durable-authority guard, with a single lock order against `decision_context`.
- Sub-order inside mint: allocate `operationId`, mint the operation-bound source handle, stage, then commit. The eligibility rule requires the handle’s `operation_id` to equal this mint.
- Native snapshot load on JS-dead background relaunch (URLSession delegate) so verify can recompute the projection rather than trusting a stored digest alone.
- Direct `ring` (or another audited) dependency before any signing/AEAD call; AES-256-GCM-SIV is not provided by the rustls-transitive edge, and the RFC already refuses the feature without an audited implementation.
- Conformance list in §8 is the right set; do not grow the RFC to specify each vector.
- Callback-affinity row for the JSI-entry capture, as §7 already requires.
- macOS HMAC isolation almost certainly cannot be “access group on the file-based login keychain” (`SecureStoreModuleImpl.swift:263-268` already records that this keychain ignores iOS data-protection attributes). The §2 proof on Mac will need the data-protection keychain, a helper, or unavailability.

## Design evaluation (the questions that earn the review)

**(a) Key facility.** Sufficient against the stated attacker (JS + same-sandbox files + public modules; no arbitrary native code). SE P-256 `kSecClassKey` is unreachable from today’s JS surfaces: Secure Store only queries `kSecClassGenericPassword` (`SecureStoreModuleImpl.swift:298-303`); `__exactSignSync` takes a PEM string from JS and cannot name a `SecKey` (`hermes_runtime_crypto.cc:2916-2939`); I found no `kSecClassKey` / application-tag lookup in the tree. HMAC is the weaker half, and the RFC treats it that way: default access group forbidden, public query must be proven unable to address the item, any future access-group or `kSecClassKey` JS surface withdraws HMAC until re-proven. The SE-minted-device-refuses-HMAC pin is airtight against planted-HMAC-after-SE-delete *if* the pin/continuity marker is outside rollbackable journal state and a transient enclave failure is not treated as “no hardware.” That is specified. Residual routes are same-class generic-password queriers in-process (`desktop.secureStorage`, embedded host-resources); they do not break the rule if the rule is proven. They are inventory, not a hole.

**(b) TLV + algorithm rule.** Closes the usual canonicalization and downgrade set. `U` is the exact received bytes of tags 1 and 2; algorithm, `keyId`, issuer, and audience are inside the MAC; unknown/duplicate/out-of-order/trailing bytes are rejected before acceptance; verifiers never re-encode. Algorithm is taken from the out-of-band record, never from the message; ES256 public bytes are never used as HMAC keys; tag encodings are fixed (64-byte low-S `r||s` vs 32-byte HMAC). HS256-as-issuer is correctly reasoned and correctly confined. Cross-audience replay is closed by MAC’d `intendedAudience` plus `(issuer, intendedAudience, operationId)` consumption. The remaining confused-verifier residue is operational key reuse across kinds (nit 5), not a missing check in the protocol.

**(c) Mint ordering.** The order is correct and race-free against every revocation that linearizes through the common guard or is visible to the live OS/broker re-query held across commit. A Settings mutation that never publishes is the residual 0476 already named; bytes already on the wire cannot be recalled; later transitions are not grandfathered. “No raw caller path” does close the 0475 confused-deputy (signing a deputy-chosen `sourceUri`). Sync capture at a dedicated JSI host-function entry works with the actual trampoline: `exact.dispatchModule` does not capture (`hermes_runtime_ios.cc:392-425`), and Exact’s action path may `DispatchQueue.main.async` (`ModuleBridge.swift:73-82`). `currentPrincipalId()` plus `checkCapabilityWithFsMode`’s constrained-stack walk (`hermes_runtime_internal.h:1735-1881`) are valid only while the JS frame is live. Reading them at JSI entry, then doing async work with the captured snapshot, is compatible with LLP 0297 and with how attribution actually works. Unarmed mint is correctly unavailable, so this path is never the diagnostic module bus.

**(d) Verify + write-once.** §5 constructs the sole-writer property as a requirement on the platform primitive (atomic verify-to-seal or fd-unreachability through the writable window), names why `O_CREAT|O_EXCL` and same-UID-clearable `UF_IMMUTABLE` fail, and includes existing-descriptor writes and seal-clearing in the theorem. Digest recheck is correctly labeled defense in depth. The Apple `fromFile:` named-file tension is an honest blocker, not a hand-wave: background durable upload stays unavailable until one of the two named constructions is proven. Verify is specified with no live-JS dependency; JS-dead restart still needs a native armed-snapshot load, which is an implementation obligation, not a missing decision.

**(e) Freshness + revocation.** Sound and honest. A mutable Keychain item is not a counter; server evidence replaces only the operation-replay theorem, never the GCM-SIV nonce allocator. The JS-dead registry consumes 0013/0021 publications (projection, not raw snapshot digest; full `{policy, negative, dynamic, handle}` tuple) and 0472 four-layer vectors; that matches why a handle-only generation is unsafe (`mint_typed_handle` advances only `generations.handle` at `host/mod.rs:4340-4374`; `revoke_typed_dynamic` advances `negative` and `dynamic` but not `handle` at `4149-4168`; asserted at `13669-13685`). Restoring generations rather than republishing zero is required for JS-dead verify. Per-install boot salt is real anti-clone binding (`installationBinding` in the sealed record) and is correctly forbidden from making a resurrection claim if it restores with the journal.

**(f) Coherence + altitude.** This extends 0013/0021. It does not re-own typed transport or the policy engine. Against 0476 §14/§16 (and §3, §4, §6–§8, §10, §17) it covers every delegated obligation: typed mint witness and compare-and-commit, source ownership, mandatory inbox/journal, key/epoch/registry, the sole signed envelope, WP6 adapter, module gate, conformance. Resolutions of 0476 shorthand (`armedSnapshotDigest` → projection + `policyDigest`; “AES-GCM” → AES-256-GCM-SIV; `(sourceId, grantId)` → tagged provenance) are explicit and stricter, not contradictory. Deferring the portable kind is the right altitude; 0476 already deferred it. The WP6/armed-closed stance matches `hermes_runtime_fetch.cc:188-214` and LLP 0021 WP6 (`vendor/ibex/llp/0021-capsec-effect-model-migration.plan.md:1803-1805`): a mint-time signature cannot attest the future peer, and the simulator loopback carve-out is correctly banned as a mint oracle.

### Claim verification (all hold)

1. **`ArmedSessionToken`.** 32-byte `getrandom` nonce (`evaluation.rs:254-260`), stored with `snapshot_digest` (`205-213, 261-262`), wiped in `Drop` (`236-239`), compared by `Arc::ptr_eq` (`274-276`). Host mint caches and clones that identity (`host/mod.rs:2362-2446`). Possession-based, non-portable. Accurate.

2. **`check_handle_mint` / `mint_typed_handle`.** Explicit grant, Root ambient bypassed (`capability.rs:705-728`); Permissive/Audit still proceed via `gate_and_record` (`557-559`). Armed `Host::check_handle_mint` hard-denies (`host/mod.rs:4638-4650`). `mint_typed_handle` binds `armed_snapshot_digest` (`4356-4365`); initial mint requires the actor in the constrained stack (`4305-4312`); re-attenuation checks holder and containment (`4263-4288`). Accurate, and durable mint correctly refuses to use the legacy/ambient oracle.

3. **`digest_authenticated_projection`.** `domain || u64_be(len) || payload` (`host/mod.rs:448-456`). The durable preimage extends that shape with an extra `V1` delimiter; it does not reuse the function verbatim. Accurate.

4. **Principals / network / guard.** Tagged `Principal::{Package, Root, Runtime, ModuleLoader, Quarantine}` (`model.rs:306-324`). `FetchEndpoint` carries `schemes` / `host` / `port` (`1058-1062`). `ProtectedObjectGuard` exists (`decision.rs:124-132`). Accurate.

5. **Secure Store cannot hold a JS-unreachable signing key.** `getItem` returns UTF-8 secret bytes for any caller-chosen service/account (`SecureStoreModuleImpl.swift:111, 221-241, 298-303`; `api.ts:94-98`). Authenticated items throw (`222-224, 197-199`). No sign/verify surface. Accurate.

6. **Armed fetch closed; WP6 peer/redirect residual.** Armed `__nativeFetch` throws unless the simulator carve-out (`hermes_runtime_fetch.cc:188-214`); sync Windows path is closed (`552-555`). WP6: live fetch stays closed until the adapter reports the connected peer (`0021` WP6, lines 1803-1805). Accurate.

7. **Crypto resourcing.** Direct `hmac` / `sha2` (`vendor/ibex/Cargo.toml:85-86`). `ring` is a rustls feature and a `[patch.crates-io]` path to `vendor/ring` (`123, 315`), not a root `[dependencies]` entry. CryptoKit is already used on the Swift side. Accurate, including the “direct ring use needs a direct dependency” requirement.

## Verdict

The r4 revision decides the remaining security questions, matches the code it cites, covers what 0476 delegates without contradiction, and fail-closes where Apple or WP6 cannot yet prove the premise.

VERDICT: READY — no unresolved unforgeability, TOCTOU, key-reachability, downgrade, or missed-revocation defect in the r4 decisions.
