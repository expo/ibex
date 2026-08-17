# Review artifact: ibex LLP 0052 — Durable Authority Mint & Verify (family: codex)

Super-refine loop artifact. Reviews recorded verbatim per round.

## Round 1 — 2026-08-17

**Round record (persisted before launch):**

- Target: `vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md` r1 (     332 lines) — the ibex-corpus mechanism LLP that Exact LLP 0476 (Accepted 2026-08-17) delegates its byte-exact crypto / protected-object / mint-verify / WP6 work to.
- Target sha256: `984d69f5da2f8df89f6ea3140e7e729054c6276f3b89f4d7bd591f73cc6f47ae`
- Instruction (shared prompt) sha256: `a9bdc329106eb65c483bb085f09bbe912c22cfbbc6212e47635dd861061c7b7c`
- Topology (author-directed, Charlie Cheever, 2026-08-17 — same method as LLP 0475 and 0476): reviewers codex `gpt-5.6-sol` @ xhigh + grok `grok-4.6` @ xhigh; editor codex `gpt-5.6-sol` @ xhigh; late Claude (fable) final review once both families READY/nitpicking. Orchestrating Claude neither reviews nor revises.
- Capsule: read-only checkout; blindness instruction-fenced (self-attested) — forbidden vendor/ibex/llp/reviews/, llp/reviews/, scratchpad/tmp, non-target 0052* files, and the 0476 review artifacts; no network. Reviews sealed in orchestrator scratchpad on receipt, copied here once both round reviews land.
- Runner: codex exec -s read-only, gpt-5.6-sol @ xhigh

**Receipt:** completed 2026-08-17; codex gpt-5.6-sol @ xhigh; body sha256 `f3f16c202711fa1324f66ce62c5cd7d5d0b642bc8226dbd0f9caa41f8eb23818`; binds r1 sha256 `984d69f5…`. Verbatim below.

---

## Overall Assessment

The architecture is a good idea: native-held receipts, authority-before-copy, authenticated source handles, JS-dead verification, and fail-closed WP6/write-once/platform gates are the right foundations. The RFC also stays at the correct boundary relative to ibex LLP 0013/0021.

The substantive implementation claims are supported:

- `ArmedSessionToken` contains a 32-byte OS-random nonce, stores the armed-snapshot digest, wipes the nonce on final drop, and compares `Arc` identity (`vendor/ibex/src/engine/evaluation.rs:193-275`; `vendor/ibex/src/host/mod.rs:2362-2446`).
- Legacy handle mint bypasses Root fallback and requires an explicit grant (`vendor/ibex/src/host/capability.rs:705-727`). Typed mint authenticates the actor at the engine bridge and intersects every constrained principal’s static floor (`vendor/ibex/src/engine/hermes_runtime.cc:5564-5597`; `vendor/ibex/src/host/abi.rs:7600-7641`; `vendor/ibex/src/host/mod.rs:4305-4335`).
- The digest frame is exactly `domain ‖ u64_be(len) ‖ payload` (`vendor/ibex/src/host/mod.rs:448-456`).
- Principals and network endpoints are typed as claimed (`vendor/ibex/crates/capsec-semantics/src/model.rs:304-324`, `1050-1070`, `1233-1243`).
- Secure Store exposes caller-selected generic-password service/account operations and no sign/verify API (`packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:42-67`, `99-114`, `221-303`; `packages/exact-secure-store/src/api.ts:10-16`, `34-42`, `85-115`).
- Armed fetch is closed except for the separately marked simulator observer carve-out (`vendor/ibex/src/engine/hermes_runtime_fetch.cc:188-215`), matching WP6 (`vendor/ibex/llp/0021-capsec-effect-model-migration.plan.md:1789-1856`).
- `hmac` and `sha2` are direct dependencies; `ring` is rustls-transitive and locally patched/vendored, not direct (`vendor/ibex/Cargo.toml:85-86`, `118-124`, `309-315`).

However, four security-critical decisions remain defective or underdetermined. Revision r1 is not ready.

## Material Findings

1. **Mint is not actually linearized with revocation through the durable commit.**

   **Severity: MATERIAL.**

   The RFC specifies a before/after generation comparison followed by a separate bind-and-commit step (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:181-190`). That leaves the classic window:

   1. final generation comparison observes generation G;
   2. revocation publishes G+1;
   3. mint commits a receipt carrying G.

   Calling this “compare-and-commit” does not close the race without a shared lock, reservation, or atomic CAS spanning the final comparison and SQLite commit. Current typed mutations construct their atomicity by holding the decision-context write lock through publication (`vendor/ibex/src/host/mod.rs:4138-4179`, `4249-4375`, `4439-4480`). Exact LLP 0476 explicitly requires the corresponding durable guard to serialize authority publication/revocation with mint through SQLite commit (`llp/0476-durable-capability-capsules.rfc.md:264-269`).

   The RFC must define a native mint guard or equivalent reservation protocol whose linearization point covers the complete durable transaction. It must also join every relevant generation—policy, armed snapshot, negative, dynamic, handle, and all LLP 0472 OS/app/view/module publications—not merely an unspecified singular “typed authority generation.” Otherwise a revocation can linearize first yet leave a committed authority row, and durable-registry publication ordering may permit verification against stale state.

2. **The proposed key facility does not structurally close the HMAC/pin reachability and forced-fallback path.**

   **Severity: MATERIAL.**

   The RFC offers “a sibling native key module with no JS surface” *or* an access-control class the public module cannot satisfy (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:92-107`). A sibling module alone is not isolation: an HMAC key stored as a generic-password item in the same default Keychain access group remains addressable by the existing public module using arbitrary service/account values. That module queries exactly `kSecClassGenericPassword + service + account` and supports get/update/add/delete (`packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:221-303`).

   The Secure Enclave private key itself can be isolated by its distinct key class, but the HMAC fallback and the algorithm/key-family pin have no equally concrete protection here. If either is stored in the public generic-password namespace, JS can at minimum overwrite or delete it; if encoded as UTF-8/base64, it can extract it. If deletion or rollback erases the ES256 history/pin, an attacker can attempt to induce initial-HMAC fallback.

   Require both:

   - no JS registration/arbitrary signing surface; and
   - structural Keychain isolation—distinct item class and application tag for the Secure Enclave key, and a separately entitled access group, ACL/access-control requirement, helper-process boundary, or equally strong construction for HMAC and pin state that the public Secure Store query cannot satisfy.

   The algorithm/key pin must be atomically created with the installation key, inaccessible and rollback-resistant under the stated threat, and missing/deleted key material must fail closed rather than be treated as “hardware unavailable.” Negative tests are necessary evidence, but they do not replace the construction.

3. **The portable envelope is neither byte-exact nor replay-safe, and the audience claim is false.**

   **Severity: MATERIAL.**

   The TLV sketch leaves undecided:

   - tag numbers and ordering;
   - length widths/endian and nesting;
   - duplicate-known-field handling;
   - bounded field sizes;
   - the domain-separation bytes;
   - the exact signed preimage and exclusion of the signature TLV;
   - ES256 encoding—“ASN.1 or fixed `r‖s`” is explicitly not a choice;
   - canonical DER/high-S rejection if DER is selected; and
   - trusted verifier mapping from `(issuer, audience, kind, kid)` to an expected algorithm and key.

   See `vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:113-150`. Authenticating `alg` and `kid` prevents their mutation but does not prevent algorithm or key confusion if the verifier uses those attacker-originated fields to select a verification mode without an out-of-band pin.

   More seriously, `iss`/`aud` does **not** make an envelope execute once, contrary to line 149. It limits where the same signed envelope is accepted; it does nothing to prevent repeated execution inside that audience. Verify contains no receiver-side atomic replay/lease creation for portable envelopes (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:199-215`). Exact LLP 0476 requires exactly one lease/replay record keyed by `(issuer, intendedAudience, operationId)` before execution (`llp/0476-durable-capability-capsules.rfc.md:478-483`).

   Freeze the complete transcript and receiver trust/replay algorithm now, or stop claiming that the general portable primitive is specified. “No kind ships here” correctly prevents immediate deployment, but it does not make an incorrect reusable primitive acceptable.

4. **The certificate loses delegated authority lineage needed for kind safety and revocation.**

   **Severity: MATERIAL.**

   Exact LLP 0476 delegates a certificate containing a protected `kind`, a canonical nonempty list of every authority source/grant/generation, and a canonical set of network selectors (`llp/0476-durable-capability-capsules.rfc.md:80-118`). The target instead lists a singular authority-source/grant identifier, singular mint generation, and singular network selector, and omits `kind` even though verify later requires it (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:192-215`).

   This is security-significant: mint authorizes every origin and multiple four-layer/typed sources, while JS-dead verify must determine whether *any* contributing grant was revoked. An omitted source cannot be revalidated. An undefined `kind` also leaves cross-kind interpretation to implementation convention.

   The target must adopt an exact protected schema with `kind`, canonical authority-source lineage, the complete generation tuple, and canonical network-selector set. Commit and restart verification must fail if any listed source is missing, stale, revoked, or no longer maps to the same selector.

## Minor Findings and Nits

- The `ProtectedObjectGuard` citation is wrong. It is defined in `vendor/ibex/crates/capsec-semantics/src/decision.rs:123-132`, not `model.rs`. The principal and endpoint citations to `model.rs` are correct.
- Secure Store’s `getItem` returns UTF-8 `String`, not arbitrary raw bytes (`SecureStoreModuleImpl.swift:238-241`). The RFC should say it exports UTF-8/base64-encoded secret material and can overwrite/delete any matching generic-password item. The security conclusion remains valid.
- `currentPrincipalId()` supplies the actor, not the complete constrained stack. The new module ABI must synchronously capture both it and the full typed stack, following the existing handle bridge (`vendor/ibex/src/engine/hermes_runtime.cc:5583-5588`). The present Exact callback carries only frame bytes before queueing (`ios/ExactApp/ExactApp/Hermes/ExactRuntimeEngine.swift:93-100`; `ios/ExactApp/ExactApp/Engine/ExactNativeHostSession.swift:16790-16801`).
- The per-install boot salt adds value only if it is generated and retained outside the state an attacker can restore. If the non-migratory journal key already supplies that property, the salt is redundant defense in depth; if it is restored with the journal, it supplies none. State its storage/threat distinction or remove the resurrection claim.
- The RFC should distinguish `ArmedSessionToken`’s structural binding more precisely: the digest and nonce coexist in one opaque identity, while authentication uses pointer identity; it is not a MAC over the snapshot. The current wording mostly does this correctly.

## Answers to the Standard Questions

- **Good idea?** Yes. The native-held receipt specialization is much safer than handing JS a bearer capsule, and the fail-closed write-once, epoch, revocation, and WP6 gates are sound architectural choices.
- **Good plan?** Directionally yes, but not yet an acceptance-quality security contract. The central extension points are identified, while their atomicity and cryptographic transcript remain incomplete.
- **Add/change?** Add the common mint/revocation commit guard, exact multi-source lineage, structural Keychain/access-group isolation, protected algorithm-pin lifecycle, complete TLV transcript, verifier trust mapping, and atomic receiver replay record.
- **Remove?** Remove the claim that issuer/audience binding gives once-only execution. Consider removing the portable-envelope section entirely if it will remain deferred; otherwise finish it byte-exactly as LLP 0476 requires.
- **Definitely wrongheaded?** Treating a before/after generation check as commit linearization, treating a no-JS sibling module as storage isolation, and treating audience binding as replay prevention.
- **Possibly wrongheaded?** Specifying a universal portable envelope before a concrete kind supplies issuer distribution, rotation, receiver lease, and revocation requirements. It can work, but the current abstraction is premature.
- **Key open questions?** The exact Apple protected-key/HMAC isolation construction, common four-layer generation publication protocol, Apple write-once primitive, rollback-resistant epoch anchor, receiver trust/key-rotation model, and whether any Apple background adapter can expose enough facts for WP6.

The RFC otherwise coheres well with LLP 0013/0021: it preserves typed principals and possession delegation, does not re-own the policy engine or live transport, and honestly keeps armed background fetch closed. It covers much of LLP 0476 §14/§16, but the four findings above are precisely within the byte-exact crypto, key-domain, compare-and-commit, and revocation obligations delegated to it.

## Novel Ideas

- Native-held authority receipts as the default same-domain representation, reserving bearer capsules for actual trust-domain crossings.
- Treating authority-before-copy as a security boundary so denied callers cannot populate protected storage.
- Explicitly separating digest recheck from the write-once theorem.
- Making unavailable platform primitives a capability-reporting outcome instead of silently weakening the feature.
- Extending authenticated in-process authority semantics into a durable witness without converting the session nonce itself into a portable token.

## Implementation-Phase Notes

- The named-file versus fd-only Apple upload tension is honestly presented and may remain an implementation-selection blocker with “feature unavailable” as the valid result.
- The hardware-counter/server-idempotency split is appropriately honest; proving a practical Apple anchor is implementation work once the normative state machine is fixed.
- Add Rust/CryptoKit interoperability vectors for the chosen ES256 encoding, low-S behavior, malformed signatures, TLV duplicates, truncation, oversized lengths, and wrong issuer/audience/key mappings.
- Conformance should exercise the real module-entry capture path, including Promise, queue, native callback, and `setTimeout(0)` hops.
- Keychain tests should cover every public service/account spelling, alternate access groups, item classes, duplicate items, deletion, app upgrade, restore, key loss, and transient Secure Enclave errors.
- Keep `ring` as an explicit direct dependency when its signing/AEAD APIs are used; the RFC correctly rejects reliance on the transitive rustls edge.

## Verdict

VERDICT: NOT READY — The RFC leaves a commit/revocation race, an HMAC/pin reachability path, and an under-specified replayable portable envelope.
## Round 2 — 2026-08-17

**Round record:** target r2 (480 lines) sha256 `5ad9b44aee67799c7b671cdf70cfd7a93459e7a3864753ff13d8d64fac522fb2`; instruction sha256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`; editor codex gpt-5.6-sol @ xhigh closed r1's convergent central finding (singular authority-generation witness → complete authorityLineage set matching 0476 §4 / ibex GenerationSet{policy,negative,dynamic,handle}) + four-layer revocation ingestion/verify re-check + atomic key+pin fail-closed + byte-exact replay-safe envelope with receiver consumption. Fence verified. Topology/capsule/blindness unchanged from Round 1.- Runner: codex exec -s read-only, gpt-5.6-sol @ xhigh (fresh)

**Receipt:** completed 2026-08-17; codex gpt-5.6-sol @ xhigh; body sha256 `05120ed4c9b6194b1f36ae17f2ab89286846b9b37caca7d0654891b10630b262`; binds r2 sha256 `5ad9b44a…`. Verbatim below. (An earlier launch of this round used an empty prompt via a build bug and self-terminated with no review; that void run is not counted.)

---

## Overall Assessment

The architecture is strong and r2 fixes the round-1 singular-generation flaw: current code confirms dynamic revocation advances `negative` and `dynamic` while leaving `handle` unchanged (`vendor/ibex/src/host/mod.rs:4149`, `vendor/ibex/src/host/mod.rs:4167`, `vendor/ibex/src/host/mod.rs:13679`). Binding the complete authority-source set plus `{policy, negative, dynamic, handle}` is the correct repair.

Most load-bearing factual claims are accurate:

- `ArmedSessionToken` contains a 32-byte OS-random nonce, wipes it on drop, and compares `Arc` identity (`vendor/ibex/src/engine/evaluation.rs:204`, `vendor/ibex/src/engine/evaluation.rs:236`, `vendor/ibex/src/engine/evaluation.rs:253`, `vendor/ibex/src/engine/evaluation.rs:274`); mint derives its fields from the authenticated snapshot (`vendor/ibex/src/host/mod.rs:2377`, `vendor/ibex/src/host/mod.rs:2431`).
- `digest_authenticated_projection` is exactly `domain || u64_be(len) || payload` (`vendor/ibex/src/host/mod.rs:448`).
- Principals are deny-unknown tagged variants, fetch endpoints carry scheme/host/port, and `ProtectedObjectGuard` exists (`vendor/ibex/crates/capsec-semantics/src/model.rs:304`, `vendor/ibex/crates/capsec-semantics/src/model.rs:1057`, `vendor/ibex/crates/capsec-semantics/src/decision.rs:123`).
- Secure Store exposes caller-selected service/account generic-password reads, writes, and deletes to JS, while authenticated items are unimplemented and no signing surface exists (`packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:42`, `packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:99`, `packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:221`, `packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:298`; `packages/exact-secure-store/src/api.ts:94`).
- Armed fetch is closed except for the explicitly named simulator observer carve-out (`vendor/ibex/src/engine/hermes_runtime_fetch.cc:188`, `vendor/ibex/src/engine/hermes_runtime_fetch.cc:196`, `vendor/ibex/src/engine/hermes_runtime_fetch.cc:210`), consistent with WP6’s candidate/peer requirements (`vendor/ibex/llp/0021-capsec-effect-model-migration.plan.md:1789`).
- `hmac` and `sha2` are direct dependencies; `ring` enters through rustls and is vendored by patch rather than being a direct root dependency (`vendor/ibex/Cargo.toml:85`, `vendor/ibex/Cargo.toml:119`, `vendor/ibex/Cargo.toml:309`).

The review binds to target SHA-256 `5ad9b44aee67799c7b671cdf70cfd7a93459e7a3864753ff13d8d64fac522fb2`. Three security-construction defects and one required factual correction remain.

## Material Findings

1. **The complete `(sourceId, grantId)` authority witness is not defined against the actual CapSec provenance model. Severity: MATERIAL.**

   Claim: the certificate contains a canonical set of `(sourceId, grantId, mintGeneration)` entries, and verification reconstructs and exactly compares that set (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:147`, `vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:168`, `vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:321`).

   Evidence: a static `BoundAuthority` has only `source_id`, with no grant identity (`vendor/ibex/crates/capsec-semantics/src/decision.rs:66`). Arming synthesizes that identifier positionally (`vendor/ibex/crates/capsec-semantics/src/arming.rs:2114`). Dynamic authority has both a `grant_id` and its nested authority’s `source_id`, while handles have a `handle_id` and nested `source_id` (`vendor/ibex/crates/capsec-semantics/src/decision.rs:102`, `vendor/ibex/crates/capsec-semantics/src/decision.rs:114`). But `DecisionEvidence` exposes only one optional `source_id` field (`vendor/ibex/crates/capsec-semantics/src/decision.rs:459`), and static sources, handle IDs, and dynamic grant IDs are all flattened into that one slot (`vendor/ibex/crates/capsec-semantics/src/decision.rs:1037`, `vendor/ibex/crates/capsec-semantics/src/decision.rs:1071`, `vendor/ibex/crates/capsec-semantics/src/decision.rs:1723`).

   Why it blocks: r2’s safety argument depends on the verifier reproducing the same complete provenance set. There is currently no total canonical mapping for a static floor, no distinction in structured evidence between authority source and grant/handle identity, and no rule defining which overlapping positive authority is “contributing.” The RFC must define and require a new authenticated provenance record—either stable grant IDs for every authority row or tagged static/dynamic/handle variants—and its deterministic selector/effect-to-provenance derivation.

2. **The native receipt and mutable execution lease lack an AES-GCM nonce and record construction. Severity: MATERIAL.**

   Claim: the first consumer verifies an AES-GCM-protected native receipt whose AAD binds schema, operation, task, and column role (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:308`).

   Evidence: the key facility mentions a journal key (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:96`), and verify mentions only an AES-GCM tag and AAD (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:313`). It specifies no nonce length or uniqueness invariant, crash-safe nonce allocation, authenticated nonce encoding, record version/algorithm binding, or key-rotation interaction. Exact explicitly delegates actual crypto/protected-object correctness to this ibex LLP (`llp/0476-durable-capability-capsules.rfc.md:448`, `llp/0476-durable-capability-capsules.rfc.md:452`).

   Why it blocks: nonce reuse under AES-GCM can destroy authenticity, particularly for a lease rewritten on every transition. This is an unforgeability premise, not implementation polish. The RFC must freeze the native receipt/lease AEAD record and require per-key nonce uniqueness across crashes, rollback, retries, and row replacement—or choose a misuse-resistant construction and specify it.

3. **The common guard does not linearize an external OS revocation with mint or send. Severity: MATERIAL.**

   Claim: an OS permission withdrawn in Settings publishes through the common guard, invalidates committed leases immediately, and does not grandfather an in-flight request (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:381`, `vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:395`).

   Evidence: LLP 0013 explicitly identifies Settings changes as occurring behind the runtime’s back and calls check/use TOCTOU the failure mode (`vendor/ibex/llp/0013-per-package-capability-compartments.rfc.md:527`). A native guard can serialize only the later observation/publication, not the external Settings mutation itself. Even a live query immediately before commit or send cannot prevent a revoke after the query but before the effect. The Exact consumer correctly limits its claim: bytes disclosed before revocation observation cannot be recalled (`llp/0476-durable-capability-capsules.rfc.md:276`).

   Why it blocks: this leaves precisely the missed-revocation interval the RFC claims to close. It must define external revocation as linearizing at authenticated native observation/publication, carry forward 0476’s pre-observation residual, and limit “not grandfathered” to later lease transitions/retries. A stronger zero-gap claim requires a platform enforcement lease or callback that is atomic with the effect; otherwise the target must remain unavailable.

4. **The stated handle-mint precedent is contradicted by current code as written. Severity: MATERIAL.**

   Claim: `check_handle_mint` requires an explicit grant, and `mint_typed_handle` always requires the authenticated actor in the constrained stack (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:81`).

   Evidence: `check_handle_mint` allows immediately in `SecurityMode::Permissive` without an explicit policy decision (`vendor/ibex/src/host/capability.rs:705`, `vendor/ibex/src/host/capability.rs:718`). The constrained-stack requirement in `mint_typed_handle` is only in the no-parent branch (`vendor/ibex/src/host/mod.rs:4299`, `vendor/ibex/src/host/mod.rs:4305`); parent-handle re-attenuation checks current holder and containment but does not inspect `constrained_principals` (`vendor/ibex/src/host/mod.rs:4253`, `vendor/ibex/src/host/mod.rs:4263`).

   Why it blocks: this is a load-bearing implementation claim the review instructions require to be accurate. Durable mint already intends the stronger armed, fresh-mint rule, so the fix is narrow: state that invariant independently, qualify `check_handle_mint` to enforced/non-permissive operation, and qualify the constrained-stack claim to initial typed-handle mint.

## Minor Findings and Nits

- `requestPlanHash` lacks an explicit hash algorithm and byte length in the otherwise byte-exact v1 table (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:166`). Pin it to raw 32-byte SHA-256 or another named representation.
- The table uses raw 32-byte armed-snapshot and policy digests, while current CapSec `Digest` values are encoded strings. Specify the canonical string-to-raw conversion and reject algorithm or length mismatches.
- The boot salt has value only if its exact bytes or digest are bound into the sealed lease/AEAD AAD and checked during JS-dead verification. Target §6 describes storage and loss behavior but not that binding (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:402`); Exact 0476 does require it (`llp/0476-durable-capability-capsules.rfc.md:145`).
- “Separately entitled access group” should not imply module-level entitlement isolation inside one app process. The defensible property is the exact fixed public query surface: it is limited to `kSecClassGenericPassword` plus service/account (`packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:298`). Secure-Enclave keys use another class; an HMAC record needs a query/access-control class that this public implementation provably cannot address.

## Answers to the Standard Questions

- **Good idea?** Yes. Native-held receipts for same-store work, portable signed envelopes only across trust domains, explicit receiver replay consumption, and WP6 closure are the right architecture.
- **Good plan?** Mostly. Principal capture before queueing, authority before staging, authenticated-handle intake, exact-artifact hashing, and guarded compare-and-commit are correctly ordered. The provenance, AEAD, and external-revocation gaps prevent readiness.
- **Key facility:** The no-registration/no-JS-method design is sufficient within the stated JS attacker model if every public native route is inventoried. The existing Secure Store cannot reach a Secure-Enclave `kSecClassKey`, and isolated HMAC storage can work if the public generic-password query cannot select its access class. Atomic pin plus an independent continuity marker correctly forbids forced fallback, provided “never provisioned” is actually distinguishable from deleted state.
- **TLV and algorithms:** The protected algorithm/key/issuer/audience fields, exact raw transcript, unknown-field rejection, low-S ES256, and out-of-band trust record close the usual canonicalization, downgrade, and audience-confusion paths. The HS256 restriction is correctly reasoned: a verifier holding the key is an issuer. Receiver-side operation consumption closes same-audience replay for future kinds.
- **Mint ordering:** Correct for ibex mutations once all mutations use one guard. The synchronous capture is feasible: `dispatchModule` currently enters a C++ HostFunction while the JS frame remains live (`vendor/ibex/src/engine/hermes_runtime_ios.cc:392`), and the runtime already has a complete typed stack collector (`vendor/ibex/src/engine/hermes_runtime_fs.cc:369`). The captured context must be passed through the callback ABI before Swift enqueues work.
- **Verify and write-once theorem:** The RFC correctly constructs sole-writer premises instead of relying on a digest. It honestly treats Apple `fromFile:` as unresolved and keeps the feature unavailable pending proof. Verify can be JS-dead once the provenance record is fixed.
- **Freshness and revocation:** The epoch section is appropriately honest that mutable Keychain storage is not inherently monotonic. The native registry and full generation tuple cohere with the CapSec generation model. External OS revocation must use observation-time semantics as described above.
- **Coherence and altitude:** It extends 0013/0021 rather than re-owning typed transport or policy. It covers 0476 §14/§16’s delegated key, mint, protected-object, epoch, revocation, module-gate, WP6, and conformance obligations. Deferring every portable kind is the correct altitude.
- **Definitely wrongheaded?** No foundational choice is wrongheaded.
- **Possibly wrongheaded?** Promising that opaque background transport never grandfathers an in-flight request is too strong unless the claim is narrowed to native lease state and future sends.
- **Add/change/remove:** Add canonical authority provenance and the AEAD record; change external-revocation wording and the handle-mint precedent; remove the implication that an external Settings event itself acquires the native guard.
- **Key open questions:** canonical provenance identity, crash-safe AEAD nonce allocation, Apple named-file immutability, rollback-resistant epoch construction, and whether any Apple background adapter can expose WP6 facts.

## Novel Ideas

- Replace the ambiguous pair with a tagged `AuthorityProvenance` algebra: static-floor source, dynamic grant plus source, bearer handle plus source, and Exact four-layer publication. Canonically encode that tagged value directly in the authority-source set.
- Bind a digest of the complete provenance-to-selector relation, not only a set of source identities. This would make omitted-edge and remapped-selector verification mechanically exact.
- Give every protected lease transition one native “freshness ticket” containing the epoch, registry generation, and AEAD nonce allocation. Committing or burning the ticket could unify crash ordering without conflating those three counters.

## Implementation-Phase Notes

- Define and test one global lock order spanning the durable-authority guard, decision-context lock, registry lock, epoch facility, and SQLite transaction.
- Produce negative Keychain queries using the real key tag, key class, access group, service/account guesses, and public APIs—not only module-level mocks.
- Pin CryptoKit/ring interoperability vectors for DER-to-raw conversion, low-S normalization, malformed scalars, and algorithm/key mismatch.
- The named-file/`UF_IMMUTABLE` and background URLSession question is an honest implementation blocker, not an additional RFC-level material defect.
- Keep the platform matrix at unavailable until the actual write-once, epoch, and WP6 evidence passes; the current matrix does this correctly.

## Verdict

The r2 set-plus-full-generation repair is correct, but the current CapSec model cannot yet produce its claimed provenance tuple, the primary native receipt lacks a safe AEAD record construction, and external OS revocation is over-linearized.

VERDICT: NOT READY — the RFC still has an unconstructible authority witness, an unspecified AES-GCM nonce invariant, and a missed external-revocation race.
## Round 3 — 2026-08-17

**Round record:** target r3 (551 lines) sha256 `b21a90f5724c977091f1b54d840988f5f00e99195dbf36718a43d0d76a0aa32a`; instruction sha256 `3d66802cd008c869f0decb796ad9ad2c822bb8542e3265121c91a8bf2044c827`; editor codex gpt-5.6-sol @ xhigh closed codex-r2's 4 findings (constructible (sourceId,grantId) provenance witness against the real DecisionEvidence model; frozen misuse-resistant AEAD lease record incl. nonce-uniqueness/AES-GCM-SIV; observation-linearized external revocation with 0476 pre-observation residual; corrected handle-mint precedent re Permissive/no-parent branch). Fence verified. r2: grok READY, codex NOT READY (4). Topology/capsule/blindness unchanged.
- Runner: codex exec -s read-only, gpt-5.6-sol @ xhigh (fresh)

**Receipt:** completed 2026-08-17; codex gpt-5.6-sol @ xhigh; body sha256 `686fb5c56c79e38c36f74345a936df026dd26b6f30396d6e2d0026042074a034`; binds r3 sha256 `b21a90f5…`; NOT READY (3 material). Verbatim below.

---

## Overall Assessment

The architecture is strong, security-conscious, and largely coherent with ibex LLP 0013/0021 and Exact LLP 0476. However, r3 is not ready: it leaves two authority-lifetime/revocation semantics underdetermined and contains one internally impossible wire-format bound.

The requested factual checks otherwise hold:

- `ArmedSessionToken` contains a 32-byte OS-random nonce, wipes it when the final shared identity drops, and compares `Arc` identity; mint derives its other fields from the authenticated armed snapshot (`vendor/ibex/src/engine/evaluation.rs:193-215,236-275`; `vendor/ibex/src/host/mod.rs:2377-2446`).
- Enforced legacy handle mint bypasses Root fallback and requires an explicit grant; typed initial mint requires the actor in the constrained set and binds the snapshot, while parent re-attenuation uses holder plus containment (`vendor/ibex/src/host/capability.rs:687-727`; `vendor/ibex/src/host/mod.rs:4230-4375`).
- `digest_authenticated_projection` is exactly `domain || u64_be(length) || payload` (`vendor/ibex/src/host/mod.rs:448-456`).
- Principals are tagged Package/Root/Runtime/ModuleLoader/Quarantine variants, and fetch endpoints contain scheme/host/port (`vendor/ibex/crates/capsec-semantics/src/model.rs:304-324,1050-1063,1233-1244`). `ProtectedObjectGuard` exists in `decision.rs`, not `model.rs` (`vendor/ibex/crates/capsec-semantics/src/decision.rs:123-132`).
- Secure Store exposes caller-selected account and service, returns UTF-8 secret representations to JS, rejects the unimplemented authenticated path, and has no signing surface (`packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:42-67,99-114,221-304`; `packages/exact-secure-store/src/api.ts:10-23,94-114`).
- Armed fetch is closed except for the explicitly diagnostic simulator observer, and WP6 requires requested/candidate/connected-peer enforcement (`vendor/ibex/src/engine/hermes_runtime_fetch.cc:188-215,548-559`; `vendor/ibex/llp/0021-capsec-effect-model-migration.plan.md:1789-1856`).
- `hmac` and `sha2` are direct dependencies; `ring` is selected transitively through rustls and patched to the vendored copy, not directly depended upon (`vendor/ibex/Cargo.toml:40-86,118-125,309-315`).

No listed load-bearing code claim is materially contradicted.

## Material Findings

1. **The RFC does not reconcile durable authority with the per-run `armedSnapshotDigest`.**

   **Severity: MATERIAL.**

   **Claim:** Durable authority is persistable and verifiable after process death, while verification preserves exact armed-snapshot lineage.

   **Evidence:** The certificate carries `armedSnapshotDigest`, mint compare-and-commit checks it, and restart verification requires current provenance/registry state (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:61-66,176-184,266-279,403-422,459-472`). But production construction generates a fresh run nonce and then recomputes the armed-snapshot digest on every run (`vendor/ibex/llp/0021-capsec-effect-model-migration.plan.md:1272-1276`; `vendor/ibex/src/bin/ibex/runtime.rs:4781-4815`).

   **Why it blocks:** The RFC does not define whether a normal restart’s new run-nonce-bearing snapshot supersedes the mint snapshot. Requiring current digest equality invalidates every outstanding durable task on restart. Accepting the old digest as current without a multi-lineage rule risks retaining stale static authority after an actual policy/snapshot replacement. The registry’s singular “armed snapshot/full positive set” language does not resolve that choice.

   The RFC must either define a stable durable-authority projection digest excluding ephemeral run/session fields, or define an authenticated multi-lineage registry with precise rules distinguishing harmless run freshening from authority-replacing policy changes.

2. **Per-effect four-layer witnesses are collapsed into a representation with only one witness per grouped source.**

   **Severity: MATERIAL.**

   **Claim:** Mint and verify preserve every `(effectIndex, principal)` contribution and its four-layer state so revocation of any source or destination edge invalidates the lease.

   **Evidence:** `DurableDecisionEvidence` must emit one contribution per effect/principal row, after which identical provenance-plus-authorizing-selector rows are grouped (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:309-327`). The text then says each selected relation seals its four-layer vector (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:329-339`), but the wire schema has only one `fourLayerWitness` per grouped `authoritySource`; individual `coveredEffect` items contain no layer witness (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:176-184`). Verification and registry publication are nevertheless specified per complete selector/effect relation (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:413-420,459-479`).

   **Why it blocks:** Two requested selectors can select the same broad ibex provenance and authorizing selector while having different OS, broker, app-root, or module generations/states. The schema cannot represent that case, and it does not require mint to refuse unless every grouped row’s vector is identical. Collapsing them can miss which covered edge was revoked.

   Move the witness into each `coveredEffect`, key grouping by the complete witness, or normatively establish and enforce that the four-layer vector is invariant for all rows admitted to one group.

3. **The mandatory TLV schema exceeds its own maximum nesting depth.**

   **Severity: MATERIAL.**

   **Claim:** Every conforming envelope has nesting depth at most four.

   **Evidence:** Structured set items use nested schemas, and every v1 field is required (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:146-167`). A required path is `envelope → certificate → authorityLineage → authoritySource → fourLayerWitness → layerState` (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:169-184`), while the stated maximum is four (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:188-199`).

   **Why it blocks:** Under ordinary root-at-zero or root-at-one counting, every certificate containing the mandatory four-layer witness violates the parser bound. This prevents interoperable implementation of the byte-exact security format. Define the counting convention and raise the limit to cover the deepest required schema path.

## Minor Findings and Nits

- The target should repeat Exact’s normative requirement that `operationId` is native-generated with at least 128 bits of strength. It currently specifies only “16–64 opaque bytes” (`llp/0476-durable-capability-capsules.rfc.md:84-90`; `vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:188-193`).
- “Wiped on drop” should say “when the final token clone drops”; the wipe belongs to the inner `ArmedSessionIdentity`, not each `ArmedSessionToken` clone (`vendor/ibex/src/engine/evaluation.rs:193-239`).
- The document should call the TLV framing general, not the entire v1 certificate: the frozen certificate schema is strongly upload-shaped even though no portable kind ships yet.
- Correct the location shorthand for `ProtectedObjectGuard`; it is defined in `crates/capsec-semantics/src/decision.rs`, not `model.rs`.

## Answers to the Standard Questions

- **Good idea?** Yes. Native-only receipts, strict source provenance, exact-artifact hashing, protected algorithm/audience fields, receiver-side replay consumption, and fail-closed platform gates are the right architecture.
- **Good plan?** Mostly. The mint ordering is correct: capture attribution synchronously, authorize before staging, admit only a native checked object, hash the actual artifact, and hold one mutation guard through generation comparison and commit.
- **What should change?** Resolve the three material findings, particularly the stable durable-lineage identity and per-effect four-layer representation.
- **What should be added?** Maximal-depth wire vectors, restart vectors covering identical policy plus fresh run nonce, and mixed four-layer-generation tests for several covered selectors sharing one broad grant.
- **What should be removed?** No major mechanism. Keep the no-portable-kind stance and fail-closed platform matrix.
- **Definitely wrongheaded?** No.
- **Possibly wrongheaded?** Requiring a rollback-resistant seal counter for every AEAD rewrite may make the feature unavailable on more targets than necessary, but the RFC states that outcome honestly.
- **Key open questions?** Apple write-once feasibility, atomic key/pin construction, global nonce allocation, stable authority lineage across fresh runtime snapshots, and whether any background transport can expose WP6’s actual peer facts.

## Novel Ideas

- Introduce two identities: an ephemeral `mintArmedSnapshotDigest` for forensic provenance and a stable `durableAuthorityProjectionDigest` covering policy, registry, graph, selectors, source identities, and generations but excluding `runNonce` and entry-session fields.
- Make the revocation registry explicitly multi-lineage: a new runtime run can join an unchanged durable projection, while a changed policy projection atomically revokes prior lineages.
- Put the four-layer witness directly on each `coveredEffect`; deduplicate it during encoding only as a non-semantic compression layer.
- Generate the TLV parser, maximum-depth constant, and deepest-valid fixture from one schema description so these values cannot drift independently.

## Implementation-Phase Notes

- The vendored `ring` exposes AES-GCM and ChaCha20-Poly1305, not AES-256-GCM-SIV (`vendor/ibex/vendor/ring/src/aead.rs:30`; `vendor/ibex/vendor/ring/src/aead/algorithm.rs:136-163`). An audited GCM-SIV implementation remains a real dependency, as the RFC acknowledges.
- Factor synchronous principal capture from the same native helper used by `checkCapabilityWithFsMode`; do not reimplement its carrier, no-user, scheduler, and truncation rules independently (`vendor/ibex/src/engine/hermes_runtime_internal.h:1801-1898`).
- The current module callback forwards only bytes/context, and Exact queues the action later, confirming why the new entry capture must occur in the JSI host function (`vendor/ibex/src/engine/hermes_runtime_ios.cc:376-422`; `ios/ExactApp/ExactApp/Engine/ExactNativeHostSession.swift:16759-16807`).
- Secure Enclave keys are structurally outside the public generic-password query. HMAC isolation still needs real entitlement/access-group tests because entitlements are process-wide even though the JS module cannot select an access group.
- The Apple `fromFile:` issue is honestly treated as an availability blocker, not hand-waved.
- External revocation is honestly observation-linearized; the document does not claim that an immediately preceding query eliminates the platform observation-to-effect gap.
- The per-install salt is legitimate defense in depth for cross-install restoration, but it contributes nothing against same-install journal rollback; the epoch anchor remains load-bearing.

## Verdict

VERDICT: NOT READY — durable snapshot lineage, per-effect four-layer revocation evidence, and the self-contradictory TLV depth bound must be resolved before the protocol is safe and implementable.
## Round 4 — 2026-08-17

**Round record:** target r4 (544 lines) sha256 `c38d5f50dc4a0ed2140c6339fe70e33ac55085db9984587a71ce7dfcc65ff97f`; instruction sha256 `948c849cc271c8d6275071beefa3867a900d5811b4200091c0cc445f6ceefbb8`; editor codex gpt-5.6-sol @ xhigh closed codex-r3's 3 findings (stable durable-authority projection digest excluding ephemeral run/session fields vs the per-run recomputed armedSnapshotDigest; per-effect four-layer witness so two selectors with differing OS/broker state cannot collapse; self-consistent TLV depth bound). Fence verified. r3: grok READY (2nd), codex NOT READY (3). Topology/capsule/blindness unchanged.
- Runner: codex exec -s read-only, gpt-5.6-sol @ xhigh (fresh)

**Receipt:** completed 2026-08-17; codex gpt-5.6-sol @ xhigh; body sha256 `80ce9a7867e9ea485b2de1d53377ab6efab7e2822a1074f52c480edd90085dc1`; binds r4 sha256 `c38d5f50…`; NOT READY (2 material). Verbatim below.

---

## Overall Assessment

The architecture is strong, conservative, and appropriately honest about unavailable platform primitives. The native receipt, strict TLV envelope, algorithm pinning, generation-linearized mint, write-once theorem, JS-dead verification, and WP6 closure are good decisions.

The seven load-bearing implementation claims are substantially accurate:

- `ArmedSessionToken` contains a 32-byte OS-random nonce, wipes it when the final `Arc` drops, stores the snapshot digest, and authenticates by `Arc::ptr_eq` (`vendor/ibex/src/engine/evaluation.rs:193`, `:204`, `:236`, `:242`, `:274`; `vendor/ibex/src/host/mod.rs:2362`).
- Enforced legacy handle mint bypasses Root fallback, while the typed JSI path captures actor and constrained stack and binds handles to the armed snapshot (`vendor/ibex/src/host/capability.rs:705`; `vendor/ibex/src/engine/hermes_runtime.cc:5564`; `vendor/ibex/src/host/abi.rs:7614`; `vendor/ibex/src/host/mod.rs:4230`, `:4305`, `:4363`).
- The digest framing is exactly `domain || u64_be(length) || payload` (`vendor/ibex/src/host/mod.rs:448`).
- Principals are tagged variants; network resources carry scheme/host/port; `ProtectedObjectGuard` exists (`vendor/ibex/crates/capsec-semantics/src/model.rs:304`, `:1057`, `:1233`; `vendor/ibex/crates/capsec-semantics/src/decision.rs:123`).
- Secure Store exposes caller-selected service/account generic-password reads and writes, returns bytes as UTF-8, rejects authenticated-item use as unimplemented, and has no sign/verify API (`packages/exact-secure-store/ios/SecureStoreModuleImpl.swift:42`, `:99`, `:178`, `:221`, `:298`; `packages/exact-secure-store/src/api.ts:10`).
- Armed fetch is closed pending peer-aware transport, apart from the explicitly named simulator-observer build carve-out (`vendor/ibex/src/engine/hermes_runtime_fetch.cc:188`, `:196`, `:210`, `:548`); WP6 requires candidate and actual-peer enforcement (`vendor/ibex/llp/0021-capsec-effect-model-migration.plan.md:1789`).
- `hmac` and `sha2` are direct dependencies; `ring` arrives through rustls and is patched to the vendored copy rather than being a direct root dependency (`vendor/ibex/Cargo.toml:83`, `:118`, `:309`).

Two defective security decisions remain.

## Material Findings

1. **The stable durable-authority projection omits the existing authenticated `preparedGraphs` authority.**

   - Claim: the target says `P` copies an exact list of armed-snapshot fields, excludes exactly `armedSnapshotDigest`, `runNonce`, and `channelEpoch`, and refuses new or unclassified fields (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:153`).
   - Evidence: `ArmedSnapshot::load` already accepts, validates, and retains `preparedGraphs` (`vendor/ibex/crates/capsec-semantics/src/arming.rs:448`, `:506`, `:517`, `:541`). Accepted LLP 0042 defines it as authenticated authority for prepared publications, covered by the snapshot digest (`vendor/ibex/llp/0042-prepared-graph-independent-commitment.rfc.md:146`), and production snapshot construction emits it (`vendor/ibex/src/module_loader/runner_pipeline.rs:4339`).
   - Severity: **MATERIAL**.
   - Why it blocks: following the RFC literally either makes durable authority unavailable for current snapshots containing `preparedGraphs`, or—if an implementation merely copies the enumerated fields without enforcing the unclassified-field rule—allows prepared-publication authority, producer, semantic inventory, or principal-set changes without replacing durable lineage. The RFC must classify `preparedGraphs`: normally include it in `P`; otherwise explicitly exclude it with a security rationale. Add conformance proving a prepared-graph change changes the projection.

2. **The four-layer witness does not bind the authenticated view-broker grant or execution scope.**

   - Claim: the target says its per-effect witness and native registry completely preserve the four-layer decision and revocation relation.
   - Evidence: `fourLayerWitness` carries only `{generation,state}` for each layer, while `coveredEffect` contains only effect index, principal, selector, and that witness (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:128`). The native-registry key likewise omits a broker grant, root, view, or execution-scope identity (`vendor/ibex/llp/0052-durable-authority-mint-and-verify.rfc.md:449`). `effectOwner` cannot fill the gap because it is a typed `Principal` (`vendor/ibex/crates/capsec-semantics/src/model.rs:1552`), whose variants contain no view scope (`vendor/ibex/crates/capsec-semantics/src/model.rs:304`). Exact’s governing model describes broker revocation for a particular view (`llp/0472-web-standards-first-runtime-apis.rfc.md:754`) and its access API already takes `rootId`/`viewId`, although that layer is not implemented yet (`vendor/ibex/packages/ibex-runtime-js/src/security/Permissions.ts:184`, `:223`).
   - Severity: **MATERIAL**.
   - Why it blocks: two calls from the same package principal for the same selector but under different view-broker grants collapse to the same sealed relation. Revoking view A can either incorrectly preserve A’s task by borrowing view B’s surviving grant, or force global over-revocation; the schema cannot prove which grant authorized mint. The module-gate capture contract also captures only actor/effect owner/principal stack, so an unauthorized view can be indistinguishable at JSI entry. Each covered effect needs an owner-issued, unforgeable broker-grant/execution-scope identity, captured synchronously and included in the certificate, registry key, compare-and-commit, and revocation publication. A raw JS-supplied `viewId` is insufficient.

## Minor Findings and Nits

- “`check_handle_mint` requires an explicit grant” is true under Enforce. Permissive allows directly, and Audit records denial while allowing; the target itself correctly preserves that qualification (`vendor/ibex/src/host/capability.rs:718`).
- The armed-fetch closure has a compile-time simulator performance-observer exception. The RFC correctly forbids using that path as mint authority, so this is not a contradiction.
- “No capsule kind ships here” would be clearer as “no **portable** capsule kind ships here,” because the native certificate still protects `kind="durable-upload"`.
- Reconcile the armed-snapshot JSON schema with `ArmedSnapshot::load`: the schema currently has `additionalProperties: false` but does not list `preparedGraphs` (`vendor/ibex/capsec/schema/armed-snapshot.schema.json:36`, `:289`).

## Answers to the Standard Questions

- **Good idea?** Yes. A native-held receipt for same-domain durable work is materially safer and simpler than giving JS a signed bearer token. Portable signatures only when authority crosses a trust domain is the right split.
- **Good plan?** Yes after the two material bindings are repaired. Mint ordering is otherwise correct: synchronous attribution, full authority before copy, checked-object staging, exact-artifact hashing, then compare-and-commit under the shared guard.
- **Add/change?** Include `preparedGraphs` in the durable projection and add an authenticated broker-grant/execution-scope identity per covered effect.
- **Remove?** Nothing substantial. Keep the fail-closed platform gates and portable-kind deferral.
- **Definitely wrongheaded?** Public Secure Store key reuse, cross-domain HMAC, hash-then-open as immutability, and mint-time network signatures as peer evidence would be wrongheaded; the RFC correctly rejects all four.
- **Possibly wrongheaded?** Requiring a rollback-resistant deterministic nonce counter for AES-GCM-SIV may make Apple deployment harder than necessary. A CSPRNG nonce construction deserves comparison, but the current decision is secure and not acceptance-blocking.
- **Key open questions?** Apple named-file write-once enforcement, a real rollback-resistant epoch/nonce anchor, WP6-compatible background transport, GCM-SIV implementation choice, prepared-graph projection treatment, and the authenticated broker-scope carrier.

## Novel Ideas

- Generate the durable projection from an exhaustive field-classification manifest: every armed-snapshot field is marked `included`, `session-excluded`, or `refuse`. CI should compare that manifest against the actual loader’s accepted fields.
- Represent the view-broker decision as an owner-issued capability identity—such as `{brokerDomain, executionScopeId, grantId, generation}`—rather than a raw view number.
- Produce a key-facility reachability manifest enumerating every JS-addressable Keychain class/access-group query and prove the facility’s key class is disjoint.

## Implementation-Phase Notes

- The key-facility design is sufficient only after the Apple access-group/default-query behavior and every other native module route are proven. The RFC correctly makes this a platform gate.
- The vendored `ring` provides ECDSA/Ed25519 and ordinary AEAD, but not AES-256-GCM-SIV; the repository currently has no direct GCM-SIV implementation. A reviewed direct dependency or native implementation is required.
- CryptoKit/ring vectors must test raw `r||s`, low-S normalization, DER rejection, and key-identity derivation.
- The current Exact module action path loses attribution before its queued dispatch: `dispatchModule` forwards only bytes (`vendor/ibex/src/engine/hermes_runtime_ios.cc:392`), and Exact later queues the action (`ios/ExactApp/ExactApp/Engine/ExactNativeHostSession.swift:16790`). The new dedicated JSI ingress can capture ibex actor/stack synchronously, but must also capture the broker identity identified above.
- Apple `fromFile:` remains an honest blocker, not a hand-wave. Background durable upload must stay unavailable until the named-file theorem or a viable alternative transport is proven.
- Verify is correctly capable of running without live JS once the native registry, snapshot restoration, OS query, and broker-scope repair exist.

## Verdict

VERDICT: NOT READY — The projection omits current authenticated prepared-graph authority, and the four-layer witness does not bind the view-broker grant or execution scope needed to close cross-view mint and revocation aliasing.