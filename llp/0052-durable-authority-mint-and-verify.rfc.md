# LLP 0052: Durable Authority — Mint, Verify, and the Protected Native Facility

**Type:** RFC
**Status:** Accepted
**Systems:** Security, Policy, CapSec, Host ABI, Engine, Crypto, Modules, Apple, Android, Conformance
**Author:** Charlie Cheever / Claude
**Date:** 2026-08-17
**Revised:** 2026-08-17 (r6 — nit polish after tri-family READY: mechanical projection key-set equality; insecure-build + channelEpoch conformance assertions; anchor refresh. **Accepted 2026-08-17** by Charlie Cheever after the super-refine loop converged: grok READY on r2/r3/r4 (3 consecutive); codex NOT READY r1–r4 with a strictly narrowing non-repeating finding set (4→4→3→2), all closed by r5; late Claude/fable READY on r5 with independent verification of all seven load-bearing ibex-code claims and zero material findings; r6 nit polish. Reviews: llp/reviews/0052-durable-authority-mint-and-verify.{codex,grok,fable}.md. This LLP is the ibex-corpus mechanism that Exact LLP 0476 delegates to; both accepted 2026-08-17.)
**Related:** LLP 0013 (per-package capability compartments — principals, grants, authority-bearing handle mint; this extends the mint semantics to a persistable, cross-process form), LLP 0021 (typed CapSec effect model, armed snapshot, WP6 network staging — the authority root and the transport-closure rule this obeys), LLP 0014 (import-site grants and the generated policy artifact), Exact LLP 0476 (Durable Capability Capsules — the consumer that delegates this mechanism here; its §3–§8, §10, and §14–§16.1 enumerate this LLP's obligations), Exact LLP 0472 (the four-layer capability intersection mint must evaluate), `capsec/registry/capability-definitions.json`, `capsec/registry/ingress-obligations.json`, `crates/capsec-semantics/src/model.rs` (typed principals/selectors), `crates/capsec-semantics/src/decision.rs` (`ProtectedObjectGuard`), `src/host/capability.rs` (`check_handle_mint`), `src/host/mod.rs` (`mint_typed_handle`, `revoke_typed_dynamic`, `mint_armed_session_token`, `digest_authenticated_projection`), `src/engine/hermes_runtime_fetch.cc` (the armed-fetch closure), `src/engine/hermes_runtime_internal.h` (`currentPrincipalId`, constrained-stack walk)

## Summary

Exact LLP 0476 establishes that durable, background native work (uploads first; downloads, resident isolates, native extensions,
cross-device operations later) needs authority that a native engine can verify **while the JS runtime is absent or dead**, and JS
must never hold or author it. LLP 0476 delegates every byte-exact and native-trust-domain mechanism to this blocking ibex LLP.

It specifies, as extensions of the LLP 0013/0021 capability model:

1. A **protected native key facility** — a non-exportable signing/MAC key held in hardware where available (Secure Enclave),
   unreachable through JS-addressable Secure Store routes, exposing only a native sign/verify oracle, with downgrade-proof pinning.
2. A **byte-exact protected authority envelope** — length-prefixed TLV (not signed canonical JSON) with version, algorithm, key id,
   issuer, and intended audience protected, unknown-field rejection, fixed signature/MAC encoding, HS256 confined to one native
   authority domain, and ES256 mandatory across trust domains.
3. **Mint** — `mintDurableAuthority` synchronously captures the typed principal stack and owner-issued execution-scope binding at
   JSI entry, evaluates the LLP 0472 four-layer intersection plus holder/owner and network authority **before** staging, hashes the
   artifact natively, then compare-and-commits the complete authority-source and snapshot/policy/generation witness under the
   common mutation guard.
4. **Verify** — a JS-dead-safe native check of authority, lease, artifact digest, every source/selector, ibex and LLP 0472
   four-layer/execution-scope registry state, and an external monotonic epoch that defeats journal-snapshot rollback.
5. **Protected objects** — mandatory protected inbox/journal objects extending `ProtectedObjectGuard`, with a write-once
   sole-writer construction against same-credential code that holds through every background transport reopen.
6. A **WP6-compatible background transport adapter contract**, **module-gate synchronous authority-context-capture contract**, and CapSec
   **registry + conformance** entries for the new native authority boundary.

The length-prefixed framing and signing rule are reusable outside this native store; the frozen v1 certificate is deliberately
upload-shaped. Exact LLP 0476's first consumer uses a native-held receipt and never emits a portable capsule. No **portable**
capsule kind ships here; the first portable consumer proves the signed envelope end to end.

## 1. Where this sits in the capability model

This LLP adds neither a policy engine nor a capability namespace. It carries an **already-evaluated typed grant** forward across
time and a process boundary—the durable analogue of `ArmedSessionToken` (`mint_armed_session_token`: 32-byte OS-random nonce bound
to the authenticated snapshot digest, wiped when the final clone drops, pointer-identity compared). That token is possession-based
and non-portable; durable authority adds exactly **persistability** and **cross-process, JS-dead verifiability**.

Vocabulary is LLP 0013/0021's, unchanged:

- **Principal** is the typed CapSec `Principal` (Root/Package/Runtime/…; `model.rs`). `currentPrincipalId()` is only the native
  `uint64_t` actor id; mint synchronously captures it **and** the `checkCapabilityWithFsMode` constrained-stack walk, then maps those
  authenticated ids through the snapshot. It never substitutes Exact's `{name, locator}`, which cannot represent Root/integrity.
- **Execution scope** is a separate native-owner binding because no `Principal` variant carries root/view/scope identity. Mint never
  overloads `effectOwner` or accepts a caller-authored view id for this relation.
- **Grants** are typed CapSec capabilities (`network:fetch` scheme/host/port; typed protected-inbox resource—§5). There is no
  fictional `fs:read:transfer-inbox`; inbox reach is a typed protected object or LLP 0013 handle.
- **Mint authority** does **not** inherit permissive/general handle mint. The legacy unarmed string manager's `check_handle_mint`
  requires an explicit grant in Enforce but may allow in Permissive/Audit; armed `Host::check_handle_mint` hard-denies
  (`capability.rs:557-559,710-728`; `host/mod.rs:4638-4650`). The live precedent is `mint_typed_handle`: it binds the snapshot; only
  initial no-parent mint requires the actor across the constrained stack, while re-attenuation checks holder plus containment
  (`host/mod.rs:4230-4375`). Durable mint is always armed, enforced, and fresh: legacy string/ambient Root/bootstrap authority and
  parent-handle re-attenuation are not its oracle; it applies its own complete stack witness.

## 2. Protected native key facility

Verifiability with JS dead and unforgeability by JS require a facility-owned key that never returns to JS. Existing
`com.exact.securestore` cannot provide it: caller-chosen generic-password service/account queries return matching UTF-8 secret
material and can overwrite/delete it; authenticated items are unimplemented. The Apple isolation inventory also includes the
`desktop.secureStorage` generic-password host calls and the embedded host-resource Keychain store; neither is assumed disjoint.

The facility has **no module registration, JS methods, or arbitrary-byte signing API**. Its key, algorithm/key-family pin,
continuity state, journal key, epoch anchor, and registry are unreachable through every public Secure Store, filesystem,
process/alias, backup/restore, and module route in the threat model. On Apple, the asymmetric key is a sign-only, non-exportable
Secure Enclave P-256 `kSecClassKey` with a distinct application tag. HMAC is `ThisDeviceOnly`, non-synchronizing, and isolated by a
separately entitled access group, helper, or equally strong class the public generic-password query cannot satisfy; the default
group is forbidden. Entitlement is not in-process module isolation: a group qualifies only while every JS-addressable module and
host-call query, including the current routes above, provably cannot address it. No present/future JS module or host call may accept
an access-group selector or `kSecClassKey`/application-tag lookup capable of naming facility state; such a route makes HMAC
unavailable until isolation is reproven.

**Atomic provisioning and pinning are construction requirements.** “Truly fresh” means no continuity/key/pin state **and** no
journal, receipt, or epoch residue; a missing pin alone is key loss. One transaction creates the key and immutable `(algorithm,
keyId, key class/token)` pin, or one protected object uses live immutable key attributes as the pin. Secure Enclave `keyId` is
SHA-256 of SEC1 uncompressed public-key bytes; verify confirms P-256 and `kSecAttrTokenIDSecureEnclave`. For HMAC, an OS-random
32-byte `keyId`, key bytes, and `HS256` pin share the isolated atomic record. A two-phase primitive conforms only as one linearizable
operation: nothing activates before key+pin commit; every partial/crash state permanently fails closed. Pin and continuity marker
are outside rollbackable journal state and MUST resist the stated attacker. Otherwise durable authority is unavailable.

Initial HMAC selection requires a probe proving no enclave **and** proof the facility never provisioned a key. Thereafter no
fallback or automatic reprovisioning exists: missing/inaccessible/deleted/rolled-back/mismatched key, pin, or continuity is terminal
key loss and all mint/verify operations refuse. A transient enclave/Keychain failure is not hardware absence. An attacker-planted HMAC key
and public flag cannot replace a deleted enclave key: verify accepts only the facility atomic pin/live-key identity, never message
or public-store selection; its loss refuses rather than bootstraps. Required extraction/overwrite/delete/fallback tests prove this.

The only signing entry is mint (§4). ES256 is preferred; HMAC-SHA256 is confined
to one native authority domain because every HMAC verifier is also an issuer.

## 3. Byte-exact protected authority envelope

The transcript is TLV, not signed canonical JSON. Every TLV is
`tag:u16_be || length:u32_be || value[length]`. A container value is the exact
concatenation of its child TLVs. Children are in strictly increasing tag order;
every defined field occurs exactly once unless its schema says optional, and v1
has no optional fields. Duplicate known tags, unknown tags, non-minimal/trailing
bytes, out-of-order tags, invalid UTF-8/ASCII, and unknown enum values are
rejected **before** signature acceptance. Verification authenticates received
bytes and never parses then re-encodes them.

A `set<T>` value is `count:u16_be` followed by `count` frames of
`itemLength:u32_be || itemBytes`. Structured items use their named nested schema;
typed scalar items use their canonical bytes. Items are sorted by unsigned
lexicographic `itemBytes` and are unique; `authoritySources` also rejects duplicate
`(provenanceBytes, authorizingSelectorBytes)` group keys, and one covered
`(effectIndex, principal)` may occur in exactly one authority-source item.
Non-canonical order or an empty set where nonempty is required is rejected. Integers are fixed-width
unsigned big-endian; booleans are exactly `00` or `01`. Principal, checked-object,
and selector values are the exact UTF-8 bytes returned by
`capsec_semantics::canonical::to_jcs_bytes` (RFC 8785 JCS over I-JSON) for the
deny-unknown-fields typed value; decoding then re-encoding MUST reproduce the
received bytes. That inner typed encoding is owned by LLP 0013/0021 and consumed,
not forked, here; a type-schema change requires a new envelope version.

The v1 tags are fixed:

| container | tags in order |
|---|---|
| envelope | `1 header`, `2 certificate`, `3 authenticator` |
| header | `1 version(u16=1)`, `2 algorithm(u8: 1=ES256, 2=HS256)`, `3 keyId(32 bytes)`, `4 issuer`, `5 intendedAudience` |
| certificate | `1 schemaVersion(u16=2)`, `2 kind`, `3 operationId`, `4 taskId`, `5 issuedAt(u64 ms)`, `6 expiresAt(u64 ms)`, `7 actor`, `8 effectOwner`, `9 constrainedPrincipals(set)`, `10 authorityLineage`, `11 source`, `12 networkSelectors(set)`, `13 serviceIdentity`, `14 adapter`, `15 requestPlanHash(32-byte SHA-256)`, `16 redirectPolicy(u8: 0=none, 1=allow-within-origins)`, `17 acceptBackgroundRedirectLeak(bool)`, `18 byteCeiling(u64)` |
| authorityLineage | `1 durableAuthorityProjectionDigest(32 bytes)`, `2 policyDigest(32 bytes)`, `3 authoritySources(set)` |
| authoritySource item | `1 provenance`, `2 authorizingSelector`, `3 coveredEffects(set)`, `4 mintGeneration` |
| static provenance | `1 kind(u8=1)`, `2 principal`, `3 sourceId`, `4 stratum(u8: 1=static-floor, 2=implicit-package-self)` |
| dynamic provenance | `1 kind(u8=2)`, `2 principal`, `3 sourceId`, `4 grantId` |
| handle provenance | `1 kind(u8=3)`, `2 owner`, `3 holder`, `4 sourceId`, `5 handleId`, `6 operationId` |
| coveredEffect item | `1 effectIndex(u16)`, `2 principal`, `3 requestedSelector`, `4 fourLayerWitness`, `5 executionScope` |
| mintGeneration | `1 policy(u64)`, `2 negative(u64)`, `3 dynamic(u64)`, `4 handle(u64)` |
| fourLayerWitness | `1 osPermission`, `2 appRoot`, `3 viewBroker`, `4 moduleDeclaration` (each a `layerState`) |
| layerState | `1 generation(u64)`, `2 state(u8: 1=granted, 2=denied, 3=prompt, 4=unavailable)` |
| executionScope | `1 class(u8: 1=native-unscoped, 2=view-broker-grant)`, `2 ownerServiceIdentity`, `3 bindingId(32 bytes)` |
| source | `1 checkedObjectIdentity`, `2 sourceAuthoritySelector`, `3 artifactManifestRoot(32 bytes)`, `4 totalLogicalLength(u64)` |
| adapter | `1 id`, `2 version` |

`kind`, issuer, intended audience, service/adapter ids/versions, provenance string ids, and `ownerServiceIdentity` are 1–255 ASCII
bytes in `0x21..=0x7e` (`kind` at most 64).
`operationId` is a native-generated 16–64-byte opaque identifier with at least
128 bits of CSPRNG strength; `taskId` is 1–255 bytes, and canonical typed objects
are at most 16 KiB. Each set has 1–256 items. One TLV value is at most 256 KiB
and the envelope at most 1 MiB. Structured-container depth counts `envelope` as
0; each nested named container or structured set item adds one, while scalar
leaves and set framing do not. The maximum is 6, covering the deepest required
path: `envelope(0) → certificate(1) → authorityLineage(2) → authoritySource(3) →
coveredEffect(4) → fourLayerWitness(5) → layerState(6)`. Times and generations
MUST also be within ibex `SafeUint` (`0..=9_007_199_254_740_991`); expiry is greater than
issuance. `Digest` values arrive as the canonical `sha256-` plus unpadded
base64url string used by CapSec; an envelope decodes the suffix to exactly 32
bytes and requires byte-for-byte re-encoding equality. `requestPlanHash` is the
raw 32-byte SHA-256 of the consumer-owned exact request-plan transcript. These
are rejection bounds, not allocator hints.

Every covered effect has an owner-issued execution-scope binding. Its `bindingId` is a fresh 32-byte CSPRNG value minted and
retained by the native owner; its protected owner-side relation names exactly one scope lifetime and, for class 2, one root, view,
and broker-grant instance. It is a registry identity, not a JS bearer: JSI ingress captures its live native carrier and serializes
the owner-recorded identity. Raw JS `rootId`, `viewId`, or binding bytes refuse. An ID is never reused for another scope/grant;
revoke/regrant and a new scope lifetime get fresh values. Class 1 is legal only when the capability/target proves no view-broker
distinction applies and its owner publishes that layer as non-distinguishing `granted`; otherwise class 2 is required and absence
of its native owner/carrier makes durable authority unavailable.

**Stable durable-authority projection.** Mint computes this only after normal
armed-snapshot loading authenticates the complete current document. Let `P`
copy exactly these top-level values into a deny-unknown object:
`snapshotSchema`, `capsVocab`, `semanticCore`, `vocabDigest`, `registryDigest`,
`policyDigest`, `workflow`, `effectiveMode`, `engine`, `rootIdentity`, `entry`,
`projectRootDiscovery`, `packageGraph`, `rootBindings`, `pathCanonicalizers`,
`principals`, `environmentBase`, `bootstrapCompatibilityModes`,
`processAuthorityCeiling`, `rootAuthorityCeiling`, `bootstrapAuthorityFloor`,
`generations`, `protectedObjects`, `networkPosture`, and `structuralPosture`, plus
`preparedGraphs`, `devServedProjectRoot`, `exactEmbedder`, and `runtimeExtensions` iff present. Those four optional fields are
included with their exact authenticated value whenever present; absence and a present empty value remain distinct.
It excludes exactly `armedSnapshotDigest`, `runNonce`, and `channelEpoch`; the
latter two are fresh run/session values and the first necessarily commits them.
Arming emits alongside the authenticated snapshot identity, outside the snapshot object, an
`armedSnapshotTopLevelKeySetDigest = digest_authenticated_projection(ASCII("ibex:armed-snapshot-top-level-key-set:1") || 0x00,
to_jcs_bytes(K))`, where `K` is every actual top-level key sorted by unsigned UTF-8 bytes.
Before minting, the durable facility MUST recompute `K` and that digest, require the emitted digest to match, require the present
`classifiedFields` copied into `P` and `excludedFields` to be disjoint, and assert
`(classifiedFields ∪ excludedFields) == actualTopLevelKeySet`; any mismatch makes durable mint/verify unavailable.
The canonical digest is `digest_authenticated_projection(ASCII("ibex:durable-authority-projection:1") || 0x00,
to_jcs_bytes(P))`; the terminal NUL is part of the domain and the wire stores the digest's decoded 32 bytes. Any new or
unclassified armed-snapshot field makes durable mint/verify unavailable until this projection
is versioned. Mint binds this digest, never raw `armedSnapshotDigest`; verify
recomputes it from the current authenticated snapshot and requires equality. A
restart that freshens only excluded fields preserves authority; any included
policy, principal, grant, evaluator, resource, or generation change replaces the
lineage and invalidates old authority. In particular, any prepared-publication authority, producer, semantic-inventory, or
principal-set change in `preparedGraphs` changes the projection and invalidates stale durable authority.

Let `U` be the exact received bytes of envelope tags 1 and 2, including their
TLV headers. Tag 3 MUST be the final field and is explicitly excluded. The exact
signed/MACed preimage is:

```
ASCII("IBEX-DURABLE-AUTHORITY") || 0x00 || ASCII("V1") || 0x00 ||
u64_be(length(U)) || U
```

For ES256, tag 3 is exactly 64 bytes `r || s`, each a 32-byte big-endian P-256
integer. Signers emit low-S; verifiers require `1 <= r < n` and
`1 <= s <= n/2`, where `n` is the P-256 group order. DER and high-S encodings
are rejected. For HS256, tag 3 is exactly the 32-byte HMAC-SHA256 tag and compare
is constant-time. Rust/CryptoKit interoperability vectors pin both forms; direct
`ring` signing/AEAD use requires a direct dependency, not the rustls-transitive
edge.

The receiver has an out-of-band trust record mapping
`(issuer, intendedAudience, kind, keyId)` to exactly one expected algorithm and key. Across that store, one `keyId` maps to at
most one `(algorithm, key, kind, issuer)`; conflicting reuse refuses provisioning and lookup. It
may parse those untrusted fields only to locate that record, then requires exact
field equality and verifies with the record's algorithm. It never selects HMAC
from the message, never treats ES256 public-key bytes as an HMAC key, and refuses
an algorithm/pin mismatch. `kind` is in the certificate rather than the header;
bounded lookup-before-authentication is permitted only for record selection, and
no semantic use occurs until the authenticated value is equality-checked. HS256 is allowed only where every key holder is an
authorized issuer; ES256 is mandatory across authority domains.

`intendedAudience` scopes **where** a portable capsule may execute; it does not make it
execute once. Before any portable kind executes, the receiving domain MUST, in
one protected durable transaction, consume `operationId` as the nonce by
creating/binding the one native lease/replay record keyed by
`(issuer, intendedAudience, operationId)`. A pre-existing or ambiguous record refuses
execution; its terminal tombstone remains at least through capsule expiry and
the verification-key retention window. The receiver's rollback-resistant epoch
rules protect that consumption state. No portable kind ships until its threat
model, key distribution/rotation, receiver consumption, and conformance proof
are complete. Exact LLP 0476's first consumer instead uses the private receipt
and its native execution lease; JS receives neither form.

## 4. Mint

`mintDurableAuthority` is a native witness invoked on the JS-alive path (Exact's
`authorizeAndEnqueue` is its first caller). It performs, in order, and refuses
on any failure:

1. **Synchronous authority-context capture at the JSI entry**, before any async module
   dispatch hop. The current native module trampolines to a work queue before the
   handler runs, capturing nothing; the module-gate contract (§7) must expose a
   synchronous capture hook so the actor, effect owner, constrained-principal stack, and live native execution-scope carrier are
   read at entry, not after a queue hop.
2. **Authority evaluation before staging bytes.** Evaluate the LLP 0472
   four-layer intersection (OS permission ∩ app-root grant ∩ view-broker grant ∩
   module declaration) plus the typed holder/owner and the typed `network:fetch`
   authority for every authorized origin — **before** any source is copied. Read
   the typed durable decision evidence defined below and enumerate its complete
   authority lineage and selector sets. A holder lacking mint/network authority
   must not be able to fill the protected inbox with orphaned bytes.
3. **Authenticated source staging.** The source is admitted only as an
   authenticated native file handle / retained checked object bound to its
   owner/source authority; mint compares that ownership against the authenticated
   constrained-principal set. A caller-authored raw path is not accepted (it
   would authenticate the wrong provenance — the confused-deputy hole).
4. **Native digest** of the exact transport artifact (the framed multipart body
   or tus chunk that will actually be sent — not merely the enclosing source
   object), into the protected inbox (§5).
5. **Generation-linearized compare-and-commit.** After staging, acquire the
   native durable-authority commit guard that every ibex authority mutation and
   LLP 0472 registry publication MUST also use. Under that guard, re-read and require exact
   equality of the durable-authority projection digest, policy digest, **every**
   provenance record and covered-effect relation, each full four-component
   generation tuple, per-effect four-layer vector and execution-scope binding, and the complete source and network-selector sets.
   Re-query live OS permission and the owner-side view-broker/scope relation under
   the guard; the last publication alone is insufficient. Hold
   the guard from this last read through epoch
   advance and SQLite commit/rollback; a separate before/after check is not
   sufficient. A mismatch refuses and publishes no receipt.
6. **Bind and commit under the same guard** the certificate, authenticated
   execution lease, and task row in one transaction, after advancing the
   monotonic epoch anchor (§6). For the native-held receipt, the sealed authority
   goes in a JS-unwritable protected column and JS receives only an opaque task
   handle. A future portable kind emits §3's envelope only after satisfying its
   receiver-consumption requirements.

The protected v2 certificate is §3's exact schema and the normative total
resolution of Exact LLP 0476's shorthand; its consumer updates mechanically
before implementation:

```
DurableUploadCertificate:
  schemaVersion: 2
  kind: "durable-upload"
  operationId / taskId / issuedAt / expiresAt
  actor / effectOwner
  constrainedPrincipals: canonical nonempty typed Principal set
  authorityLineage:
    durableAuthorityProjectionDigest
    policyDigest
    authoritySources: canonical nonempty set [{
      provenance: Static | Dynamic | Handle,
      authorizingSelector, mintGeneration: { policy, negative, dynamic, handle },
      coveredEffects: canonical nonempty set [{ effectIndex, principal,
        requestedSelector, executionScope: { class, ownerServiceIdentity, bindingId },
        fourLayerWitness: { osPermission, appRoot, viewBroker, moduleDeclaration }
      }]
    }]
  source: {
    checkedObjectIdentity, sourceAuthoritySelector,
    artifactManifestRoot, totalLogicalLength
  }
  networkSelectors: canonical nonempty network:fetch AuthoritySelector set
  serviceIdentity / adapter { id, version } / requestPlanHash
  redirectPolicy / acceptBackgroundRedirectLeak / byteCeiling
```

**Constructible provenance witness.** Existing `DecisionEvidence.source_id`
cannot feed this record: it flattens a static `BoundAuthority.source_id`, a
dynamic `grant_id`, or a bearer `handle_id` into one optional string
(`decision.rs:66-72,459-467,1037-1076,1723-1735`). Durable
evaluation MUST add native `DurableDecisionEvidence` before that flattening and
emit exactly one typed contribution for every `(effectIndex, principal)` row.
For `durable-upload`, effect 0 is `sourceAuthoritySelector`; the canonically
ordered `networkSelectors` are effects 1..N. A future kind defines its complete
effect-to-index mapping before it may ship. Each row carries its own complete
four-layer witness and execution-scope binding; rows from distinct scope/grant identities never collapse.

After ordinary denials and ceilings, use the existing positive-stratum order,
but only static-floor, bearer-handle, dynamic-session, and
implicit-package-self are durable-eligible. Bootstrap and ambient Root refuse.
For a row, the **contributing** authority is in the first eligible stratum with a
match; if multiple rows in that stratum overlap, choose the unsigned-lexicographic
minimum `(provenanceBytes, authorizingSelectorBytes)`, never vector position.
Group identical provenance+selector choices and put their canonical nonempty
per-effect-witness-bearing `coveredEffects` set in one item. Verify repeats this
algorithm from the sealed effect vector and requires exact set equality; missing,
extra, substituted, or witness-collapsed rows refuse.

The tagged provenance is a total resolution of Exact 0476's
`(sourceId, grantId)` shorthand: Static is
`(BoundAuthority.source_id, principal, stratum)`; Dynamic adds the containing
`DynamicGrant.grant_id`; Handle adds the containing handle's `handle_id`, owner,
holder, and operation id. A handle is eligible only when operation-bound to this
fresh mint. The exact tagged bytes are the grant identity—no fictional scalar
grant id is synthesized for a static floor. Static `source_id` is positional in
today's arming code (`arming.rs:2114-2144`), but is total within its authenticated
snapshot: its principal, stratum, selector, and durable projection are sealed, so
a reorder changes lineage and refuses. Each covered effect seals its own complete
authenticated LLP 0472 vector; all four states must be `granted`.

`kind` is protected and cross-kind reinterpretation is forbidden. The
authenticated mint witness is the complete `authorityLineage`, not a scalar:
the current cache `GenerationSet` holds `negative`, `dynamic`, and `handle`
(`vendor/ibex/crates/capsec-semantics/src/cache.rs:40-44`),
`SnapshotGenerations` adds `policy`
(`vendor/ibex/crates/capsec-semantics/src/arming.rs:301-305`), and
the run-scoped `DecisionCacheKey` binds `policy_digest`,
`armed_snapshot_digest`, the generation set, and exact positive source identity
(`vendor/ibex/crates/capsec-semantics/src/cache.rs:19-27,57-73`). That raw digest
is cache precedent, not the durable field. Each `mintGeneration` is the full
`{policy, negative, dynamic, handle}` tuple; the enclosing durable lineage binds
the stable projection and policy digest.

A handle-only or singular generation is unsafe in the actual ibex code:
`mint_typed_handle` advances **only** `generations.handle`
(`vendor/ibex/src/host/mod.rs:4374`), while `revoke_typed_dynamic` advances
`negative` and `dynamic`, not `handle`
(`vendor/ibex/src/host/mod.rs:4129-4168`); the test at
`vendor/ibex/src/host/mod.rs:13669-13685` asserts that handle generation remains
unchanged across dynamic grant and revoke. Such a scalar would commit after a
dynamic revocation. Durable upload also has at least source and network authority
edges, so `authoritySources` is the canonical **complete** set, not one
representative. V1 deliberately carries the global tuple on every item: unrelated
authority mutation may invalidate a lease, an accepted fail-closed availability
cost. Per-source clocks require a later schema. An omitted edge is a mint refusal.

## 5. Verify and protected objects

**Native receipt and lease AEAD record.** Exact LLP 0476's generic “AES-GCM”
requirement resolves here to AES-256-GCM-SIV (RFC 8452), not plain GCM. The
facility uses an independent non-exportable 32-byte journal key. The v1 record
uses §3 TLV rules and exactly these required fields:

| container | tags in order |
|---|---|
| nativeSealedRecord | `1 recordVersion(u16=1)`, `2 algorithm(u8=1: AES-256-GCM-SIV)`, `3 keyId(32)`, `4 nonce(12)`, `5 columnRole(u8: 1=receipt, 2=lease)`, `6 operationId`, `7 taskId`, `8 installationBinding(32)`, `9 ciphertext`, `10 tag(16)` |

Let `H` be the exact received TLVs 1..8. AAD is
`ASCII("IBEX-DURABLE-NATIVE-RECORD") || 00 || ASCII("V1") || 00 ||
u64_be(length(H)) || H`; nonce is authenticated through `H`, and ciphertext is
the AEAD payload. Receipt plaintext is the exact §3 certificate bytes. Lease
plaintext is the consumer-owned strict canonical lease object, including every
status/ordinal/offset/retry field and raw 32-byte SHA-256 `certificateHash`.
`installationBinding` is raw SHA-256 of
`ASCII("IBEX-DURABLE-INSTALL") || 00 || protectedBootSalt`, recomputed at verify.

**Per-key nonce uniqueness is mandatory.** Each active journal key owns a
rollback-resistant `u64 sealSequence` in a distinct namespace of the §6 epoch
anchor. Under the facility lock, allocation atomically advances that anchor
before sealing; nonce is `ASCII("DAR1") || u64_be(sealSequence)`. Allocations are
burned on abort/crash, and every retry, transition, or row replacement allocates
again. Anchor rollback/fork, counter exhaustion, or uncertain allocation refuses.
GCM-SIV's nonce-misuse resistance limits damage from an allocator defect; it is
defense in depth, not permission to reuse. Plain AES-GCM is not a v1 substitute.

Rotation atomically provisions a new `(key, keyId, counter=0, algorithm pin)`;
only the new key seals, while old keys are verify-only until records are retired.
A record selects by protected `keyId`, then must match the pinned algorithm.
Rollback may never reactivate an old key/counter, and missing old material makes
affected records terminal. Without an audited AES-256-GCM-SIV implementation
and the crash/rollback-safe allocator, native durable authority is unavailable.

**Verify** runs natively on restart and before every lease transition, send,
retry, resume, and redirect, with no dependency on live JS:

1. Verify the portable MAC/signature or open the exact native receipt and lease
   records above. After both native opens, require the lease's `certificateHash`
   to equal raw SHA-256 of the exact receipt certificate bytes and require their
   protected `operationId` and `taskId` values to match.
2. Check expiry and protected `kind`; for portable envelopes, require this
   receiving `intendedAudience` and atomically consume/bind the receiver lease before any
   effect as §3 requires.
3. Recompute the protected inbox artifact's **actual digest** and require equality
   with the sealed value. This is defense in depth, **not** the immutability
   theorem: hash-then-open on a mutable file is still check-then-use.
4. Recompute the durable projection from the current authenticated snapshot and
   require equality, then re-read the registry (§6), recompute every contributing
   source for the bound source selector and every network selector, and require
   that canonical set to equal `authoritySources`. Every typed provenance and
   covered effect must be present, current, unrevoked, at the same full generation
   tuple, its own four-layer vector and owner-side execution-scope relation, and mapped to the same selector/effect.
   Missing, omitted, stale, extra-substitute, witness-collapsed, or remapped state
   refuses; checking only listed entries is forbidden. Re-check the live LLP 0472
   OS-permission ∩ view-broker intersection; the ibex tuple is not its proxy.
5. Check the monotonic epoch against its anchor; a rolled-back journal whose
   epoch is behind the anchor is refused.
6. Check byte ceiling, authorized method, and the resolved URL against the
   complete canonical `networkSelectors` set under the redirect policy.

**Protected objects (the write-once theorem).** The inbox and the authority
journal are **mandatory** protected CapSec objects (extending
`ProtectedObjectGuard` in `crates/capsec-semantics/src/decision.rs`), unreachable through every
filesystem, process-spawn, module, and alias route. The sole-writer property is
**constructed, not assumed**: the platform primitive must either close the
verify-to-seal edge atomically or prove no external writable descriptor can exist
during the writable window (fd-unreachability). `O_CREAT|O_EXCL` alone is
insufficient (another same-credential thread may open the pathname afterward);
`UF_IMMUTABLE` is same-UID-clearable and its guessed-path caveat is stated.
Existing-descriptor writes and seal-clearing attempts are part of the theorem,
not merely tested. Where no adequate primitive exists on a target, the durable
feature is **unavailable** there rather than weakened.

**Background transport tension (the load-bearing selection question):** Apple
background `uploadTask(with:fromFile:)` requires a **named** file URL, which is in
tension with the strongest write-once guarantee (an fd-only, unlinked inode).
Background durable upload is therefore forced into the named-file +
same-UID-clearable-`UF_IMMUTABLE` regime the theorem must defeat. The viable
mechanisms — a custom `URLProtocol`/stream over an fd-only inode, or accepting
that background durable upload is unavailable on a target while foreground durable
is not — are the concrete decision this LLP's implementation must make. Until one
is proven on a target, that target reports background durable upload unavailable.

## 6. Freshness epoch and native revocation registry

- **Monotonic epoch anchor.** A per-operation freshness epoch lives **outside**
  the rollbackable journal, checked under a native transition lock, advanced
  before commit. The construction must be genuinely rollback-resistant: a
  hardware monotonic counter where available; otherwise the residual is named and
  the only supported mode is server-idempotency evidence (the consumer's
  outcome-unknown resume). A mutable Keychain item is **not** automatically a
  monotonic counter and does not by itself satisfy this. Server evidence may
  replace only the operation-replay theorem; it never waives §5's per-key nonce anchor.
- **Native revocation registry, usable with JS dead.** This protected registry
  consumes authenticated publications from the existing owners; it is not a new
  policy engine. Ibex LLP 0013/0021 publishes the current durable projection
  digest (not raw `armedSnapshotDigest`), policy digest, full `{policy, negative,
  dynamic, handle}` generations, the complete positive provenance set, and its
  selector/effect mapping. Exact LLP 0472 publishes the current four-layer vector
  keyed by the complete `(provenanceBytes, authorizingSelectorBytes, effectIndex,
  principalBytes, requestedSelectorBytes, executionScopeBytes)` relation and, for OS permission,
  app-root grant, view-broker grant, and module declaration, an owner-issued
  `(generation: SafeUint, state: granted|denied|prompt|unavailable)`; only
  `granted` contributes authority. The scope owner also publishes the protected binding-to-scope relation and its revocation
  tombstone; for a view-broker binding this includes its root, view, grant instance, and scope lifetime. Publications enter by an
  in-process native call or facility-authenticated IPC that JS cannot call or author. Across
  process death, the registry durably retains the projection, full positive set,
  mapping, high-water generations, and revocation tombstones; ibex restores
  generations before verify, never by republishing zero. Publishing a new
  authenticated snapshot with the same projection may replace only excluded
  run/session fields without revocation. A different projection is an authority
  replacement: under the common guard, advance registry generation and terminally
  revoke every lease bound to the old value before exposing the new one; an old
  projection is never accepted as current. The lease binds registry generation.
  Missing, unauthenticated, rolled-back, or stale state refuses.
- **Changing layers reach the same guard.** OS permission observation and the
  restart/transition-time native OS query publish current status directly; the
  native view broker publishes grant/scope mutation, teardown, or drop before returning success.
  App-root and module changes arrive through their owning authenticated policy
  publication. Each publication acquires the durable-authority guard, advances
  its registry generation before exposing the mutation, marks dependent leases
  revoked, commits registry state, and cancels their native tasks. Verify still
  performs a live native OS check and reads current broker state on restart and
  before every transition, because both can change while JS is dead. If a target
  cannot observe/query either layer with the required freshness, durable
  authority is unavailable there. In particular, an OS API that exposes only
  current `granted` state but cannot distinguish revoke-then-regrant while dead
  cannot preserve an old lease: uncertainty is revocation, or the feature is unavailable.
- **External-revocation linearization.** A Settings mutation occurs behind ibex;
  it does not acquire this guard. It linearizes for durable authority only when
  an authenticated native query/callback observes it and that publication wins
  the guard. Bytes disclosed before observation/publication cannot be recalled,
  and a query immediately before use cannot eliminate that residual. Once
  publication wins, dependent leases become terminal, later transitions,
  sends/retries/restarts are not grandfathered, and cancellation is attempted;
  a later native completion is audit evidence only and permits no next ordinal.
  A terminal success counts only if its lease transition linearized first. A
  stronger zero-gap claim requires a platform enforcement lease or callback
  atomic with the effect; any kind/target requiring that claim remains unavailable.
- **Per-install boot salt** (defense in depth) is generated and retained by the
  isolated facility outside the rollbackable journal. If it restores with the
  journal it provides no cross-install protection and the implementation MUST
  make no resurrection claim; missing salt is terminal key/facility loss.

## 7. Module-gate, WP6 transport, and armed closure

- **Module-gate synchronous authority-context capture.** The armed mint JSI host-function
  entry—not ambient `exact.dispatchModule`—must capture the actor, effect owner, principal stack, and native execution-scope carrier
  synchronously (the current trampoline captures nothing). This is a read of ambient principal
  at entry followed by async work — not a cross-thread synchronous module call —
  so it is compatible with the LLP 0297 async-first rule; its callback affinity is
  registered. The current `evaluateRegisteredPermissionAccess` accepts but ignores `rootId`/`viewId` and reports `viewBroker: null`:
  class-2 durable authority is gated until the broker owner issues, carries, queries, and revokes the unforgeable binding above.
  No raw-view-id shortcut is conforming. Until then, durable authority is available only for capability/target pairs whose
  authoritative model has no view-broker distinction; every view-scoped grant reports the feature unavailable.
- **WP6-compatible background transport adapter.** LLP 0021 WP6 holds live/armed
  fetch **closed** until the transport can report and recheck the actual connected
  peer, candidate addresses, and redirects — a mint-time signature cannot attest
  future DNS candidates or the connected peer. A durable background adapter must
  perform the typed requested/candidate/commit checks with protected-peer and
  redirect enforcement. **Armed durable upload remains unavailable** until an
  adapter meets WP6; unarmed mint is likewise unavailable. The endpoint-string
  `checkCapability` path and the
  `IBEX_CAPSEC_SIMULATOR_PERFORMANCE_OBSERVER` loopback carve-out are never a
  mint oracle.

## 8. CapSec registry and conformance

- Register the typed `durable-capability-capsule`, protected inbox/journal, and typed module/resource selectors for authorize/enqueue, start, pause, resume, cancel, delete, reconcile, janitor, and listing in `capsec/registry/`. Add the mint/verify boundary to `ingress-obligations.json` as `durable-authority-signed-required`, the first **native-engine ↔ persisted authority** boundary.
- Projection conformance recomputes the arming-emitted sorted top-level key-set digest and directly asserts `(classifiedFields ∪ excludedFields) == actualTopLevelKeySet` before mint; an injected unclassified key or any classification-set mismatch makes the facility unavailable.
- Positive classification conformance proves that `runNonce` and `channelEpoch` carry no authority-relevant state and that changing either alone preserves the projection. Under `feature = "insecure"`, the durable facility is compiled out or reports unavailable (`Cargo.toml:205`; `host/mod.rs:4643`), so the development mint bypass can never expose a durable signing oracle.
- Conformance covers: forged/tampered/wrong-key/no-signature and cross-kind `keyId`-reuse refusal; JS-dead verify; atomic key+pin bootstrap; complete JS/module/host-call Keychain reachability inventory, key non-export/loss, and planted-HMAC/downgrade refusal; TLV unknown/duplicate/order/size/depth (deepest-valid 6 and over-depth), DER, high-S, exact-preimage/domain-NUL, digest-conversion, and request-plan-hash cases; armed-loader/schema/projection field-classification equality, same-policy restart with fresh run nonce/epoch preserving the projection, and every included-field change replacing it, including prepared-graph producer/authority/facet mutations; static/dynamic/handle provenance round trips, overlapping-source canonical choice, mixed per-effect four-layer generations under one broad grant, distinct view grants for one principal+selector remaining distinct, view-A revocation terminating A without borrowing B or globally revoking B, raw-view-id/binding injection refusal, scope teardown/regrant freshness, and refusal of flattened/omitted/remapped/collapsed evidence; dynamic revoke with unchanged handle generation; full positive-set restoration; OS/broker/scope revoke before commit, before/after observation, and after restart; view-scoped unavailability without the owner carrier; complete-selector enforcement; epoch and boot-binding rollback; receipt/lease certificate-hash mismatch; GCM-SIV record version/algorithm/role swaps, nonce uniqueness through crash/retry/row replacement, and rotation; write-once descriptor/seal attacks; confused-deputy staging; cross-intended-audience and receiver replay refusal; and fail-closed unavailable premises.

## 9. Platform matrix (honest)

| facility | iOS | macOS | Android | web | Windows |
|---|---|---|---|---|---|
| protected key + atomic pin | pending §2 proof: fresh-install SE P-256 or isolated HMAC selection; never runtime fallback | pending §2 proof (SE on supported Macs) | **catch-up** (Keystore/StrongBox) | n/a (no durable native replay) | catch-up |
| mint/verify | specified here; unavailable until §2/§5/§6/§7 proofs pass | specified here; unavailable until §2/§5/§6/§7 proofs pass | catch-up | n/a | catch-up |
| protected write-once inbox | pending §5 primitive proof | pending §5 primitive proof | catch-up | n/a | catch-up |
| monotonic epoch anchor | pending §6 construction proof | pending | catch-up | n/a | catch-up |
| WP6 background adapter | pending §7 | pending | catch-up | n/a | catch-up |

No target is granted durable background authority until its §2/§5/§6/§7 premises are proven. Web has no durable native replay domain and is not a consumer.

## 10. Non-goals and migration

- No portable capsule **kind** ships here; the signed envelope is proven only when the first portable consumer (Exact LLP 0476 defers this) arrives.
- No compatibility shim for the pre-0476 unsigned Exact capsule; that break is owned by LLP 0476.
- This LLP does not re-own LLP 0021's typed transport, LLP 0013's policy engine, or the Exact-side consumer surface. It provides the native trust-domain mechanism those consumers call.

## 11. Open questions

Implementation-selection questions with fail-closed defaults, mirroring Exact LLP 0476 §17:

1. Which verified Apple write-once mechanism is viable across every supported iOS/macOS background-resume path (§5)? If none, durable background upload stays unavailable.
2. Which Apple construction proves atomic isolated key+pin provisioning (§2) and the monotonic epoch across restore (§6)? Without the first, authority is unavailable; server evidence may replace only operation freshness, never §5 nonce allocation.
3. Which future kind first proves the portable signed envelope, and what issuer, intended-audience, receiver-lease, revocation, and key-rotation protocol does it need (§3/§4)?
4. Can an Apple background adapter expose enough actual network facts to meet WP6 (§7), or must armed durable upload use a different transport implementation?
5. Does the typed model represent the private inbox through the retained source handle plus receipt, or add a first-class typed private-inbox resource (§5)? Either must preserve owner/constrained-stack containment.
