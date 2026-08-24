# LLP 0053: Carrier-Bearing Ingress Coordination (Exact 0510 Carrier Arc — Asks I1–I4)

**Type:** RFC
**Status:** Draft
**Systems:** Host ABI, Engine, CapSec, Security, Conformance
**Author:** Charlie Cheever / Claude
**Date:** 2026-08-23
**Revised:** 2026-08-24 (r2 — the proposed designs for all four asks, tree-verified (evidence spot-checked byte-for-byte by the orchestrator before fold): I1 = one JS entry point with an optional third positional carrier argument + a sibling C setter ex_hermes_set_exact_host_call_async_v2 with an engine-attributed versioned attribution struct; I2 = one schema addition, exact/host-operation-endowments/2 with a required carrierBinding; I3 = frame-attribution/principal-stack machinery surfaced on the v2 callback, root discriminator resolved from I2 pins — the I3-requires-I2 dependency r1 omitted is now stated; I4 = one record shape with a stage tag. Four r1 corrections folded, incl. the surface-authority miscitation inherited from the Exact carrier-arc plan. Still Draft — this corpus decides.) 2026-08-23 (r1 — the four coordination asks from the Exact 0510 carrier arc, drafted as a proposal into this corpus per that plan's own rule: "their process decides shape; this plan only names the need." Nothing here is decided until this corpus decides it.)
**Related:** LLP 0002 (host-embedding ABI — I1's surface), LLP 0021 (typed CapSec effect model, armed snapshot — I2's surface), LLP 0049 (Draft — armed-snapshot evolution I2 rides), LLP 0013 / LLP 0040 (principal carriers — I3's natural vehicle), LLP 0024 (Draft — structured evaluation and session semantics — I4's surface), LLP 0052 (durable authority mint/verify — the lease-side machinery already consuming Exact-side lineage), Exact LLP 0510 (native boundary schemas v2 — the carrier model these asks serve; §6.1 dispatch order, §6.2 lease presentation, §6.4 "Ibex is a carrier, never an installer"), Exact LLP 0554 §5 (carrier sequencing), Exact docs/reports/carrier-arc-implementation-plan.md §3 (the tree-verified needs statement this RFC transcribes), `src/engine/root_global_disposition.generated.h` + `capsec/generated/surface-inventory.md` (the actual authorities for the `exact.*` JS global surface — r2 corrects r1s runtime-surface.json citation, which pins the CLI command surface, not JS globals)

## Summary

Exact's 0510 carrier arc — the work that takes capability-carrier
binding from accepted policy to enforced reality on the Hermes app
ingress — needs four things from this corpus. This RFC names them as
proposals and deliberately does not design them: each ask states the
need, the boundary rule it must respect, and the ibex surface it
touches. The governing division of labor is Exact LLP 0510 §6.4
item 1: **ibex is a carrier, never an installer** — it transports and
authenticates presentation; the host session enforces.

## I1 — Carrier-bearing typed ingress ABI

**Need:** `exact.invokeHostAsync` and
`ex_hermes_set_exact_host_call_async` (include/exact_runtime.h) carry
no carrier today. The Exact host needs an ABI revision letting the
app present a grant handle per invocation — an envelope field or a
sibling entry point — delivered to the host callback alongside
`(operation_id, payload)`.

**Boundary rules:** ibex transports the handle opaquely; validation,
consumption, and attenuation are host-session acts. Any new `exact.*`
surface joins the root-global disposition manifest and capsec surface inventory (r2 CORRECTION: r1 cited `runtime-surface.json` here, inheriting the error from the Exact carrier-arc plan §3 — that file pins the ibex CLI command surface; the JS `exact.*` surface authorities are `src/engine/root_global_disposition.generated.h` and `capsec/generated/surface-inventory.md`).
Absence of a carrier on an armed target is a host-side refusal, not
an ibex default — the ABI must make "no carrier presented"
distinguishable from "carrier field absent because old ABI."

## I2 — Carrier identity in the armed snapshot

**Need:** the armed snapshot already authenticates the
operation-manifest digest. Host-side carrier issuance needs it to
additionally bind the mapping digest, `authorityCommitmentDigest`,
and per-root grant-set pins, so issuance is provably against the
artifact ibex armed — the in-process analogue of the transport
`ConnectionAuthorization`.

**Boundary rules:** schema evolution rides LLP 0021/0049's
armed-snapshot process (`capsec/schema/armed-snapshot.schema.json`
et al.); strict ingestion (unknown-field refusal) is preserved; the
pins are authenticated inputs to host issuance, never authority in
themselves.

## I3 — Derived-root attribution on ingress

**Need:** Exact LLP 0510 §6.1 step 3 requires the engine/host
session's own attribution of which admitted root's execution issued a
call. The principal-carrier machinery (LLP 0013/0040 class — the
real-input/no-user carriers already in the engine) is the natural
vehicle. What Exact needs surfaced is a **trusted root discriminator
on the ingress callback** — engine-attributed, never a request field
the app supplies.

**Boundary rules:** the discriminator is attribution, not
authorization; a call whose root cannot be attributed fails closed on
the Exact side. The carrier-vs-payload distinction that already
separates real-input from synthetic principals is the precedent.

## I4 — CapSec presentation of the carrier tuple

**Need:** Exact LLP 0510 §6.2's lease-presentation tuple (items 1–7
plus the embedded row and derived root) is presented to capsec at
candidate and commit stages, additive to the LLP 0052/Exact-0476
stage facts. The presentation record's capsec-side shape belongs to
this corpus (LLP 0024/0021's session-semantics surface under
`capsec/session-semantics/`).

**Boundary rules:** additive to existing stage facts — no removal or
re-interpretation of what LLP 0052 already presents; the shape is
this corpus's decision.

## Sequencing and what does NOT wait

Exact's slices S2 (Hermes-path carrier custody + dispatch bind) and
S5 (terminal receipts on that path) wait on I1–I3 landing here. I4
gates lease-path conformance claims, not the walking skeleton.
Exact's pure-Rust worker-path slices (S1/S3/S4), its label mechanics,
and its bypass checks proceed independently — nothing in this RFC
blocks them, and none of them preempt this corpus's design choices.

## Open questions (for this corpus)

1. I1's vehicle: envelope field on the existing entry point vs a
   sibling carrier-bearing entry point (old surface retired at the
   Exact epoch boundary)?
2. I2: are the three pin classes one schema addition or staged
   (mapping digest first, commitment + per-root pins with I1)?
3. I3: does the root discriminator ride the existing principal
   carrier records or a parallel attribution channel?
4. I4: candidate-stage and commit-stage records — one shape with a
   stage tag, or two?

---

# r2: Proposed designs (Draft — for this corpus's review)

Every existence claim below was tree-verified at drafting and
spot-checked byte-for-byte by the orchestrator before fold; cites are
against the working tree at origin/main (494c2b25e ancestry — none of
the intervening commits touch the cited surfaces).

## r2 §I1 — Carrier-bearing typed ingress ABI

**Decision (open question 1): the JS surface stays ONE entry point
that grows an optional third positional argument; the C ABI gets a
SIBLING setter, with the v1 setter refused on carrier-armed targets
and retired at the Exact epoch boundary.** No options object, no
second JS method.

Ground truth: the shipped host function throws on any arity other
than exactly 2 (src/engine/hermes_runtime.cc:16828-16831), so
carrier-presenting code on an old engine fails LOUDLY at the first
call — "absence-of-carrier" vs "old-ABI absence-of-field" can never
be confused at the JS boundary. A sibling JS method would add a new
root-global row to the closed armed surface
(src/engine/root_global_disposition.generated.h:1029) for no gain.
The callback runs inline on the runtime owner thread
(include/exact_runtime.h:1966-1967), which is what makes
engine-attributed context capture at call time sound. Completions
ride ex_hermes_resolve_exact_host_call unchanged.

Proposed C surface:

```c
typedef enum ExHermesExactCarrierStatus {
  EX_HERMES_EXACT_CARRIER_PRESENT = 1,
  EX_HERMES_EXACT_CARRIER_ABSENT  = 2
} ExHermesExactCarrierStatus;

typedef enum ExHermesExactRootAttributionStatus {
  EX_HERMES_EXACT_ROOT_ATTRIBUTED  = 1,
  EX_HERMES_EXACT_ROOT_UNAVAILABLE = 2,
  EX_HERMES_EXACT_ROOT_AMBIGUOUS   = 3
} ExHermesExactRootAttributionStatus;

#define EX_HERMES_EXACT_INGRESS_ATTRIBUTION_ABI_VERSION 1u

/* Engine-attributed per-invocation context; borrowed for the callback
   invocation only. Nothing in it is app-suppliable. Versioned-struct
   discipline per ExHermesAsyncFailureEvent (exact_runtime.h:1421-1432). */
typedef struct ExHermesExactIngressAttribution {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t context_kind;      /* ExactEmbedderContext installed (:247-251) */
  uint32_t carrier_status;    /* ExHermesExactCarrierStatus */
  uint32_t root_status;       /* ExHermesExactRootAttributionStatus */
  uint32_t principal_status;  /* ExHermesAsyncFailurePrincipalStatus (:1415-1419) */
  uint64_t runtime_nonce;     /* ex_hermes_current_runtime_nonce() at entry */
  uint64_t principal_id;      /* frame-attributed actor id (:590-593) */
  const char* root_id;        /* borrowed; non-NULL only when ATTRIBUTED (I2) */
} ExHermesExactIngressAttribution;

/* Sibling of ex_hermes_set_exact_host_call_async (exact_runtime.h:1972).
   Identical thread, one-shot, endowment, pending-cap, and size rules;
   at most ONE of v1/v2 succeeds per runtime. carrier is borrowed;
   PRESENT => 1..=64 bytes (Exact handles are 32; bound is transport
   headroom — ibex never parses the bytes). ABSENT => NULL/0 and the
   status enum is the authoritative discriminator. */
int ex_hermes_set_exact_host_call_async_v2(
    ExactHermesRuntime* runtime,
    ExactEmbedderContext context_kind,
    const uint32_t* allowed_operation_ids,
    size_t allowed_operation_count,
    const char* operation_manifest_digest,
    void (*callback)(ExactHermesRuntime* runtime,
                     uint64_t call_id,
                     uint32_t operation_id,
                     const uint8_t* payload,
                     size_t payload_len,
                     const uint8_t* carrier,
                     size_t carrier_len,
                     const ExHermesExactIngressAttribution* attribution,
                     void* context),
    void* context);
```

JS surface under v2 install: exactly 2 args => carrier ABSENT;
exactly 3 args => args[2] MUST be an ArrayBuffer/View of 1..=64
bytes, else JSError — no undefined coercion, no silent truncation.
Same sealed property, same finalization transaction.

Fail-closed matrix on armed targets: generic armed => both setters
-8 (today's rule). Snapshot bound at /1 (no carrierBinding) => v1
allowed until the epoch, v2 REFUSED (-8: a carrier-bearing ingress
may not install against a snapshot that does not pin what issuance
is bound to). Snapshot bound at /2 => v1 REFUSED (a carrier-armed
artifact never runs behind the carrier-less surface), v2 allowed.
Unarmed diagnostic => both allowed; attribution still delivered
with root_status = UNAVAILABLE. Enforced by a carrier_capable input
to Host::authorizes_exact_endowment (src/host/mod.rs:2606-2630) via
a sibling ex_host_authorize_exact_endowment_v2 hook. Absence of a
carrier on a JS call is NEVER an ibex refusal — delivered with
carrier_status = ABSENT; presence policy is the host session's
(Exact 0510 §6.3), exactly the boundary r1 assigned.

Surface deltas: NO runtime-surface.json change (no new command, no
new JS property — see the r2 correction above); regenerate the
root-global disposition manifest + capsec surface inventory for the
changed semantics of the existing exact.invokeHostAsync row.

## r2 §I2 — Carrier identity in the armed snapshot

**Decision (open question 2): one single schema addition, not
staged** — exact/host-operation-endowments/2 with a REQUIRED
carrierBinding object: {schema: "exact/carrier-binding/1",
mappingDigest, authorityCommitmentDigest, rootGrantSets}, where
rootGrantSets maps Exact rootId -> {context: "app"|"agentIsolate",
grantSetId, grantSetDigest} (1..=256 entries, additionalProperties
false throughout, digest fields on the snapshot's common tagged
digest $def — one deliberate divergence from transport's raw
grantSetSha256 hex; the producer converts).

Rationale: the only consumer (Exact's mint_host_custody_grants,
exact:packages/exact-native-runtime/src/host_custody.rs:210-267)
binds all three pin classes at once — a mapping-digest-only stage
authenticates nothing issuance can use alone; and each
strict-ingestion transition costs one atomic ibex-commit +
Exact-pointer update (LLP 0002's evolution rule), so staging doubles
cost for zero interim capability. Transport precedent lands the
same three as one record (exact-native-transport handshake.rs
ConnectionAuthorization).

Ground truth: exactEmbedder is OPTIONAL in the snapshot schema
(capsec/schema/armed-snapshot.schema.json:75-95) with const /1;
ingestion is strict twice over (deny_unknown_fields on
ExactEmbedderBinding, crates/capsec-semantics/src/arming.rs:293-298;
validate_exact_embedder_binding refuses non-/1, arming.rs:1829-1831).
Snapshot producers are per-run on-target
(ex_host_build_exact_armed_embedder_artifacts,
exact_runtime.h:2111-2117), so per-boot grant-set pins are feasible:
the host mints pools BEFORE building/arming. Producer ABI delta: a
_v2 sibling taking one additional (carrier_binding_json, len) input,
validated and embedded before nonce freshening; v1 producers keep
emitting /1 until the epoch retires them with the v1 setter.

Strict-ingestion consequences: old engine + new snapshot => refused
at arming (deny_unknown_fields + schema const), fail-closed and
loud. New engine + /1 snapshot => arms, but only the v1 ingress may
install (I1 matrix). The pins are authenticated INPUTS to host
issuance, never authority (r1's rule preserved); the engine
compares, never mints.

## r2 §I3 — Derived-root attribution on ingress

**Decision (open question 3): rides the EXISTING frame-attribution /
principal-stack machinery — no parallel channel** — surfaced as the
engine-populated attribution struct on the v2 callback. Engine truth
captured inline at the JSI entry; there is no request field and
nowhere in the JS arity for one.

The mechanism, by its code names (r2 correction: "real-input/no-user
principal carriers" names nothing in this engine's source): per-entry
frame attribution (src/engine/hermes_runtime_internal.h:745-749,
EXACT_HAVE_FRAME_ATTRIBUTION) surfaced as
ex_hermes_current_principal_id paired with the runtime nonce
(include/exact_runtime.h:585-593); principal stacks carried across
async hops (TimerEntry/NextTickEntry/FetchCallbackEntry,
hermes_runtime_internal.h:65-107); and the engine-attributed-status
discipline of ExHermesAsyncFailureEvent (authenticated/unavailable/
ambiguous; missing ownership never replaced with the root principal
— exact_runtime.h:1397-1432), copied verbatim.

**Structural fact r1 omitted, now stated: I3 DEPENDS ON I2.** Ibex
principals cannot represent Exact roots by prior decision (LLP 0052
§1: no Principal variant carries root/view/scope identity; execution
scope is a separate native-owner binding). Exact rootIds enter the
ibex trust domain for the first time as I2's rootGrantSets keys. The
root discriminator resolves the calling context against those
authenticated pins: exactly one pinned root for the context =>
ATTRIBUTED with root_id; multiple => AMBIGUOUS in v1 (the Exact host
fails the dispatch closed per 0510 §6.1 step 3); unarmed =>
UNAVAILABLE. The engine supplies the trusted side of 0510's
three-way rootId equality; the echo and grant-side comparisons are
host-session acts; ibex never sees the grant. Finer-than-runtime
attribution (which view within a multi-root runtime) is out of scope
for v1 and assigned to LLP 0052's execution-scope carrier machinery
(class-2 view-broker-grant bindings) as the designated growth path.

## r2 §I4 — CapSec presentation of the carrier tuple (shape sketch)

**Decision (open question 4): ONE record shape with a stage tag.**
Precedent: the armed snapshot's runtime-extension fragment already
models stages as one record with a stage enum
(armed-snapshot.schema.json:598-608), and Exact 0510 §6.2 presents
the identical tuple content at both candidate and commit. Sketch: a
new capsec/schema/exact-carrier-presentation.schema.json defining
exact/carrier-presentation-record/1 with {stage:
"candidate"|"commit", leasePredicate {generation, capabilityId,
capabilityMajor, mappingDigest, selectorSet,
authorityCommitmentDigest, mintGenerationTuple, rootId}, embeddedRow
{resources, selectors, hostCalls, moduleCalls?, rootId}, derivedRoot
{rootId, status}}, joined to the session-semantics surface as
generated model outputs, additive to LLP 0052's stage facts and
never re-interpreting them. Punted to implementation: the
candidate<->commit linkage (digest-link vs replay) and the
selector-set encoding — both constrained by LLP 0052's
no-row-collapse rule, neither changes the shape answer.

## r2: What this design does NOT decide

Exact-side enforcement semantics (0510 §6.1 refusal codes, receipt
commits); how app JS obtains a handle; the Exact epoch's calendar for
deleting the v1 setter and /1 producers (Exact 0554 §5 owns
sequencing); whether the regenerated disposition row gets a new
token (generator owner's call); the rootId string pattern for
rootGrantSets keys (joins Exact's deployment-manifest grammar at
implementation); anything about the module table or 0533.
