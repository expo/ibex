# LLP 0053: Carrier-Bearing Ingress Coordination (Exact 0510 Carrier Arc — Asks I1–I4)

**Type:** RFC
**Status:** Draft
**Systems:** Host ABI, Engine, CapSec, Security, Conformance
**Author:** Charlie Cheever / Claude
**Date:** 2026-08-23
**Revised:** 2026-08-24 (r5 — round-3 codex-scoped residue: the I1 boundary-rule sentence (line 33) cleaned — ONE authority (the disposition-manifest generator), the stale plural-authorities tail superseded in place, and the correction labeled to its actual round (r4s edit was mislabeled r3). Dispositions 1/2/4/5 passed byte verification at round 3.) 2026-08-24 (r4 — round-2 split fold: grok READY at r3; codex NOT READY with five residues, all verified and closed: grantSetId gains its 1..=256-byte no-NUL grammar; the issuance replay check compares the COMPLETE pin (grantSetId AND grantSetDigest); the three repudiated-but-live r1/r2 prose sites (surface-inventory-as-authority in Related+I1, the real-input/no-user I3 vehicle sentence, the I4 session-semantics placement) each carry explicit SUPERSEDED corrections in place; and the LLP 0052 rows-never-collapse citation is RESTORED — r3 withdrew it on grok r1s unverified no-such-rule claim, codex proved the rule exists verbatim at 0052:314-320, and the verify-before-fold lesson is recorded in the text. Codexs fifth finding (review artifacts absent from the checkout) is REFUTED as capsule blindness: the artifacts are structurally excluded from review capsules and exist on this repos main.) 2026-08-24 (r3 — dual-review fold (codex gpt-5.6-sol@ultra + grok-4.6@xhigh, both NOT READY, convergent; artifacts under llp/reviews/). The material fixes: (1) authorization is SCHEMA-AWARE ON BOTH PATHS — the existing v1 authorize path itself refuses /2 (the r2 sibling-hook-only construction left v1-on-/2 open, the rounds worst hole); (2) ONE owner-thread tagged ingress latch None|V1|V2 with separately typed slots, all lifecycle helpers on it, schema-aware finalize; (3) the ingest shape is an internally tagged serde enum (/1 no-binding / /2 binding-required), the rootGrantSets dictionary stated implementably (patternProperties), per-context >=1-pin arming rule, zero-pin case specified; (4) root_id gains root_id_len + a frozen no-NUL UTF-8 grammar; (5) attribution capture ordering made normative (capture before app-observable accesses, immediate carrier copy, bootstrap-captured Promise, kNoUserPrincipalId maps to UNAVAILABLE) and the binding reaches the runtime as an installation-time copied immutable projection; (6) /2 replay defused at issuance against live grant pools; all three producer routes get _v2 siblings; (7) I3 restated honestly — root fields are a second authenticated-snapshot channel, not frame attribution; I3-requires-I2 scoped to this construction; multi-root-in-one-runtime = permanently AMBIGUOUS in v1, named; (8) I4 re-homed to the DecisionSet/DecisionContext stage machinery, candidate-commit digest linkage + full-typed-row selector encoding DECIDED, the nonexistent LLP 0052 no-row-collapse citation withdrawn; (9) Fetch principal-stack claim corrected; non-app-suppliable phrasing corrected to engine-observed; surface deltas completed with the new native rows. Still Draft — round 2 next.) 2026-08-24 (r2 — the proposed designs for all four asks, tree-verified (evidence spot-checked byte-for-byte by the orchestrator before fold): I1 = one JS entry point with an optional third positional carrier argument + a sibling C setter ex_hermes_set_exact_host_call_async_v2 with an engine-attributed versioned attribution struct; I2 = one schema addition, exact/host-operation-endowments/2 with a required carrierBinding; I3 = frame-attribution/principal-stack machinery surfaced on the v2 callback, root discriminator resolved from I2 pins — the I3-requires-I2 dependency r1 omitted is now stated; I4 = one record shape with a stage tag. Four r1 corrections folded, incl. the surface-authority miscitation inherited from the Exact carrier-arc plan. Still Draft — this corpus decides.) 2026-08-23 (r1 — the four coordination asks from the Exact 0510 carrier arc, drafted as a proposal into this corpus per that plan's own rule: "their process decides shape; this plan only names the need." Nothing here is decided until this corpus decides it.)
**Related:** LLP 0002 (host-embedding ABI — I1's surface), LLP 0021 (typed CapSec effect model, armed snapshot — I2's surface), LLP 0049 (Draft — armed-snapshot evolution I2 rides), LLP 0013 / LLP 0040 (principal carriers — I3's natural vehicle), LLP 0024 (Draft — structured evaluation and session semantics — I4's surface), LLP 0052 (durable authority mint/verify — the lease-side machinery already consuming Exact-side lineage), Exact LLP 0510 (native boundary schemas v2 — the carrier model these asks serve; §6.1 dispatch order, §6.2 lease presentation, §6.4 "Ibex is a carrier, never an installer"), Exact LLP 0554 §5 (carrier sequencing), Exact docs/reports/carrier-arc-implementation-plan.md §3 (the tree-verified needs statement this RFC transcribes), `src/engine/root_global_disposition.generated.h` via its generator (the authority for the `exact.*` JS global surface — r2 corrects r1s runtime-surface.json citation, which pins the CLI command surface, not JS globals; r4 tightens r2: `capsec/generated/surface-inventory.md` is generated review OUTPUT to regenerate, per its own header, not a second authority)

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
surface joins the root-global disposition manifest — the generator is the ONE authority for the JS `exact.*` global surface; the capsec surface inventory (`capsec/generated/surface-inventory.md`) is generated REVIEW OUTPUT that must be regenerated, never an authority (r4 correction, corrected label at r5: r4's edit here was mislabeled "r3 tightening" and left a stale plural-"authorities" tail live; r2 had corrected r1's `runtime-surface.json` citation — that file pins the ibex CLI command surface, not JS globals — but named the inventory as a co-authority, which this sentence SUPERSEDES).
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
call. (r1's "principal-carrier machinery (LLP 0013/0040 class — the
real-input/no-user carriers)" phrasing is SUPERSEDED at r2/r3: that
name exists nowhere in this engine's source; the real mechanisms
are frame attribution + principal stacks + currentPrincipalId, and
the root fields ride a second authenticated-snapshot channel — see
the design §I3 below.) What Exact needs surfaced is a **trusted root discriminator
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
this corpus. (r1's placement "under `capsec/session-semantics/`"
is SUPERSEDED at r3: that directory is LLP 0024's
evaluation-session generator, not stage ingestion — the record
joins the DecisionSet/DecisionContext stage machinery; see the
design §I4 below.)

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
   invocation only. Engine-attributed fields cannot be
   overridden by request data; carrier presence/bytes are engine-OBSERVED
   presentation facts, unauthenticated until the host validates (r3). Versioned-struct
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
  size_t root_id_len;         /* r3 — UTF-8 byte length; the id grammar forbids
                                 embedded NUL (refused at arming) but the ABI
                                 still carries an explicit length so two
                                 authenticated ids can never collapse at a
                                 C-string consumer */
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
with root_status = UNAVAILABLE.
**Enforcement, restated at r3 (both reviewers proved the r2
sibling-hook-only construction left the worst hole open — a /2
snapshot would still authorize the EXISTING v1 setter, whose
authorize path never reads binding.schema):** the matrix is
enforced by making authorization SCHEMA-AWARE ON BOTH PATHS —
Host::authorizes_exact_endowment (src/host/mod.rs:2606-2630) gains
the schema dimension, and the V1 PATH ITSELF refuses
schema == …/2 (this is a semantic change to the existing hook,
named as such; the sibling _v2 hook carries the carrier_capable
ask). Finalization reporting becomes schema-aware too — the single
EXACT_INGRESS capability bit cannot detect a /1-vs-v2 or /2-vs-v1
mismatch, so the finalize check asserts the latch tag against the
armed schema. And the two setters share ONE owner-thread tagged
ingress latch — `None | V1(fn) | V2(fn)` with separately typed
callback slots — on which every lifecycle helper (one-shot check,
begin/finalize embedder-capability transaction, JS dispatch,
rollback, seal, disposition activation) operates; the r2 reading
of "a second independent pointer" is withdrawn as a torn-state
bug. Attribution capture ordering is normative (r3): the engine
captures every attribution field AND carrier presence BEFORE any
app-observable property access (the current dispatch is
Promise-executor-mediated and the byte-view helper invokes
observable getters/proxy traps — hermes_runtime.cc:16846,
hermes_runtime_internal.h:2355); carrier bytes are copied
immediately at capture; dispatch uses a bootstrap-captured trusted
Promise constructor or a native primitive, never the mutable
global binding; and kNoUserPrincipalId (0xFFFFFFFE) maps to
principal_status = UNAVAILABLE, never conflated with root
principal 0. The authenticated binding reaches the runtime as an
INSTALLATION-TIME COPIED IMMUTABLE PROJECTION owned by the runtime
at v2-setter success (r3 — there is no trusted live Rust→C++
channel: the boolean hooks transfer nothing and
exact_embedder_binding() returns an owned clone, so the projection
is copied once under the same authorization that admitted the
setter). Absence of a
carrier on a JS call is NEVER an ibex refusal — delivered with
carrier_status = ABSENT; presence policy is the host session's
(Exact 0510 §6.3), exactly the boundary r1 assigned.

Surface deltas (r3 — completed; r2 under-counted): NO
runtime-surface.json change (no new command, no new JS property);
regenerate the root-global disposition manifest for the changed
semantics of the existing exact.invokeHostAsync row (the generator
is the authority; capsec/generated/surface-inventory.md is
generated REVIEW OUTPUT, not itself an authority — r3 tightens
r2's phrasing); and the NEW native surfaces each get their rows —
the v2 C setter, the _v2 authorize hook, the three _v2 producers,
and a host-task-ingress-inventory row for the v2 ingress.

## r2 §I2 — Carrier identity in the armed snapshot

**Decision (open question 2): one single schema addition, not
staged** — exact/host-operation-endowments/2 with a REQUIRED
carrierBinding object: {schema: "exact/carrier-binding/1",
mappingDigest, authorityCommitmentDigest, rootGrantSets}, where
rootGrantSets maps Exact rootId -> {context: "app"|"agentIsolate",
grantSetId (r4: UTF-8, 1..=256 bytes, no embedded NUL — the bound the r3 punch list promised but the text lacked), grantSetDigest} (r3 — the dictionary shape stated
implementably: `patternProperties` keyed by the frozen rootId
grammar WITH `additionalProperties: false` alongside — the JSON
Schema dictionary idiom, not a bare closed object; minProperties 1
/ maxProperties 256 TOTAL; and a new arming rule — every endowed
context MUST hold ≥1 pin at arming, refused otherwise, which makes
armed-/2 zero-pin runtimes structurally unreachable; if the
invariant is somehow violated at runtime, root_status =
UNAVAILABLE and the host fails closed. Value objects stay
`additionalProperties: false` with digest fields on the snapshot's
common tagged digest $def — one deliberate divergence from
transport's raw grantSetSha256 hex; the producer converts). The
Rust ingest shape is an INTERNALLY TAGGED ENUM on the schema const
(r3): `V1 {…no carrierBinding…}` / `V2 {…carrierBinding
required…}` — "/1 ⇒ field absent, /2 ⇒ field present" is enforced
by the type, not by an Option cross-check, and
validate_exact_embedder_binding dispatches on the tag. Producer
siblings cover ALL THREE Exact-bearing routes (r3 — prepare,
ordinary build, runtime-extension build; exact_runtime.h:2088+),
not one. Replay (r3): a persisted /2 snapshot replayed into
another Host is defused at ISSUANCE — the host validates the pins
against its live grant pools at mint — the COMPLETE pin per root (r4: grantSetId AND grantSetDigest, not ids alone; plus mapping digest, commitment
digest); rotated pools refuse with the
existing mismatch classes, so stale pins are inert even where the
install transaction accepts the bytes. Root-id wire grammar (r3,
frozen before ABI v1): UTF-8, 1..=256 bytes, NO embedded NUL
(refused at arming), pattern joining Exact's deployment-manifest
rootId grammar at implementation.

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

**Decision (open question 3), restated honestly at r3:** the
PRINCIPAL fields (`principal_id`, `principal_status`,
`runtime_nonce`) ride the existing frame-attribution machinery;
the ROOT fields (`root_id`, `root_status`) are a DIFFERENT thing —
a lookup of I2's authenticated pins against the runtime's
installed `ExactEmbedderContext`, which is runtime-granularity
context labeling, not per-frame attribution (r3 withdraws r2's
"no parallel channel" phrasing: the root discriminator IS a second
channel, an authenticated-snapshot one, and saying otherwise
obscured exactly the multi-root limitation §I3 must own). Both are
surfaced on the engine-populated attribution struct on the v2
callback; there is no request field and nowhere in the JS arity
for one.

The mechanism, by its code names (r2 correction: "real-input/no-user
principal carriers" names nothing in this engine's source): per-entry
frame attribution (src/engine/hermes_runtime_internal.h:745-749,
EXACT_HAVE_FRAME_ATTRIBUTION) surfaced as
ex_hermes_current_principal_id paired with the runtime nonce
(include/exact_runtime.h:585-593); principal identity carried across
async hops (r3 correction: TimerEntry/NextTickEntry carry
principalStack; FetchCallbackEntry carries a SINGLE principal —
hermes_runtime_internal.h:65-107); and the engine-attributed-status
discipline of ExHermesAsyncFailureEvent (authenticated/unavailable/
ambiguous; missing ownership never replaced with the root principal
— exact_runtime.h:1397-1432), copied verbatim.

**Dependency, scoped precisely at r3 (r2's "I3 DEPENDS ON I2"
overstated it as structural):** the dependency is true FOR THE
CONSTRUCTION CHOSEN HERE — ATTRIBUTED Exact root_id strings enter
the ibex trust domain only as I2's rootGrantSets keys, because
ibex principals cannot represent Exact roots by prior decision
(LLP 0052 §1: no Principal variant carries root/view/scope
identity). It is not structural for I3-in-general: the rest of the
attribution struct is deliverable unarmed as UNAVAILABLE, and a
future multi-root design could join roots through LLP 0052's
execution-scope carriers instead. The matrix also couples I1's v2
setter to I2 (v2 refuses /1 snapshots) — a deliberate
serialization, named here so it is chosen, not discovered. The
root discriminator resolves the runtime's installed context
against the authenticated pins: exactly one pinned root for the
context => ATTRIBUTED with root_id; multiple => AMBIGUOUS in v1
(the Exact host fails the dispatch closed per 0510 §6.1 step 3 —
and note the honest consequence: a production topology hosting
multiple Exact roots in ONE app runtime makes v1 I3 permanently
AMBIGUOUS; the current topology is a single bundled root per
LLP 0002, and the multi-root answer is the LLP 0052 growth path,
not a v1 widened rule); zero matching pins on an armed /2 runtime
=> structurally unreachable per §I2's per-context arming rule,
and if violated anyway, UNAVAILABLE + host fails closed; unarmed
=> UNAVAILABLE. The engine supplies the trusted side of 0510's
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
{rootId, status}}. RE-HOMED at r3 (both reviewers: r2's
session-semantics join point repeated r1's authority-miscitation
class — capsec/session-semantics/ is LLP 0024's evaluation-session
generator, not stage ingestion): the record joins the strict
DecisionSet/DecisionContext stage machinery
(crates/capsec-semantics/src/model.rs; stage vocabulary already on
capsec/schema/effect.schema.json) as a versioned addition to the
decision-context schema, additive to LLP 0052's stage facts and
never re-interpreting them; if the record carries its own stage
field beside DecisionContext.stage, exact equality is enforced.
DECIDED at r3 (no longer punted — candidate↔commit linkage is
substitution-critical, not an implementation detail): the commit
record embeds the candidate record's digest (presentationDigest),
so a commit cannot be paired with a substituted candidate; the
selector-set encoding is FULL TYPED ROWS (canonical equality —
digests don't compose across distinct scope/grant identities,
which is exactly LLP 0052's rule: "rows from distinct scope/grant
identities never collapse," 0052 lines 314–320. r4 RESTORES this
citation: r3 withdrew it on one reviewer family's unverified claim
that no such rule exists — the rule exists verbatim, the other
family caught the false withdrawal, and the lesson is recorded:
reviewer claims fold only after byte verification, in both
directions).

## r2: What this design does NOT decide

Exact-side enforcement semantics (0510 §6.1 refusal codes, receipt
commits); how app JS obtains a handle; the Exact epoch's calendar for
deleting the v1 setter and /1 producers (Exact 0554 §5 owns
sequencing); whether the regenerated disposition row gets a new
token (generator owner's call); the rootId string pattern for
rootGrantSets keys (joins Exact's deployment-manifest grammar at
implementation); anything about the module table or 0533.
