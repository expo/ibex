# LLP 0053: Plan-Artifact Update Admission

**Type:** RFC
**Status:** Draft
**Systems:** Security, CapSec, Arming, Module Loader, Runtime, Host ABI, Distribution
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-23
**Revised:** 2026-08-23 (r3 — blind grok-4.6 cross-family round folded, all 6
MATERIAL findings and the verified minors
(`llp/reviews/0053-plan-artifact-update-admission.r2.grok.md`): the
activation fence constructed — admit-path digest re-verification at the boot
fence, the snapshot recipe with policy regeneration under embedder ceilings,
the binding shape promoted from §9 Q1 to §10 obligation 4 with the LLP 0052
§3 projection interaction named; revert r5 re-runs checks 4–6's
compatibility half including `minimumRuntime`; totality — companion
pinned-format digests consumed by check 4, the manifest schema obligated,
`companion-format-unsupported` / `directive-epoch-regression` /
`revert-target-unavailable` codes added, every 0541-relation outcome mapped,
the refusal→Exact-0553-§3.1 class map published; the dev/production
separation made structural (distinct schema, kind, workflow marker, digest
domain, trust-store class) with a session-bounded dev re-arm story for L-E;
the single-guard linearizable commit specified per 0052 §4 step 5's corpus
standard, staging is not an epoch spend, the sibling-epoch-swap window
closed, the committed-failure epoch cost stated as deliberate; the anchor
"where available" made a platform predicate over LLP 0052 §9's matrix with
epoch genesis defined; the Exact 0553 citation corrected to the
commissioning record — 0553's printed text carries neither the ask nor
this RFC's name; plus the same-day codex delta-pass fold — D2 scoped to
the decision checks, the revert-commit tuple, refusal-code
disambiguation with `baseline-integrity-failure`, in-guard
durable-authority projection mutations, the dev re-arm predicate
obligated, the key-compromise horizon as §9 Q5)
2026-08-23 (r2 — adversarial consistency fold, all 14 findings of the
gpt-5.6-sol read-only pass applied; see Revision history)
2026-08-23 (r1 — initial draft, commissioned after the 2026-08-23 probe
confirmed the gap: the armed snapshot is the capability-security arming
attestation, not an update-admission mechanism, and no Ibex LLP owns OTA
admission of plan artifacts — Exact
`issues/20260821-eplan-ota-armed-snapshot-confirmation.md`)
**Related:** LLP 0021 (typed CapSec effect model — `ArmedSnapshot`, the
CapSec execution-authority root; this RFC proposes the admitted-update
binding as a new authenticated field of it, constructed under §10
obligation 4), LLP 0042 (independent prepared-graph commitment — the
digest-only committed-admission pattern, the re-verify-before-use rule, the
development-commitment class with its distinct schema id and workflow
marker, and the production/development never-interchangeable rule this RFC
restates structurally at update granularity), LLP 0052 (durable authority —
the byte-exact TLV envelope rule set, the
`(issuer, intendedAudience, kind, keyId)` trust-record match, the §3
stable-projection rule a new armed-snapshot field must be classified under,
the §4 step-5 single-guard commit standard, and the §6/§9 epoch-anchor
construction and platform matrix this RFC's check 6 predicates on),
LLP 0048 (external script admission — deliberately does NOT cover this: its
scope is one caller-selected `.ts`/`.js`/stdin source), LLP 0030 (audit
graph admission — its foreground snapshot carries no authority rows and
cannot reach this surface), LLP 0038 (unadvertised dev arming — an
independent axis, not this RFC's dev/production separation) / LLP 0039
(secure and insecure modes), LLP 0027 (ModuleArtifact wire and carriers),
LLP 0013/0021 (principals; the fail-closed no-user sentinel), LLP 0012
(runtime identity — `runtime-identity.json`, the authenticated local
operand of §3 check 6's minimum-runtime relation, which this RFC owns),
LLP 0010 (runtime surface — this RFC adds no `ibex` CLI command), LLP 0002
(host embedding ABI — the presentation surface lands as an ordinary 0002
amendment), LLP 0029 (single-file packaging — the immutable embedded
namespace and release pins; it excludes self-update, which supports this
RFC's boundary; baseline *retention* is new law here); **external:** Exact
LLP 0553 §4 L-E / §9 D6 (the embedded-reload lane whose restart class joins
the host re-arm/boot path — the first consumer of this predicate; the
commission is the program-side record taken with 0553's acceptance, not
text inside 0553, whose printed §11 carries no such ask), Exact LLP 0504
§3 row 54c (the confirmed gap and this commission's durable anchor;
discharged by this RFC's commissioning), Exact LLP 0526 (expo-updates-class OTA ruled
NOT-A-MODULE: update admission is runtime/Ibex territory), Exact LLP 0485
§3/§11/§12.1.2 + Track R (`plan/format-schema.json` — the `.eplan` format's
law; the `PlanAdmissionCertificate`; the versioned compatibility relation),
Exact RFC 0536 (catalogs) / RFC 0537 (payload segments) — the
referenced-artifact companions, Exact LLP 0541 (Contract edition identity —
the layered-digest coordinates an update unit declares), Exact LLP 0507 /
LLP 0517 (pinned wire/host formats; 0517 explicitly leaves `.eplan` tables
and plan admission to the plan authorities), Exact LLP 0500 (embedded
rollout deliberately deferred to the program this RFC serves); Snapback
LLP 0052 (update economy — the delivery side, out of scope here)

## Summary

Exact apps ship as plan artifacts: one `.eplan` container plus
referenced-artifact companions (catalogs, payload segments). Exact LLP 0526
ruled expo-updates-class OTA **NOT-A-MODULE** — update admission is
runtime/Ibex territory — and the 2026-08-23 probe confirmed no Ibex law
covers it: the armed snapshot (LLP 0021) is the capability-security arming
attestation for a runtime, not an app-update admission mechanism, and
LLP 0048's admission surface is one caller-selected script, not an artifact
set.

This RFC is the missing admission decision. It defines **the update unit**
(a closed, digest-enumerated artifact set), **the admission predicate**
(presenter authority → envelope authenticity → digest closure →
format-and-companion window → edition compatibility → runtime minimum +
epoch monotonicity → the constructed generation fence: re-verify, rebuild
the snapshot, commit epoch and binding under one guard), **the typed
fail-closed refusal set with its Exact 0553 §3.1 class map**, **the trust
boundary** (only the authenticated embedded host presents; JS never
presents, accepts, or bypasses; production and development update
credentials are structurally distinct), and **the rollback/kill-switch
posture** (retain-until-healthy with normative defaults, forward-epoch
admission only, revert as re-arm under its own predicate with digest
revalidation and compatibility recheck, a signed revert directive). It is
deliberately small: the admission decision document, not a delivery
pipeline. Delivery, hosting, and update economics stay with the embedder
and Snapback LLP 0052; the artifact format's internal law stays with
Exact's plan authorities. Ibex admits bytes against digests and declared
coordinates; it never re-interprets the format to decide. Byte-exact
schemas, grammars, and the fence construction are named obligations (§10),
not open questions.

## 1. The gap and the commission

- **What exists:** arming (LLP 0021) attests the capability posture of a
  runtime over an already-present artifact set. Committed prepared-graph
  admission (LLP 0042) verifies a *cache* against an authenticated
  commitment by digest alone. External script admission (LLP 0048) admits
  one caller-selected source file under an erasable profile. None of these
  answers "may this runtime replace its shipped application content with
  bytes that arrived over the air?"
- **The commission:** Exact LLP 0504 §3 row 54c recorded the question, the
  probe answered NO (armed snapshot ≠ update admission), and the
  commissioning record taken with Exact LLP 0553's acceptance assigned
  this ibex-side document. The durable, checkable anchors are 0504 §3
  row 54c and the issue ticket; Exact 0553's printed text carries neither
  the assignment nor this RFC's name — the dependency runs the other
  way: its L-E embedded-reload lane's restart class "joins the host's
  re-arm/boot path" (0553 §4), and that re-arm's artifact-admission law
  is this document. Its D6 phase (embedded reload + mirror retirement)
  is the first consumer of the §3 predicate.
- **Division of law:** the `.eplan` container, its segments, digests, and
  content addressing are Exact LLP 0485 §3 / Track R's
  (`plan/format-schema.json` is the generated authority). EXWF frames
  (Exact 0507) and the wasm PHI (Exact 0517) own their pinned surfaces, and
  0517 explicitly leaves plan admission to the plan authorities. Ibex owns
  exactly the runtime-side admission decision specified here.

## 2. The update unit

**D1.** The unit of update admission is a **`PlanUpdateUnitV1`**:

- exactly one `.eplan` plan artifact (Exact 0485 §3's container), and
- zero or more **referenced-artifact companions** — catalogs (Exact
  RFC 0536), payload segments (Exact RFC 0537), the loci sidecar, and any
  artifact class the plan format's referenced-artifact shape (Exact 0485
  §3.3.14) names —

**closed by enumeration** in the unit's manifest: one row per artifact
with `(kind, digest, byteLength)`; `(kind, digest)` pairs are unique. An
artifact not enumerated is not part of the unit and is never read during
admission; an enumerated artifact that is missing or digest-mismatched
refuses the **whole unit**. v1 units are **full-set only** — no
differential units (§9 Q3). The manifest's schema, digest algorithm and
domain separation, and integer/epoch bounds are §10 obligation 5.

The unit's manifest also carries, as **declared coordinates** — every one
of them consumed by a named §3 check:

- the plan-format schema version (Exact 0485 Track R's version line) —
  check 4;
- pinned-format digests for companions whose law lives elsewhere (e.g. an
  EXWF schema digest per Exact 0507 §8 where a companion binds one) —
  check 4;
- the Exact LLP 0541 edition-identity coordinates (the layered digests and
  posture the producer stamped) — check 5;
- `minimumRuntime` — a constraint whose grammar and comparison relation
  **this RFC owns** (§10 obligation 2); the authenticated LLP 0012
  runtime identity is the local operand it is evaluated against, and
  nothing more is attributed to LLP 0012 — check 6;
- `updateEpoch` — check 6;
- opaque producer provenance: the producer's Exact 0485 §11
  `PlanAdmissionCertificate` digest where one was emitted.
  **Correlation-only**: bound into the manifest so receipts and audits can
  join the producer's build evidence; it proves nothing at admission and
  no admission check evaluates it. (Being no operand, it needs no check —
  the one deliberate exception to the rule above.)

**D2.** The admission **decision** — §3 checks 1–6 — is **digest-only**
(LLP 0042's discipline restated): those checks hash bytes and compare
declared coordinates against the runtime build's embedded registers, and
never parse plan tables, never evaluate expressions, never execute any
admitted byte. The fence (check 7) is **arming, not decision**: its
snapshot construction reads the admitted content under LLP 0021's own
validation law, and a failure there is an arming refusal of an
already-decided unit, not an admission input. Format validity beyond the
digest is the producer's law and the runner's fail-closed load path.

## 3. The admission predicate

**D3.** Checks run in order; the first failure refuses the unit with the
§4 code; every check is fail-closed (an unevaluable check is a refusal,
never a pass).

1. **Presenter authority.** The presenting principal is the authenticated
   embedded host in the native trust domain — the same trusted-embedder
   standing LLP 0048 requires of its parent — holding the
   update-presentation authority for this app identity. Presentation is a
   native host-ABI surface (LLP 0002; landed as an ordinary 0002
   amendment). No JS-addressable route reaches it; a presentation
   attributed to the no-user sentinel or to any package/JS principal
   (LLP 0013/0021) refuses.
2. **Envelope authenticity.** The unit's manifest arrives inside a signed
   **`ibex/plan-update-envelope/1`** — a **sibling schema** of LLP 0052's
   certificate: distinct schema and kind registry, obeying 0052's envelope
   **rule set** — byte-exact length-prefixed TLV; version, algorithm, key
   id, issuer, audience, and kind all inside the signed preimage
   (field-by-field header-vs-certificate placement follows 0052's layout
   and is fixed by §10 obligation 1, which also copies 0052's
   never-select-verification-material-from-the-message, keyId-uniqueness,
   and algorithm-pin rules verbatim); unknown-field rejection; fixed
   signature encoding. The production kind registry is closed:
   `update-unit` and `revert-directive` (§6); the development sibling
   schema (§5) is a different schema id, never a kind here. Cross-kind and
   cross-schema reinterpretation are forbidden (0052's rule). The
   protected audience **is the canonical app identity**, and the check
   requires exact equality across the presenter's authority scope
   (check 1), the pinned trust record's
   `(issuer, intendedAudience, kind, keyId)` tuple (0052 §3's match
   shape), and the epoch namespace (check 6). **ES256 is mandatory** for
   any signer outside the device's native authority domain — which every
   real OTA producer is; HS256 remains confined to one native authority
   domain per LLP 0052. Producer-signature verification runs natively
   against a **verify-only producer trust store** pinned by the embedder
   at build time — a **new mechanism this RFC introduces** (§10
   obligation 3), deliberately *not* LLP 0052's protected key facility,
   which owns the device-local non-exportable key and is not a
   producer-root verifier. Key custody, rotation, and enrollment stay with
   the embedder (§8); this RFC owns only the pinned store's match
   semantics.
3. **Digest closure.** The manifest payload is schema-valid
   (`manifest-invalid` otherwise); then every enumerated artifact is
   hashed and must equal its manifest row, byte length included; nothing
   outside the enumeration is read or admitted. Closure completes
   **before** any activation effect exists (verify-then-activate; no
   partial admission, no streaming activation).
4. **Format-and-companion window.** The declared plan-format schema
   version is a member of the runtime build's **pinned supported set** —
   declared, not sniffed from bytes — and **every declared companion
   pinned-format digest** (D1) is a member of the runtime build's
   companion register for its kind. An unsupported companion format
   refuses (`companion-format-unsupported`); an unknown or
   newer-than-supported plan-format version refuses
   (`format-unsupported`).
5. **Edition compatibility.** The declared Exact 0541 coordinates are
   evaluated against the runtime build's embedded compatibility register
   under the **separately versioned compatibility relation** (Exact 0485
   §12.1.2 / 0541 §3). The outcome map is total: `equal` and
   `compatible-widening` admit; `reset` **admits** — a boot-authority
   replacement restarts from scratch and carries no preserved state, so a
   reset-class outcome costs nothing here; the outcome is recorded in the
   receipt so downstream consumers (Exact 0553's lanes) know state will
   not carry. `incompatible`, an unknown relation version, or absent
   coordinates refuse. Ibex evaluates the relation as published machine
   data; it never re-derives edition semantics.
6. **Runtime minimum and epoch monotonicity** — in this internal order,
   so a unit failing both refuses as `runtime-below-minimum`. (a)
   `minimumRuntime` is evaluated under this RFC's relation (§10
   obligation 2) against the authenticated LLP 0012 identity — the
   native, JS-unwritable identity record, never the JS-visible
   `process.versions` surface. (b) `updateEpoch` is **strictly greater**
   than the recorded high-water epoch for this app identity (the epoch
   namespace is per app identity — check 2's joined audience). **Genesis:**
   at install both high-water marks (unit and directive, §6) are `0` and
   the embedded baseline carries epoch `0`; every admissible envelope
   carries an epoch ≥ 1. The high-water record lives in
   **runtime-integrity-protected storage: the same protection class as
   the writable armed snapshot's own authenticated bindings** (an
   attacker who can rewrite it can already substitute the artifact
   bindings themselves, so it adds no new trust assumption; the
   read-only 0029 embedded baseline is a different, stronger class and is
   not this store). Passing check 6 stages the unit as
   **verified-but-not-live**; staging is **not** an epoch spend — the
   high-water advances only inside check 7's commit. Where a
   rollback-resistant external anchor is **available** — a platform
   predicate, decided by the target's construction row being marked
   proven in LLP 0052 §9's platform matrix (or its successor register),
   never by implementer judgment — the record MUST additionally bind to
   it, in a namespace of its own (a 0052 amendment exporting a named
   foreign-anchor namespace is part of §10 obligation 4), which extends
   the defense to whole-filesystem-snapshot restore. Absent a qualifying
   anchor the receipt (§7) records `anchor: none` and the threat model
   explicitly does not claim snapshot-restore resistance — declared,
   never silent, and never claimed as an 0052 §6 construction.
   Unreadable, corrupt, or fork-evident epoch state refuses
   (`epoch-state-unavailable`).
7. **The generation fence — constructed, not gestured at.** An admitted
   unit becomes live only through a full re-arm at the host's re-arm/boot
   path, in this order:
   - (a) **Re-verification at the fence:** every staged byte that will
     become live is re-hashed against the unit's manifest immediately
     before publication — the admit-path twin of §6 r4's rule; retained
     bytes are never trusted from storage, and the binding is
     **digest-only, never a path** (LLP 0042's re-verify-before-use
     precedent). A fence-time mismatch refuses (`digest-mismatch`) and
     spends nothing.
   - (b) **Snapshot construction:** the new **`ArmedSnapshot`** is
     *constructed*, never copied wholesale: artifact bindings are rebuilt
     from the admitted unit; CapSec policy is **regenerated** from the
     admitted content under the embedder's install-time authority
     ceilings and trust roots, then passes LLP 0021's full validation. An
     update can change what the application declares and requests; it can
     never change the embedder-granted ceilings, the trust roots, or any
     embedder-owned snapshot field — the copied-vs-rebuilt field recipe
     is §10 obligation 4. The admitted-update binding is a new
     authenticated armed-snapshot field, and per LLP 0052 §3's stable
     projection rule (an unclassified field makes durable mint/verify
     unavailable), obligation 4 includes the 0052 projection amendment
     classifying the field as **included**: an application replacement
     invalidates outstanding durable authority.
   - (c) **One linearizable commit** (LLP 0052 §4 step 5's corpus
     standard: a single guard held from the last high-water read through
     the commit; "a separate before/after check is not sufficient"):
     under that one guard, the high-water epoch advances, the
     admitted-update binding is published, the previous unit's retention
     record (§6) is written, the admission receipt (§7) is persisted,
     and — where the LLP 0052 durable-authority facility is present —
     the facility's own required mutations for a changed projection run
     to completion (registry-generation advance and outstanding-lease
     revocation/cancellation, per 0052's rules; §10 obligation 4), so no
     durable authority minted against the replaced application is
     verifiable after the new projection is exposed — together or not at
     all. Crash before the commit: the
     old unit remains the boot authority and the staged unit is
     re-presentable (no epoch spent). Crash after: the new unit is the
     boot authority with the epoch spent. There is **no window** in
     which the new snapshot is live while the high-water is old — the
     sibling-epoch-swap (a second unit with the same `updateEpoch`
     replacing the first) is structurally closed. That a unit which
     commits and then fails health (§6) has spent its epoch and can
     never be re-presented is **deliberate** — the availability cost §6
     accepts so a failed unit is gone for good; the fixed successor
     takes a higher epoch.

   Admission **never mutates a live generation**: the running generation
   continues on its current artifact set until the fence. This is exactly
   Exact 0553 §3.1's `regenerate-policy-and-restart` class, and the
   running app's view of a refused or pending update is `keep-last-good`.

## 4. Refusal shapes

**D4.** Refusals are a closed typed set; every refusal leaves the
currently armed artifact set untouched and emits a §7 receipt:

| Code | Meaning |
| --- | --- |
| `presenter-unauthorized` | check 1 / §6 r1 — wrong or unattributable principal |
| `envelope-invalid` | check 2 / §6 r2 — framing, unknown field, protected-field, kind, schema-class, audience-join, or encoding failure |
| `signer-unauthorized` | check 2 / §6 r2 — signature invalid, trust-record tuple mismatch, key not pinned, algorithm out of domain |
| `manifest-invalid` | check 3 — manifest payload fails its schema, or a constraint field (e.g. `minimumRuntime`) is malformed |
| `unit-incomplete` | check 3 — enumerated artifact missing |
| `digest-mismatch` | check 3 / check 7(a) / §6 r4 (retained-unit target) — artifact bytes or byte length differ from the governing manifest or retained binding; on §6 r4 it falls through to the next target |
| `format-unsupported` | check 4 / §6 r5 — plan-format schema version outside the pinned set |
| `companion-format-unsupported` | check 4 / §6 r5 — a declared companion pinned-format digest outside the companion register |
| `edition-incompatible` | check 5 / §6 r5 — 0541 coordinates evaluate to `incompatible`, or relation version unknown, or coordinates absent |
| `runtime-below-minimum` | check 6(a) / §6 r5 — this build fails the `minimumRuntime` relation |
| `epoch-regression` | check 6(b) — `updateEpoch` ≤ the recorded unit high-water |
| `directive-epoch-regression` | §6 r2 — `directiveEpoch` ≤ the recorded directive high-water |
| `epoch-state-unavailable` | check 6 / §6 — high-water record unreadable, corrupt, or fork-evident |
| `revert-target-unavailable` | §6 r3 — the named target is not in the retention set; falls through to the next target |
| `baseline-integrity-failure` | §6 r3/r4, embedded baseline only — the baseline is unresolvable or fails revalidation; **terminal** (nothing coherent remains to arm) |
| `activation-unavailable` | check 7 / §6 r6 — no re-arm fence reachable (e.g. retention store unwritable) |
| `admission-internal` | any check — an implementation fault that fits no other code; the raw cause goes in the receipt |

There is no warn-and-admit tier, no partial admission, and no
nearest-code guessing: a failure that fits no specific code refuses as
`admission-internal`, keeping the set closed while never admitting.

**The Exact 0553 §3.1 class map is total:** every code above, as the
disposition of a *presented* envelope, is `keep-last-good` for the running
generation — the live graph is untouched and nothing was applied. A
*committed* admission's or revert's activation is
`regenerate-policy-and-restart` (a real host restart). The terminal
`baseline-integrity-failure` is a boot-integrity failure outside 0553's
reload taxonomy — nothing coherent remains to reload into. No 0053
outcome maps to `full-reload-current-authority`, and none is
unclassified.

## 5. The trust boundary

**D5.**

- **Who presents:** only the authenticated embedded host (native trust
  domain). Application JS — any package principal, any evaluated code,
  any agent surface — can never present, accept, veto, or bypass an
  update, and no admission *decision* input is JS-authored: bytes may
  transit JS-adjacent transports on their way to the host (an embedder
  may download with whatever stack it owns), but authenticity and
  authority derive solely from the envelope signature (check 2) and the
  presenter's native attribution (check 1), never from the transport. A
  read-only JS observation surface (current update state, last receipt)
  is future work (§9 Q4) and grants no authority.
- **Production/development separation — structural, both directions**
  (LLP 0042's pattern, not a policy comment). The development update
  credential is a **distinct sibling schema**
  (`ibex/plan-update-envelope-dev/1`, §10 obligation 1) with its own kind
  registry, a protected `workflow: "development"` marker, a **distinct
  digest domain**, and a **distinct trust-store class** whose keys the
  production pin set can never contain (§10 obligation 3; keyId-to-kind
  uniqueness per 0052's rule). The production predicate refuses the dev
  schema at check 2 (`envelope-invalid`, schema-class) no matter who
  signed it; a dev verifier conversely never accepts a production
  envelope. **The dev re-arm story for Exact 0553 L-E:** a development
  embedded-reload restart may mint a boot-authority snapshot only under
  the dev schema, scoped to the producing development session — it never
  writes the §3 check 6 high-water, never persists as boot authority, and
  a boot without that live session falls back to the last
  production-admitted unit or the embedded baseline. Only production
  envelopes create a *persistent* boot authority. The dev sibling's own
  re-arm predicate — its verification checks, the authenticated
  live-session binding the credential names, and the no-persistence
  rule's enforcement point — is §10 obligation 7. LLP 0038's
  `unadvertised-dev-arming` build feature is an **independent axis** — it
  substitutes synthesized target advertisement and raises the synthesized
  root ceiling while retaining the other authenticators — and is context
  here, not the separation mechanism.
- **Not a diagnostic surface:** LLP 0030's foreground audit snapshot
  carries no authority rows and cannot be presented here (its own rule,
  acknowledged).
- **No CLI surface:** this RFC adds nothing to `runtime-surface.json`
  (LLP 0010); presentation is host-ABI only.

## 6. Rollback and kill switch

**D6.** A **revert is a re-arm, not an admission**: it re-activates
content this runtime already admitted (or shipped with) and therefore
does not run the §3 admission predicate; it runs the revert predicate
below. The epoch high-water record is an **admission high-water mark**,
not a pointer to the armed unit: it never decreases, including across any
revert — so a failed unit (same epoch) can never be re-presented, while a
fixed successor (higher epoch) can, and no old epoch-bearing binding is
ever "restored" as current epoch state.

- **Retention.** v1 retains exactly the **immediately previous
  production-admitted unit** plus the **embedded baseline** — the install
  package's immutable payload (LLP 0029's embedded namespace; a store
  binary update replaces it wholesale as a new install). Admission never
  deletes or overwrites the embedded baseline (**new law here**; 0029
  supplies the immutability of embedded release bytes, not the retention
  rule), so revert-to-baseline is always resolvable.
- **Retain-until-healthy.** The previous unit's authenticated binding is
  retained until the successor generation reaches a **health mark**.
  Normative defaults (an embedder may declare a *stronger* predicate
  through the presentation ABI, never a weaker one): the default health
  mark is **the successor generation's arming commit completing**
  (check 7(c) committing), and the fallback trigger is **`N = 2`
  consecutive launches that fail to reach it**. On the trigger, the
  runtime reverts to the retained unit at the next boot fence. Whether
  the default mark should be stronger than arming-commit — and what, if
  anything, answers a *post*-commit crash loop, which today does not
  fall back — is §9 Q1.
- **Revert predicate** (automatic and directed reverts): (r1) for a
  directed revert, presenter authority per §3 check 1; (r2) for a
  directed revert, a signed **`revert-directive`** envelope per §3
  check 2 — same rule set, its kind in the signed preimage, the same
  app-identity join — carrying its own `directiveEpoch`, strictly greater
  than the directive high-water for this app identity
  (`directive-epoch-regression` otherwise; a separate mark in the same
  store, genesis 0; the unit mark is unaffected); (r3) authenticated
  target lookup: the directive names its target **by digest** — the
  retained unit's or the embedded baseline's — never by role or path, so
  a successor committing between directive signing and r3 cannot swap
  the referent; an unretained named digest refuses
  (`revert-target-unavailable`, fall-through); (r4) **digest
  revalidation** of every target artifact against its retained
  authenticated binding (LLP 0042's re-verify-before-use precedent —
  retained bytes are never trusted from storage; a retained-unit
  failure is `digest-mismatch`, fall-through); (r5) compatibility
  recheck: **§3 checks 4–6(a)** against the target's retained
  coordinates and the **live** LLP 0012 operand — format window,
  companion window, edition, **and `minimumRuntime`**; a runtime
  replaced under the target (rolled back, sideloaded, restored) may no
  longer satisfy the target's own minimum, and revert must refuse what
  admission would refuse; (r6) generation-fenced activation through the
  **revert commit**: fence re-verification (§3 check 7(a)), snapshot
  construction from the target's retained content (7(b) — the same
  recipe and LLP 0021 validation), then one single-guard commit of
  7(c)'s construction (its in-guard durable-authority projection
  mutations included) with the **revert tuple**: a directed revert
  advances only the directive
  high-water (the unit mark is untouched); an automatic revert advances
  **no** mark; the failed unit leaves the retention set (it is never
  re-presentable, so it is not retained); the revert receipt persists in
  the commit. Automatic (health-mark) reverts run r3–r6 only — they are
  runtime-initiated, with no envelope; their r3 target is the retained
  unit by its recorded digest. A revert predicate failure refuses with
  the §4 codes and falls through to the next target (retained →
  embedded baseline); the embedded baseline failing r3 or r4 is an
  integrity failure outside this RFC's repair scope and refuses
  terminally (`baseline-integrity-failure`).
- **Operator rollback is forward-moving.** Re-shipping *older content* is
  the re-admission of that content under a **new envelope with a fresh,
  higher `updateEpoch`**, through the full §3 predicate. The epoch never
  regresses; there is no admit-older-epoch override.
- **Kill switch.** The `revert-directive` above, commanding revert to the
  retained unit or to the embedded baseline. LLP 0029's exclusion of
  self-update supports this RFC's boundary: the runtime binary never
  updates itself here; only application content does.

## 7. Receipts and the Exact seam

**D7.** Every admission decision — admit, refuse, revert — emits one
**`PlanUpdateAdmissionReceiptV1`**: unit digest set (or directive target
digest), presenter identity, per-check outcomes (the check 5 relation
outcome included), disposition code, epoch transition, anchor posture
(check 6's declared strength), and the resulting generation coordinate on
admit. Required receipt properties — this RFC claims exactly these, not
LLP 0052 §5's sealed-record construction: receipts are written natively
(never by JS), persisted atomically with the decision they record
(check 7(c) puts the admit receipt inside the single commit), retained
across the generation fence and across reverts, and readable by the
embedder. An LLP 0052-§5-class sealed journal is an optional
strengthening an embedder may choose, not an assumption of this RFC.

**The seam to Exact 0553:** the receipt is consumable by Exact 0553
§3.3's single receipt instrument (its L-E lane's apply receipts cite the
admission receipt of the unit they patched against), the §4 class map
gives every disposition its 0553 §3.1 class, and the restart class of
0553 §3.1 resolves, on the embedded tier, to this document's generation
fence. This RFC is the ibex-side owner assigned by the commissioning
record taken with Exact 0553's acceptance, and discharges Exact 0504 §3
row 54c and
`issues/20260821-eplan-ota-armed-snapshot-confirmation.md`; 0553's own
text predates and does not name it.

## 8. Non-goals

- **Delivery:** transport, hosting, channels-as-product, phased rollout
  percentages, and update economics — Snapback LLP 0052 and the embedder.
  This RFC begins when bytes and an envelope are already local.
- **Format definition:** the `.eplan` container and companions — Exact
  0485 Track R and the pinned-format owners (0507/0517).
- **Patch-granular HMR:** dev-loop lanes and their budgets — Exact 0553.
- **Key custody, rotation, and enrollment:** the embedder's. This RFC
  owns the pinned verify-only trust store's match semantics (§3 check 2,
  §10 obligation 3) and nothing upstream of it.
- **Store policy:** platform-store review rules are the embedder's
  compliance problem, not an admission input.

## 9. Open questions

1. **Health-mark strength:** should the normative default mark exceed
   arming-commit (first frame rendered, a crash-free interval); what
   embedder-declared predicates does the presentation ABI accept; and
   does anything answer a post-commit crash loop, which today never
   falls back?
2. **App/channel identity minting:** who names the canonical app identity
   the audience join and epoch namespace are scoped to
   (embedder-declared? an Exact-side project identity?), and whether one
   runtime hosting several roots holds several namespaces. The §3 check 2
   equality join holds regardless of who mints the name.
3. **Differential units:** a later `PlanUpdateUnitV2` with
   patch-transport of unchanged artifacts must preserve full digest
   closure over the *resulting* set; nothing in v1 may make that harder.
4. **JS observation surface:** the read-only update-state view and which
   corpus (this one or Exact's Acto law) owns its shape.
5. **Producer-key compromise horizon:** replay defense is epoch-only, so
   a stolen producer key that pre-signed a stack of future epochs is a
   stacked-update oracle until the pin set changes — and a pin-set
   change is a binary update today (§8). Do envelopes need a validity
   window or a revocation mechanism, and against what time authority?

## 10. Obligations before implementation

Named obligations, not open questions — each must exist (as an amendment
to this RFC or a companion spec) before an implementation may claim the
corresponding check:

1. **The byte-exact envelope definitions** for
   `ibex/plan-update-envelope/1` **and** the development sibling
   `ibex/plan-update-envelope-dev/1`: TLV tags, ordering, bounds, signed
   preimage, header-vs-certificate field placement, signature encoding,
   the closed kind registries (`update-unit`, `revert-directive`; the dev
   registry), and the `workflow` marker — to LLP 0052's level of
   precision, copying its never-select-verification-material-from-the-
   message, keyId-uniqueness, keyId-to-kind-uniqueness, and
   algorithm-pin rules verbatim.
2. **The `minimumRuntime` constraint grammar and comparison relation**,
   naming the exact authenticated, native, JS-unwritable LLP 0012
   identity field it is evaluated against (the JS-visible
   `process.versions`/compat surface is not the operand and compat modes
   must not change the result).
3. **The verify-only producer trust store**: record shape (the
   `(issuer, intendedAudience, kind, keyId)` tuple plus key material),
   pinning location, native verification path, and the structural
   separation of the production and development store classes.
4. **The activation-fence and snapshot construction** (this was Draft
   r2's open question 1, closed here as an obligation): the
   admitted-update binding as a new authenticated `ArmedSnapshot` field;
   retained digest-only descriptors (never paths); the fence re-hash
   rule; the copied-vs-rebuilt snapshot field recipe including policy
   regeneration under embedder ceilings with full LLP 0021 validation;
   the single-guard linearizable commit (epoch + binding + retention +
   receipt) with its named crash states, including the in-guard
   durable-authority mutations for a changed projection
   (registry-generation advance, outstanding-lease
   revocation/cancellation) where the 0052 facility is present; the
   revert-commit tuple (§6 r6); the epoch-store construction with
   genesis values and bounds; the foreign-anchor namespace as an
   LLP 0052 amendment (both the §3 projection amendment classifying the
   new field as **included** — OTA invalidates durable authority — and
   the §6-adjacent named anchor namespace the high-water binds to where
   the 0052 §9 matrix marks the platform proven).
5. **The `PlanUpdateUnitV1` manifest schema**: field grammar, digest
   algorithm and domain separation, `(kind, digest)` uniqueness,
   integer/epoch bounds.
6. **Conformance fixtures — adversarial, not only diagnostic**: refusal
   twins for every §4 code and golden admit/refuse/revert receipts, plus
   substitution-gate fixtures in LLP 0042's style: artifact
   mix-and-match across units, fence-time byte swap (TOCTOU), epoch
   snapshot-restore replay, sibling-epoch-swap, a development credential
   presented to the production predicate, and a production envelope
   presented to the dev verifier.
7. **The development re-arm predicate** (§5): the dev sibling schema's
   verification checks, the authenticated live-development-session
   binding the credential must name (a boot without that session cannot
   resolve the credential), the never-writes-the-production-high-water
   rule, and the enforcement point that prevents a dev-armed generation
   from persisting as boot authority.

## 11. Decision requested

1. Adopt the `PlanUpdateUnitV1` closed-enumeration update unit (D1) and
   digest-only admission discipline (D2).
2. Adopt the seven-check ordered admission predicate with the
   constructed generation fence (D3) and the closed fail-closed refusal
   set with its 0553 class map (D4), with the §10 obligations gating
   implementation.
3. Adopt the trust boundary (D5): host-only presentation, no JS
   authority, structural production/development separation with the
   session-bounded dev re-arm story.
4. Adopt the rollback posture (D6): retention set, retain-until-healthy
   with the normative defaults, revert as re-arm under the revert
   predicate, forward-epoch admission only, undeletable embedded
   baseline.
5. Adopt the receipt and the Exact 0553 seam (D7), discharging Exact
   0504 §3 row 54c.

## Revision history

- r3 (2026-08-23): blind grok-4.6 cross-family round folded (artifact:
  `llp/reviews/0053-plan-artifact-update-admission.r2.grok.md`; NOT
  READY, 6 MATERIAL, spot-verified). M1: check 7 constructed (fence
  re-hash on admit, digest-only binding, snapshot recipe with policy
  regeneration under embedder ceilings, 0052 §3 projection interaction),
  r2's Q1 promoted to §10 obligation 4. M2: revert r5 now re-runs
  checks 4–6(a) including `minimumRuntime` against the live operand.
  M3: the dev/production split made structural (dev sibling schema,
  workflow marker, digest domain, trust-store class, both-direction
  refusal) with the session-bounded dev re-arm story for 0553 L-E.
  M4 residue: anchor availability is a platform predicate over the 0052
  §9 matrix; epoch genesis defined. M5: companion digests consumed by
  check 4 with `companion-format-unsupported`; manifest schema obligated
  (ob. 5); `directive-epoch-regression` and `revert-target-unavailable`
  added; every 0541-relation outcome mapped; the total §4 → 0553 §3.1
  class map published. M6: the single-guard linearizable commit per
  0052 §4 step 5, staging-is-not-a-spend, sibling-epoch-swap closed,
  committed-failure epoch cost stated as deliberate. Minors folded:
  0038 two-change characterization; adversarial fixtures (ob. 6); 0052
  field-placement and key-rule verbatim copies (ob. 1); native
  JS-unwritable 0012 operand (ob. 2); check 6 internal order; retention
  depth and digest-named directive targets; JS-transport clarification;
  baseline defined as the install package's immutable payload. The
  Exact 0553 citation corrected: the commission is the record taken with
  0553's acceptance, anchored on 0504 §3 row 54c and the issue ticket;
  0553's printed text carries neither the ask nor this RFC's name.
  r3 additionally folds the codex delta pass
  (`llp/reviews/0053-plan-artifact-update-admission.r3.codex-delta.md`):
  D2 scoped to the decision checks (the fence is arming, not decision);
  the revert commit's own tuple (directed advances only the directive
  mark, automatic advances none, the failed unit leaves retention); the
  r3/r4 refusal codes disambiguated with `baseline-integrity-failure`
  as the terminal case; the in-guard durable-authority projection
  mutations added to 7(c) and obligation 4; the dev re-arm predicate
  obligated (ob. 7); the producer-key compromise horizon recorded as
  §9 Q5.
- r2 (2026-08-23): adversarial consistency fold — all 14 findings of the
  read-only gpt-5.6-sol pass against the cited ibex law applied (envelope
  decided + obligated, identity/kind join, producer trust store as new
  mechanism, epoch posture restated, revert predicate, health defaults,
  closed refusal set, minimum-runtime ownership, structural dev
  separation, correlation-only certificate digest, narrowed
  0021/0029/0052 characterizations). The pass's clean checks confirmed
  the 0021 gap, the 0042 pattern, the 0048 scope contrast, the 0030
  rule, and the 0010 surface discipline as accurately characterized.
- r1 (2026-08-23): initial draft. Commissioned by the record taken with
  Exact LLP 0553's acceptance / Exact LLP 0504 §3 row 54c after the gap
  probe. Composes LLP 0021 (arming), 0042 (digest-only committed
  admission; production/dev separation), 0052 (envelope law, epoch
  anchor), 0048 (scope contrast), 0038/0039 (dev lane), 0012/0010/0002
  (identity, surface, ABI) with Exact 0485/0536/0537/0541/0507/0517
  (artifact and coordinate law) and Exact 0553 §4 L-E/§9 D6 (the
  consuming program).
