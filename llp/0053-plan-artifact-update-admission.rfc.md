# LLP 0053: Plan-Artifact Update Admission

**Type:** RFC
**Status:** Draft
**Systems:** Security, CapSec, Arming, Module Loader, Runtime, Host ABI, Distribution
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-23
**Revised:** 2026-08-23 (r2 — adversarial consistency fold, all 14 findings of
the gpt-5.6-sol read-only pass applied: the envelope decided as a sibling
schema with its byte-exact definition moved to §10 obligations; signed kind +
app-identity join required in authenticated data; the producer trust store
stated as a new verify-only mechanism, not LLP 0052's device-key facility;
the epoch posture restated against the actual threat model instead of
borrowing 0052 §6; revert defined as re-arm-not-admission with its own
predicate and digest revalidation; normative health-fallback defaults; the
refusal table closed without a nearest-code fallback; the minimum-runtime
relation owned here with LLP 0012 as operand only; the dev/production
separation made structural rather than 0038-mode-based; certificate digest
correlation-only; ArmedSnapshot/0029/receipt characterizations narrowed)
2026-08-23 (r1 — initial draft, commissioned by Exact LLP 0553 ask 7 / Exact
LLP 0504 §3 row 54c after the 2026-08-23 probe confirmed the gap: the armed
snapshot is the capability-security arming attestation, not an
update-admission mechanism, and no Ibex LLP owns OTA admission of plan
artifacts — Exact `issues/20260821-eplan-ota-armed-snapshot-confirmation.md`)
**Related:** LLP 0021 (typed CapSec effect model — `ArmedSnapshot`, the
CapSec execution-authority root; this RFC proposes the admitted-update
binding as a new authenticated field of it), LLP 0042 (independent
prepared-graph commitment — the digest-only committed-admission pattern, the
re-verify-before-use rule, the development-commitment class, and the
production/development never-interchangeable rule this RFC restates at
update granularity), LLP 0052 (durable authority — the byte-exact TLV
envelope rule set, the `(issuer, intendedAudience, kind, keyId)` trust-record
match, and the §6 rollback-resistant epoch-anchor construction this RFC
composes with where present), LLP 0048 (external script admission —
deliberately does NOT cover this: its scope is one caller-selected
`.ts`/`.js`/stdin source), LLP 0030 (audit graph admission — its foreground
snapshot carries no authority rows and cannot reach this surface), LLP 0038
(unadvertised dev arming — an independent axis, not this RFC's dev/production
separation) / LLP 0039 (secure and insecure modes), LLP 0027 (ModuleArtifact
wire and carriers), LLP 0013/0021 (principals; the fail-closed no-user
sentinel), LLP 0012 (runtime identity — `runtime-identity.json`, the
authenticated local operand of §3 check 6's minimum-runtime relation, which
this RFC owns), LLP 0010 (runtime surface — this RFC adds no `ibex` CLI
command), LLP 0002 (host embedding ABI — the presentation surface lands as an
ordinary 0002 amendment), LLP 0029 (single-file packaging — immutable
embedded bytes and release pins; it excludes self-update, which supports
this RFC's boundary; baseline *retention* is new law here); **external:**
Exact LLP 0553 §4 L-E / §9 D6 (the embedded-reload lane whose restart class
joins the host re-arm/boot path; **D6 blocks on this document existing**),
Exact LLP 0504 §3 row 54c (the confirmed gap; discharged by this RFC's
commissioning), Exact LLP 0526 (expo-updates-class OTA ruled NOT-A-MODULE:
update admission is runtime/Ibex territory), Exact LLP 0485 §3/§11/§12.1.2 +
Track R (`plan/format-schema.json` — the `.eplan` format's law; the
`PlanAdmissionCertificate`; the versioned compatibility relation), Exact
RFC 0536 (catalogs) / RFC 0537 (payload segments) — the referenced-artifact
companions, Exact LLP 0541 (Contract edition identity — the layered-digest
coordinates an update unit declares), Exact LLP 0507 / LLP 0517 (pinned
wire/host formats; 0517 explicitly leaves `.eplan` tables and plan admission
to the plan authorities), Exact LLP 0500 (embedded rollout deliberately
deferred to the program this RFC serves); Snapback LLP 0052 (update
economy — the delivery side, out of scope here)

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
format-version window → edition compatibility → runtime minimum + epoch
monotonicity → generation-fenced activation), **the typed fail-closed
refusal set**, **the trust boundary** (only the authenticated embedded host
presents; JS never presents, accepts, or bypasses), and **the
rollback/kill-switch posture** (retain-until-healthy with normative
defaults, forward-epoch admission only, revert as re-arm-not-admission, a
signed revert directive). It is deliberately small: the admission decision
document, not a delivery pipeline. Delivery, hosting, and update economics
stay with the embedder and Snapback LLP 0052; the artifact format's
internal law stays with Exact's plan authorities. Ibex admits bytes against
digests and declared coordinates; it never re-interprets the format to
decide. Byte-exact schemas and grammars this RFC requires are named
obligations (§10), not open questions.

## 1. The gap and the commission

- **What exists:** arming (LLP 0021) attests the capability posture of a
  runtime over an already-present artifact set. Committed prepared-graph
  admission (LLP 0042) verifies a *cache* against an authenticated
  commitment by digest alone. External script admission (LLP 0048) admits
  one caller-selected source file under an erasable profile. None of these
  answers "may this runtime replace its shipped application content with
  bytes that arrived over the air?"
- **The commission:** Exact LLP 0504 §3 row 54c recorded the question,
  the probe answered NO (armed snapshot ≠ update admission), and Exact
  LLP 0553 — the dev-loop program — needs the answer for its L-E
  embedded-reload lane, whose restart class "joins the host's re-arm/boot
  path" (0553 §4). That re-arm's artifact-admission law is this document.
  Exact 0553's D6 phase (embedded reload + mirror retirement) blocks on
  this document existing.
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
with `(kind, digest, byteLength)`. An artifact not enumerated is not part
of the unit and is never read during admission; an enumerated artifact
that is missing or digest-mismatched refuses the **whole unit**. v1 units
are **full-set only** — no differential units (§9 Q4).

The unit's manifest also carries, as **declared coordinates** (operands of
§3's predicate, opaque otherwise):

- the plan-format schema version (Exact 0485 Track R's version line);
- the Exact LLP 0541 edition-identity coordinates (the layered digests and
  posture the producer stamped);
- pinned-format digests for companions whose law lives elsewhere (e.g. an
  EXWF schema digest per Exact 0507 §8 where a companion binds one);
- `minimumRuntime` — a constraint whose grammar and comparison relation
  **this RFC owns** (§10 obligation 2); the authenticated LLP 0012
  runtime identity is the local operand it is evaluated against, and
  nothing more is attributed to LLP 0012;
- `updateEpoch` (§3 check 6);
- opaque producer provenance: the producer's Exact 0485 §11
  `PlanAdmissionCertificate` digest where one was emitted.
  **Correlation-only**: bound into the manifest so receipts and audits can
  join the producer's build evidence; it proves nothing at admission and
  no admission check evaluates it.

**D2.** Admission is **digest-only** (LLP 0042's discipline restated):
the predicate hashes bytes and compares declared coordinates against the
runtime build's embedded registers. It never parses plan tables, never
evaluates expressions, never executes any admitted byte to decide. Format
validity beyond the digest is the producer's law and the runner's
fail-closed load path, not an admission input.

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
   certificate (decided here; it was this draft's r1 open question):
   distinct schema and kind registry, obeying 0052's envelope **rule
   set** — byte-exact length-prefixed TLV; protected version, algorithm,
   key id, issuer, audience, and **kind**; unknown-field rejection; fixed
   signature encoding. Its complete byte-exact definition (tags, ordering,
   bounds, signed preimage) is §10 obligation 1 and must exist before any
   implementation claims this check. Two kinds exist: `update-unit` and
   `revert-directive` (§6); the kind is inside the signed preimage and
   cross-kind reinterpretation is forbidden (0052's rule). The protected
   audience **is the canonical app identity**, and the check requires
   exact equality across the presenter's authority scope (check 1), the
   pinned trust record's `(issuer, intendedAudience, kind, keyId)` tuple
   (0052 §3's match shape), and the epoch namespace (check 6). **ES256 is
   mandatory** for any signer outside the device's native authority
   domain — which every real OTA producer is; HS256 remains confined to
   one native authority domain per LLP 0052. Producer-signature
   verification runs natively against a **verify-only producer trust
   store** pinned by the embedder at build time — a **new mechanism this
   RFC introduces** (§10 obligation 3), deliberately *not* LLP 0052's
   protected key facility, which owns the device-local non-exportable key
   and is not a producer-root verifier. Key custody, rotation, and
   enrollment stay with the embedder (§8); this RFC owns only the pinned
   store's match semantics.
3. **Digest closure.** The manifest payload is schema-valid
   (`manifest-invalid` otherwise); then every enumerated artifact is
   hashed and must equal its manifest row, byte length included; nothing
   outside the enumeration is read or admitted. Closure completes
   **before** any activation effect exists (verify-then-activate; no
   partial admission, no streaming activation).
4. **Format-version window.** The declared plan-format schema version is a
   member of the runtime build's **pinned supported set** — declared, not
   sniffed from bytes. Unknown or newer-than-supported refuses.
5. **Edition compatibility.** The declared Exact 0541 coordinates are
   compared against the runtime build's embedded compatibility register
   under the **separately versioned compatibility relation** (Exact 0485
   §12.1.2 / 0541 §3). Compatible admits; incompatible, unknown relation
   version, or absent coordinates refuse. Ibex evaluates the relation as
   published machine data; it never re-derives edition semantics.
6. **Runtime minimum and epoch monotonicity.** `minimumRuntime` is
   evaluated under this RFC's relation (§10 obligation 2) against the
   authenticated LLP 0012 identity. `updateEpoch` is **strictly greater**
   than the recorded high-water epoch for this app identity (the epoch
   namespace is per app identity — check 2's joined audience). The
   high-water record lives in **runtime-integrity-protected storage: the
   same protection class as the armed snapshot's own authenticated
   bindings** (an attacker who can rewrite it can already substitute the
   artifact bindings themselves, so it adds no new trust assumption), and
   transitions atomically with admission. Where a rollback-resistant
   external anchor of LLP 0052 §6's class is available, the record MUST
   additionally bind to it, which extends the defense to
   whole-filesystem-snapshot restore; absent such an anchor the receipt
   (§7) records `anchor: none` and the threat model explicitly does not
   claim snapshot-restore resistance — declared, never silent, and never
   claimed as an 0052 §6 construction. Unreadable, corrupt, or
   fork-evident epoch state refuses (`epoch-state-unavailable`).
7. **Generation-fenced activation.** An admitted unit becomes live only
   through a full re-arm: a **new `ArmedSnapshot`** whose artifact binding
   references the admitted unit (the LLP 0042 pattern — the admitted-update
   binding is proposed as an authenticated field of the armed snapshot,
   held outside any writable cache), taken at the host's re-arm/boot path.
   Admission **never mutates a live generation**: the running generation
   continues on its current artifact set until the fence. This is exactly
   Exact 0553 §3.1's `regenerate-policy-and-restart` class, and the
   running app's view of a refused or pending update is `keep-last-good`.

## 4. Refusal shapes

**D4.** Refusals are a closed typed set; every refusal leaves the
currently armed artifact set untouched and emits a §7 receipt:

| Code | Meaning |
| --- | --- |
| `presenter-unauthorized` | check 1 — wrong or unattributable principal |
| `envelope-invalid` | check 2 — framing, unknown field, protected-field, kind, audience-join, or encoding failure |
| `signer-unauthorized` | check 2 — signature invalid, trust-record tuple mismatch, key not pinned, algorithm out of domain |
| `manifest-invalid` | check 3 — manifest payload fails its schema, or a constraint field (e.g. `minimumRuntime`) is malformed |
| `unit-incomplete` | check 3 — enumerated artifact missing |
| `digest-mismatch` | check 3 — artifact bytes or byte length differ from the manifest row |
| `format-unsupported` | check 4 — schema version outside the pinned set |
| `edition-incompatible` | check 5 — 0541 coordinates fail the relation, or relation version unknown |
| `runtime-below-minimum` | check 6 — this build fails the `minimumRuntime` relation |
| `epoch-regression` | check 6 — `updateEpoch` ≤ the recorded high-water epoch |
| `epoch-state-unavailable` | check 6 — high-water record unreadable, corrupt, or fork-evident |
| `activation-unavailable` | check 7 — no re-arm fence reachable (e.g. retention store unwritable) |
| `admission-internal` | any check — an implementation fault that fits no other code; the raw cause goes in the receipt |

There is no warn-and-admit tier, no partial admission, and no
nearest-code guessing: a failure that fits no specific code refuses as
`admission-internal`, keeping the set closed while never admitting.

## 5. The trust boundary

**D5.**

- **Who presents:** only the authenticated embedded host (native trust
  domain). Application JS — any package principal, any evaluated code,
  any agent surface — can never present, accept, veto, or bypass an
  update, and no admission input is JS-authored. A read-only JS
  observation surface (current update state, last receipt) is future work
  (§9 Q5) and grants no authority.
- **Not the dev lane — a structural separation.** Development reload
  (Exact 0553's dev patch channels, the evidence-lane embedded-reload
  repair, dev-served content) runs under a **development-session
  credential class** in the shape of LLP 0042's development commitment —
  session-scoped, bounded lifetime, an explicit development workflow
  marker — and nothing bearing that class is admissible through this
  predicate, in either direction: a production envelope never rides a
  development credential and a development artifact never becomes the
  boot authority (LLP 0042's production/development rule, restated at
  update granularity). LLP 0038's `unadvertised-dev-arming` build feature
  is an **independent axis** — it bypasses target advertisement only and
  retains every other authenticator — and is context here, not the
  separation mechanism. An embedded app crosses into this predicate
  exactly when its shipped artifact set is to be **replaced** as the boot
  authority.
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

- **Retain-until-healthy.** The previously armed unit and its
  authenticated binding are retained until the successor generation
  reaches a **health mark**. Normative defaults (an embedder may declare
  a *stronger* predicate through the presentation ABI, never a weaker
  one): the default health mark is **the successor generation's arming
  commit completing** (check 7's fence committing), and the fallback
  trigger is **`N = 2` consecutive launches that fail to reach it**. On
  the trigger, the runtime reverts to the retained unit at the next boot
  fence. Whether the default mark should be stronger than arming-commit
  (first frame, crash-free interval) is §9 Q2.
- **Revert predicate** (automatic and directed reverts): (r1) for a
  directed revert, presenter authority per §3 check 1; (r2) for a
  directed revert, a signed **`revert-directive`** envelope per §3
  check 2 — same rule set, its kind in the signed preimage, the same
  app-identity join — carrying its own `directiveEpoch`, strictly greater
  than the last processed directive epoch for this app identity (replay
  defense, recorded in the same high-water store; the artifact epoch
  mark is unaffected); (r3) authenticated target lookup: the target is
  the retained unit or the **embedded baseline**, resolved through its
  retained authenticated binding, never a path; (r4) **digest
  revalidation** of every target artifact against that binding
  (LLP 0042's re-verify-before-use precedent — retained bytes are never
  trusted from storage); (r5) compatibility recheck: §3 checks 4–5
  against the target's retained coordinates (a runtime binary updated
  since the target was admitted may no longer support it); (r6)
  generation-fenced activation per §3 check 7. Automatic (health-mark)
  reverts run r3–r6 only — they are runtime-initiated, with no envelope.
  A revert predicate failure refuses with the §4 codes and falls through
  to the next target (retained → embedded baseline); the embedded
  baseline failing r4 is an integrity failure outside this RFC's repair
  scope and refuses terminally.
- **Operator rollback is forward-moving.** Re-shipping *older content* is
  the re-admission of that content under a **new envelope with a fresh,
  higher `updateEpoch`**, through the full §3 predicate. The epoch never
  regresses; there is no admit-older-epoch override.
- **Kill switch.** The `revert-directive` above, commanding revert to the
  retained unit or to the **embedded baseline** — the artifact set
  packaged with the install. LLP 0029 supplies the precedent that
  embedded release bytes are immutable and release-pinned (and its
  exclusion of self-update supports this RFC's boundary); the
  **undeletable-baseline retention rule is new law here**: admission
  never deletes or overwrites the embedded baseline, so revert-to-baseline
  is always resolvable.

## 7. Receipts and the Exact seam

**D7.** Every admission decision — admit, refuse, revert — emits one
**`PlanUpdateAdmissionReceiptV1`**: unit digest set (or directive id),
presenter identity, per-check outcomes, disposition code, epoch
transition, anchor posture (check 6's declared strength), and the
resulting generation coordinate on admit. Required receipt properties —
this RFC claims exactly these, not LLP 0052 §5's sealed-record
construction: receipts are written natively (never by JS), persisted
atomically with the decision they record, retained across the generation
fence and across reverts, and readable by the embedder. An
LLP 0052-§5-class sealed journal is an optional strengthening an embedder
may choose, not an assumption of this RFC.

**The seam to Exact 0553:** the receipt is consumable by Exact 0553
§3.3's single receipt instrument (its L-E lane's apply receipts cite the
admission receipt of the unit they patched against), and the restart
class of 0553 §3.1 resolves, on the embedded tier, to this document's
generation fence. Exact 0553 **D6** — embedded reload with receipts —
depends on this RFC existing and names it; Exact 0504 §3 row 54c and
`issues/20260821-eplan-ota-armed-snapshot-confirmation.md` are discharged
by its commissioning.

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

1. **Snapshot binding shape:** a new authenticated field of the armed
   snapshot (the 0042 production-commitment pattern) vs a separate
   commitment record referenced by it. Leaning: new field, same
   verification story.
2. **Health-mark strength:** should the normative default mark exceed
   arming-commit (first frame rendered, a crash-free interval), and what
   embedder-declared predicates does the presentation ABI accept?
3. **App/channel identity minting:** who names the canonical app identity
   the audience join and epoch namespace are scoped to
   (embedder-declared? an Exact-side project identity?), and whether one
   runtime hosting several roots holds several namespaces. The §3 check 2
   equality join holds regardless of who mints the name.
4. **Differential units:** a later `PlanUpdateUnitV2` with
   patch-transport of unchanged artifacts must preserve full digest
   closure over the *resulting* set; nothing in v1 may make that harder.
5. **JS observation surface:** the read-only update-state view and which
   corpus (this one or Exact's Acto law) owns its shape.

## 10. Obligations before implementation

Named obligations, not open questions — each must exist (as an amendment
to this RFC or a companion spec) before an implementation may claim the
corresponding check:

1. **The byte-exact envelope definition** for
   `ibex/plan-update-envelope/1`: TLV tags, ordering, bounds, signed
   preimage, signature encoding, and the closed kind registry
   (`update-unit`, `revert-directive`) — to LLP 0052's level of
   precision, as a sibling schema.
2. **The `minimumRuntime` constraint grammar and comparison relation**,
   with the authenticated LLP 0012 identity field it is evaluated
   against named exactly.
3. **The verify-only producer trust store**: record shape (the
   `(issuer, intendedAudience, kind, keyId)` tuple plus key material),
   pinning location, and native verification path.
4. **Conformance fixtures**: refusal-shape twins for every §4 code and
   golden admit/refuse/revert receipt fixtures, in the ibex conformance
   style.

## 11. Decision requested

1. Adopt the `PlanUpdateUnitV1` closed-enumeration update unit (D1) and
   digest-only admission discipline (D2).
2. Adopt the seven-check ordered admission predicate (D3) and the closed
   fail-closed refusal set (D4), with the §10 obligations gating
   implementation.
3. Adopt the trust boundary (D5): host-only presentation, no JS
   authority, structural dev/production separation.
4. Adopt the rollback posture (D6): retain-until-healthy with the
   normative defaults, revert as re-arm under the revert predicate,
   forward-epoch admission only, undeletable embedded baseline.
5. Adopt the receipt and the Exact 0553 seam (D7), discharging Exact
   0504 §3 row 54c.

## Revision history

- r2 (2026-08-23): adversarial consistency fold — all 14 findings of the
  read-only gpt-5.6-sol pass against the cited ibex law applied (envelope
  decided + obligated, identity/kind join, producer trust store as new
  mechanism, epoch posture restated, revert predicate, health defaults,
  closed refusal set, minimum-runtime ownership, structural dev
  separation, correlation-only certificate digest, narrowed
  0021/0029/0052 characterizations). The pass's clean checks confirmed
  the 0021 gap, the 0042 pattern, the 0048 scope contrast, the 0030
  rule, and the 0010 surface discipline as accurately characterized.
- r1 (2026-08-23): initial draft. Commissioned by Exact LLP 0553 ask 7 /
  Exact LLP 0504 §3 row 54c after the gap probe. Composes LLP 0021
  (arming), 0042 (digest-only committed admission; production/dev
  separation), 0052 (envelope law, epoch anchor), 0048 (scope contrast),
  0038/0039 (dev lane), 0012/0010/0002 (identity, surface, ABI) with
  Exact 0485/0536/0537/0541/0507/0517 (artifact and coordinate law) and
  Exact 0553 §4 L-E/§9 D6 (the consuming program).
