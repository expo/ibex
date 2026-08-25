# LLP 0056: Package-Aware Composition Admission (the ibex leg of Exact LLP 0413.001 §6)

**Type:** Spec
**Status:** Accepted
**Systems:** Module Loader, Engine, Host Embedding, Security, Conformance
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-24
**Revised:** 2026-08-24 (Amendment A2 — approved by Charlie Cheever
("sure amend it"), relayed via session exact-b7, on the recommendation
of the legs-2/3 implementation lane + exact-9e + exact-b7's independent
read, resolving the implementation-exposed defect in
`issues/closed/20260824-llp0056-s10-grant-authority-defect.md`. Two changes,
both entirely outside the §6.2 lockstep row bytes (row #34's predicate
text is unchanged and remains valid): §10's external-reference rule is
now the explicit v1 DENY-ALL-CROSSING policy — every external edge
crossing defining principals refuses #34; equal principals never
consult the policy; relaxation is a future O-4/armed amendment — and
§4.7's phantom `resolverInventoryDigest` alias-input claim is DELETED
with the field marked RESERVED on the wire (rationale recorded in
§4.7; the pinned O-3 preimage and vector corpus are untouched).)
2026-08-24 (ACCEPTED by Charlie Cheever — decision relayed
via session exact-b7; basis = r5 dual-READY (round-4 final delta:
codex gpt-5.6-sol xhigh READY + grok-4.6 READY x3, 0 MATERIAL in both
families on r5 @494fad727) plus the byte-verified A1 lockstep;
recorded Exact-side @3ef12a99b. Mechanical status edit only — no
normative text changed.) 2026-08-24 (r5 — round-3 delta fold (grok-4.6 READY, 0
MATERIAL, second consecutive; codex gpt-5.6-sol xhigh NOT READY, 2
MATERIAL, both verified): §3.3's authority claim made precise — the
landed expectations schema is field-for-field on names/requiredness
but its three integer fields lack the `2^53-1` JSON-Schema `maximum`,
and the parity check inspects neither channel schema (exact-side
repair = named handoff; the I-JSON rule stays normative here);
producer-mismatch routing made deterministic (§6.4 `_PRODUCER` row
split: index-vs-envelope → #22, carrier/artifact-vs-authenticated-
index → #14, matching §4.8); grok round-3 slips fixed (step-3 range
#11–#23; step-8 wording consumes the step-6 capability; §9.1
"in-flight" caveat retired with aligned-vs-pending rows named; §3.3
field counting); candidate-table dispatch order pinned (schema
identifier first, digest authenticates the wire form before stamping;
new §9.2 v1-candidate-table fixture row); #16 precedence wording made
origin-neutral; `invoke_named_export` returns `InvokeOutcomeV1` as the
thenable-diagnostic transport.) 2026-08-24 (r4 — round-2 dual-family fold on r3 (grok-4.6
READY, 0 MATERIAL; codex gpt-5.6-sol xhigh NOT READY, every decisive
claim verified before folding): **generation-free candidate-table v2**
(the landed `ComputedCandidateTableV1.generation` would smuggle a
serialized generation into package bytes — codex, converging with a
blind grok verification request; §4.3, §4.8, an O-1 row); **full
producer identity in the package index** (`(producerId,
producerBinaryDigest)` vs the envelope — r7 §3.1 item 2 and shared
row #22 already required identity equality; §4.3/§4.8); **external-ref
cap at both surfaces** (§3.1); **`AuthorizedCompositionPlanV1` typed
handoff** step 6 → step 8 (codex/grok convergent — policy denial can
never misreport as #38; §5/§7.2); acceptance coupling and §6 rewritten
to ONE normative meaning (peer blocker resolved; generated-halves
parity = implementation gate); §6.2 scope-declaration overclaim fixed
(Exact-side sibling note = named handoff); step-3 ordinal-outer sweep
rule; `*_for_roots` entry-plan argument order; report
serialization-failure null rule unified; `agentInvokeReturnedThenable`
diagnostic; expiry/policy-digest note; d1 pin clarified
(literal-dynamic-only + §2.1 identity clause). Alignment-wave fold
(Exact `@a049ed9aa`, verified): §3.2/§3.3 re-pointed from provisional
to their **landed authority files** (field-for-field);
generation-carrier duplication RESOLVED exact-side (wrapper carries no
generation); §4.7 evidence basis widened to the landed collection
basis (declared edges + host-bridged rows); §6.3 arming note (the
lockstep leg reports unarmed until the vendor/ibex pointer advances —
expected posture); §11 leg-1 r6-shape hold released, the 21-vector
corpus named as the leg-1 Rust differential target.) 2026-08-24 (r3 — peer-blocker resolution + dark-impl pins:
Exact 0413.001 r7 / Amendment A1 `@246f959cc` adopted §6.2 verbatim
(doc tables byte-verified identical; §6/§6.2/§11 status updated, the
acceptance peer blocker recorded resolved with the generated-halves
parity pin remaining an implementation-leg gate); two exact-b7
dark-implementation findings pinned — the §2.5 package-scope reason
mapping BLESSED with the locality-rule rationale and no third enum
member (§4.3), and the envelope attestation triple pinned as the ONE
canonical serialized generation carrier, rejecting the
`PreparedPackageDeliveryV1`-style sidecar (§4.8); O-1 status updated
(seed landed `@9018e0bbd`, r6-shaped, provisionality holds until the
parity check pins r7-shaped bytes; §11 leg 1 holds until the exact-side
alignment landing report); §6.2 row-byte section references declared
0056-relative in both repositories.) 2026-08-24 (r2 — round-1 dual-family fold; both families NOT
READY on r1 (grok 11 MATERIAL conformance + 5 MATERIAL design; codex 4
factual + 8 MATERIAL design), convergent on the load-bearing set and
every decisive claim verified before folding. The unified changes: **the
full ordinalized replacement registry table lives in §6.2** (38 rows,
one precedence tuple `(step, ordinal, roleOrder)`, one default per step
— the r1 dual-default at step 3 deleted) [grok C1/C2, codex]; **the
amendment-delta list is explicit** — 6 placeholders → 11 imported rows,
step/class moves named, `ibex:engine-binary-digest-mismatch` and
`ibex:compiler-fingerprint-mismatch` given dispositions (the latter
**dropped from v1 as unreachable**: the dev posture's fingerprint
expectation derives from the artifact itself, `runner_pipeline.rs:3765`
— codex's catch; O-6 forbids unreachable rows) [grok C3/C4, codex];
**the covering map is total and injective** with a machine-checkable
site→code fixture, the additional untokenized sites codex found added,
and producer-side `carrier.rs:170` removed [grok C5, codex];
**`cross-principal-denied` is a defining-principal predicate again** on
the authorized linker path — v1 generalizes `link_authorized_prepared`,
never the `link_prepared` bypass, closing r6 §3.3's authorized-linker
requirement [grok C6/C7/D5, codex]; **`ibex:encoding-incompatible` gets
a reachable predicate** (declared-encoding/byte-shape sniff — the landed
peek makes `carrier.rs:327` unreachable, codex's catch);
**generation-splice is made decidable** via per-role attestation rows in
the envelope (package bytes stay generation-free) [codex]; **verifier
inputs are complete** — commitment slimmed to a digest, expectations
carry target and the O-3 frozen-inventory digest, engine identity comes
from named runtime queries, integers are I-JSON-safe [grok C8/C9/D1,
codex]; **bounds are enforced at the right surfaces** (envelope vs
package) [grok C8]; **step 7 proves the invoke-before-app guarantee**
(app root excluded from the agent closure) and resolves export presence
through the star-export-resolved namespace plan [codex]; **multi-root
execution names `mainRoot = app`** and a monotonic descriptor executor
[codex]; **the report has tagged per-outcome shapes** (§8) [grok C11,
codex]; **alias-id/SourceId disjointness** required [grok D2]; **HBC
preflight is composition-lane-only** (the landed single-publication
entry is byte-for-byte unaffected) [grok D3]; the purity theorem
restated (agent digest names app `SourceId`s in external rows only,
never app bytes/digests) [grok D4/c4]; fixture 35 split 35a/35b with the
r6 §7 erratum flagged [grok C10, codex]; binding rows become a tagged
`local`/`external` enum [codex]; minors folded (domain literals
restated, safe-integer bounds, thenable honesty, OQ-C closed to counts,
report-superset clause, expiry/policy note). Per the 0413.001 track
owner's coordination constraints: **§6 is named as the authoritative
token enumeration the O-2 parity check consumes**, and **every concrete
field sketch is provisional pending the O-1 schema package** at Exact
`docs/schemas/prepared-composition/v1/` (not yet landed at review time —
verified empty on Exact origin/main), which this spec references as the
canonical home rather than freezing a competitor. Acceptance is coupled
to the 0413.001 §4.1 amendment (§11).) 2026-08-24 (r1 — initial draft,
commissioned by Exact `issues/20260824-ibex-package-aware-admission-llp.md`
after Exact LLP 0413.001 was Accepted at r6 (@377caa657) with
obligations O-1–O-6; this document is O-2's owner and the §6 "one ibex
LLP". Designed against the landed tree at `94c85abab`.)
**Related:** Exact LLP 0413.001 (the governing spec — §2 packages, §3
composition, §4 nine-step admission + §4.1 registry, §5 receipts, §6 the
ibex obligation, §7 fixtures, §10 obligations; Accepted r6; r7 /
Amendment A1 `@246f959cc` adopts §6.2 as the lockstep registry), Exact
LLP 0413 (§5.3 per-defining-principal carriers, §5.4 fallback, §5.7/§14
admission/tamper), LLP 0042 (independent prepared-graph commitment — the
landed single-publication admission this spec generalizes; extended,
never re-decided), LLP 0043 (registered external transform fingerprints
— why `ibex:compiler-fingerprint-mismatch` is dormant in v1), LLP 0026
(ESM module runner — link/evaluate lifecycle), LLP 0027 (module artifact
and interop), LLP 0013 / LLP 0040 (principals — the term `Principal`
keeps its meaning here), `src/module_loader/runner_pipeline.rs`
(`admit_committed_publication_v1`, the dev-unarmed embedder entry),
`src/module_loader/carrier.rs` (`PreparedModuleCarrierV2`),
`src/module_loader/artifact.rs` (`ModuleArtifactV1`, `ProducerIdentityV1`),
`src/module_loader/graph.rs` (`SynchronousGraphPlan`),
`src/engine/module_runner.rs` (`NativeSynchronousGraph`),
`src/module_loader/security.rs` (`ModuleGraphAuthorizer`,
`GraphImportPolicy`), `llp/reviews/0056-package-aware-composition-admission.codex.md`
/ `.grok.md` (round 1)

## Summary

Exact LLP 0413.001 makes the prepared-graph publication a **composition
of per-role packages**: a required `app` package and an optional `agent`
package, declared per session, committed under an anti-replay composition
commitment, and admitted authentication-first through nine ordered
fail-closed steps. Its §6 names one cross-repo obligation: **no
composition admits until the ibex package-aware leg lands.** This spec is
that leg.

It specifies, against the landed module loader at `94c85abab`:

1. the **package artifact schema** — per-package roots replacing the
   whole-publication `deploymentGraphDigest` inside package bytes, so app
   bytes are identical across session shapes (§4);
2. the **admission inputs at the embedder boundary** — served bytes,
   host-held commitment (a digest), verifier-held expectations, and
   named runtime queries (§3);
3. the **ibex half of the nine steps** — which predicate each existing
   function decides, what is new code, and the refusal code every failure
   maps to, evaluated in registry-ordinal order (§5);
4. the **authoritative refusal enumeration for O-2** — the full
   ordinalized replacement registry (§6.2), the covering map from every
   landed refusal class to exactly one registry row (§6.1/§6.4), and the
   parity-check relationship that discharges O-2 (§6.3);
5. **authorized multi-root link planning and descriptor execution** —
   the `SynchronousGraphPlan` / `NativeSynchronousGraph` evolution for
   an ordered two-root evaluation with evaluate-then-invoke, a named
   main root, and a retained composition session (§7);
6. the **report** the embedder receives, with a tagged total shape for
   every outcome (§8); and
7. the **conformance surface** — the shared canonical-byte vector corpus
   (O-1) and the §7-fixture rows that live ibex-side (§9).

Everything here is fail-closed: every admission step names its refusal
codes and exactly one default, and an outcome outside the registry is a
defect in this implementation, never a pass.

**Schema provisionality (coordination rule):** the canonical home of the
composition schemas, preimages, and the shared vector corpus is the O-1
package at Exact `docs/schemas/prepared-composition/v1/`. As of r4 the
O-1 seed (`@9018e0bbd`, status `dark`, plus the steps-1–5 TS admission
mirror `@8d06de59e`) has been **r7-aligned by the exact-side alignment
wave at `@a049ed9aa`** (attestation triples, the §3.3 channel records,
the expectations-driven mirror; `prepared-composition-schema-parity`
PASS): the §3.2 commitment and §3.3 expectations blocks now have
**landed authority files, field-for-field** (their sections cite
them), and the generation-carrier duplication is resolved in this
spec's favor (§4.8). The remaining field sketches (§4.3–§4.6, §8 —
the carrier-bearing ibex-half schema rows the seed does not yet carry)
stay **provisional pending their O-1 rows**: this spec fixes names,
semantics, invariants, and refusal behavior — byte-level encodings
defer to O-1, and the ibex side consumes and extends that corpus rather
than freezing a second format (§9.1).

## 1. Scope and non-goals

**In scope:** the package and composition decode types and their bounds;
the per-package root schema (index, carrier v3, producer identity); the
nine-step admission driver and its placement across
`module_loader/composition.rs` (new), `runner_pipeline.rs`, `graph.rs`,
`module_runner.rs`, and `security.rs`; the one-way `agent → app` typed
external references at union closure; the authoritative refusal
enumeration and its parity mechanics; authorized multi-root linking, the
descriptor executor, and the evaluate-then-invoke primitive; the
dev-unarmed C-ABI entry and report; the ibex-side fixture matrix.

**Non-goals (v1), inherited from 0413.001 §1:** roles beyond
`app`/`agent`; partial admission (whole-or-nothing); any armed posture
(the production-armed row is a deferred amendment — the landed
`load_prepared_graph_committed_v1` armed wrapper is untouched);
`parseFree` semantics; a second runtime (RFC 0495); binding computed
dynamic imports (host-bridged only, §7.5); full-agent-graph packing
(`boot-core-v1` is the only v1 agent packing). Also out of ibex scope:
the produce algorithm, cache identity, produce atomicity, warm-cache
freshness (O-4), the O-3 import-site digest algorithm's definition (an
O-1 package row this spec consumes), and the `unavailable-*` receipt
variants — all producer/exact-side; ibex never emits them (§8).

## 2. Terminology — composition role is not Principal

This distinction was a round-1 catch in the 0413.001 loop that would
otherwise have refused every real publication, and it is binding
vocabulary for this document and its implementation:

- **`Principal`** (LLP 0013/0040, `capsec_semantics::model::Principal`)
  keeps its existing ibex meaning: the per-record **defining principal**
  (Root, `Package { name, .. }`, builtin domains). One prepared package
  contains **many** per-defining-principal carriers; every record keeps
  its `definingPrincipal`; carrier grouping by defining principal
  (`runner_pipeline.rs:3631-3650`) is unchanged. `cross-principal-denied`
  is a **defining-principal** refusal (§5 step 6, §10) — never a
  composition-role check.
- **Composition role** (`app` | `agent`) is a **package-level** fact: the
  role one package plays in one session's composition. A package is
  never "a principal." No API, field, token, or log line introduced by
  this spec may use "principal" to mean the composition role; the
  serialized field is `role`, the Rust type is `CompositionRole`.

**Domain literals.** The composition-side constants are 0413.001 §3.1's
seven, byte-for-byte (`ibex:prepared-composition-root:1`,
`ibex:prepared-package-root:1`, `ibex:prepared-partition:1`,
`ibex:prepared-union-table:1`, `ibex:prepared-boundary-inventory:1`,
`ibex:prepared-alias-table:1`, `ibex:prepared-entry-plan:1`); this spec
adds one ibex-side literal, `ibex:prepared-package-graph:1` (§4.2). The
O-1 schema package carries the same strings; any divergence is a
corpus-parity failure, not a negotiable rename.

Other terms: **package root** — the digest, domain
`ibex:prepared-package-root:1`, over one package's canonical index
bytes; **package graph digest** — the digest, domain
`ibex:prepared-package-graph:1`, over one package's role-scoped semantic
graph, replacing `deploymentGraphDigest` inside package bytes;
**composition root** — the digest, domain
`ibex:prepared-composition-root:1`, over the canonical composition
envelope; **envelope** — the served `composition.json`
(`PreparedCompositionV1`); **commitment** — the host-held
`PreparedCompositionCommitmentV1` (§3.2); **expectations** — the
verifier-held live values (§3.3).

## 3. Inputs at the embedder boundary

Three trust channels, each with a single owner; no fact rides two
channels (the r1 draft duplicated declaration/target/producer facts on
the commitment — a parity pair that could drift; deleted).

### 3.1 Served bytes (artifact storage; untrusted until admitted)

A composition directory:

```
<composition_dir>/
  composition.json          # canonical JCS PreparedCompositionV1 (the envelope)
  packages/app/             # one package publication (§4)
    index.json
    <carrier manifest/bytes files>
    <candidate table files>
  packages/agent/           # present iff declared
    ...
```

Every file is read through the landed `read_bounded_prepared_file`
discipline (`runner_pipeline.rs:3240` — no-follow, regular-file,
exact-size, hard byte limits). Package directories keep the landed
`activation/` carve-out: a real, non-symlink `activation` directory is
permitted and excluded from the inventory (`runner_pipeline.rs:3595`
rule, applied per package); anything else unexpected is an inventory
refusal.

**Bounds, by enforcement surface** (0413.001 §3.1 set, split to where
each collection actually lives — the r1 draft enforced package-level
bounds at envelope decode, the wrong surface):

- **Envelope decode (step 1):** envelope ≤ `MAX_PREPARED_INDEX_BYTES_V1`
  (64 MiB); roles ≤ 2; alias rows ≤ 1 024; union-table rows ≤ 1 048 576;
  external references ≤ 4 096; strings ≤ 4 KiB; nesting ≤ 16.
- **Package index decode (step 3):** index ≤ 64 MiB; records ≤ 65 536
  per package; declared edges ≤ 1 048 576 per package; external
  reference rows ≤ 4 096 per package (r4 — the envelope-only cap left
  a committed package free to carry more until step 6; the same cap is
  enforced at both surfaces); strings ≤ 4 KiB;
  nesting ≤ 16; manifest ≤ 16 MiB, carrier ≤ 512 MiB, candidate table
  ≤ 64 MiB (the landed per-file caps).

Limit and limit+1 are fixture rows at **both** surfaces (§9.2).

### 3.2 Host-held commitment (the §3.3 channel) — a digest, nothing else

*O-1 authority LANDED (r4):*
`docs/schemas/prepared-composition/v1/prepared-composition-commitment-v1.schema.json`
(Exact `@a049ed9aa`, field-for-field with this block — three fields,
`additionalProperties: false`; the file self-describes as the authority
this block awaited). The composition analog of today's
`commitment_json` argument, slimmed so no envelope fact is duplicated:

```jsonc
// schema "ibex/prepared-composition-commitment/1"
{
  "schema": "ibex/prepared-composition-commitment/1",
  "workflow": "production",           // production-SHAPED record; dev posture
                                      // lives in the entry type (LLP 0042 rule)
  "compositionRootDigest": "<digest over the envelope bytes>"
}
```

Delivered on the host-held boot-configuration channel, independent of
artifact storage — never read from `composition_dir`. Declaration,
target, producer identity, freshness facts: all live in the envelope
(authenticated by this digest) and are compared against §3.3's
expectations — never against a second host-held copy. Channel-level
prechecks (strict JSON, canonical JCS, schema, workflow) refuse with the
sibling tokens `IBEX_DEV_COMPOSITION_CORRUPT` / `_SCHEMA` /
`_ARMED_CONTEXT`; like the landed `IBEX_DEV_COMMITTED_*` family these
are **channel failures outside the registry**, reported through the §8
`channel-error` variant.

### 3.3 Verifier-held expectations

*O-1 authority LANDED (r4; claim made precise at r5):*
`docs/schemas/prepared-composition/v1/composition-verifier-expectations-v1.schema.json`
(Exact `@a049ed9aa`) is field-for-field with this block on **names and
requiredness** — the nine properties (`schema` plus the eight live
values), every one required, `additionalProperties: false`,
`expectedRoles` as the two const arrays. **Known authority-file gap
(r5 — codex round 3):** the three integer fields carry only
`minimum: 0`; the `0..=2^53-1` ceiling is normative in this spec (and
stated in the file's description text and the O-1 index `numberRule`)
but is NOT yet a JSON-Schema `maximum` keyword, and the landed parity
check inspects neither channel schema. Admission enforces the full
I-JSON range regardless of the keyword. **Named exact-side handoff:**
add `maximum: 9007199254740991` to `authorityGeneration`,
`resolverGeneration`, and `nowUnixMs`, and extend
`check-prepared-composition-schema-parity.mjs` to validate both
channel schema files.
One versioned JSON argument carrying every
live value step 2b compares against (the r1 draft left target and the
O-3 inventory with no input channel — codex/grok convergent):

```jsonc
// schema "ibex/composition-verifier-expectations/1" — every field mandatory
{
  "schema": "ibex/composition-verifier-expectations/1",
  "expectedTarget": "<embedder target string>",
  "expectedRoles": ["app"] | ["app", "agent"],   // effective live state
  "sessionNonce": "...",
  "authorityGeneration": <int>,
  "resolverGeneration": <int>,
  "policyDigest": "<digest>",
  "resolverInventoryDigest": "<digest>",  // the frozen resolver/transform
                                          // inventory digest. A2: RESERVED —
                                          // mandatory on the wire (landed O-1
                                          // schema), consumed by NO v1
                                          // admission predicate (§4.7's r5
                                          // alias-input claim was a phantom;
                                          // consumption arrives with O-4)
  "nowUnixMs": <int>
}
```

All integers are I-JSON safe (`0..=2^53-1`), matching r6's RFC 8785
number rules; `nowUnixMs` is an input so expiry outcomes are
deterministic under test. Credential material never appears here or in
the envelope (0413.001 §3.1 item 8). Expiry is decided only as
envelope-vs-`nowUnixMs`; a producer-chosen far-future expiry is a
policy question the policy digest (#4) owns — no second lifetime
channel exists or should be added (r4, grok d5).

**Runtime-queried identity (not expectations):** the loaded-engine
identity for `hermes-bytecode` carriers comes from the authoritative
in-process queries the landed dev lane already uses —
`crate::engine::loaded_engine_binary_digest()` and
`loaded_engine_bytecode_version()` (`runner_pipeline.rs:6011-6033`) —
never from the publication and never from the host (0413/0413.001: the
engine identity is owned by the loaded engine).

### 3.4 The C-ABI entry (dev-unarmed, the only v1 posture)

```c
int32_t ibex_dev_unarmed_composition_prepared_startup_v1(
    void *runtime, uint64_t runtime_nonce,
    const char *composition_dir,
    const char *commitment_json,      // §3.2, host-held
    const char *expectations_json,    // §3.3, verifier-held
    const char *project_root,
    char **out_report_json,           // written on every outcome — §8 tagged
                                      // shapes; null ONLY on report-serialization
                                      // failure (§8's never-convert rule)
    char **out_error);
```

Return codes keep the landed phase semantics exactly
(`DevCommittedStartupFailurePhase`, `runner_pipeline.rs:6410-6417`,
`exact_runtime.h:535`): `0` success; `1` refusal in step 0 or steps 1–8
(**before evaluation** — the Exact host may select the LLP 0413 §5.4
fallback); `2` failure at step 9 or later (**during evaluation** — the
generation is failed, no encoding switch, no fallback). The
construction-time armed exclusion
(`installed_host_is_armed_for_dev_exclusion`) applies unchanged. The
existing single-publication entry
`ibex_dev_unarmed_committed_prepared_startup_v1` remains for
non-composition embedders **byte-for-byte unaffected** (§5 step 3 note,
§11); Exact's package-aware host moves to this one.

## 4. The package artifact schema (per-package roots)

### 4.1 Why the landed schema forbids the identity guarantee

0413.001 §2.1 requires app-package bytes identical across session shapes
and names this "a requirement on the §6 schema." At `94c85abab` the
whole-publication `deploymentGraphDigest` is bound **inside served
publication bytes** at three places:

1. the index's top-level field —
   `PreparedGraphIndexV2.deployment_graph_digest`
   (`runner_pipeline.rs:228`);
2. every carrier manifest — `PreparedModuleCarrierV2.deployment_graph_digest`
   (`carrier.rs:101`), covered by the index-committed manifest bytes;
3. every record artifact — `ProducerIdentityV1::Prepared
   { deployment_graph_digest, .. }` (`artifact.rs:270-275`), inline in
   `index.json`.

(The commitment — `PreparedGraphCommitmentV1.deployment_graph_digest`,
`crates/capsec-semantics/src/arming.rs:53` — is a fourth binding
surface, but host-held, not package bytes.) Because that digest covers
the whole publication, adding or editing the agent side would change
every app carrier manifest and every app record byte. The fix is
per-package binding, with this **purity theorem** (restated per review —
the r1 "no fact outside this graph" sentence overstated it):

- **App:** app-package bytes are a pure function of the app module graph
  under the declared boundary — no `entry` field (§4.3), `role` is the
  constant `"app"`, host-bridged reasons satisfy the §2.5 locality rule,
  and no agent `SourceId` appears anywhere in app bytes. App bytes are
  therefore identical across session shapes.
- **Agent:** agent-package bytes may name app `SourceId`s **only inside
  typed external-reference rows** (§4.5) — never app bytes, digests, or
  source integrity. The agent package graph digest includes the ordered
  external-reference row set, so it changes exactly when that set or the
  agent-owned graph changes, and never when app payload bytes change
  (0413.001 §2.1's agent-identity rule, delivered by construction).

### 4.2 The package graph digest

Per package, the producer computes the **package graph digest**: domain
`ibex:prepared-package-graph:1` over the canonical JCS encoding of the
package's role-scoped semantic graph — the ordered set of
`(SourceId, semanticDigest)` pairs of owned records plus the ordered
declared binding rows (including external-reference rows by target
`SourceId` only). It is a pure function of the package's own graph
facts, computable before any carrier or artifact is built (no
circularity: it binds semantics, not artifact or index bytes — exactly
the role `deploymentGraphDigest` plays today; `ModuleSemanticsV1`
contains no graph-level digest). The precise preimage is a named row of
the O-1 schema package; this spec fixes the domain string and the purity
requirement.

### 4.3 The package index — `ibex/prepared-package/1`

*Provisional pending O-1.* The per-package sibling of
`PreparedGraphIndexV2` (`runner_pipeline.rs:224`), canonical JCS,
`deny_unknown_fields`:

```jsonc
{
  "schema": "ibex/prepared-package/1",
  "role": "app" | "agent",
  "producerId": "<producer id>",           // r4: full identity, not digest-only —
  "producerBinaryDigest": "<digest>",      // §4.8 compares BOTH to the envelope's
  "packageGraphDigest": "<digest, §4.2>",          // replaces deploymentGraphDigest
  "records": [ { "sourceId": ..., "bindings": [ /* §4.5 rows */ ],
                 "artifact": { /* ModuleArtifactV1, §4.6 producer identity */ },
                 "carrierIndex": <int>, "entryId": "..." } ],
  "carriers": [ { "manifestFile": "...", "bytesFile": "..." } ],
  "candidateTables": [ { "file": "...", "digest": "<digest>" } ],
  "hostBridgedInventory": [ /* 0413.001 §2.5 rows, package-root-committed */ ]
}
```

Deliberate deltas from V2: **no `entry` field** — entry facts live only
in the composition's entry plan (0413.001 §3.1 item 7), so a package is
a pure content set and the same app package serves `["app"]` and
`["app","agent"]` byte-identically; **no generation field** — package
bytes are generation-free by design (content addressing); generation is
attested in the envelope (§4.8); **`role` is present** — the package
names the one role it was produced for, and step 3 refuses a package
served under a different role; **candidate tables are the
generation-free v2** (r4 — codex round 2, converging with a blind grok
verification request: the landed `ComputedCandidateTableV1` serializes
a `generation` field (`computed_candidates.rs:43-50`), validated
non-zero and compared against the execution generation at link
(`runner_pipeline.rs:1143-1148`) — keeping it verbatim would smuggle a
serialized generation into "generation-free" package bytes, breaking
both the §2.1 identity guarantee and §4.8's one-carrier pin. The
composition lane requires the candidate-table successor row — an O-1
schema row, `ibex/computed-candidates/2` — which is v1 **minus the
`generation` field**; everything else carries over. A v1 table inside
a composition package is an unsupported schema, #12
`ibex:prepared-commitment-schema`. The landed single-publication lane
keeps v1 byte-for-byte. Dispatch and order (r5): the composition lane
inspects the candidate-table **schema identifier first** — a v1
identifier refuses as #12 before any v2 `deny_unknown_fields` decode
(so a v1 table can never misreport as #14) — and the index-committed
candidate-table **digest authenticates the generation-free wire form
before** any generation-stamped in-memory execution representation is
constructed. Incorporated tables then receive the envelope-attested
composition generation in memory (§4.8), so the landed link-time
generation-uniformity check passes by construction); **the host-bridged inventory is in the
index** — §2.5 requires it package-root-committed, its `reason` values
drawn from the closed two-member enum with the locality rule (derivable
from this package's own graph facts, never referencing the other
package). **Per-package root-principal invariant (normative):** each
package's derived principal set must include the root principal (the
landed builtin-attribution requirement, `runner_pipeline.rs:3626-3630`,
applied per package); a package without one refuses
(`ibex:prepared-commitment-schema`).

**Package-scope reason semantics (r3 pin — blessing the exact-b7
dark-lane mapping at `prepared-composition-producer.ts` `bindEdge`):**
at package scope, `"target is not a bundle module"` means **"the
specifier does not resolve to a record this package publishes."** It
deliberately covers both an unresolvable specifier and a resolvable
target excluded by traversal or the served subset (a boot-core
traversal termination; an app-owned target outside the declared
external universe): under the locality rule the distinction is
**underivable** — telling the two apart requires the other package's
contents or whole-project resolver state, exactly the facts §2.5
forbids a reason to reference — so **no third enum member is minted**;
new members remain spec amendments. `"target excluded by lowering
fallback"` stays reserved for a producing path that actually applies a
lowering fallback (none in the v1 composition producer). The step-6
#30 recomputation applies the same package-scope rule: reasons
recompute from the owning package's own graph facts only, and any
reason value outside the two members, or any divergence from the
committed rows, is `boundary-inventory-mismatch`. Two clarifications
(r4, grok round 2): these reasons apply to **unbound literal-dynamic
inventory rows only** — never to typed external references, whose
legality is owned by §4.5 and steps 5–6; and the locality rule is also
an identity-guarantee fact — a third member distinguishing by the
other package's facts would make app inventory bytes change when
`agent` joins, breaking §2.1.

The **package root** is `digest(ibex:prepared-package-root:1,
index_bytes)` — the value the composition's ordered
`(role, packageRoot)` pairs commit.

### 4.4 Carrier manifest v3 — `ibex/module-carrier/3`

*Provisional pending O-1.* `PreparedModuleCarrierV2` with exactly one
field change: `deploymentGraphDigest` → `packageGraphDigest` (§4.2).
Everything else — `encoding` (`javascript-factory-table` |
`hermes-bytecode` with engine binding + bytecode version),
`carrierDigest` over the bytes (domain `ibex/module-carrier-bytes/1`
unchanged), `definingPrincipal`, `producerId`, `producerBinaryDigest`,
ordered unique `entries` with per-entry `ModuleSemanticsV1` +
`semanticDigest` — carries over, and
`AdmittedPreparedCarrierV2::decode_and_admit`'s check set
(`carrier.rs:245-345`) applies with the expectation's deployment digest
replaced by the expected package graph digest, **plus one new explicit
predicate** (codex round 1: the landed caller peeks the manifest's own
declared kind, `runner_pipeline.rs:3676-3685`, which makes
`carrier.rs:327` unreachable and lets a mislabeled carrier through to
native load): the **declared-encoding/byte-shape agreement check** — a
carrier declaring `javascript-factory-table` whose bytes begin with the
Hermes bytecode magic refuses (`ibex:encoding-incompatible`); a carrier
declaring `hermes-bytecode` whose bytes fail the HBC header parse
refuses (`ibex:bytecode-preflight`). The role is deliberately **not** in
the carrier manifest: carriers are bound by the index, the index by the
committed `(role, packageRoot)` pair — one authority per fact.

### 4.5 Binding rows — a tagged target

*Provisional pending O-1.* `PreparedGraphBindingV1`
(`runner_pipeline.rs:246-250`) evolves into a row whose target is a
**tagged enum** (codex round 1 — no optional-field ambiguity, no
omitted-vs-null question):

```jsonc
{ "specifier": "...", "resolutionKind": ...,
  "target": { "kind": "local",    "sourceId": <SourceId> } }
{ "specifier": "...", "resolutionKind": ...,
  "target": { "kind": "external", "role": "app", "sourceId": <SourceId> } }
```

Rules, enforced at steps 5–6: `external` accepts the single role `"app"`
in v1; an `external` row is legal **only in the agent package**; its
target is exempt from local target-presence and resolves at union
closure against app-owned records **by `SourceId` only** (never by
digest — §4.1's purity theorem); a `local` row must resolve inside the
owning package. An `external` row in the app package, an unknown
external role, or an undeclared cross-package resolution is a step-5
refusal (`local-agreement-disagreement`), except the declared
`app → agent` static edge which is always `app-references-agent` (the
0413.001 step-5 precedence rule).

### 4.6 Artifact producer identity — `prepared-package`

*Provisional pending O-1.* `ProducerIdentityV1` (`artifact.rs:265-275`)
gains a third variant:

```rust
PreparedPackage {
    producer_id: NonEmptyString,
    producer_binary_digest: Digest,
    package_graph_digest: Digest,   // replaces deployment_graph_digest
}
```

with serde kind `prepared-package`. The artifact schema string stays
`ibex/module-artifact/1` (the variant is additive; an older ibex refuses
it at decode — fail-closed, acceptable pre-1.0). Mixing is refused: in a
package-aware admission every record must carry `prepared-package`; a
`prepared` or `in-process` identity inside a package is a step-3 refusal
(`ibex:prepared-commitment-schema`). `ArtifactAdmissionV1` gains the
matching `DigestBoundPreparedPackage` expectation — the
`DigestBoundPrepared` field set (`artifact.rs:296-308`) with
`deployment_graph_digest` replaced by `package_graph_digest`; the check
set in `verify_for_admission` carries over unchanged.

### 4.7 The committed alias table (verification inputs)

The alias table is composition-committed (0413.001 §2.2, §3.1 item 6):
per row `aliasId`, representative `SourceId`, the representative's
`sourceIntegrity` digest, and an import-site inventory digest.
**Namespace disjointness (normative, grok round 1):** the committed
`aliasId` set must be disjoint from the union of owned record
`SourceId`s; a collision refuses (`alias-conflict`) — otherwise
owned-record vs alias resolution is ambiguous. Alias verification is
**composition-wide** over the union of admitted records (the
representative may live in either package; its owning package is the one
whose partition owns the row's representative `SourceId`), and runs at
step 3 after both packages admit, before the step-4 partition
recomputation. The ibex half verifies: the representative exists in its
owning package, its admitted artifact's `semantics.source_integrity`
equals the committed row's, and the import-site inventory digest
recomputes over the served packages' committed facts naming the alias
— every packed record's declared binding rows **plus the package's
committed host-bridged inventory rows** (r4: the landed collection
basis, `collectAliasImportSites` at Exact `@a049ed9aa`, draws from
exactly these two committed surfaces, so producer and verifier compute
over the same universe by construction) —
under the O-3 algorithm the O-1 package fixes. **(Amendment A2 —
phantom-input correction):** the r5 text additionally named
`resolverInventoryDigest` (§3.3) as "the explicit verifier input" to
this verification, but the pinned O-3 preimage (O-1 `preimages.json`)
computes the import-site inventory digest solely over the committed
`{importer, specifier}` rows and defines no operation consuming that
field; the claim is DELETED rather than wired in. Rationale: the
preimage bytes are pinned cross-repo (the 21-vector corpus, its TS
half, and the `prepared-composition-schema-parity` corpus legs), the
field is mandatory in the landed §3.3 authority schema so it stays on
the wire, and inventing a comparison target would be new normative
surface. `resolverInventoryDigest` is therefore RESERVED: v1 admission
performs no comparison with it; its consumption arrives with the
O-4/armed real-policy work.
Divergence is `alias-conflict`. At resolution time (steps 6–8 and
runtime dynamic-import lookups through the composition session, §7.5), a
target id owned by no package that appears as an `aliasId` resolves
through the table to its representative **before** ownership and
no-third-state checks; the real computed bootstrap alias reaching its
admitted record is fixture row 9.

### 4.8 Generation attestation (envelope-side, decidable splice)

Package bytes carry no generation (§4.3), so the r1 draft's "one
generation across the composition" was undecidable (codex round 1). The
envelope's ordered package pairs therefore carry a **per-role
attestation**: `(role, packageRoot, producerGeneration)`, committed
under the composition root next to the composition's single generation
and producer identity (0413.001 §3.1 items 2 and 8). Decidable step-3
predicates: every attestation's `producerGeneration` equals the
composition generation, and every package index's **full producer
identity** — the `(producerId, producerBinaryDigest)` pair (§4.3;
r4: r7 §3.1 item 2 requires identity equality, and the shared row #22
already says "producer identity"; a digest-only comparison
under-delivered the row) — equals the envelope's producer identity;
disagreement is `generation-splice`. The per-record `prepared-package`
identities (§4.6) carry the same pair and are checked against the
index by the landed artifact admission; an index-vs-record
disagreement is package-internal inconsistency (#14). This is producer-accountable attestation, not
independent proof (package bytes are deliberately generation-free);
independence comes from the freshness half — a whole composition
produced under a stale resolver generation refuses at 2b
(`composition-replayed`) regardless of what it attests.

**One canonical carrier (r3 pin — resolving the exact-b7 dark-lane
duplication):** the envelope attestation triple is the **only
serialized carrier** of a package's produce generation in the served
artifact set. No sidecar or delivery wrapper — e.g. a
`PreparedPackageDeliveryV1`-shaped struct carrying `produceGeneration`
beside package bytes, as the dark exact-side schema module sketched —
may be serialized, served, or consumed by admission: a wrapper-carried
generation sits outside every committed digest (the package root
covers index bytes only; the composition root covers the envelope), so
it would be an unauthenticated input to the step-3 splice check, and a
second serialized carrier of one fact is a drift-capable parity pair
(the defect class the r2 commitment slimming killed). A
producer-internal, in-memory struct ferrying the generation from
produce to envelope assembly is fine; nothing serialized, and the O-1
schema package must not define one.

**Resolved exact-side (r4):** the alignment wave at Exact `@a049ed9aa`
adopted exactly this — `PreparedPackageDeliveryV1` now carries **no
generation** (its doc comment names the envelope triple the one
carrier), the envelope carries the attestation triples, and the dark
admission mirror consumes `producerGeneration` from the envelope pairs
only. The sidecar alternative is dead. **How the attested generation
enters execution (r4, codex round 2):** admission constructs every
execution configuration — and stamps every incorporated
generation-free v2 candidate table (§4.3) — under the single
envelope-attested composition generation, in memory; the landed
link-time generation-uniformity checks then pass by construction, and
no serialized generation exists below the envelope.

## 5. The nine steps — the ibex half

The driver is `admit_prepared_composition_v1` in a new
`src/module_loader/composition.rs`, reusing the landed per-publication
internals rather than duplicating them: the per-package core of step 3
is `admit_package_v1`, extracted by refactor from
`admit_committed_publication_v1` (`runner_pipeline.rs:3532`), returning
a typed `AdmittedPackageV1` capability (not raw `SourceGraphRecordV1`
internals — codex round 1), with the commitment-facet expectations
parameterized and the composition-only additions (encoding sniff, HBC
preflight placement, package-graph binding) **behind parameters so the
landed single-publication entries are byte-for-byte unaffected** (grok
D3; pinned by the existing tests before the refactor).

Steps 1–8 are admission — any failure produces a total `refused` report
(§8) and return code 1; nothing after step 8 refuses. **Predicate order
is the §6.2 registry ordinal order — the table IS the evaluation order**;
the precedence tuple for multi-fault outcomes is
`(step, ordinal, roleOrder)` with `app` before `agent`. Every step has
exactly one default code (0413.001 §4.1 totality clause, r6 defaults
verbatim); the r1 draft's second step-3 catch-all is deleted — every
*known* class maps to a specific row (§6.4), and only a genuinely
novel failure takes the step default.

**Step 0 (channel precheck, outside the registry):** armed-context
exclusion; parse the host-held commitment (§3.2) and the expectations
(§3.3) — strict JSON, canonical JCS, schema, `workflow == "production"`.
Failures use the `IBEX_DEV_COMPOSITION_*` channel tokens and the §8
`channel-error` report variant. Only an authentic channel presentation
starts the nine steps.

1. **Bounded canonical decode of the envelope.** Read
   `composition.json` under the bounded-file discipline; strict JSON;
   byte-exact canonical JCS; decode `PreparedCompositionV1` with
   `deny_unknown_fields`; enforce the §3.1 envelope-surface bounds. Any
   failure ⇒ `envelope-malformed` (#1), with the §8 sentinel shape.
2. **Commitment, freshness, live state.**
   **2a (integrity, no verifier state):**
   `digest(ibex:prepared-composition-root:1, envelope_bytes)` equals the
   commitment's `compositionRootDigest`; the envelope is internally
   consistent (entry-plan cardinality equals declaration cardinality;
   `(role, packageRoot, producerGeneration)` pairs ordered and
   role-consistent with the declaration). Failure ⇒
   `composition-commitment-mismatch` (#2) — also where role swaps and
   alias-table tamper land (they change envelope bytes).
   **2b (against the expectations, in ordinal order):** session nonce,
   expiry (vs `nowUnixMs`), authority generation, resolver generation
   each equal/valid ⇒ else `composition-replayed` (#3; authority
   generation folded here is an r6 clarification — item 8 makes it
   mandatory without naming its code); policy digest equal ⇒ else
   `composition-policy-stale` (#4); envelope target/engine/encoding
   facts match `expectedTarget` and the runtime-queried engine profile ⇒
   else `ibex:target-profile-mismatch` (#5); declaration role-set
   validity (#6 `composition-unknown-role`, #7
   `composition-duplicate-role`); served package directories vs
   declaration (#8 `composition-package-extra`, #9
   `composition-package-missing`); declaration equals `expectedRoles`
   (#10 `composition-mismatch`, also 2b's default).
3. **Per-package admission** (`admit_package_v1`, app then agent), in
   ordinal order #11–#23 (r5 — the r2–r4 "#11–#24" was a citation
   slip: #24 opens step 4). **Ordinal-outer across packages (r4, grok
   round 2):** the precedence tuple is authoritative — a conforming
   driver must not let one package's later-ordinal failure suppress the
   other package's earlier-ordinal predicate (full-app-then-full-agent
   short-circuiting would report `(3, #12, app)` over `(3, #11,
   agent)`). Either evaluate ordinal-outer (#11 for both packages, then
   #12 for both, ...) or complete the step's predicate sweep over both
   packages and select the lowest `(step, ordinal, roleOrder)` tuple;
   fixture 38's property generator asserts the result either way.
   Per package: bounded read of `index.json`;
   `digest(ibex:prepared-package-root:1, index_bytes)` equals the
   committed package root ⇒ else `package-root-mismatch` (#11); schema,
   role, producer-identity-variant, and root-principal checks (#12
   `ibex:prepared-commitment-schema`); file inventory with the
   `activation/` carve-out (#13 `ibex:package-inventory`); structural
   decode and internal consistency — canonicality, package-surface
   bounds, filename safety, candidate-table digests, absent/unreferenced
   carriers, repeated bindings, record identity vs artifact, facet
   derivation (#14 `ibex:prepared-commitment-corrupt`); per-carrier
   admission via `decode_and_admit` against v3 expectations — byte
   digest and binding tamper (#15 `carrier-integrity`),
   defining-principal grouping (#16 `ibex:principal-grouping` —
   admission sites `carrier.rs:281`/`307` plus the composition grouping
   recomputation; classed producer-defect because grouping is
   producer-computed — #15 wins by ordinal exactly when byte/digest
   tamper is present; #16 is reached when grouping is violated with
   digests intact, whether that state is the producer's own output or
   crafted upstream of signing (r5 wording; the P class reads the
   honest-origin case, precedence needs no origin judgment)),
   declared-encoding/byte-shape agreement (#17
   `ibex:encoding-incompatible`, the §4.4 sniff), engine identity (#18
   `ibex:engine-unavailable`, #19 `ibex:engine-binding-mismatch`),
   HBC header parse + engine preflight of every admitted hermes-bytecode
   carrier (#20 `ibex:bytecode-preflight` — `preflight_hermes_bytecode`
   runs here on the composition lane only, with diagnostic detail
   distinguishing header-parse from engine rejection); per-record
   artifact admission via `DigestBoundPreparedPackage` — package-graph
   membership and binding disagreement (#21
   `ibex:package-graph-binding`: manifest or artifact
   `packageGraphDigest` ≠ the index's; a carrier entry or record
   semantic digest outside the package's derived authorized set).
   Composition-wide, after both packages: generation/producer
   attestation (#22 `generation-splice`, §4.8); alias verification
   (#23 `alias-conflict`, §4.7 — evidence divergence and aliasId
   collisions). Step default: `package-root-mismatch`.
4. **Partition recomputation** (#24–#26). Recompute the partition over
   the union of admitted record `SourceId`s under
   `ibex:prepared-partition:1`; byte-compare with the committed summary
   ⇒ else `partition-mismatch` (#24); a repeated `SourceId` within one
   package ⇒ `ibex:duplicate-source-id` (#25 — the landed
   `runner_pipeline.rs:3825` predicate, relocated and given its own
   token); the same `SourceId` owned by both packages ⇒
   `package-overlap` (#26). Default: `partition-mismatch`.
5. **Per-package local agreement (no third state)** (#27–#28). Every
   binding row of every record is exactly one of: a `local` binding
   (target owned by this package and present), an `external` reference
   (§4.5, agent package only), or a refusal — a declared `app → agent`
   edge is always `app-references-agent` (#27, precedence); every other
   miss is `local-agreement-disagreement` (#28, also the default).
6. **Union closure and recomputation** (#29–#34). Recompute the union
   binding table under `ibex:prepared-union-table:1` and byte-compare ⇒
   else `union-table-mismatch` (#29, default); recompute each package's
   host-bridged inventory under `ibex:prepared-boundary-inventory:1`
   (locality rule included) ⇒ else `boundary-inventory-mismatch` (#30);
   resolve every external reference to a present record of the named
   owner ⇒ `external-target-absent` (#31) / `external-owner-mismatch`
   (#32); resolve imported names through the union plan's
   star-export-resolved namespace machinery (`graph.rs` export
   resolution — never raw descriptor presence) ⇒ else
   `export-disagreement` (#33); run the **defining-principal
   authorization** over the union closure's authorized-linker plan
   (§10) ⇒ denial is `cross-principal-denied` (#34). **Typed handoff
   (r4 — codex/grok convergent):** step 6's authorization run produces
   an `AuthorizedCompositionPlanV1` — the authorized union plan with
   its retained receipts over reachable operations and dynamic
   candidates, internal and external edges. Step 8 (§7.2) **consumes**
   that capability and makes no fresh policy decisions: every policy
   denial is decided here as #34, and a step-8 failure is mechanical
   linking (#38) — a policy denial surfacing at step 8 is a defect in
   this implementation, not an outcome.
7. **Entry-plan check (one code per predicate)** (#35–#37). Recompute
   the expected plan from the declaration and `expectedRoles` (order:
   `agent` before `app`; app descriptor `{root, action: "evaluate"}`;
   agent descriptor `{root, action: "evaluate-then-invoke", export:
   "installExactNativeAgentBootstrap"}`) and byte-compare under
   `ibex:prepared-entry-plan:1` ⇒ inequality — order, cardinality,
   actions — is `entry-plan-mismatch` (#35, default), **including the
   order-guarantee proof**: the app root must be absent from the agent
   descriptor's evaluation closure (recomputed from the union plan;
   otherwise step 9's invoke-before-app guarantee is unsatisfiable —
   codex round 1); a structurally invalid descriptor, an unknown
   action, a root not owned by its role's package (a delta from r6's
   "wrong roots under mismatch" phrasing: with no-entry packages,
   root-ownership is the implementable form), or an agent entry whose
   **resolved namespace plan** lacks the named export ⇒
   `entry-descriptor-invalid` (#36); a present well-formed root whose
   closure cannot produce a linkage order ⇒ `composition-root-unlinked`
   (#37).
8. **Atomic authorized multi-root link** (#38). Build one
   `SynchronousGraphPlan` over the union record set; compute the
   composition linkage and evaluation orders (§7); link every
   reachable record under one generation through the §7.2 constructor
   **consuming the step-6 `AuthorizedCompositionPlanV1`** (r5 — no
   fresh policy decision here; §7.2's consume-only rule). Any failure ⇒ `link-failure` (#38, the
   step's only and default code). The §5.4 fallback boundary closes
   here.
9. **Evaluation per descriptor (post-admission)** — the monotonic
   descriptor executor (§7.4): run the agent root's evaluation segment;
   invoke the agent entry's `installExactNativeAgentBootstrap` export
   synchronously through the engine primitive (§7.3) — the invocation
   must return without throwing before any app-entry evaluation begins
   (the landed `native-startup-bootstrap.template.js` order); then run
   the app root's remaining segment (records already evaluated under the
   agent segment evaluate once and are skipped — ESM once-only
   semantics; the app ROOT itself is proven absent from the agent
   closure at step 7). A step-9 throw, a non-callable export object, or
   an engine invoke failure is a **startup error on the admitted lane**
   (return code 2, the landed `DuringEvaluation` phase) with the §8
   `admitted-startup-error` report; it never reopens the fallback.

**Per-package status transitions** (implemented here, reported in §8),
restating 0413.001 §5's single rule: a package is `verified` iff every
step up to the failing step (or step 8 on admission) completed for it;
`refused` iff it is the package a step-≤5 refusal names; `not-checked`
otherwise — including every package of a step-1/2a failure.

## 6. The authoritative refusal enumeration (O-2)

This section is the **authoritative token enumeration the O-2 parity
check consumes** (the 0413.001 track owner's coordination rule): §6.1
enumerates the landed reality, §6.2 is the replacement registry —
**adopted verbatim by Exact LLP 0413.001 r7 / Amendment A1
(`@246f959cc`)**, with the 38 rows and the defaults paragraph
byte-identical across the two documents (verified at r3 and re-verified
at r4) — §6.3 fixes the parity mechanics, §6.4 the covering map.
**O-2's one current status (r4, single normative meaning):** discharged
at the **document level** by the A1 adoption, exactly as the Exact side
records; the generated-registry byte-match (§6.3) and the F-i
reachability fixtures (§9.2) are **implementation-leg gates**, not
acceptance conditions. The live exact-side parity check has already
caught the r6-shaped O-1 seed drifting from the A1 table (§9.1) —
the gate works.

### 6.1 The landed token enumeration (at `94c85abab`)

The complete typed refusal-token set on the
`admit_committed_publication_v1` path and its wrappers — grok's round-4
finding on 0413.001 stands confirmed: the r5/r6 placeholder names were
**not** these identifiers. (Codex round 1 verified this table complete
for literal tokens.)

| Landed token | Sites | Predicates |
| --- | --- | --- |
| `IBEX_PREPARED_COMMITMENT_CORRUPT` | 18 (`runner_pipeline.rs` 3261, 3271, 3283, 3288, 3350, 3547, 3549, 3552, 3559, 3564, 3598, 3612, 3621, 3634, 3649, 3728, 3749, 3825) | bounded-file violations (non-regular, reparse point, over-limit, changed-while-retained); unsafe/repeated filename; index not UTF-8 / not strict JSON / not canonical JCS / wrong shape; empty graph; activation root not a real directory; duplicate candidate digest; candidate digest mismatch; record names absent carrier; unreferenced carrier; record identity ≠ artifact; repeated typed binding; repeated `SourceId` |
| `IBEX_PREPARED_COMMITMENT_SCHEMA` | 3561, 3792 | unsupported index schema; synthetic prepared records |
| `IBEX_PREPARED_COMMITMENT_MISMATCH` | 3556 | publication root ≠ commitment |
| `IBEX_PREPARED_COMMITMENT_ENTRY` | 3567 | prepared entry ≠ commitment |
| `IBEX_PREPARED_COMMITMENT_DEPLOYMENT` | 3570 | deployment graph ≠ commitment |
| `IBEX_PREPARED_COMMITMENT_PRODUCER` | 3573 | producer binary ≠ commitment |
| `IBEX_PREPARED_COMMITMENT_SEMANTICS` | 3581 | semantic-inventory digest ≠ commitment |
| `IBEX_PREPARED_COMMITMENT_PRINCIPALS` | 3584, 3645 | principal-set digest ≠ commitment; carrier crosses defining principals |
| `IBEX_PREPARED_COMMITMENT_INVENTORY` | 3605 | publication file inventory ≠ index |
| `IBEX_PREPARED_ENGINE_UNAVAILABLE` | 3689 | hermes-bytecode carrier with no loaded-engine identity |
| `IBEX_PREPARED_COMMITMENT_MISSING` / `_AUTHORITY` | 3443, 3446 | production armed wrapper only |
| `IBEX_DEV_COMMITTED_ARMED_CONTEXT` / `_CORRUPT` / `_SCHEMA` / `_TARGET` | 5996, 6305/6308/6312, 6314/6318, 6324 | dev channel precheck |

**Untokenized refusal classes on the same path** (prose `bail!`/`anyhow!`
only — no stable identifier today). From the core and its callees:
carrier admission (`AdmittedPreparedCarrierV2::decode_and_admit` and
`validate`, `carrier.rs:245-345` — canonicality, schema, byte digest,
entry ordering/uniqueness, stale entry semantic digest, principal
crossing/authorization at `carrier.rs:281`/`307` (the `carrier.rs:170`
site is the **producer-side constructor**, not admission — codex round
1), producer/deployment staleness, deployment-set membership,
`"source carrier admission must not claim a bytecode engine"` (327 —
**unreachable through the landed caller**, which selects the engine
expectation from the manifest's own declared kind,
`runner_pipeline.rs:3676-3685`; hence §4.4's new sniff predicate),
`"prepared Hermes carrier targets a different engine"` (339)); the HBC
header parse (`carrier.rs:51-63`) and engine preflight
(`module_runner.rs:459-469`); artifact admission
(`verify_for_admission`, `artifact.rs:461-623` — canonicality, schema,
producer/deployment staleness, semantic-digest membership,
carrier/entry binding, `SourceId`/integrity disagreement,
`"artifact transform fingerprint is stale"` (571 — **tautological under
the dev posture**: the expectation derives from the artifact's own
fingerprint, `runner_pipeline.rs:3765`; see the #dropped disposition
below)); and — codex round 1's completeness catch — the further
untyped anyhow-class sites: file open/metadata/read errors
(`runner_pipeline.rs:3255-3258`), commitment-facet construction and the
missing-root-principal error (3309-3330, 3626-3630), directory
enumeration I/O (3589-3603), candidate-table decode
(`ComputedCandidateTableV1::decode_canonical`, 3619), missing carrier
entries and display conversion (3752-3755, 3777-3794), and the dev
wrapper's plan/config/runtime construction (6091-6194). The
package-aware implementation MUST route every one of these classes to
its §6.4 disposition; a prose-only refusal reaching the composition
report is non-conformant, and a genuinely novel failure inside a step
takes that step's single default.

The production-posture currency check
(`verify_current_transform_fingerprint_v1`, `producer_spike.rs:131`)
**does not run** under the dev posture — the only v1 posture.

### 6.2 The replacement registry (adopted by 0413.001 §4.1 as Amendment A1, `@246f959cc`)

The full ordinalized table. The ordinal order IS the within-step
predicate evaluation order (§5); precedence tuple
`(step, ordinal, roleOrder)`, `app` before `agent`. Classes:
A = attacker, P = producer-defect, E = environment.

| # | Code | Step | Class | Unique predicate |
| --- | --- | --- | --- | --- |
| 1 | `envelope-malformed` | 1 | A | envelope bounds/canonicality/shape only; sentinel receipt |
| 2 | `composition-commitment-mismatch` | 2 | A | envelope digest ≠ host-held commitment; envelope-internal inconsistency (role swap, alias-table tamper) |
| 3 | `composition-replayed` | 2 | A | nonce / expiry / authority-generation / resolver-generation vs expectations |
| 4 | `composition-policy-stale` | 2 | E | policy digest ≠ verifier-held |
| 5 | `ibex:target-profile-mismatch` | 2 | E | envelope target/engine/encoding facts ≠ expectations/runtime-queried profile |
| 6 | `composition-unknown-role` | 2 | A | declared role outside the closed set |
| 7 | `composition-duplicate-role` | 2 | A | repeated role in the declaration |
| 8 | `composition-package-extra` | 2 | P | served package dir with no declared role |
| 9 | `composition-package-missing` | 2 | P | declared role with no served package dir |
| 10 | `composition-mismatch` | 2 | P | declaration ≠ `expectedRoles` (2b default) |
| 11 | `package-root-mismatch` | 3 | A | package index digest ≠ committed `(role, packageRoot)` (step-3 default) |
| 12 | `ibex:prepared-commitment-schema` | 3 | P | unsupported index/carrier/artifact schema; wrong `role`; synthetic records; non-`prepared-package` identity; no root principal |
| 13 | `ibex:package-inventory` | 3 | A | package file inventory ≠ index (with the `activation/` carve-out) |
| 14 | `ibex:prepared-commitment-corrupt` | 3 | A | bounded-read/canonicality/structural decode/internal-consistency violations at package scope |
| 15 | `carrier-integrity` | 3 | A | carrier byte/digest/binding tamper (bytes ≠ carrierDigest; entry semantic digest stale; record's expected carrier digest ≠ admitted) |
| 16 | `ibex:principal-grouping` | 3 | P | carrier or entry crosses / is unauthorized for its defining principal |
| 17 | `ibex:encoding-incompatible` | 3 | P | declared encoding kind disagrees with byte shape (§4.4 sniff) |
| 18 | `ibex:engine-unavailable` | 3 | E | HBC carrier with no runtime-queried engine identity |
| 19 | `ibex:engine-binding-mismatch` | 3 | E | HBC carrier engine binding / bytecode version ≠ loaded engine |
| 20 | `ibex:bytecode-preflight` | 3 | E | HBC header parse failure; engine preflight rejection |
| 21 | `ibex:package-graph-binding` | 3 | A | manifest/artifact `packageGraphDigest` ≠ index's; semantic digest outside the package's derived set |
| 22 | `generation-splice` | 3 | P | attestation generation ≠ composition generation; package producer identity ≠ envelope's (§4.8) |
| 23 | `alias-conflict` | 3 | P | alias evidence divergence; aliasId ∩ owned SourceIds ≠ ∅ |
| 24 | `partition-mismatch` | 4 | P | recomputed partition ≠ committed (step-4 default) |
| 25 | `ibex:duplicate-source-id` | 4 | P | repeated `SourceId` within one package |
| 26 | `package-overlap` | 4 | P | one `SourceId` owned by both packages |
| 27 | `app-references-agent` | 5 | P | declared `app → agent` edge (precedence over #28) |
| 28 | `local-agreement-disagreement` | 5 | P | every other no-third-state miss (step-5 default) |
| 29 | `union-table-mismatch` | 6 | P | recomputed union table ≠ committed (step-6 default) |
| 30 | `boundary-inventory-mismatch` | 6 | A | recomputed host-bridged inventory ≠ committed; locality violation |
| 31 | `external-target-absent` | 6 | P | external reference target not present in the named owner |
| 32 | `external-owner-mismatch` | 6 | P | external reference target owned by a different package |
| 33 | `export-disagreement` | 6 | P | resolved-namespace export resolution failure |
| 34 | `cross-principal-denied` | 6 | A | defining-principal authorization denial on the authorized-linker plan (§10) |
| 35 | `entry-plan-mismatch` | 7 | P | recomputed expected plan ≠ committed (order/cardinality/actions; order-guarantee proof) (step-7 default) |
| 36 | `entry-descriptor-invalid` | 7 | P | malformed descriptor; unknown action; root not owned by its role's package; named export absent from the resolved namespace plan |
| 37 | `composition-root-unlinked` | 7 | P | well-formed root with no linkage order |
| 38 | `link-failure` | 8 | E | authorized multi-root link failure (step-8 default) |

**Defaults (one per step, r6's verbatim where a step existed):** 1→#1,
2a→#2, 2b→#10, 3→#11, 4→#24, 5→#28, 6→#29, 7→#35, 8→#38. Producing a
default where a specific row applies is non-conformant; the defaults
exist so no failure can escape the registry.

**Row-byte section references are 0056-relative wherever the table is
read:** the lockstep rule shares row bytes verbatim, so the `§4.4`,
`§4.8`, and `§10` strings inside row predicates (#17, #22, #34) refer
to this document's sections even when the table is read in 0413.001
§4.1 — never to the Exact document's own §4.4/§4.8/§10. This
declaration lives here; the Exact half does not yet carry the sibling
note, and adding one **outside the shared row bytes** is a named
handoff to the exact-side alignment lane (r4 — codex/grok convergent;
until it lands, only this document declares the scope).

**Amendment deltas vs r6 §4.1 (explicit — none of this is a silent O-2
substitution):**

- **D1:** the six placeholder rows (#14–18, #20 in r6 numbering) are
  replaced by **eleven** imported rows (#5, 12, 13, 14, 16, 17, 18, 19,
  20, 21, 25 above); the landed reality does not compress to six without
  burying attacker-relevant distinctions.
- **D2:** `ibex:engine-binary-digest-mismatch` (r6 #15) was never a
  landed identifier; its intent splits into `ibex:engine-unavailable`
  (#18, the landed typed token) and `ibex:engine-binding-mismatch`
  (#19, the landed prose class at `carrier.rs:339`).
- **D3 (dropped row):** `ibex:compiler-fingerprint-mismatch` (r6 #18)
  is **unreachable in the only v1 posture** — the dev path's
  fingerprint expectation derives from the artifact's own fingerprint
  (`runner_pipeline.rs:3765`; the artifact is index-committed, so
  tamper is #11/#21), and the independent currency check is
  posture-skipped (`runner_pipeline.rs:3734-3738`). O-6 forbids rows
  without reachability fixtures; the row returns with the armed posture
  / LLP 0043 amendment.
- **D4:** `ibex:target-profile-mismatch` moves from r6's step 3 to
  step 2 ordinal #5 — target/engine facts are envelope-vs-expectation
  comparisons and belong to authentication-first 2b. Multi-fault
  consequence: wrong-target + tampered package is now
  `(2, ibex:target-profile-mismatch)` rather than r6's
  `(3, package-root-mismatch)`.
- **D5:** step-3 within-step order is re-sequenced to the verification
  dependency order above (r6's placeholder-era order — integrity,
  splice, alias, then imports — cannot be a predicate order: carrier
  checks require a decoded index).
- **D6:** `generation-splice` widens to the §4.8
  attestation/producer-identity invariant (subsumes the landed
  `_PRODUCER` facet check).
- **D7:** class changes: `ibex:encoding-incompatible` environment → P
  (a producer mislabel, not an environment fact).
- **D8:** the r6 §7 fixture-35 erratum (missing-export listed under
  `entry-plan-mismatch`, contradicting r6's own step-7 split) is
  corrected: 35a recompute-inequality → #35, 35b missing-export /
  unknown-action / malformed → #36 (§9.2).
- **D9:** ordinals are renumbered 1–38 as above; r6 #33 `link-failure`
  becomes #38.

### 6.3 Registry mechanics (parity, generated halves)

One registry authority: 0413.001 §4.1 as amended by §6.2, generated
exact-side as
`packages/exact-devtools/src/prepared-composition-refusals.generated.json`.
The ibex half: the `CompositionRefusalCode` enum in `composition.rs` is
**generated from** a vendored pinned copy of that registry at
`tests/fixtures/prepared-composition/v1/refusals.generated.json` (never
hand-maintained in parallel — codex round 1), carrying
`as_str()`/`step()`/`ordinal()`/`class()` projections; a unit test
asserts generated-enum ↔ vendored-file byte parity, and the vendored
file's digest is recorded in the fixture manifest so the exact-side
O-1/O-2 parity check (`prepared-composition-schema-parity`) asserts both
repos pin identical registry bytes. **This is the named gate
relationship: O-2 is discharged through that check, extended to the
imported rows, with §6.2 as the enumeration it consumes.** The driver
evaluates predicates in ordinal order so precedence is by construction.
No `_ =>` arm may produce anything outside the registry. **Arming note
(r4):** the exact-side check's lockstep leg — the §6.2-vs-§4.1
byte-comparison against the vendored ibex document — deliberately
reports itself **unarmed** while the Exact `vendor/ibex` submodule pin
predates this file, and arms automatically when the pointer advances
past `llp/0056` (verified in the landed check at Exact `@a049ed9aa`);
an "unarmed" report before the pointer bump is expected posture, not a
parity gap.

### 6.4 The covering map (total, injective, machine-checked)

Every landed refusal class from §6.1 maps to exactly one §6.2 row:

| Landed class | Registry row |
| --- | --- |
| `_CORRUPT` package-scope predicates (except repeated-`SourceId`); file open/metadata/read/enumeration I/O; candidate-table decode; carrier/artifact canonicality prose; facet-construction errors; missing-carrier-entry/display-conversion internal errors | #14 |
| `_CORRUPT` repeated-`SourceId` (3825) | #25 |
| `_SCHEMA` (3561, 3792); carrier/artifact schema prose; missing root principal (3626-3630) | #12 |
| `_MISMATCH` (3556) | #11 (per-package root replaces publication root) |
| `_ENTRY` (3567) | dissolved → #35/#36 (packages carry no entry) |
| `_DEPLOYMENT` (3570); carrier/artifact deployment-binding prose; deployment-set membership | #21 (package-graph binding) |
| `_PRODUCER` (3573) — the publication-level producer-vs-commitment check, whose successor is the index-vs-envelope identity comparison (§4.8) | #22 |
| carrier/artifact producer staleness prose — under the per-package model these compare a carrier/artifact identity against the expectation **derived from the authenticated index** (§4.6), so disagreement is package-internal inconsistency (r5 split — codex round 3: one failure class must have one disposition) | #14 |
| `_SEMANTICS` (3581); `_PRINCIPALS` digest half (3584) | dissolved — the package root covers the index; facets derive per package (#11/#14 on tamper) |
| `_PRINCIPALS` grouping half (3645); `carrier.rs:281`/`307` | #16 |
| `_INVENTORY` (3605) | #13 |
| `IBEX_PREPARED_ENGINE_UNAVAILABLE` (3689) | #18 |
| engine-binding prose (`carrier.rs:339`) | #19 |
| HBC header parse (`carrier.rs:51-63`); engine preflight (`module_runner.rs:459-469`) | #20 |
| encoding mislabel (landed 327 unreachable; the §4.4 sniff) | #17 |
| carrier byte/digest/entry-integrity prose (263, 268, 272; record carrier-digest binding) | #15 |
| fingerprint staleness (571) | dropped in v1 (D3) — tamper routes are #11/#21 |
| `_MISSING`/`_AUTHORITY` (3443/3446) | production-armed wrapper, deferred with that posture |
| `IBEX_DEV_COMMITTED_*` (5996, 6305-6324) | channel precheck → `IBEX_DEV_COMPOSITION_*` siblings, §8 `channel-error` (target's admission-time half is #5) |
| dev-wrapper plan/config/runtime construction (6091-6194) | step-8 #38 (link construction) or step-9 startup error, per phase |

This map lands as a **machine-checkable fixture**
(`tests/fixtures/prepared-composition/v1/covering-map.json`): rows keyed
by `(file, token-or-message-class)` — never line numbers, which move
under the extraction — mapping each class to its registry code; a test
greps the pinned sources for refusal sites and fails on any site absent
from the map (grok round 1's rot-proofing).

## 7. Authorized multi-root link planning and descriptor execution

### 7.1 `SynchronousGraphPlan` (graph.rs)

Two additions, generalizing the landed single-entry functions
(`linkage_order` `graph.rs:548`, `synchronous_evaluation_order`
`graph.rs:587`) without changing them:

- `linkage_order_for_roots(&[SourceId]) -> Result<Vec<SourceId>, GraphError>`
  — the deterministic dependency-first order over the union closure of
  an ordered root list (concatenated per-root DFS with cross-root
  dedup: a record links under the first root that reaches it).
- `synchronous_evaluation_order_for_roots(&[SourceId])` — same
  discipline for evaluation order, returning per-root **segments** so
  the descriptor executor knows where the agent segment ends and the
  invoke point sits.

Both take their root list in **entry-plan order** (`agent` before
`app`, §5 step 7) — that argument order is what makes a shared
app-owned record evaluate in the agent segment, once (fixture 1's
segment-order assertion; r4, grok round 2).

Both surface `GraphErrorCode::ModuleLink` / `RequireAsyncModule` exactly
as today; at step 7 a root that cannot produce an order maps to
`composition-root-unlinked`, and at step 8 a link-time `GraphError` maps
to `link-failure`. TLA remains refused on this synchronous lane.

### 7.2 The authorized composition linker (module_runner.rs)

**The authorized path, not the bypass** (r6 §3.3's authorized-linker
rule — the landed dev lane's `link_prepared` call at
`runner_pipeline.rs:6187` supplies empty authorization receipts and is
exactly the shortcut r6 forbids for compositions). One new constructor
generalizes `link_authorized_prepared` (`module_runner.rs:2937`):

```rust
pub fn link_authorized_prepared_composition(
    runtime, plan, root_plan: &CompositionRootPlan,
    configs, authorized: &AuthorizedCompositionPlanV1,   // step-6 output (§5)
    authority_contexts, prepared_entries,
) -> Result<Self>
```

It **consumes** the `AuthorizedCompositionPlanV1` step 6 produced —
the authorized union plan with retained receipts over reachable
operations and dynamic candidates, internal **and** external edges
(§10 defines the v1 policy; the authorization run itself happens at
step 6, where denial is #34) — and links every reachable record under
one generation — atomically: a failure while linking any record fails
the whole composition, no partially-linked graph is ever evaluated,
and no fresh policy decision is made here (r4 — codex/grok
convergent: without the typed handoff, a policy denial could
misreport as #38).
Landed invariants carry over: every reachable record needs a config;
generation uniformity (`module_runner.rs:3606-3608`); the sticky
outcome discipline with record-attributed errors
(`module_runner.rs:4012-4059`).

**Main root is named, not positional** (codex round 1: `link_inner`
uses its single `entry` both for generation selection,
`module_runner.rs:3589`, and `import.meta.main`,
`module_runner.rs:3984` — a naive ordered-roots generalization would
mark the agent as main): `CompositionRootPlan` carries
`mainRoot = the app root` explicitly; `import.meta.main` is true for
the app entry only; generation comes from the uniform config set.

### 7.3 The invoke primitive (the one new engine call)

Step 9's evaluate-then-invoke needs a primitive the engine does not have
at `94c85abab` — the graph-level namespace accessor
(`module_runner.rs:4065`) reaches native as a `JSON.stringify` of the
namespace (`hermes_module_runner.cc:4205`), which cannot preserve or
invoke function values; a **new native ABI call** is required (codex
round 1 confirms the seam: the length-aware export-property helper at
`hermes_module_runner.cc:197` is the suitable building block).

```rust
/// Invoke the named export of an evaluated record as a zero-argument
/// function, synchronously, on the runtime's owner thread. Returns after
/// the call returns; a JS throw, a missing binding at runtime, or a
/// non-callable value is an error. Never used before the record's
/// evaluation completes. Errors retain the structured sticky-error
/// conversion and the record identity.
pub fn invoke_named_export(&mut self, source_id: &SourceId, export: &str)
    -> Result<InvokeOutcomeV1>   // r5: { returned_thenable: bool } — the
                                 // explicit transport for §8's
                                 // agentInvokeReturnedThenable diagnostic
```

The **JS** return value is ignored (the landed bootstrap template's
`installExactNativeAgentBootstrap()` contract) apart from thenable
detection feeding `InvokeOutcomeV1`; "synchronous
completion" means **the function returned** — a returned thenable is
not awaited (template parity, stated honestly: setup a bootstrap
schedules asynchronously is app-visible but not guaranteed complete;
correctness-bearing agent readiness is 0413.001 OQ3 / Acto territory;
r4: when the invoke returns a thenable, the §8 report carries the
diagnostic `agentInvokeReturnedThenable: true` so a bootstrap
regressing to async setup is visible without failing step 9 — OQ-D's
strictness lever stays available).
Errors here are step-9 startup errors (return code 2), never admission
refusals: export **presence** was verified at step 7 against the
resolved namespace plan, but descriptors and namespace plans do not
carry types, so **callability is only decidable at runtime** — a
non-callable export is the admitted lane failing loudly, not a fallback
trigger.

### 7.4 The descriptor executor (monotonic, sticky)

The single sticky outcome of the landed `evaluate()` cannot represent
"agent segment succeeded, invoke pending, app segment pending" (codex
round 1). The composition graph owns a monotonic executor:

```
state: Pending -> AgentEvaluated -> AgentInvoked -> AppEvaluated (terminal ok)
                       |                 |               |
                       +---- failure (sticky terminal, record-attributed) ----+
```

Each transition runs at most once; a failure is sticky and re-reads
return the same structured error (the landed sticky discipline); the
executor is the only caller of `invoke_named_export` for descriptor
entries; segment timings feed the §8 report.

### 7.5 The retained composition session, aliases, and dynamic imports

On success the linked graph is retained for the process lifetime (the
landed leak-on-success rule) inside a **`CompositionSessionV1`** that
unifies what the r1 draft left unowned (codex round 1): the linked
multi-root graph, the admitted alias table, the admitted record set,
and the report. v1 dynamic-import semantics:

- **Literal dynamic imports within a package** keep the landed dev-lane
  behavior (candidate tables admitted and incorporated eagerly into the
  plan, as at `runner_pipeline.rs:6091`).
- **The computed bootstrap seam and every cross-package or undeclared
  literal edge stay host-bridged** (0413.001 §2.1/§2.4): never linked,
  never bound at admission (fixture 10). Post-admission, the host
  resolves a bridged request by asking the session's **alias-aware
  lookup** (`resolve_id(id) -> alias-table representative -> admitted
  record`), which is how the real computed bootstrap alias reaches the
  admitted agent entry (fixture 9).
- The session owns deferred-activation interplay: v1 does not enroll
  composition records in the deferred-dynamic machinery
  (`deferred_dynamic` stays default-empty exactly as the landed
  committed lane, `runner_pipeline.rs:3813`); enrolling it is a named
  future amendment, not an accident of generalization.

## 8. The report — tagged shapes, one per outcome

`ibex/dev-unarmed-composition-startup-report/1` (*provisional pending
O-1*), serialized to `out_report_json` on **every** outcome (the landed
entry writes a report only on success — `runner_pipeline.rs:6396-6410`;
the composition entry must hand the embedder a total receipt so the
Exact-side §5 report variants are a projection, never a
reconstruction). `admissionStatus` is the tag; exactly four variants:

| Variant | Return code | Present fields |
| --- | --- | --- |
| `channel-error` | 1 | `channelToken` (`IBEX_DEV_COMPOSITION_*`), detail; no registry fields; `packages: []`, declaration fields null-typed |
| `refused` | 1 | `failureStage` (1–8), `reasonCode` (§6.2 code), `packageRole` when a package is named, `packages[]` with per-package `verificationStatus` per the §5 transition rule; step-1 failures use the sentinel (`failureStage: 1`, `packages: []`, declaration fields null-typed) |
| `admitted` | 0 | no `failureStage`/`reasonCode`; `packages[]` all `verified`; timings incl. segment/invoke |
| `admitted-startup-error` | 2 | admission fields as `admitted` (`packages[]` all `verified`); `startupPhase` (`agent-evaluate` \| `agent-invoke` \| `app-evaluate`), structured error detail; **never** a registry `reasonCode` (the registry ends at step 8) |

Common fields on every variant: `schema`,
`compositionSchemaVersion: 1`, `authority: "dev-unarmed-dev-served
(non-production)"`, `posture`, `nonProduction: true`,
`fingerprintPosture`, `attribution`, and — when decoded —
`declaredRoles`, `compositionRootPrefix`, `entryPlan` echo,
`engineBindingDigestPrefix`, per-package rows `{role,
packageRootPrefix, recordCount, carrierCount, hbcCarrierCount,
javascriptCarrierCount, verificationStatus}`, timings
(`commitmentParseUs`, `admissionUs`, `graphLinkUs`, `agentEvaluateUs`,
`agentInvokeUs`, `appEvaluateUs`), and the OQ-C counts
(`agentEvaluatedRecordCount`, `appEvaluatedRecordCount`,
`sharedEvaluatedRecordCount` — counts only, no source identifiers;
0413.001 OQ2's lean), and — on the `admitted` /
`admitted-startup-error` variants — the `agentInvokeReturnedThenable`
diagnostic (§7.3). All counters are I-JSON safe integers. A report
serialization failure never converts an outcome (the landed rule:
surface through the error slot alongside the outcome's return code);
in that one case `out_report_json` is null and the error slot names
both the outcome and the serialization failure (§3.4; r4 — the ABI
comment and this rule now say the same thing).

The `unavailable-unserved` / `unavailable-unadmitted` variants of
0413.001 §5 are **producer/exact-host states that ibex never emits** —
the Exact host composes its total §5 receipt from this report or from
its own producer outcome; the Exact projection is a **defined subset**
of this report's fields (no Exact field may require information absent
here).

## 9. Conformance: the shared corpus and the ibex-side fixtures

### 9.1 The shared canonical-byte vector corpus (O-1) — coordination

The canonical home is the O-1 package at Exact
`docs/schemas/prepared-composition/v1/` (exact-side owned; seeded
`@9018e0bbd` status `dark`, **r7-aligned by the alignment wave at
`@a049ed9aa`** with the parity check green — r5: the "alignment in
flight" caveat is retired. Aligned and landed today: the envelope
with attestation triples, the §3.2 commitment and §3.3 expectations
channel records (with the §3.3-noted maximum-keyword gap), the
21-vector corpus. Still to land: the ibex-half rows — §4.3 package
index, §4.4 carrier v3, §4.5 binding rows, §4.6 identity, §4.2
preimage, candidate-table v2). It is the byte authority
for: the envelope, the commitment (§3.2), the expectations (§3.3), the
package index (§4.3), carrier v3 (§4.4), binding rows (§4.5), the
`prepared-package` producer identity (§4.6), the package-graph preimage
(§4.2), the attestation rows (§4.8), the alias import-site inventory
preimage (§4.7/O-3), the refusal registry (§6.3), and the report (§8).
**The ibex side consumes and extends that corpus — it never freezes a
competitor format**: the shared vectors (valid rows, limit and limit+1
rows at both §3.1 surfaces, canonicality-violation rows) are vendored at
`tests/fixtures/prepared-composition/v1/vectors/` with the corpus digest
pinned in the fixture manifest; a Rust conformance test derives
encode/decode/digest results for every vector and must be green; the
exact-side parity check asserts both repos pin the same corpus digest.
Until the parity check confirms the landed O-1 package is r7-shaped
(r4 — the seed itself has landed, § Summary), the not-yet-confirmed
field sketches here remain provisional — implementation leg 1 (§11)
starts only against the confirmed r7-shaped O-1 schemas. The §3.2/§3.3
records are already past that bar (their authority files landed
field-for-field at `@a049ed9aa`).

### 9.2 The ibex-side fixture rows

Of the 0413.001 §7 matrix, the rows that execute in this repo (as Rust
tests in `composition.rs`/`runner_pipeline.rs` test modules over crafted
compositions, mirroring the existing committed-admission test style):
**A:** 1 (plus the segment-order assertion: the shared app-owned lib
evaluates in the agent segment, once), 4, 5b, 6, 7, 8, 9, 10
(host-bridged never bound at admission); **B:** 12–19 (both directions
of 19 via `expectedRoles`; 18's limit/limit+1 rows at both bound
surfaces); **C:** 20–29 (freshness via the expectations input; tamper
via byte-mutation recipes); **D:** 30–34, **35a/35b** (the D8 split —
r6 §7 row 35 as written implements the erratum), 36–38 (38's
multi-fault by-`(step, ordinal, roleOrder)` assertion, plus a
property-based generator over random fault conjunctions asserting
lowest-tuple wins); **E:** 39 (the ibex report half — every refusal
row's `(failureStage, reasonCode)` and per-package transitions, plus
the four §8 tagged shapes; 40–42 are exact-side fail-loud rows); plus
**F-i1…F-i11** — one demonstrated-reachability fixture per §6.2
imported row (#5, 12, 13, 14, 16, 17, 18, 19, 20, 21, 25), each with a
mutation/re-signing recipe, satisfying O-2's gate and feeding O-6's
matrix-completeness assertion; plus the **v1-candidate-table row**
(r5): a v1 candidate table inside a composition package →
`(3, ibex:prepared-commitment-schema)`, exercising the §4.3
schema-identifier dispatch without a new imported row; plus the
**order-guarantee row**: a
crafted composition whose agent closure reaches the app root →
(7, `entry-plan-mismatch`). Producer-side rows (2, 3, 5a, 11, 43–45)
live exact-side; row 11's membership pin is consumed here only as the
fixture composition those tests admit.

## 10. Security posture (v1) — authorized linker, defining principals

The only v1 posture is dev-unarmed (0413.001 §3.3): the composition
entry is feature-gated like the landed embedder, refuses under an armed
Host at construction time, and names its authority in every receipt.

**The authorized linker is required** (r6 §3.3): compositions link
through §7.2's authorized constructor — never the `link_prepared`
bypass the landed single-publication dev lane uses. v1 defines a
**dev-unarmed `GraphImportPolicy`** for the composition lane; its
inputs are the admitted records' `definingPrincipal` fields, the
declaration, and the composition's committed facts. Its v1 rules:

- **Internal edges** (within a package): authorized under the same
  effective policy the landed lanes apply to those principals today —
  the dev-unarmed policy does not invent new denials for edges the
  single-publication lane accepts.
- **External references** (`agent → app`): structurally legal per §4.5
  and §5 steps 5–6 (those checks own role direction and ownership);
  **additionally** the policy decides each external edge crossing
  defining principals (origin record's `definingPrincipal` ≠ target's),
  and **the v1 dev-unarmed rule is DENY-ALL-CROSSING (Amendment A2)**:
  every such crossing refuses as #34 `cross-principal-denied` — no v1
  grant exists, and no channel or committed fact carries one. Equal
  defining principals never consult the policy (the authorizer's
  `importer != imported` gate), so external references between
  Root-principal records — the real boot-core-v1 shape — are unaffected.
  This is the defining-principal predicate that makes #34 reachable and
  meaningful (fixture F: an external reference crossing defining
  principals — no v1 grant exists — not a role-direction duplicate).
  The rule is deliberately fail-closed and monotonically relaxable: a
  real grant mechanism arrives with the O-4 real-policy / armed-posture
  work as a future amendment, never as an implementation choice.
  *(A2 provenance: the r5 text named the predicate and its inputs but
  no derivable grant relation — the implementation-exposed defect in
  `issues/closed/20260824-llp0056-s10-grant-authority-defect.md`; option 1 of
  that analysis was taken.)*

EXECUTION attribution on this lane still collapses to the root
principal exactly as landed (`runner_pipeline.rs:6119-6131` — no
compartment registry binds in the unarmed runtime); that is an
execution-attribution fact, orthogonal to admission-time
authorization, named in the receipt (`attribution`), and it retires
with the armed posture. The armed wrapper
(`load_prepared_graph_committed_v1`) and its `_MISSING`/`_AUTHORITY`
tokens are untouched until the production-armed amendment.

## 11. Implementation plan and acceptance coupling

1. **Schema leg** — lands only against the landed O-1 package (§9.1).
   *(r4: the r6-shape hold is released — the alignment wave at
   `@a049ed9aa` confirmed r7-shaped schemas with the parity check
   green. What leg 1 still waits for from O-1 is its **ibex-half
   rows**: the §4.3 package index, §4.4 carrier v3, §4.5 binding rows,
   §4.6 producer identity, the §4.2 preimage, and the §4.3
   generation-free candidate-table v2.)* Contents:
   `composition.rs` decode types + bounds + the generated
   `CompositionRefusalCode`; carrier v3 and `prepared-package` producer
   identity; `admit_package_v1` extracted from
   `admit_committed_publication_v1` returning `AdmittedPackageV1`
   (landed single-publication behavior pinned by existing tests before
   the refactor; composition-only checks behind parameters). Vendored
   corpus + registry + covering-map fixtures green before any admission
   logic exists. **The leg-1 differential target (r4):** the landed
   21-vector canonical-byte corpus (O-1 `vectors/`, TS half green at
   `@a049ed9aa`) — the Rust conformance test derives encode / decode /
   digest results for every vector and must match byte-for-byte, the
   §9.1 gate's Rust half.
2. **Admission leg** — steps 0–7 with fixture groups B/C, the F-i
   reachability rows, and the covering-map test; the `refused` and
   `channel-error` report variants.
3. **Link/evaluate leg** — graph.rs multi-root segments, the authorized
   composition linker, the descriptor executor, `invoke_named_export`
   (new native ABI), the composition session, the C-ABI entry, fixture
   groups A/D/E-39; the `admitted` / `admitted-startup-error` variants.
4. **Exact fold** — the §6.2 amendment adopted into 0413.001 §4.1
   (including the D8 fixture-35 erratum), the parity check extended to
   the imported rows, Exact's host on the new entry. *(The amendment
   half landed as A1 `@246f959cc`; the parity-extension and host
   halves follow the implementation legs.)*

**Acceptance coupling (normative, r4 — one current meaning):** the
acceptance peer blocker was the 0413.001 §4.1 amendment adopting §6.2;
it is **resolved** — Amendment A1 (`@246f959cc`) adopts §6.2 verbatim
and the doc-level tables are byte-verified identical (§6). Nothing
further blocks this spec's acceptance cross-repo. The generated-halves
parity pin and the F-i reachability fixtures are implementation-leg
gates (§6.3, §9.2), deliberately NOT acceptance conditions — coupling
`Accepted` to a generated implementation artifact that 0413.001 itself
did not wait for would invert the dependency. Each leg is landable
alone; nothing admits for real until leg 3, which is the moment
0413.001's "no composition admits until the ibex leg lands" flips.

## 12. Open questions

- **OQ-A:** should the package index inline artifacts (the landed V2
  shape, kept in §4.3) or reference them by digest into carrier
  manifests only? Inline keeps the landed admission flow and one
  bounded read; a split index would shrink the 64 MiB pressure for very
  large apps. v1 keeps inline; revisit if a real app package index
  approaches its bound.
- **OQ-B:** `invoke_named_export`'s native call shape — a dedicated
  `ex_hermes_module_invoke_export` beside the existing export-property
  helper (`hermes_module_runner.cc:197`), with evaluated-state checking
  and structured-error retention. Decided at implementation; the §7.3
  contract is frozen.
- **OQ-D:** should a thenable returned by the bootstrap invoke fail
  step 9 (strictness) or pass with the template-parity semantics §7.3
  states (current choice)? Revisit if a real bootstrap regresses to
  async setup.
- *(OQ-C closed at r2: counts only — the three evaluated-record counts
  in §8.)*

## Revision history

- **A2 (2026-08-24, post-acceptance amendment):** §10 external-reference
  rule made decidable — v1 DENY-ALL-CROSSING (every external edge whose
  origin `definingPrincipal` ≠ target's refuses #34; equal principals
  never consult the policy; no v1 grant exists; relaxation is a future
  O-4/armed amendment) — and the §4.7/§3.3 `resolverInventoryDigest`
  phantom-input claim deleted (field RESERVED on the wire, pinned O-3
  preimage untouched). Both edits outside the §6.2 lockstep bytes.
  Approved by Charlie Cheever via session exact-b7 after the
  implementation lane's STOP-AND-REPORT
  (`issues/closed/20260824-llp0056-s10-grant-authority-defect.md`).
- **r5 (2026-08-24):** Round-3 delta fold (grok READY 0-MATERIAL,
  second consecutive; codex NOT READY with 2 MATERIALs, both verified
  against the trees). Codex: the §3.3 authority claim overstated the
  landed expectations schema (no `2^53-1` maxima on its three integer
  fields; parity check inspects neither channel schema) — claim made
  precise, exact-side repair named as a handoff; producer-mismatch
  routing was contradictory between §4.8 (#14) and §6.4 (#22) — split
  deterministically (index-vs-envelope → #22; carrier/artifact-vs-
  authenticated-index → #14). Grok round-3 catches: step-3 ordinal
  range corrected to #11–#23; step-8 "authorize and link" replaced
  with consuming the step-6 capability; §9.1 stale "alignment in
  flight" retired; candidate-table schema-identifier dispatch and
  digest-before-stamp order pinned (+ the §9.2 v1-candidate-table
  fixture row); #16 wording made origin-neutral; §3.3 field count.
  Codex minor: `invoke_named_export` → `Result<InvokeOutcomeV1>` as
  the `agentInvokeReturnedThenable` transport.
- **r4 (2026-08-24):** Round-2 dual-family fold on r3 (grok READY /
  codex NOT READY; every decisive codex claim verified against the
  trees before folding) plus the `@a049ed9aa` alignment-wave fold.
  Codex MATERIALs: generation-free candidate-table v2 (§4.3/§4.8 — the
  landed table's serialized `generation` field broke the one-carrier
  invariant; blind cross-family convergence with grok's verification
  request); full producer identity `(producerId, producerBinaryDigest)`
  in the index vs the envelope (§4.3/§4.8); external-reference cap
  enforced at package decode too (§3.1); typed
  `AuthorizedCompositionPlanV1` handoff from step 6 to step 8
  (§5/§7.2); single-meaning acceptance coupling (§6/§11); §6.2
  scope-declaration fixed with the Exact-side sibling note as a named
  handoff. Grok/codex MINORs: ordinal-outer step-3 sweep; entry-plan
  argument order for `*_for_roots`; report null-on-serialization-
  failure unification; thenable diagnostic; expiry/policy note; d1
  literal-dynamic-only + identity clauses; #16 wording. Alignment
  fold: §3.2/§3.3 landed authority files (field-for-field,
  `prepared-composition-schema-parity` PASS); generation-carrier
  duplication resolved exact-side; §4.7 basis widened to declared
  edges + host-bridged rows (`collectAliasImportSites`); §6.3
  unarmed-lockstep-leg arming note; §11 leg-1 hold released to the
  ibex-half O-1 rows, 21-vector corpus as the Rust differential
  target.
- **r3 (2026-08-24):** Peer-blocker resolution and dark-impl pins.
  Recorded Exact 0413.001 r7 / Amendment A1 (`@246f959cc`) adopting
  §6.2 verbatim (38 rows + defaults byte-verified identical across the
  two documents); acceptance coupling updated (peer blocker resolved;
  generated-halves parity pin stays an implementation-leg gate). Two
  MATERIAL findings from exact-b7's dark implementation folded:
  (1) §2.5 package-scope reason semantics blessed — "target is not a
  bundle module" = "does not resolve to a record this package
  publishes," covering resolvable-but-excluded targets, because the
  locality rule makes the distinction underivable; no third member
  (§4.3); (2) the envelope attestation triple pinned as the only
  serialized generation carrier — no `PreparedPackageDeliveryV1`-style
  sidecar may be serialized, served, or consumed by admission (§4.8).
  O-1 status refreshed (seed landed `@9018e0bbd`/`@8d06de59e`,
  r6-shaped, drift caught by the live parity check; §11 leg 1 holds
  until the alignment landing report confirms r7-shaped schemas).
  §6.2 row-predicate section references declared 0056-relative in both
  repositories.
- **r2 (2026-08-24):** Round-1 dual-family fold (codex gpt-5.6-sol
  xhigh, repo-access read-only; grok-4.6 xhigh, full-text-inlined; both
  NOT READY on r1, convergent). Full ordinalized replacement registry
  (§6.2, 38 rows) with explicit amendment deltas D1–D9 (including the
  unreachable-fingerprint drop and the encoding-sniff predicate);
  single default per step; total injective covering map with a
  machine-checkable fixture; authorized linker + defining-principal
  `cross-principal-denied`; decidable generation attestation; complete
  verifier inputs (slim commitment, expectations with target + O-3
  inventory digest, runtime-queried engine identity); bounds split by
  surface; order-guarantee proof at step 7; `mainRoot` + descriptor
  executor + composition session; tagged report shapes; alias
  disjointness; preflight composition-only; tagged binding targets;
  fixture 35a/35b; coordination rules folded (§6 as the O-2 parity
  enumeration; O-1 corpus home canonical, all field sketches
  provisional pending it; acceptance coupled to the §4.1 amendment).
- **r1 (2026-08-24):** Initial draft against `94c85abab`, commissioned
  by Exact `issues/20260824-ibex-package-aware-admission-llp.md`
  (0413.001 §6 + O-2).
