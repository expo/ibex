# LLP 0056: Package-Aware Composition Admission (the ibex leg of Exact LLP 0413.001 §6)

**Type:** Spec
**Status:** Draft
**Systems:** Module Loader, Engine, Host Embedding, Security, Conformance
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-24
**Revised:** 2026-08-24 (r1 — initial draft, commissioned by Exact
`issues/20260824-ibex-package-aware-admission-llp.md` after Exact
LLP 0413.001 was Accepted at r6 (@377caa657) with obligations O-1–O-6;
this document is O-2's owner and the §6 "one ibex LLP". Designed against
the landed tree at `94c85abab` — every cited function, token, and line
was read at that pin, not inferred.)
**Related:** Exact LLP 0413.001 (the governing spec — §2 packages, §3
composition, §4 nine-step admission + §4.1 registry, §5 receipts, §6 the
ibex obligation, §7 fixtures, §10 obligations; Accepted r6), Exact
LLP 0413 (§5.3 per-defining-principal carriers, §5.4 fallback, §5.7/§14
admission/tamper), LLP 0042 (independent prepared-graph commitment — the
landed single-publication admission this spec generalizes; extended,
never re-decided), LLP 0043 (registered external transform fingerprints
— the dormant currency half of `ibex:compiler-fingerprint-mismatch`),
LLP 0026 (ESM module runner — link/evaluate lifecycle), LLP 0027 (module
artifact and interop), LLP 0013 / LLP 0040 (principals — the term
`Principal` keeps its meaning here), `src/module_loader/runner_pipeline.rs`
(`admit_committed_publication_v1`, the dev-unarmed embedder entry),
`src/module_loader/carrier.rs` (`PreparedModuleCarrierV2`),
`src/module_loader/artifact.rs` (`ModuleArtifactV1`, `ProducerIdentityV1`),
`src/module_loader/graph.rs` (`SynchronousGraphPlan`),
`src/engine/module_runner.rs` (`NativeSynchronousGraph`),
`src/module_loader/security.rs` (graph authorization seam)

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
   host-held commitment, verifier-held expectations (§3);
3. the **ibex half of the nine steps** — which predicate each existing
   function decides, what is new code, and the refusal code every failure
   maps to (§5);
4. the **O-2 covering map** — the enumeration of the landed refusal
   tokens on the `admit_committed_publication_v1` path and their
   one-for-one disposition into the composition registry's imported
   `ibex:` rows, replacing 0413.001 §4.1's placeholders (§6);
5. **multi-root link planning and descriptor execution** — the
   `SynchronousGraphPlan` / `NativeSynchronousGraph` evolution for an
   ordered two-root evaluation with evaluate-then-invoke (§7);
6. the **report** the embedder receives, total on every outcome (§8); and
7. the **conformance surface** — the shared canonical-byte vector corpus
   (O-1) and the §7-fixture rows that live ibex-side (§9).

Everything here is fail-closed: every admission step names its refusal
codes, every step has a default code, and an outcome outside the
registry is a defect in this implementation, never a pass.

## 1. Scope and non-goals

**In scope:** the package and composition decode types and their bounds;
the per-package root schema (index, carrier v3, producer identity); the
nine-step admission driver and its placement across
`module_loader/composition.rs` (new), `runner_pipeline.rs`, `graph.rs`,
`module_runner.rs`, and `security.rs`; the one-way `agent → app` typed
external references at union closure; the refusal-code enum and its
parity with the shared generated registry; multi-root linking and the
evaluate-then-invoke primitive; the dev-unarmed C-ABI entry and report;
the ibex-side fixture matrix.

**Non-goals (v1), inherited from 0413.001 §1:** roles beyond
`app`/`agent`; partial admission (whole-or-nothing); any armed posture
(the production-armed row is a deferred amendment — the landed
`load_prepared_graph_committed_v1` armed wrapper is untouched);
`parseFree` semantics; a second runtime (RFC 0495); binding computed
dynamic imports; full-agent-graph packing (`boot-core-v1` is the only v1
agent packing). Also out of ibex scope: the produce algorithm, cache
identity, produce atomicity, warm-cache freshness (O-4), and the
`unavailable-*` receipt variants — all producer/exact-side; ibex never
emits them (§8).

## 2. Terminology — composition role is not Principal

This distinction was a round-1 catch in the 0413.001 loop that would
otherwise have refused every real publication, and it is binding
vocabulary for this document and its implementation:

- **`Principal`** (LLP 0013/0040, `capsec_semantics::model::Principal`)
  keeps its existing ibex meaning: the per-record **defining principal**
  (Root, `Package { name, .. }`, builtin domains). One prepared package
  contains **many** per-defining-principal carriers; every record keeps
  its `definingPrincipal`; carrier grouping by defining principal
  (`runner_pipeline.rs:3631-3650`) is unchanged.
- **Composition role** (`app` | `agent`) is a **package-level** fact: the
  role one package plays in one session's composition. A package is
  never "a principal." No API, field, token, or log line introduced by
  this spec may use "principal" to mean the composition role; the
  serialized field is `role`, the Rust type is `CompositionRole`.

Other terms: **package root** — the digest, domain
`ibex:prepared-package-root:1`, over one package's canonical index
bytes; **package graph digest** — the digest, domain
`ibex:prepared-package-graph:1` (new, §4.2), over one package's
role-scoped semantic graph, replacing `deploymentGraphDigest` inside
package bytes; **composition root** — the digest, domain
`ibex:prepared-composition-root:1`, over the canonical composition
envelope; **envelope** — the served `composition.json`
(`PreparedCompositionV1`); **commitment** — the host-held
`PreparedCompositionCommitmentV1` (§3.2); **expectations** — the
verifier-held live values (§3.3).

## 3. Inputs at the embedder boundary

The landed dev-unarmed lane already separates the three input channels
this design needs; the composition leg widens each without changing its
trust class.

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
exact-size, hard byte limits). The envelope is capped at the inherited
`MAX_PREPARED_INDEX_BYTES_V1` (64 MiB); per-package files keep their
landed caps (index 64 MiB, manifest 16 MiB, carrier 512 MiB, candidate
table 64 MiB). The 0413.001 §3.1 collection bounds are enforced at
envelope decode: roles ≤ 2, records ≤ 65 536 per package, declared edges
≤ 1 048 576, alias rows ≤ 1 024, external references ≤ 4 096, strings
≤ 4 KiB, nesting ≤ 16. Limit and limit+1 are fixture rows (§9).

### 3.2 Host-held commitment (the §3.3 channel)

The composition analog of today's `commitment_json` argument to
`ibex_dev_unarmed_committed_prepared_startup_v1`: canonical JCS bytes of

```jsonc
// schema "ibex/prepared-composition-commitment/1"
{
  "schema": "ibex/prepared-composition-commitment/1",
  "workflow": "production",           // production-SHAPED record; dev posture
                                      // lives in the entry type (LLP 0042 rule)
  "target": "<embedder target>",
  "declaredRoles": ["app"] | ["app", "agent"],
  "compositionRootDigest": "<digest over the envelope bytes>",
  "producer": { "id": "...", "binaryDigest": "..." }
}
```

Delivered on the host-held boot-configuration channel, independent of
artifact storage — never read from `composition_dir`. Channel-level
prechecks (strict JSON, canonical JCS, schema, workflow, target vs the
embedder's expectation) keep the landed dev-token style as sibling
tokens (`IBEX_DEV_COMPOSITION_CORRUPT` / `_SCHEMA` / `_TARGET` /
`_ARMED_CONTEXT`); like today's `IBEX_DEV_COMMITTED_*` family these are
**channel/environment failures outside the composition registry** — the
registry's clock starts when an authentic channel presents a commitment
(§5 step 0 note).

### 3.3 Verifier-held expectations

The freshness half of step 2b compares envelope facts against values the
verifier holds. The embedding host owns those values (it armed the
session); ibex receives them as one versioned JSON argument:

```jsonc
// schema "ibex/composition-verifier-expectations/1" — every field mandatory
{
  "schema": "ibex/composition-verifier-expectations/1",
  "sessionNonce": "...",
  "authorityGeneration": <u64>,
  "resolverGeneration": <u64>,
  "policyDigest": "<digest>",
  "expectedRoles": ["app"] | ["app", "agent"],   // effective live state
  "nowUnixMs": <u64>                             // host clock; ibex reads no clock
}
```

`nowUnixMs` is deliberately an input so expiry outcomes are
deterministic under test. Credential material never appears here or in
the envelope (0413.001 §3.1 item 8).

### 3.4 The C-ABI entry (dev-unarmed, the only v1 posture)

```c
int32_t ibex_dev_unarmed_composition_prepared_startup_v1(
    void *runtime, uint64_t runtime_nonce,
    const char *composition_dir,
    const char *commitment_json,      // §3.2, host-held
    const char *expectations_json,    // §3.3, verifier-held
    const char *project_root,
    char **out_report_json,           // ALWAYS written on refusal AND success (§8)
    char **out_error);
```

Return codes keep the landed phase semantics exactly
(`DevCommittedStartupFailurePhase`): `0` success; `1` refusal in steps
1–8 (**before evaluation** — the Exact host may select the LLP 0413 §5.4
fallback); `2` failure at step 9 or later (**during evaluation** — the
generation is failed, no encoding switch, no fallback). The
construction-time armed exclusion
(`installed_host_is_armed_for_dev_exclusion`) applies unchanged. The
existing single-publication entry
`ibex_dev_unarmed_committed_prepared_startup_v1` remains for
non-composition embedders; Exact's package-aware host moves to this one.

## 4. The package artifact schema (per-package roots)

### 4.1 Why the landed schema forbids the identity guarantee

0413.001 §2.1 requires app-package bytes identical across session shapes
and names this "a requirement on the §6 schema." At `94c85abab` the
whole-publication `deploymentGraphDigest` is bound inside package bytes
at three places:

1. every carrier manifest — `PreparedModuleCarrierV2.deployment_graph_digest`
   (`carrier.rs:101`), covered by the index-committed manifest bytes;
2. every record artifact — `ProducerIdentityV1::Prepared
   { deployment_graph_digest, .. }` (`artifact.rs:270-275`), inline in
   `index.json`;
3. the commitment — `PreparedGraphCommitmentV1.deployment_graph_digest`
   (`crates/capsec-semantics/src/arming.rs:53`).

Because that digest covers the whole publication, adding or editing the
agent side would change every app carrier manifest and every app record
byte. The fix is per-package binding: nothing inside a package's bytes
may name a fact outside that package's own graph.

### 4.2 The package graph digest

Per package, the producer computes the **package graph digest**: domain
`ibex:prepared-package-graph:1` over the canonical JCS encoding of the
package's role-scoped semantic graph — the ordered set of
`(SourceId, semanticDigest)` pairs of owned records plus the ordered
declared edge rows (including typed external reference rows, §4.5). It
is a pure function of the package's own graph facts, computable before
any carrier or artifact is built (no circularity: it binds semantics,
not artifact bytes — exactly the role `deploymentGraphDigest` plays
today). The app package's digest is therefore untouched by agent-side
changes; the agent package's digest changes only when its owned records
or its ordered external-reference set change — the 0413.001 §2.1
identity guarantee, delivered by construction. The precise preimage is a
named row of the O-1 schema package (§9.1); this spec fixes the domain
string and the purity requirement.

### 4.3 The package index — `ibex/prepared-package/1`

The per-package sibling of `PreparedGraphIndexV2`
(`runner_pipeline.rs:224`), canonical JCS, `deny_unknown_fields`:

```jsonc
{
  "schema": "ibex/prepared-package/1",
  "role": "app" | "agent",
  "producerBinaryDigest": "<digest>",
  "packageGraphDigest": "<digest, §4.2>",          // replaces deploymentGraphDigest
  "records": [ { "sourceId": ..., "bindings": [ /* §4.5 rows */ ],
                 "artifact": { /* ModuleArtifactV1, §4.6 producer identity */ },
                 "carrierIndex": <usize>, "entryId": "..." } ],
  "carriers": [ { "manifestFile": "...", "bytesFile": "..." } ],
  "candidateTables": [ { "file": "...", "digest": "<digest>" } ],
  "hostBridgedInventory": [ /* 0413.001 §2.5 rows, package-root-committed */ ]
}
```

Deliberate deltas from V2: **no `entry` field** — entry facts live only
in the composition's entry plan (0413.001 §3.1 item 7), so a package is
a pure content set and the same app package serves `["app"]` and
`["app","agent"]` byte-identically; **`role` is present** — the package
names the one role it was produced for, and step 3 refuses a package
served under a different role (this backstops the composition-level
role-swap refusal with a package-level fact); **the host-bridged
inventory is in the index** — §2.5 requires it package-root-committed,
and its `reason` values must satisfy the locality rule (derivable from
this package's own graph facts, never referencing the other package).

The **package root** is `digest(ibex:prepared-package-root:1,
index_bytes)` — the value the composition's ordered
`(role, packageRoot)` pairs commit.

### 4.4 Carrier manifest v3 — `ibex/module-carrier/3`

`PreparedModuleCarrierV2` with exactly one field change:
`deploymentGraphDigest` → `packageGraphDigest` (§4.2). Everything else —
`encoding` (`javascript-factory-table` | `hermes-bytecode` with
engine binding + bytecode version), `carrierDigest` over the bytes
(domain `ibex/module-carrier-bytes/1` unchanged), `definingPrincipal`,
`producerId`, `producerBinaryDigest`, ordered unique `entries` with
per-entry `ModuleSemanticsV1` + `semanticDigest` — carries over, and
`AdmittedPreparedCarrierV2::decode_and_admit`'s check set
(`carrier.rs:245-345`) applies verbatim with the expectation's
deployment digest replaced by the expected package graph digest. The
role is deliberately **not** in the carrier manifest: carriers are bound
by the index, the index by the committed `(role, packageRoot)` pair —
one authority per fact, no parity pair to drift.

### 4.5 Binding rows and the typed external reference

`PreparedGraphBindingV1` (`runner_pipeline.rs:246-250`) gains one
optional field, giving the one-way cut its structural discrimination
(0413.001 §2.3 — never inferred):

```jsonc
{ "specifier": "...", "resolutionKind": ..., "target": <SourceId>,
  "externalRole": "app" }   // present ⟺ this is a typed external reference
```

Rules, enforced at steps 5–6: `externalRole` accepts the single value
`"app"` in v1; a row carrying it is legal **only in the agent package**;
its target is exempt from local target-presence and resolves at union
closure against app-owned records; a row **without** it must resolve
inside the owning package. An `externalRole` row in the app package, an
unknown `externalRole` value, or an undeclared cross-package resolution
is a step-5 refusal (`local-agreement-disagreement`), except the
declared `app → agent` static edge which is always
`app-references-agent` (the 0413.001 step-5 precedence rule).

### 4.6 Artifact producer identity — `prepared-package`

`ProducerIdentityV1` (`artifact.rs:265-275`) gains a third variant:

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
(`ibex:prepared-commitment-schema`, §6.2). `ArtifactAdmissionV1` gains
the matching `DigestBoundPreparedPackage` expectation — the
`DigestBoundPrepared` field set (`artifact.rs:296-308`) with
`deployment_graph_digest` replaced by `package_graph_digest`; the check
set in `verify_for_admission` carries over unchanged.

### 4.7 The committed alias table (verification inputs)

The alias table is composition-committed (0413.001 §2.2, §3.1 item 6):
per row `aliasId`, representative `SourceId`, the representative's
`sourceIntegrity` digest, and an import-site inventory digest. The ibex
half at step 3 verifies what is verifiable from admitted bytes: the
representative exists in its owning package, its admitted artifact's
`semantics.source_integrity` equals the committed row's, and the
import-site inventory digest recomputes over the admitted records'
binding rows naming the alias — under the algorithm the O-1/O-3 schema
package fixes (an explicit verifier input, never a producer-trusted
digest). Divergence is `alias-conflict`. At resolution time (steps 6–8
and runtime dynamic-import lookups), a target id that is not owned by
any package but appears as an `aliasId` resolves through the table to
its representative **before** ownership and no-third-state checks; the
real computed bootstrap alias reaching its admitted record is fixture
row 9.

## 5. The nine steps — the ibex half

The driver is `admit_prepared_composition_v1` in a new
`src/module_loader/composition.rs`, reusing the landed per-publication
internals rather than duplicating them: the per-package core of step 3
is `admit_package_v1`, extracted by refactor from
`admit_committed_publication_v1` (`runner_pipeline.rs:3532`) with the
commitment-facet expectations parameterized; the landed
single-publication entries keep their behavior through the same
extracted core.

Steps 1–8 are admission — any failure produces a total `refused` report
(§8) and return code 1; nothing after step 8 refuses. Step ordering is
normative; within a step, predicate order is the registry's ordinal
order; within a step touching packages, `app` before `agent`. Every step
names its default code (the 0413.001 §4.1 totality clause); the codes
below are the registry's, with the imported `ibex:` rows defined in §6.

**Step 0 (channel precheck, outside the registry):** armed-context
exclusion; parse the host-held commitment (§3.2) — strict JSON,
canonical JCS, schema, `workflow == "production"`, target equality.
Failures use the `IBEX_DEV_COMPOSITION_*` channel tokens (§3.2). Only an
authentic channel presentation starts the nine steps.

1. **Bounded canonical decode of the envelope.** Read
   `composition.json` under the bounded-file discipline; strict JSON;
   byte-exact canonical JCS; decode `PreparedCompositionV1` with
   `deny_unknown_fields`; enforce every §3.1 bound (collection caps,
   string caps, nesting). Any failure ⇒ `envelope-malformed`, with the
   §5 sentinel receipt (`failureStage: 1`, `packages: []`).
2. **Commitment, freshness, live state.**
   **2a (integrity, no verifier state):**
   `digest(ibex:prepared-composition-root:1, envelope_bytes)` must equal
   the commitment's `compositionRootDigest`; the envelope's internal
   commitments must be mutually consistent (entry-plan cardinality
   equals declaration cardinality; `(role, packageRoot)` pairs ordered
   and consistent with the declaration's order). Failure ⇒
   `composition-commitment-mismatch` (this is also where role swaps and
   alias-table tamper land — they change envelope bytes).
   **2b (against verifier-held values, in ordinal order):** session
   nonce, expiry (vs `nowUnixMs`), authority generation, and resolver
   generation each equal/valid ⇒ else `composition-replayed`; policy
   digest equal ⇒ else `composition-policy-stale`; envelope
   target/engine/encoding facts match this embedder ⇒ else
   `ibex:target-profile-mismatch` (imported, §6.2); declaration role-set
   validity (`composition-unknown-role`, `composition-duplicate-role`);
   served package directories vs declaration
   (`composition-package-extra`, `composition-package-missing`);
   declaration equals `expectedRoles`
   (`composition-mismatch`, also 2b's default).
3. **Per-package admission** (`admit_package_v1`, app then agent). Per
   package: bounded read of `index.json`; UTF-8/strict/canonical;
   `digest(ibex:prepared-package-root:1, index_bytes)` equals the
   committed package root ⇒ else `package-root-mismatch`; schema and
   role fields (`ibex:prepared-commitment-schema` on unsupported schema,
   wrong-role, synthetic records, or non-`prepared-package` producer
   identities); non-emptiness, filename safety, file inventory
   (`ibex:package-inventory`), candidate-table digests; carrier
   admission per carrier via `decode_and_admit` against v3 expectations
   — byte digest, canonicality, principal grouping
   (`ibex:principal-grouping` for cross-defining-principal carriers),
   producer identity, package-graph binding, encoding/engine
   (`ibex:encoding-incompatible`, `ibex:engine-unavailable`,
   `ibex:engine-binding-mismatch`), with tamper-shaped byte/digest
   failures as `carrier-integrity`; HBC preflight of every admitted
   hermes-bytecode carrier through the linked engine decoder
   (`preflight_hermes_bytecode`, moved from the landed post-admission
   position into this step) ⇒ `ibex:bytecode-preflight`; artifact
   admission per record via `DigestBoundPreparedPackage`
   (source integrity, semantic digests, carrier/entry binding,
   transform-fingerprint digest ⇒ `ibex:compiler-fingerprint-mismatch`);
   alias-row verification (§4.7) ⇒ `alias-conflict`. Composition-wide at
   this step: one producer identity and one generation across the
   envelope and every package ⇒ else `generation-splice`. Undecidable
   remainder defaults to `ibex:prepared-commitment-corrupt`, and
   step 3's registry default stays `package-root-mismatch`.
4. **Partition recomputation.** Recompute the partition over the union
   of admitted record `SourceId`s; byte-compare with the committed
   partition summary ⇒ else `partition-mismatch`; a repeated `SourceId`
   within one package ⇒ `ibex:duplicate-source-id` (the landed
   `runner_pipeline.rs:3825` predicate, relocated and given its own
   token); the same `SourceId` owned by both packages ⇒
   `package-overlap`.
5. **Per-package local agreement (no third state).** Every binding row
   of every record is exactly one of: an internal binding (target owned
   by this package and present), a typed external reference (§4.5,
   agent package only), or a refusal — a declared `app → agent` edge is
   always `app-references-agent` (precedence); every other miss is
   `local-agreement-disagreement`.
6. **Union closure and recomputation.** Recompute the union binding
   table and byte-compare ⇒ else `union-table-mismatch`; recompute each
   package's host-bridged inventory (locality rule included) ⇒ else
   `boundary-inventory-mismatch`; resolve every external reference to a
   present record of the named owner ⇒ `external-target-absent` /
   `external-owner-mismatch`; resolve imported names against the
   target's export descriptors (`ExportDescriptorV1`) through the union
   plan ⇒ else `export-disagreement`; apply the cross-defining-principal
   authorization rule (§10) ⇒ else `cross-principal-denied`.
7. **Entry-plan check (one code per predicate).** Recompute the
   expected plan from the declaration and `expectedRoles` (order:
   `agent` before `app`; app descriptor `{root, action: "evaluate"}`;
   agent descriptor `{root, action: "evaluate-then-invoke", export:
   "installExactNativeAgentBootstrap"}`) and byte-compare ⇒ inequality
   is `entry-plan-mismatch`; a structurally invalid descriptor, an
   unknown action, a root not owned by its role's package, or an agent
   entry whose admitted artifact's export descriptors lack the named
   export ⇒ `entry-descriptor-invalid` (presence is static; callability
   is not — see step 9); a present well-formed root whose closure cannot
   produce a linkage order ⇒ `composition-root-unlinked`.
8. **Atomic multi-root link.** Build one `SynchronousGraphPlan` over the
   union record set; compute the composition linkage and evaluation
   orders (§7); create and link every reachable record under one
   generation via `link_prepared_composition` (§7). Any failure ⇒
   `link-failure`. The §5.4 fallback boundary closes here.
9. **Evaluation per descriptor (post-admission).** In plan order: run
   the agent root's evaluation order; then invoke the agent entry's
   `installExactNativeAgentBootstrap` export synchronously through the
   new engine primitive (§7.3) — the invocation must return without
   throwing before any app-entry evaluation begins (the landed
   `native-startup-bootstrap.template.js` order); then run the app
   root's remaining evaluation order (records already evaluated under
   the agent root evaluate once and are skipped — ESM once-only
   semantics). A step-9 throw, a non-callable export object, or an
   engine invoke failure is a **startup error on the admitted lane**
   (return code 2, the landed `DuringEvaluation` phase) with the
   composition receipt attached; it never reopens the fallback.

**Per-package status transitions** (implemented here, reported in §8),
restating 0413.001 §5's single rule: a package is `verified` iff every
step up to the failing step (or step 8 on admission) completed for it;
`refused` iff it is the package a step-≤5 refusal names; `not-checked`
otherwise — including every package of a step-1/2a failure.

## 6. The refusal registry's ibex half and the O-2 covering map

### 6.1 The landed token enumeration (at `94c85abab`)

The complete typed refusal-token set on the
`admit_committed_publication_v1` path and its wrappers — this is the
enumeration 0413.001 §10 O-2 requires; grok's round-4 finding stands
confirmed: the r5/r6 placeholder names were **not** these identifiers.

| Landed token | Sites | Predicates |
| --- | --- | --- |
| `IBEX_PREPARED_COMMITMENT_CORRUPT` | 18 (`runner_pipeline.rs` 3261, 3271, 3283, 3288, 3350, 3547, 3549, 3552, 3559, 3564, 3598, 3612, 3621, 3634, 3649, 3728, 3749, 3825) | bounded-file violations (non-regular, reparse point, over-limit, changed-while-retained); unsafe/repeated filename; index not UTF-8 / not strict JSON / not canonical JCS / wrong shape; empty graph; activation root not a real directory; duplicate candidate digest; candidate digest mismatch; record names absent carrier; unreferenced carrier; record identity ≠ artifact; repeated typed binding; repeated `SourceId` |
| `IBEX_PREPARED_COMMITMENT_SCHEMA` | 3560, 3792 | unsupported index schema; synthetic prepared records |
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
only — no stable identifier today): carrier admission
(`AdmittedPreparedCarrierV2::decode_and_admit` and `validate`,
`carrier.rs:245-345` — canonicality, schema, byte digest, entry
ordering/uniqueness, stale entry semantic digest, principal
crossing/authorization, producer/deployment staleness, deployment-set
membership, `"source carrier admission must not claim a bytecode
engine"`, `"prepared Hermes carrier targets a different engine"`); the
HBC header parse (`carrier.rs:51-63`) and engine preflight
(`module_runner.rs:459-469`); artifact admission
(`verify_for_admission`, `artifact.rs:461-623` — canonicality, schema,
producer/deployment staleness, semantic-digest membership,
carrier/entry binding, `SourceId`/integrity disagreement,
`"artifact transform fingerprint is stale"`); the production-posture
currency check (`verify_current_transform_fingerprint_v1`,
`producer_spike.rs:131` — **does not run** under the dev posture, the
only v1 posture). The package-aware implementation MUST give every one
of these classes a stable registry code per §6.2; a prose-only refusal
reaching the composition report is non-conformant.

### 6.2 The imported rows (the placeholder swap)

The proposal to Exact: replace 0413.001 §4.1's six placeholder rows
(#14–18, #20) with **eleven** imported rows — the landed reality does
not compress to six without burying attacker-relevant distinctions. Per
O-2 this swap is folded into §4.1 by amendment with the parity check
gating byte-equality, and each row gains a §7 reachability fixture
(rows F-i1…F-i11, §9.2).

| Imported code | Step | Class | Covers (landed classes from §6.1) |
| --- | --- | --- | --- |
| `ibex:prepared-commitment-corrupt` | 3 | attacker | the `_CORRUPT` package-scope predicates except repeated-`SourceId`; bounded-read violations; index canonicality/shape; candidate-table digests; absent/unreferenced carrier; repeated binding; carrier/artifact canonicality prose sites |
| `ibex:prepared-commitment-schema` | 3 | producer-defect | `_SCHEMA` predicates; wrong `role` field; non-`prepared-package` producer identity; unsupported carrier/artifact schema prose sites |
| `ibex:package-inventory` | 3 | attacker | `_INVENTORY` — package file inventory ≠ index |
| `ibex:principal-grouping` | 3 | producer-defect | `_PRINCIPALS` site 3645 + `carrier.rs` 170/281/307 — carrier or entry crosses/violates its defining principal |
| `ibex:engine-unavailable` | 3 | environment | `IBEX_PREPARED_ENGINE_UNAVAILABLE` |
| `ibex:engine-binding-mismatch` | 3 | environment | `carrier.rs:339` engine-binding disagreement; bytecode-version disagreement |
| `ibex:bytecode-preflight` | 3 | environment | HBC header parse failures; engine preflight rejection |
| `ibex:encoding-incompatible` | 3 | producer-defect | `carrier.rs:327` source-carrier-claims-engine; declared-encoding/bytes disagreement |
| `ibex:compiler-fingerprint-mismatch` | 3 | producer-defect | `artifact.rs:571` digest-bound fingerprint disagreement (the LLP 0043 currency half is dormant under the v1 dev posture and joins this row when an armed posture lands) |
| `ibex:target-profile-mismatch` | 2 | environment | envelope target/engine/encoding facts ≠ verifier expectation |
| `ibex:duplicate-source-id` | 4 | producer-defect | the relocated repeated-`SourceId` predicate (`runner_pipeline.rs:3825`) |

**Superseded landed tokens (not imported), with dispositions:**
`_MISMATCH` → `package-root-mismatch` (#10; the per-package root
replaces the publication root); `_ENTRY` → dissolved into step 7
(`entry-plan-mismatch` / `entry-descriptor-invalid`; packages carry no
entry); `_DEPLOYMENT` → dissolved by the §4.2 package-graph binding (its
disagreement classes land under `carrier-integrity` and the imported
corrupt/schema rows); `_SEMANTICS` → dissolved (the package root covers
the index, which inlines every artifact; the authorized-semantic-digest
set derives from admitted package bytes, per-package); `_PRINCIPALS`
site 3584 → dissolved with `_SEMANTICS` (principals derive from
records); `_PRODUCER` → the composition-wide producer/generation
identity check ⇒ `generation-splice` (#12); `_MISSING` / `_AUTHORITY` →
production-armed wrapper, deferred with that posture; `IBEX_DEV_*` →
channel precheck, outside the registry (§3.2, §5 step 0).

### 6.3 Registry mechanics (parity, generated halves)

The single registry authority is 0413.001 §4.1's literal table plus this
section's imported rows, generated exact-side as
`packages/exact-devtools/src/prepared-composition-refusals.generated.json`.
The ibex half: a `CompositionRefusalCode` enum in `composition.rs` whose
`as_str()` values byte-match the registry codes, an
`ordinal()`/`step()`/`class()` projection matching the table, and a
pinned vendored copy of the generated registry at
`tests/fixtures/prepared-composition/v1/refusals.generated.json` with
(a) a unit test asserting enum ↔ vendored-file byte parity and (b) the
vendored file's digest recorded in the fixture manifest so the
exact-side O-1 parity check can assert both halves pin identical bytes.
Multi-fault precedence is implemented as specified: lowest ordinal wins;
within a step, `app` before `agent`; the driver evaluates predicates in
ordinal order so precedence is by construction, not by sorting
afterthought. Every step's default code (0413.001 §4.1 totality clause)
is the terminal arm of that step's match — no `_ =>` arm may produce
anything outside the registry.

## 7. Multi-root link planning and descriptor execution

### 7.1 `SynchronousGraphPlan` (graph.rs)

Two additions, generalizing the landed single-entry functions without
changing them:

- `linkage_order_for_roots(&[SourceId]) -> Result<Vec<SourceId>, GraphError>`
  — the deterministic dependency-first order over the union closure of
  an ordered root list (concatenated per-root DFS with cross-root
  dedup: a record links under the first root that reaches it).
- `synchronous_evaluation_order_for_roots(&[SourceId])` — same
  discipline for evaluation order; per-root segments are retained so the
  step-9 driver knows where the agent segment ends and the invoke point
  sits.

Both surface `GraphErrorCode::ModuleLink` (`ERR_MODULE_LINK`) /
`RequireAsyncModule` exactly as today; at step 7 a root that cannot
produce an order maps to `composition-root-unlinked`, and at step 8 a
link-time `GraphError` maps to `link-failure`. TLA remains refused on
this synchronous lane (`ERR_REQUIRE_ASYNC_MODULE` — unchanged: the
bootstrap and app entries are synchronous today).

### 7.2 `NativeSynchronousGraph` (module_runner.rs)

One new constructor,
`link_prepared_composition(runtime, plan, root_plan, configs,
prepared_entries)`, where `root_plan` is the ordered descriptor list
from the verified entry plan. It is `link_inner` with the multi-root
linkage/evaluation orders; one records map, one graph generation
(uniformity check unchanged, `module_runner.rs:3606-3608`), every
reachable record created and linked before any evaluation — the union
closure links **atomically** (step 8): a failure while linking any
record fails the whole composition, and no partially-linked graph is
ever evaluated. The struct's `entry` field generalizes to the ordered
root list; `evaluation_order` becomes per-root segments; the sticky
`evaluation_outcome` discipline (`module_runner.rs:4012-4059`),
including record-identity annotation of failures, carries over.

### 7.3 The invoke primitive (the one new engine call)

Step 9's evaluate-then-invoke needs a primitive the engine does not have
at `94c85abab` (the linked graph exposes only `namespace_json`):

```rust
/// Invoke the named export of an evaluated record as a zero-argument
/// function, synchronously, on the runtime's owner thread. Returns after
/// the call returns; a JS throw, a missing binding at runtime, or a
/// non-callable value is an error. Never used before the record's
/// evaluation completes.
pub fn invoke_named_export(&mut self, source_id: &SourceId, export: &str) -> Result<()>
```

Implemented against the same engine seam as `namespace_json` (namespace
object get → property get → callable check → call, with the existing
sticky-error conversion). The return value is ignored (the landed
bootstrap template's `installExactNativeAgentBootstrap()` contract);
"synchronous completion" means the function returned — anything it
scheduled is app-visible but not awaited, matching the template. Errors
here are step-9 startup errors (return code 2), never admission
refusals: export **presence** was verified statically at step 7 from
export descriptors, but descriptors do not carry types, so
**callability is only decidable at runtime** — a non-callable export is
the admitted lane failing loudly, not a fallback trigger.

### 7.4 Evaluation-once semantics

Because typed external references make app records reachable from the
agent root, an app record referenced by the agent evaluates during the
agent segment (dependency-first), before the invoke point, and is
skipped in the app segment — standard ESM once-only evaluation over one
records map. Fixture row 1 (agent static import of app-owned lib →
admitted) plus a segment-order assertion pin this.

## 8. The report

`ibex/dev-unarmed-composition-startup-report/1`, serialized to
`out_report_json` on **every** outcome — success and refusal both (the
landed entry writes a report only on success; the composition entry must
hand the embedder a total receipt so the Exact-side §5 report variants
are a projection, never a reconstruction):

```jsonc
{
  "schema": "ibex/dev-unarmed-composition-startup-report/1",
  "compositionSchemaVersion": 1,
  "authority": "dev-unarmed-dev-served (non-production)",
  "posture": "dev-unarmed", "nonProduction": true,
  "fingerprintPosture": "dev-vouched-index-external-producer (LLP 0043 pending)",
  "admissionStatus": "admitted" | "refused",
  "declaredRoles": [...],                     // null-typed under the step-1 sentinel
  "compositionRootPrefix": "...",             // ditto
  "failureStage": <1..9>, "reasonCode": "<registry code>",
  "packageRole": "app" | "agent",             // when a package is named
  "packages": [ { "role": "...", "packageRootPrefix": "...",
                  "recordCount": n, "carrierCount": n,
                  "hbcCarrierCount": n, "javascriptCarrierCount": n,
                  "verificationStatus": "verified" | "refused" | "not-checked" } ],
  "entryPlan": [ { "role": "...", "action": "...", "export": "..." } ],
  "attribution": "collapsed-to-root (dev-unarmed; no compartment registry)",
  "engineBindingDigestPrefix": "...",
  "commitmentParseUs": n, "admissionUs": n, "graphLinkUs": n,
  "agentEvaluateUs": n, "agentInvokeUs": n, "appEvaluateUs": n
}
```

`admissionStatus` here has exactly two values: ibex only ever runs when
packages were served, so the `unavailable-unserved` /
`unavailable-unadmitted` variants of 0413.001 §5 are **producer/exact
host states that ibex never emits** — the Exact host composes its total
§5 receipt from this report (admitted/refused) or from its own producer
outcome (unavailable). Refusals carry deterministic
`failureStage`/`reasonCode` and the §5 per-package transition rule;
step-1 failures use the sentinel shape (`failureStage: 1`,
`packages: []`, declaration fields null-typed). A step-9 failure returns
code 2 with `admissionStatus: "admitted"` (admission succeeded), the
error in `out_error`, and per-package rows all `verified` — the receipt
the startup-error path attaches. Counts and digest prefixes only — no
source identifiers beyond what the landed report already exposes
(0413.001 OQ2's lean).

## 9. Conformance: the shared corpus and the ibex-side fixtures

### 9.1 The shared canonical-byte vector corpus (O-1)

The schema/IDL package `docs/schemas/prepared-composition/v1/`
(exact-side owned, O-1) is the byte authority for: the envelope, the
commitment (§3.2), the expectations (§3.3), the package index (§4.3),
carrier v3 (§4.4), binding rows (§4.5), the `prepared-package` producer
identity (§4.6), the package-graph preimage (§4.2), the alias
import-site inventory preimage (§4.7/O-3), and the report (§8). Its
shared canonical-byte vector corpus (valid rows, limit and limit+1 rows,
canonicality-violation rows) is vendored at
`tests/fixtures/prepared-composition/v1/vectors/` with the corpus digest
pinned in the fixture manifest; a Rust conformance test derives
encode/decode/digest results for every vector and must be green — the
exact-side O-1 parity check asserts both repos pin the same corpus
digest. Schema drift therefore fails closed on whichever side moved
unilaterally.

### 9.2 The ibex-side fixture rows

Of the 0413.001 §7 matrix, the rows that execute in this repo (as Rust
tests in `composition.rs`/`runner_pipeline.rs` test modules over crafted
compositions, mirroring the existing committed-admission test style):
**A:** 1, 4, 5b, 6, 7, 8, 9, 10 (host-bridged never bound at admission);
**B:** 12–19 (both directions of 19 via `expectedRoles`);
**C:** 20–29 (freshness via the expectations input; tamper via byte
mutation recipes); **D:** 30–38 (38's multi-fault by-ordinal assertion
included); **E:** 39 (the ibex report half — every refusal row's
`(failureStage, reasonCode)` and per-package transitions; 40–42 are
exact-side fail-loud rows); plus **F-i1…F-i11** — one demonstrated
reachability fixture per §6.2 imported row (mutation/re-signing recipe
per row, satisfying O-2's gate and feeding O-6's matrix-completeness
assertion). Producer-side rows (2, 3, 5a, 11, 43–45) live exact-side;
row 11's membership pin is consumed here only as the fixture composition
those tests admit.

## 10. Security posture honesty (v1)

The only v1 posture is dev-unarmed (0413.001 §3.3): the composition
entry is feature-gated like the landed embedder
(`dev-committed-embedder`), refuses under an armed Host at construction
time, and names its authority in every receipt. On this lane, EXECUTION
attribution collapses to the root principal exactly as landed
(`runner_pipeline.rs:6119-6131` — no compartment registry binds), while
carrier ADMISSION stays fully per-defining-principal. Consequently
`cross-principal-denied` (#29) is decided in v1 by the **structural**
authorization rule at union closure: an external reference is authorized
iff it originates in the agent package, carries `externalRole: "app"`,
resolves to an app-owned record, and the declaration includes `agent`;
any other cross-package resolution is denied. The compartment-enforced
version of this check joins the armed posture through the existing
`security.rs` seam (`GraphAuthorityContext` /
`ModuleGraphAuthorizer`) — named here so the hook point is decided, not
invented later. The armed wrapper
(`load_prepared_graph_committed_v1`) and its `_MISSING`/`_AUTHORITY`
tokens are untouched until the production-armed amendment.

## 11. Implementation plan

1. **Schema leg** — `composition.rs` decode types + bounds + refusal
   enum; carrier v3 and `prepared-package` producer identity;
   `admit_package_v1` extracted from `admit_committed_publication_v1`
   (landed single-publication behavior pinned by existing tests before
   the refactor). Vendored corpus + parity tests (§6.3, §9.1) land with
   this leg — the corpus gate is green before any admission logic
   exists.
2. **Admission leg** — steps 0–7 with the full fixture groups B/C and
   the F-i reachability rows; the report on refusal.
3. **Link/evaluate leg** — graph.rs multi-root orders,
   `link_prepared_composition`, `invoke_named_export`, the C-ABI entry,
   fixture groups A/D/E-39; the report on success.
4. **Exact fold** — hand §6.2's covering map to the 0413.001 §4.1
   amendment; the O-1 parity check extends to the imported rows (O-2's
   gate); Exact's host adopts the new entry.

Each leg is landable alone; nothing admits for real until leg 3, which
is the moment 0413.001's "no composition admits until the ibex leg
lands" flips.

## 12. Open questions

- **OQ-A:** should the package index inline artifacts (the landed V2
  shape, kept in §4.3) or reference them by digest into carrier
  manifests only? Inline keeps the landed admission flow and one
  bounded read; a split index would shrink the 64 MiB envelope pressure
  for very large apps. v1 keeps inline; revisit if a real app package
  index approaches its bound.
- **OQ-B:** `invoke_named_export`'s engine seam — reuse the
  `namespace_json` C++ path or add a dedicated
  `ex_hermes_module_invoke_export`? Decided at implementation; the
  contract in §7.3 is fixed either way.
- **OQ-C:** whether the agent segment's evaluated-record set should be
  named in the report (would let Exact assert fixture-1 sharing without
  a tree diff). Leaning yes if counts-only (OQ2 discipline).

## Revision history

- **r1 (2026-08-24):** Initial draft against `94c85abab`, commissioned
  by Exact `issues/20260824-ibex-package-aware-admission-llp.md`
  (0413.001 §6 + O-2).
