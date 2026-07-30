# LLP 0043: Registered External Transform Fingerprints

**Type:** RFC
**Status:** Review
**Author:** Charlie Cheever / Claude
**Date:** 2026-07-30
**Revised:** 2026-07-30 (round-1 review revision: closed per-(principal, goal)
transform-authority assignment replaces additive registration scope; complete
embedded downstream identity; scoped no-fallback rule; validation-site split;
named schema rotations); 2026-07-30 (round-2 review revision: committed-only
entry marking makes the no-downgrade rule authority-independent; index and
carrier schema rotations completed; admission-time `STALE` reclassified as
operative in every lane; goal-typed registrations; D2 cited as recommendation);
2026-07-30 (post-round-3 close-out revision, **unreviewed**: consumer-side
enforcement boundary for the dev committed-only check; LLP 0026/0029 join the
sibling-revision set incl. the `StubContractV1` carrier-pin migration;
registration identity domain pinned; production multi-entry scoping;
fixture sequencing note)
**Systems:** Module Loader, Transforms, CapSec, Arming, Security
**Related:** LLP 0027 (ModuleArtifact wire, transform-fingerprint composition,
carrier v2); LLP 0028 (Oxc-only transform authority, canonical
transform-configuration manifest); LLP 0042 (independent prepared-graph
commitment — the authority surface this contract rides); LLP 0026 (module
runner); LLP 0039 (secure and insecure modes); Exact LLP 0413 §9.5 (one
transform truth — external, Exact repo); Exact LLP 0416 §D2 (adapter
tournament resolution — external, Exact repo);
issues/20260729-transform-fingerprint-registry-contract.md

## Summary

Admission currently verifies transform-fingerprint currency with one rule:
the artifact's fingerprint digest must equal the digest of ibex's own pinned
toolchain configuration (`verify_current_transform_fingerprint_v1`,
`src/module_loader/producer_spike.rs`, generated from
`config/module-transform.json`). That is exactly right for artifacts ibex
produced, and it structurally refuses every artifact whose ESM-level
transform ran anywhere else. Exact's LLP 0416 D2 measurement closes with a
recommendation — the decision remains the author's (LLP 0416 §6) — to
proceed **adapter 1** for the root/app principal: Vite's plugin pipeline is
the transform authority for those modules, because the Vite-owned semantics
(Contract compilation, automatic-runtime JSX, define/env replacement,
aliases, platform suffixes) are real and must stay single-sourced
(Exact LLP 0413 §9.5). That recommendation names a recognized-fingerprint
registry as its non-negotiable precondition. This RFC is that precondition,
and it is needed under any outcome that keeps root-principal transforms
Vite-owned — which is every option D2 measured as live: adapter-1
publications structurally cannot admit today.

This RFC defines the missing contract. A host-authorized external producer
declares its complete output-affecting pipeline as a **registered external
transform fingerprint**, and the prepared-graph commitment (LLP 0042 —
armed snapshot in production, session-MAC'd credential in development)
carries both the registrations and a **closed transform-authority
assignment**: for each (defining principal, source goal) cell of the
publication, exactly one authority — ibex's own toolchain (the default) or
one named registration. Admission verifies every prepared record against
its assigned authority, exactly; there is no additive "recognized set" a
record can choose from.

The registry **names what transformed the source; it does not bless it**.
Authority labels are commitment-vouched declarations checked against the
assignment, not admission-derived provenance: admission proves that every
record carries exactly the fingerprint its host-authorized assignment
requires, in the right digest domain; the defense against a publication
pipeline that lies about provenance is the arming ceremony's authorization
of that pipeline (LLP 0042's trust model), not a re-derivation ibex cannot
perform. LLP 0028's one-authority claim is preserved at its stated scope:
ibex remains the only *in-process runtime* transform engine, and the only
module-runner/Hermes lowering authority for every artifact it admits.

## Background

### Where the check runs

`verify_current_transform_fingerprint_v1` runs per prepared record in both
admission paths (`src/module_loader/runner_pipeline.rs`): rejoin admission,
and LLP 0042 committed admission (step 6 of its algorithm). The expected
value is the authored transform-configuration manifest (LLP 0028 §1)
rendered per source goal and digested in
`ibex:module-artifact:transform-fingerprint:1`.

### Why only committed admission can ever accept external artifacts

Rejoin admission reconstructs the authenticated inline source graph with
ibex's own producer and requires every cached byte to equal that
deterministic rendering. An externally transformed artifact can never
byte-equal ibex's rendering, so rejoin admission refuses it regardless of
check ordering. External fingerprints are therefore meaningful **only under
committed admission** (LLP 0042), where the commitment vouches for the
publication root. Inline (in-process) production and rejoin admission
remain ibex-fingerprint-only.

### What D2 measured

The bounded adapter-2 comparison (Exact LLP 0416 §D2, 2026-07-29)
established the dimensions an external fingerprint must carry because they
are load-bearing and divergent between the two pipelines today:

- **define/env replacement table** — `import.meta.env.DEV` is read by real
  entry code; Vite defines it, ibex preserves it: divergent observable
  meaning.
- **JSX runtime mode** — ibex pins classic; Vite runs automatic through a
  shim that appears as a graph module.
- **resolution condition set** — custom conditions (`"native"`) join
  resolution identity.
- **alias table and platform-suffix rules** — resolved upstream by Vite;
  platform-suffix resolution is not expressible in ibex-native resolution.
- **Contract compiler identity and options** — a Vite-owned transform whose
  compiler identity joins the fingerprint whichever side packages the
  result (D2 recommendation).

## Terminology

- **External producer**: a host-authorized transform pipeline outside the
  ibex process — concretely, Exact's Vite dev server / build emitting
  canonical per-module JavaScript for the root/app principal (adapter 1).
- **External stage**: the declared ESM-level transform the external
  producer performed (TS/JSX/define/Contract/aliases/suffixes), upstream
  of ibex.
- **Downstream stage**: ibex's own parse-and-lower pipeline (Oxc parse,
  module-runner factory, Hermes-compat lowering, codegen), which runs on
  the external producer's output exactly as it runs on ibex-parsed source.
  Adapter 1 is by construction a *composed* pipeline: external ESM
  transform, then ibex lowering.
- **Registration**: an authenticated record declaring one external stage
  and the complete downstream identity it was lowered under.
- **Authority assignment**: the commitment's closed map from
  (defining principal, source goal) to exactly one transform authority —
  `ibex-toolchain` or a named registration. Absent cells default to
  `ibex-toolchain`.

## Design principles

1. **Naming, not blessing.** Registration is a provenance claim plus an
   authorization to admit. Ibex cannot re-run Vite's transforms;
   verification covers the claim chain (authenticated registration and
   assignment, exact fingerprint match, currency), never semantic
   equivalence. Semantic-parity evidence lives where it can be produced —
   Exact's compat-loader oracle and on-device lanes (LLP 0416 R2/arm C) —
   and is the host's basis for choosing to register, not something
   admission re-derives.
2. **Domain separation.** External composed fingerprints digest in a new
   domain, `ibex:external-transform-fingerprint:1`, disjoint from
   `ibex:module-artifact:transform-fingerprint:1`. No external value can
   collide into ibex's toolchain identity, and vice versa.
3. **Closed sets everywhere.** Registrations and assignments are strict
   I-JSON, canonical JCS, `deny_unknown_fields`; the assignment is a
   closed unique-keyed map, never a pattern or a search. A record whose
   fingerprint is not exactly its assigned authority refuses. This is the
   same closed-variant discipline as LLP 0027's edges and LLP 0042's
   schema.
4. **Composition honesty, no subsetting.** An adapter-1 artifact's
   fingerprint declares *both* stages. The downstream identity is the
   complete current ibex fingerprint value for the record's source goal —
   embedded verbatim, mechanically derived from the authored manifest,
   never a hand-picked subset. Fields that happen not to fire on external
   input (e.g. TypeScript options on already-lowered JS) still rotate the
   identity: over-rotation refuses more than strictly necessary and is
   accepted; subsetting risks admitting stale lowering and is rejected.
5. **Fail-closed currency, per lane.** When ibex's toolchain rotates, every
   registration embedding the old downstream identity goes stale and the
   admission-time currency check refuses it — an ordinary, operative
   refusal in every lane (Currency below). When the external pipeline
   changes anything output-affecting, its stage digest changes, artifacts
   stop matching the registration, and admission refuses until the host
   registers the new stage. The stage schema makes this a schema
   obligation, not host folklore: `pipelineToolsDigest` covers the tool
   closure *and its resolved output-affecting configuration*, so a
   config-only pipeline change rotates the stage digest too.
6. **No semantic downgrade, independent of the commitment.** For source
   whose transform authority is external, ibex's own transform of that
   source must never run as a fallback: the D2 evidence is precisely that
   the two pipelines have divergent observable semantics. Because the
   assignment rides the (optional) commitment, this rule cannot hang off
   the commitment alone — a missing commitment would erase the only fact
   saying the entry is externally owned and select LLP 0042's source
   fallback. Externally owned entries are therefore marked
   **committed-only** on an authority surface that exists independent of
   any publication (below); for them, refusal dispositions are always
   refuse-or-reproduce-under-the-same-authority, never
   substitute-authority.

## Fingerprint wire evolution

`TransformFingerprintV1` (fixed ibex-shaped fields) becomes the first arm
of a closed tagged union, `TransformFingerprintV2`:

```text
TransformFingerprintV2 =
  | { authority: "ibex-toolchain",  ...TransformFingerprintV1 fields }
  | { authority: "composed-external",
      external: ExternalTransformStageV1,
      downstream: TransformFingerprintV1 }   // the complete current ibex
                                             // fingerprint value for the
                                             // record's source goal,
                                             // embedded verbatim
```

- The `ibex-toolchain` arm digests over the V1 value in the existing
  `ibex:module-artifact:transform-fingerprint:1` domain: ibex's own
  transform identity does not rotate merely because the wire grew a tag.
- The `composed-external` arm digests in
  `ibex:external-transform-fingerprint:1` over the canonical composed
  value (both stages). Because `downstream` embeds the whole V1 value —
  including `parser_version`/`transform_version` (the LLP 0028 §1 Oxc
  locked-set identity) and every options digest — any downstream rotation
  rotates every composed fingerprint by construction, with no field
  subsetting to audit.
- **Containing-schema rotations are explicit and complete.** Every closed
  schema that embeds the fingerprint shape rotates: `ibex/module-artifact/1`
  → `/2` (the union itself), and — because the prepared index embeds each
  record's complete semantic core and the carrier manifest embeds artifact
  semantics — `ibex/prepared-module-graph/2` → `/3` and
  `ibex/module-carrier/2` → `/3`, changed only by the embedded artifact
  version. The cache-key digest covers the artifact schema (LLP 0027), so
  all cache entries rotate even though the ibex-arm fingerprint digest is
  unchanged. Prepared publications are regenerable writable-cache material
  (LLP 0027 posture): an old-schema publication refuses canonical decoding
  and is cold-rebuilt under the current producer (all-ibex lanes; external
  lanes follow the committed-only dispositions below). No dual-decoding
  window, no nested-version negotiation.
- `verify_current_transform_fingerprint_v1` and both producers change to
  emit/decode the `ibex-toolchain` arm of the union; "unchanged" below
  always means *unchanged expected identity*, not unchanged wire code.

## External stage declaration

```text
ExternalTransformStageV1 {
  schema                     // exactly "ibex/external-transform-stage/1"
  producer                   // non-reserved id, e.g. "exact-vite-root-transformer";
                             // ids with the "ibex-" prefix refuse at validation
  pipelineToolsDigest        // digest over the resolved output-affecting tool
                             // closure (Vite, esbuild/rolldown, plugin set —
                             // source/version/checksum) AND its resolved
                             // output-affecting configuration (plugin options,
                             // optimizer/chunking settings): the external
                             // analogue of LLP 0028 §1's locked set + option
                             // set, minus the tables enumerated below
  ecmascriptOutputTarget     // declared output target; v1 must equal the
                             // downstream manifest's target ("es2022") —
                             // checked at committed admission with the other
                             // currency checks
  jsx {                      // explicit, not digested: load-bearing semantic
    runtime                  //   switch — "automatic" | "classic"
    importSource?            //   for automatic
    dev                      //   dev-transform flag
  }
  defineTableDigest          // env/define replacement table digest
  conditions[]               // explicit ordered resolution condition set
  aliasTableDigest           // alias table digest
  platformSuffixRules[]      // explicit ordered suffix list, e.g.
                             //   [".native", ".ios"] — empty when unused
  contractCompiler? {        // present iff Contract compilation ran
    name, version,
    optionsDigest
  }
  sourcemapPolicy            // e.g. "v3-original-source"
}
```

Field-shape rationale: values admission diagnostics and cross-checks must
*read* (JSX runtime, conditions, suffix rules, Contract identity) are
explicit; unbounded tables (define/env, aliases, plugin closure) are
digests over canonical renderings the external producer must be able to
re-emit for audit. Every field is output-affecting; nothing advisory rides
in the stage. The digests are producer-conformance obligations under the
naming-not-blessing trust model — admission verifies digest equality, not
that the preimage honestly enumerates the configuration; the
implementation must pin each digest's canonical preimage recipe and
domain so registrations are auditable, which is where the obligation is
enforced.

## Registration and authority assignment

A registration declares one composed identity; it carries no scope:

```text
ExternalTransformRegistrationV1 {
  schema                     // exactly "ibex/external-transform-registration/1"
  sourceGoal                 // the goal this registration's downstream value
                             // renders — assignments must match it, so a
                             // goal-mismatched assignment is a validation
                             // error, not a misleading admission STALE
  stage                      // ExternalTransformStageV1
  downstream                 // TransformFingerprintV1 — the complete ibex
                             // fingerprint value the stage was lowered for
}
```

Scope lives entirely in the commitment's assignment table:

```text
TransformAuthorityAssignmentV1 {
  principal                  // defining-principal identity
  sourceGoal                 // "module" | "json"  ("common-js" and
                             // "builtin" refuse at validation in v1)
  authority                  // "ibex-toolchain"
                             //   | { registration: <registration identity> }
}
```

Two identities are deliberately distinct. The **registration identity** —
digest of the canonical whole registration value (schema, sourceGoal,
stage, downstream) in a new `ibex:external-transform-registration:1`
domain — is what assignments name and what registration uniqueness is
keyed by; it covers `sourceGoal`. The **composed fingerprint digest** (the
artifact-side `ibex:external-transform-fingerprint:1` value over `stage` +
`downstream`) is what records carry; it need not cover the goal, because
admission reaches a registration only through a goal-matched assignment.

The commitment (both classes) gains two sections: `externalTransforms`
(registrations, canonically sorted, unique by registration identity) and
`transformAuthorities` (assignments, canonically sorted, **unique by
(principal, sourceGoal) key**). A cell with no assignment defaults to
`ibex-toolchain`; `builtin`-goal records are structurally unassignable and
always ibex. A duplicate key refuses at commitment validation, so a
validated commitment holds exactly one authority per cell and admission
resolves it by lookup, never by searching among competing candidates — one
observable meaning per module (Exact LLP 0413 §9.5) as a validated-schema
property. A publication may still mix transform authorities **across**
principals — the D2 end-state (external root/app principal, ibex-produced
dependency principals) — but never within one (principal, goal) cell.

The publication preparer and the transform authority remain distinct
facts: the commitment's single `producer` binds who wrote the publication;
`transformAuthorities` binds what transformed each cell's source.

## Validation and admission

### At commitment validation (`ArmedSnapshot::load` / dev-credential mint)

Only self-contained facts — this site has neither the cache index nor the
module loader's authored-manifest constants (LLP 0042's ceremony validates
without opening the cache, and the CapSec layer does not own the transform
manifest):

- schema literals of both sections; canonical sorting; uniqueness
  (registrations by registration identity, assignments by
  (principal, goal));
- reserved-producer refusal (`ibex-` prefix in `stage.producer`);
- goal well-formedness (`builtin`/`common-js` assignments refuse);
- every external assignment names a carried registration by registration
  identity, **whose `sourceGoal` equals the assignment's** (a goal
  mismatch is a validation error here, never an admission `STALE`);
  carried registrations that no assignment names refuse (dead authority
  is a misconfiguration, not inventory);
- committed-only consistency: a commitment carrying any external
  assignment is valid only for an entry marked committed-only (below).
  In production both facts live in the snapshot and this is self-contained
  at load. In development the marking lives in the *consumer's* embedding
  configuration, which the minting producer cannot see: the enforcement
  boundary is therefore the consumer's entry-bound marking check before
  any dev committed admission; a mint-time check is defense in depth
  where the producer has visibility, never the guarantee.

### At committed admission (module loader, after the root check)

Step 6 of the LLP 0042 algorithm is replaced by
`verify_transform_fingerprint_currency_v2(semantics, principal, authorities)`.
Per record, resolve the assignment for (defining principal of the binding
carrier, source goal), defaulting to `ibex-toolchain`, then:

1. **Assigned `ibex-toolchain`:** the record's fingerprint must be the
   `ibex-toolchain` arm and its digest must equal the current configured
   fingerprint for the record's source goal — the check as it exists
   today. A `composed-external` record here refuses
   (`IBEX_TRANSFORM_FINGERPRINT_AUTHORITY`).
2. **Assigned external:** the record's fingerprint must be the
   `composed-external` arm; its embedded value must canonically equal the
   assigned registration's `stage` + `downstream` (digest equality is
   necessary; byte equality is the check); and the registration's
   `downstream` must equal the *current* authored manifest for the
   record's goal, including the `ecmascriptOutputTarget` equality above.
   An `ibex-toolchain`-arm record here refuses
   (`IBEX_TRANSFORM_FINGERPRINT_AUTHORITY`) — masquerading as ibex is a
   refusal against the assignment, not a pass into leg 1. Stale
   `downstream` refuses (`IBEX_TRANSFORM_FINGERPRINT_STALE`); an
   unmatched external digest refuses
   (`IBEX_TRANSFORM_FINGERPRINT_UNRECOGNIZED`).
3. **Cross-checks:** every assignment key must be inhabited — an
   assignment whose exact (principal, sourceGoal) cell matches no record
   in the publication refuses (facet-mismatch class: the commitment and
   publication disagree about what exists; a dangling principal is the
   degenerate case). Rejoin admission and inline production keep the
   ibex-only expected identity.

### Committed-only entries and refusal disposition

The no-downgrade rule (principle 6) needs a fact that survives the
commitment's absence, because the assignment rides the commitment and the
commitment is optional (LLP 0042: no commitment → rejoin/cold source
behavior). That fact is a **committed-only marking** per entry, carried on
the lane's standing authority surface:

- **Production:** a new armed-snapshot sibling section,
  `committedOnlyEntries` (canonical, unique `entrySourceId` list),
  validated by `ArmedSnapshot::load` alongside `preparedGraphs`. A
  committed-only entry admits **only** via committed admission: no rejoin,
  no cold source preparation, whether the refusal is a failed admission
  step or a missing/omitted commitment for that entry. The snapshot digest
  covers the section; omitting the commitment while the marking stands
  refuses startup rather than selecting source fallback. (A host-authored
  snapshot that carries neither section is an ibex-transformed deployment
  and is out of this contract's scope; whole-snapshot replay/rotation is
  the arming ceremony's domain, LLP 0042. The marking is per entry — the
  unit LLP 0042 commits at — so a snapshot that marks entry A but ships a
  second, unmarked entry over the same externally owned tree has authorized
  ibex transformation of that tree for entry B; as in development, the
  contract-enforceable guarantee begins at the marking, and not marking an
  externally owned entry is the host's ceremony-authenticated
  responsibility.)
- **Development:** there is no snapshot; the marking is host embedding
  configuration supplied by the consuming app (Exact declares its dev
  entries committed-only), not something the credential can carry —
  a consumer that cannot reach a live producer has no credential at all,
  so the consumer's own entry-bound marking check before any committed
  admission (and before any cold start) is the enforcement boundary.
  With the marking, a missing credential or any refusal fails the entry;
  the consumer requests a fresh publication from the live producing
  session (session-minted credential, LLP 0042) — reproduce under the
  same authority, never substitute. Without the marking, a commitment-less
  dev cold start of the same tree through ibex is structurally
  indistinguishable from an ordinary ibex project and is the host's
  responsibility to prevent; the contract-enforceable guarantee begins at
  the marking.

LLP 0042's refuse-then-cold-rebuild rule is hereby **scoped**: it applies
only to entries not marked committed-only. For marked entries every
refusal is terminal (production) or reproduce-from-producer (development).
Rebuilding through ibex would silently change program semantics (D2:
Contract, define table, JSX runtime, suffixes), which is worse than
failing visibly.

### Currency, per lane

The admission leg-2 downstream check (`STALE`) is an **ordinary, operative
refusal in every lane**. The armed snapshot's `engine.binaryDigest` pins
the loaded *Hermes engine artifact* (`loaded_engine_artifact_path`,
`src/engine/mod.rs`), not the ibex loader binary that compiles in the
authored manifest; on framework/dylib configurations those are different
files, so an ibex toolchain rotation can leave a previously authenticated
snapshot armable and reach admission with stale registrations. Where the
engine artifact and the loader are one file (single-file executables, LLP
0029), rotation additionally refuses at arming — an earlier refusal, not a
substitute for the admission check. In development the consumer binary is
likewise unpinned from the registration's minting context (cross-process
warm start, LLP 0042 open question 1 — the dev registration lane inherits
that open dependency and is not independently landable). In all lanes a
`STALE` refusal follows the committed-only dispositions above.

## Refusal matrix

| case | disposition |
|---|---|
| adapter-1 record, assigned registration matches, downstream current | admits (the issue's acceptance line) |
| record's composed digest matches no registration / not the assigned one | refuse `UNRECOGNIZED`; no-substitute-authority disposition |
| `ibex-toolchain`-arm record in an externally assigned cell (masquerade) | refuse `AUTHORITY`; no-substitute-authority disposition |
| `composed-external` record in an ibex-assigned or unassigned cell | refuse `AUTHORITY` |
| registration `downstream` ≠ current authored manifest | refuse `STALE` — ordinary, operative refusal in every lane; committed-only disposition follows |
| external stage changed, registration not updated | composed digest mismatch → refuse `UNRECOGNIZED` |
| committed-only entry with a missing/omitted commitment (production) or unreachable producer (development) | refuse the entry — no rejoin, no cold source preparation, no ibex substitute |
| registration with `ibex-`-prefixed producer id | refuse at commitment validation, before any admission |
| assignment for `builtin` or `common-js` goal; duplicate (principal, goal) key; goal-mismatched assignment↔registration; dangling or unused registration; external assignment without the committed-only marking | refuse at commitment validation |
| assignment whose (principal, sourceGoal) cell is uninhabited in the publication | refuse at admission (facet-mismatch class) |
| `composed-external` record arriving via rejoin/inline path | refuses: rejoin's expected identity is ibex-only, and its byte-compare against ibex's rendering cannot match externally transformed bytes |
| dev registration/assignment replayed into a production snapshot | refuses structurally: the sections ride the dev commitment, whose schema `ArmedSnapshot::load` rejects in `preparedGraphs` (LLP 0042) |

## What the contract does not claim

An assignment does not assert that the external pipeline's output is
semantically equivalent to what ibex would have produced, and admission
never checks that. The registered lane's correctness rests on the oracle
evidence the host gathered before registering (Exact's compat-loader
round-trips and on-device arm C in LLP 0416) and on the external pipeline
being the *single* source of those semantics — which the unique assignment
key makes structural. Nor does admission derive *who produced* a record's
bytes: authority arms are commitment-vouched declarations checked against
the assignment. A publication pipeline that lies about provenance is a
compromised pipeline, and the defense is the arming ceremony's
authorization decision (LLP 0042's trust model), not admission forensics.

## Fixtures and adversarial gate

Production-shaped fixtures in the LLP 0042 suite pattern, runnable under
`unadvertised-dev-arming` (LLP 0038) before deployment tooling exists:

1. A minimal adapter-1-shaped publication (externally lowered JS factory,
   composed fingerprint) admits under a commitment carrying its
   registration and assignment — the issue's first acceptance line.
2. Every refusal-matrix row above has a fixture, including: single-byte
   tamper in the embedded stage value (digest mismatch); masquerade both
   directions (`AUTHORITY` rows); stale-downstream registration refused as
   an ordinary `STALE` in both lanes; duplicate assignment key,
   goal-mismatched assignment, dangling/unused registration,
   reserved-producer registration, and external-assignment-without-marking
   all refused at validation; the uninhabited-cell facet mismatch.
3. **No-downgrade fixtures:** for a committed-only entry, a deleted,
   tampered, and stale publication — **and a missing/omitted commitment or
   credential** — each refuse the entry (or, in the dev harness, trigger
   reproduce-from-producer), asserting the absence of any ibex
   cold-rebuild of externally owned source in every refusal path.
   Sequencing: the production-shaped suite lands with this contract; the
   dev-harness legs are gated on the LLP 0042 open-question-1 transport
   and do not block it.
4. A commitment with no external sections admits pure-ibex publications
   identically to today, and the LLP 0042 fallback behaves exactly as
   specified there (behavioral no-op guarantee).
5. Rotation tests per LLP 0028 §1 discipline: each downstream manifest
   component (Oxc locked set, handwritten pass, runner ABI, Hermes-compat,
   codegen options, target) rotates the composed digest and flips the
   fixture from admit to the correct refusal.

## Required sibling revisions

Landing this contract revises five governing documents in the same change
(corpus rule: doc updates land with the code they motivate):

- **LLP 0042:** the refuse-then-cold-rebuild rule gains the committed-only
  scoping above; the snapshot gains `committedOnlyEntries`; the commitment
  schema rotates to `ibex/prepared-graph-commitment/2` (and dev `/2`)
  adding the two sections. Per the closed-schema discipline the sections
  are not additive-optional inside `/1`: a `/1` commitment refuses under a
  `/2`-expecting loader and deployment tooling re-emits.
- **LLP 0027:** owns the artifact envelope, fingerprint field, digest-
  domain inventory, and cache-key composition — revised for the
  fingerprint union, the `ibex/module-artifact/2`,
  `ibex/prepared-module-graph/3`, and `ibex/module-carrier/3` rotations,
  and the two new domains/schema ids.
- **LLP 0028:** the acceptance line "one engine, one fingerprint domain"
  is rescoped to the in-process/inline lane, which remains single-engine
  and single-domain; committed admission's second domain is named there
  with a pointer here.
- **LLP 0026:** its trusted-producer enumeration (the in-process transform
  under host authority and the build-time Rolldown/Oxc producer) gains the
  third, committed-admission-only class this contract defines: a
  registered external producer under a host-authorized assignment.
- **LLP 0029:** `StubContractV1` pins the accepted carrier schema
  (`schemas/stub-contract-v1.schema.json`, `src/compiled_contract.rs`:
  `ibex/module-carrier/2`); the `/3` rotation rotates the compiled-stub
  compatibility contract and catalog artifacts even for all-ibex
  executables — the pin moves to `/3`, stub/catalog digests migrate, and
  old-stub/new-carrier refusal-and-rebuild fixtures land with it.

## Migration and coexistence

- The schema rotations (`ibex/module-artifact/2`,
  `ibex/prepared-module-graph/3`, `ibex/module-carrier/3`, commitment
  `/2`) invalidate existing prepared publications and commitments;
  publications refuse canonical decoding and cold-rebuild under the
  current producer (all-ibex lanes), and commitments are re-emitted by
  their producing tooling. Cache keys rotate via the artifact-schema
  component of the cache-key digest.
- With no external sections present, admission behavior is equivalent to
  today's: one expected identity per goal, LLP 0042 fallback unchanged.
- The adapter-1 integration lands consumer-side in Exact against this
  contract; nothing in ibex depends on Exact's timeline.

## Open questions

1. **Pipeline-tools digest granularity.** Is one locked-set digest over
   the whole Vite/plugin closure the right audit unit, or should the
   optimizer be named separately (the Contract compiler already is), so
   rotation diagnostics can say which tool moved? Current answer: one
   digest plus explicit Contract identity; revisit when the first real
   registration is authored.
2. **`common-js` external goal.** Adapter 1's root principal is ESM-goal;
   D2's dependency-principal end-state is adapter 2 (ibex-produced), so v1
   refuses external `common-js`. If a real lane needs externally
   transformed CJS, the detector-identity fields must join
   `ExternalTransformStageV1` first.
3. **Registration expiry beyond downstream rotation.** Should production
   commitments additionally carry a validity horizon so an
   old-but-internally-consistent snapshot cannot admit an old external
   lane indefinitely? The assignment already binds to one commitment,
   which binds one deployment graph; interacts with LLP 0042 open
   question 6 (retention).
4. **Receipt naming.** Committed-admission receipts (LLP 0042) should name
   the resolved authority per (principal, goal) (`ibex-toolchain` vs
   registered producer id) so startup diagnostics and the LLP 0039
   banners can show when externally transformed code is running. Exact
   shape is implementation-phase.
5. **Dev reproduce-on-refusal mechanics.** The development disposition
   (request a fresh publication from the live producing session) rides the
   unresolved LLP 0042 open question 1 transport; whether refusal triggers
   an automatic republish or surfaces to the developer is that design's
   call.
