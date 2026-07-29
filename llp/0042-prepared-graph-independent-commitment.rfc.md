# LLP 0042: Independent Prepared-Graph Commitment

**Type:** RFC
**Status:** Draft
**Systems:** Module Loader, CapSec, Arming, Security, Host Embedding
**Author:** Charlie Cheever / Claude
**Date:** 2026-07-28
**Related:** LLP 0026 (module runner; Phase 4 writable-cache honesty
paragraph); LLP 0027 (ModuleArtifact wire, prepared graph v2, carrier v2);
LLP 0036 (target advertisement completion); LLP 0038 (unadvertised dev
arming); LLP 0039 (secure and insecure modes); Exact LLP 0413 §5.7/§15/§16
(parse-free native HBC startup — external, Exact repo);
issues/20260728-prepared-graph-independent-commitment.md

## Summary

The prepared-module cache (`ibex/prepared-module-graph/2`) is deliberately
not a trust root today: `load_prepared_source_graph_v1`
(`src/module_loader/runner_pipeline.rs`) first **reconstructs the
authenticated inline source graph**, renders its deterministic publication,
and requires every cached byte to equal that rendering. That is a safe
source-mode acceleration, and it necessarily parses application source on
every warm reload, so it cannot satisfy a parse-free prepared startup gate
(LLP 0026 Phase 4; Exact LLP 0413 §5.7).

This RFC specifies the missing authority: an **independent prepared-graph
commitment** — a small authenticated record, held outside the writable
cache, that binds the prepared publication root. Admission against the
commitment verifies the cached index, carriers, and artifacts by digest
alone and never acquires, parses, or re-renders application source.

Two commitment classes exist and are never interchangeable:

- **Production** (`ibex/prepared-graph-commitment/1`): a field of the armed
  snapshot, authenticated by the existing arming ceremony
  (`ArmedSnapshot::load`).
- **Development** (`ibex/prepared-graph-commitment-dev/1`): a run/session-
  scoped credential minted by the producing session, explicitly and visibly
  non-production.

The adversarial contract is the ticket's acceptance line: an attacker who
substitutes a fully self-consistent index/carrier set — every cache-local
digest recomputed correctly — MUST still be refused, because the
substituted publication root does not match the independent commitment.

## Terminology

- **Prepared publication**: the deterministic byte set the preparer writes
  into a graph's cache directory — canonical `index.json`
  (`ibex/prepared-module-graph/2`), per-principal carrier manifests and
  bytes (`ibex/module-carrier/2`), and `ibex/computed-candidates/1`
  sidecars (LLP 0027).
- **Publication root digest**: the digest of the canonical JCS bytes of
  `index.json`. Because the index binds every carrier digest, artifact
  semantic digest, resolved edge, and sidecar digest (LLP 0027 §"Digest
  domains"), committing the index root transitively commits the entire
  publication.
- **Committed admission**: the new warm path that admits a publication
  against a commitment with zero application-source parsing.
- **Rejoin admission**: today's path — reconstruct the authenticated source
  graph, byte-compare the publication. It survives as the source-mode
  acceleration.

## Design principles

1. **The cache never authenticates itself.** No digest stored in the cache
   directory, however internally consistent, contributes trust. Trust
   enters only through the commitment (production: arming ceremony; dev:
   session credential) exactly as source trust enters only through the
   authenticated source graph today.
2. **One root digest, plus cross-checked facets.** The publication root
   digest is sufficient for integrity. The commitment nevertheless carries
   explicit target, producer, semantic-inventory, principal-set, and policy
   facets so that (a) mismatches refuse with a specific diagnostic, (b) the
   arming ceremony can validate the commitment against the snapshot's own
   engine/policy identity without opening the cache, and (c) a future
   multi-publication snapshot can be searched without parsing indexes.
3. **Dev authority is a different kind, not a weaker amount.** The dev
   commitment has a distinct schema id, a distinct digest domain, a
   `workflow: "development"` marker, and a bounded lifetime. Production
   admission refuses it structurally (unknown schema), not by policy.
4. **Refusal, then cold rebuild — never mid-run source fallback.** A
   commitment mismatch discards the cache and re-prepares from the
   authenticated source graph *before* any application evaluation begins,
   preserving Exact LLP 0413 §5.4.

## Production commitment

### Schema

`ibex/prepared-graph-commitment/1`, strict I-JSON, canonical JCS, closed
fields (`deny_unknown_fields` discipline as in LLP 0027):

```text
PreparedGraphCommitmentV1 {
  schema                     // exactly "ibex/prepared-graph-commitment/1"
  workflow                   // exactly "production"
  target                     // exact engine target tuple; must equal the
                             // armed snapshot's engine.target
  entrySourceId              // canonical authenticated LLP 0023 encoding of
                             // the graph entry
  deploymentGraphDigest      // the authenticated deployment-graph digest
                             // this publication was prepared for
  publicationRootDigest      // digest of the canonical index.json bytes,
                             // domain "ibex:prepared-publication-root:1"
  producer {
    id                       // e.g. "ibex-rolldown-module-preparer"
    binaryDigest             // prepared-producer binary digest
  }
  semanticInventoryDigest    // digest over the canonically sorted set of
                             // member semantic digests, domain
                             // "ibex:prepared-semantic-inventory:1"
  principalSetDigest         // digest over the canonically sorted set of
                             // defining-principal identities of all
                             // carriers, domain
                             // "ibex:prepared-principal-set:1"
  policyDigest               // must equal the armed snapshot's policyDigest
}
```

Notes:

- `semanticInventoryDigest` replaces the role that
  `authorized_semantic_digests` (derived from the reconstructed source
  graph) plays in rejoin admission: it is the closed authorization set for
  `ArtifactAdmissionV1::DigestBoundPrepared` and carrier admission.
- `principalSetDigest` preserves LLP 0027's one-principal-per-carrier
  constraint as a committed fact, so a substituted publication cannot
  smuggle a new defining principal even if its index is otherwise shaped
  correctly.
- Engine identity is deliberately **not** duplicated here. HBC carriers
  already bind a closed engine identity (`loaded-file` /
  `static-compatibility`, LLP 0027), verified at carrier admission against
  the actually loaded engine; the armed snapshot separately authenticates
  `engine.binaryDigest`. Recording it a third time would create a second
  authority for the same fact.

### Binding surface

The commitment is a new optional armed-snapshot section, `preparedGraphs`:
an array of `PreparedGraphCommitmentV1` values (one per prepared entry the
deployment ships). `ArmedSnapshot::load` (crates/capsec-semantics/src/
arming.rs) validates, for each element: schema and workflow literals,
`target == engine.target`, `policyDigest == policyDigest` of the snapshot,
canonical sorting and uniqueness by `entrySourceId`. The snapshot digest
already covers the whole document, so the commitment inherits the arming
ceremony's authentication and its tamper story; no new signing mechanism is
introduced.

The section is unavailable to the writable cache by construction: the
snapshot is authenticated before any module-loader code runs, and nothing
under the cache directory participates in producing it.

An armed host without a `preparedGraphs` entry for the requested entry has
**no committed admission**; it may still use rejoin admission (source
mode). This is the complete production posture until deployment tooling
emits commitments.

### Committed admission algorithm

New entry point (working name `load_prepared_graph_committed_v1(cache_dir,
commitment)`), replacing the `authenticated_source_graph` parameter of
`load_prepared_source_graph_v1` with the commitment:

1. **Retain the index.** Read `index.json` with the existing no-follow,
   regular-file, exact-read discipline (`read_authenticated_prepared_file`
   generalized to digest-expectation: the expected length is not known a
   priori, so the read is bounded by a hard limit and verified by digest,
   not by byte-compare).
2. **Root check.** Parse strict JSON, canonicalize to JCS, require the
   canonical bytes to equal the raw bytes, digest in the
   `ibex:prepared-publication-root:1` domain, require equality with
   `publicationRootDigest`. **This is the independence gate.** Everything
   after this step consumes bytes the commitment has vouched for.
3. **Facet cross-checks.** Require index schema
   `ibex/prepared-module-graph/2`, `deployment_graph_digest`,
   `producer_binary_digest`, and entry identity to equal the commitment's
   fields; recompute the semantic-inventory digest from the index's record
   semantic digests and the principal-set digest from its carrier
   inventory, and require equality. A mismatch here is a corrupt-or-forged
   publication *and* a bug (step 2 should have caught it); refuse with a
   distinct diagnostic.
4. **File inventory.** Enumerate the cache directory and require exactly
   the files the index names (as today), reading each carrier manifest,
   carrier byte file, and candidate sidecar once through the retained-
   descriptor discipline, verified against the digests the index binds.
5. **Carrier and artifact admission.** Run the existing
   `AdmittedPreparedCarrierV2::decode_and_admit` and
   `ModuleArtifactV1::verify_for_admission` exactly as rejoin admission
   does, with `authorized_semantic_digests` taken from the committed index
   (authorized transitively by `semanticInventoryDigest`) and engine
   binding checks for HBC carriers unchanged.
6. **Transform-fingerprint currency.**
   `verify_current_transform_fingerprint_v1` still runs per record: a stale
   toolchain refuses even a correctly committed publication.
7. **What is skipped, explicitly.** No inline source graph is built; no
   application source file is opened, hashed, or parsed;
   `authenticate_prepared_module_record` (the per-record source-path/
   integrity re-authentication) does not run. The artifact's
   `source_integrity` remains bound in the semantic digest as provenance,
   but committed admission does not check it against any live file. On-disk
   source drift is invisible to the warm path **by design** — production
   deployments do not serve source, and development drift detection belongs
   to the producing session (below), not to admission.

Any refusal at any step discards the publication and falls back to cold
preparation from the authenticated source graph, before application
evaluation begins. There is no partial acceptance and no mixed
committed/rejoin graph.

## Development commitment

Development needs warm parse-free reloads long before deployments exist,
and Exact Debug currently runs an unarmed diagnostic runtime (Exact LLP
0413 §15). The dev commitment is that lane's authority — Exact LLP 0413's
"Option 2", implemented as a contract rather than as relaxed admission.

### Credential shape

`ibex/prepared-graph-commitment-dev/1`: the same facet fields as
production, with these differences:

- `workflow` is exactly `"development"`.
- A `session` object: `{ runId, generation, issuedAtMs }` where `runId` is
  a fresh random nonce per producing session (dev server run or
  single-process run) and `generation` is the graph generation the
  publication was prepared from.
- A `binding` MAC: HMAC over the canonical commitment body under a
  per-session secret held **only in the producing session's process
  memory** (and its spawned session workers, passed through the existing
  worker-snapshot handoff — the LLP 0038 `prepare_session_worker_runtime`
  seam). The secret never touches disk and never enters the cache
  directory.

### Binding surface and lifetime

The dev commitment travels on the channel that already carries trust in
development: the dev-served record seam (the `dev-served` bootstrap
compatibility mode the armed snapshot enumerates). The producing session
mints the commitment at publication time and delivers it in session state /
over the local authenticated dev channel alongside the served graph
metadata — never as a file in the cache directory. A consuming warm start
that cannot obtain a live commitment from a running producer has no
committed admission and uses rejoin or cold preparation.

This is an honest trust statement, not a weakening: in development the dev
server is already the source-of-truth for what code runs. The dev
commitment does not defend against a compromised dev server; it defends
against exactly one thing — the writable cache directory becoming an
authority. A self-consistent cache substituted on disk fails step 2 because
the producing session never committed that publication root.

Lifetime and revocation:

- Valid only within the minting session (`runId` must match the live
  session; a restart mints a new secret, revoking everything prior).
- Superseded by generation advance: publishing generation N+1 revokes the
  generation-N commitment; admission against a superseded commitment
  refuses.
- Explicitly revocable: the producer drops the session record (e.g. on a
  watch event that invalidates the graph) and admission thereafter refuses.

### Visible non-production

- Distinct schema id and distinct digest/MAC domains; production admission
  refuses the dev schema structurally, before any field comparison.
- The armed production path (`preparedGraphs` in an armed snapshot) can
  never carry a dev commitment: `ArmedSnapshot::load` rejects the dev
  schema in that section.
- Every committed admission emits an admission receipt naming the
  authority class; the dev class is marked `authority:
  development-session (non-production)` in diagnostics and in the startup
  phase log, in the spirit of the LLP 0038/0039 banners.
- A build that admits under a dev commitment must not report itself as
  prepared production startup (LLP 0026 Phase 4's advertising prohibition
  stays in force until the production path is verified end to end).

### Relationship to LLP 0038

`unadvertised-dev-arming` synthesizes target cells but leaves every other
startup authenticator intact, including snapshot authentication. Therefore:
a feature-on secure build with a real (or synthesized-cells) armed snapshot
may exercise the **production-shaped** commitment end to end in CI, which
is how the fixture suite runs before LLP 0036 lands. The dev commitment is
orthogonal to arming mode: it exists for sessions whose graphs are produced
live and change under HMR, whatever the arming posture. Neither commitment
class widens any capability decision; admission consumes authority, it
never mints it.

## Adversarial gate and fixtures

The named fixture family is `prepared-commitment-substitution` (extending
the LLP 0027 tamper matrix), all of which must refuse **before any factory
evaluation or effect**:

1. **Self-consistent substitution (the gate).** Prepare and commit graph A.
   Prepare graph B (one module differing in behavior) with the genuine
   preparer so that its publication is fully self-consistent — canonical
   index, correct carrier digests, correct semantic digests, correct
   sidecar digests. Substitute B's publication into A's cache directory.
   Committed admission MUST refuse at the publication-root check, and the
   diagnostic MUST name commitment mismatch, not byte corruption.
2. **Recomputed-root variant.** As (1), plus the attacker rewrites every
   cache-local cross-reference so the substituted index is internally
   perfect. Same refusal — nothing in the cache can compensate for the
   root digest.
3. **Facet tamper.** Commitments whose `target`, `producer.binaryDigest`,
   `deploymentGraphDigest`, `policyDigest`, `semanticInventoryDigest`, or
   `principalSetDigest` disagree with an otherwise matching publication:
   each refuses with its distinct diagnostic.
4. **Class confusion.** A dev-schema commitment presented to production
   admission (and embedded in a `preparedGraphs` snapshot section) refuses
   structurally; a production-schema commitment presented without an armed
   snapshot refuses; a dev commitment with a stale `runId` or superseded
   `generation` refuses.
5. **Parse-free witness.** The committed warm path runs under an
   instrumented producer that fails the test if any source acquisition,
   transform, or parse of application source is invoked (the LLP 0413 §5.1
   artifact-property discipline applied at fixture level).

Fixture (1)/(2) are the acceptance criteria from
issues/20260728-prepared-graph-independent-commitment.md and Exact LLP 0413
§14 item 15.

## Migration and coexistence

- **Rejoin admission remains, as source mode.**
  `load_prepared_source_graph_v1` is not deprecated by this RFC: when no
  commitment is available (plain `ibex run`, no deployment, no live dev
  session), the byte-compare rejoin path remains the correct — and
  honest — acceleration of source startup. It parses source; it says so.
- **What flips when a commitment exists.** For a given entry, admission
  mode is selected before graph work begins: commitment present ⇒ committed
  admission (parse-free); absent ⇒ rejoin or cold. The two modes never mix
  within one startup, and a committed-admission refusal falls back to cold
  preparation, never to rejoin-then-accept (rejoin acceptance of a
  publication the commitment refused would reintroduce the cache as a
  de facto authority).
- **Preparer changes.** The preparer additionally emits the commitment
  facets (root digest, inventory digest, principal-set digest) at
  publication time; deployment tooling copies them into the armed
  snapshot's `preparedGraphs`; the dev producer mints the session
  credential from the same facets.
- **Advertising gate.** Only after committed admission and the
  substitution fixtures are green may Ibex describe the cache path as
  prepared production startup; LLP 0026's Phase 4 honesty paragraph is then
  revised to point here.

## Diagnostics

Committed admission logs one line per startup: authority class
(production-armed | development-session), entry, publication root digest
prefix, carrier count, admission duration, and — for dev — runId prefix and
generation. Refusals carry stable diagnostic codes per facet so Exact's
startup phase attribution (LLP 0413 §13) can distinguish "commitment
missing" (expected, source mode) from "commitment mismatch" (alarm).

## Open questions

1. **Dev binding transport.** Is session-state delivery over the dev-served
   seam sufficient for the cross-process warm start Exact needs (native app
   restarts while the dev server keeps running), or does the credential
   need an OS-level session store? The MAC design supports either, but the
   handoff for a *newly launched* consumer process needs a concrete channel
   (Exact LLP 0413 §16 Q14 — decision-blocking for the Exact integration).
2. **Snapshot schema evolution.** Does adding `preparedGraphs` require an
   armed-snapshot schema-version bump, and what do existing armed
   deployments (none yet in production, per LLP 0036/0039) require for
   rollout?
3. **Multi-entry and profile splits.** One commitment per entry is assumed;
   should route/profile split graphs (Exact LLP 0128 diet) share one
   commitment with multiple entries, or one commitment each?
4. **Source-integrity provenance in committed mode.** Committed admission
   deliberately skips live source re-authentication. Should it additionally
   record the skipped `source_integrity` set in the admission receipt so a
   post-hoc audit can compare against served source, or is that receipt
   noise?
5. **Bounded index read.** Step 1 needs a hard size bound before digesting
   an unauthenticated file; what is it, and is it commitment-carried
   (explicit `publicationRootLength`) or a fixed policy constant?
6. **Retention.** When a commitment is superseded (new deployment, dev
   generation advance), who garbage-collects the now-unadmittable
   publication directories (Exact LLP 0413 §16 Q10 overlaps)?
