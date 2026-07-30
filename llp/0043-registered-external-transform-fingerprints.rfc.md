# LLP 0043: Registered External Transform Fingerprints

**Type:** RFC
**Status:** Draft
**Systems:** Module Loader, Transforms, CapSec, Arming, Security, Host Embedding
**Author:** Charlie Cheever / Claude
**Date:** 2026-07-30
**Revised:** 2026-07-30 (initial draft)
**Related:** LLP 0027 (ModuleArtifact wire; `transform_fingerprint`
composition and digest domains); LLP 0028 (Oxc-only transform authority —
the principle this registry must not weaken); LLP 0042 (independent
prepared-graph commitment — the authorization surfaces this design rides);
LLP 0019 (hermes-compat passes; the canonical for-of repair); LLP 0038
(unadvertised dev arming); Exact LLP 0416 §D2 + D2 measurement (external);
Exact LLP 0413 §9.5/§15 (external);
issues/20260729-transform-fingerprint-registry-contract.md;
issues/20260729-prepared-graph-development-session-commitment.md

## Summary

`verify_current_transform_fingerprint_v1` has exactly one authority today:
ibex's own pinned transform configuration
(`config/module-transform.json` → the generated fingerprint constants). An
artifact whose `transform_fingerprint` digest differs from the active
configuration refuses. That is correct for ibex-produced artifacts and
structurally fatal for the one lane Exact LLP 0416's D2 resolution
selected: **adapter 1**, where Exact's Vite pipeline produces the
root/app-principal publication (`exact-vite-prepared-graph-producer`,
esbuild lowering, the vendored for-of repair, Contract compiled upstream)
and declares an honest fingerprint that is not — and must never claim to
be — ibex's. The D2 slice drove admission with harness-supplied
expectations and deliberately skipped fingerprint currency; a production
integration cannot.

This RFC specifies the missing contract: a **registry of external
transform fingerprints**. A registration is a small closed record naming a
specific external producer, its per-tool identities, and the semantic
transform dimensions the D2 measurement proved load-bearing (define/env
replacement table, JSX runtime mode, resolution condition set,
platform-suffix rules, Contract compiler identity, the for-of repair pass
identity). Registrations are authorized exactly the way prepared-graph
commitments are (LLP 0042): in production as an additive section of the
armed snapshot; in development bound to the session commitment credential.
Admission verifies a registered-external record's fingerprint by exact
digest equality against a live registration — unregistered or mismatched
fingerprints refuse.

**The boundary sentence, stated once and early because it is the crux: the
registry names what transformed the source so that currency can be
verified; it does not let an external producer claim ibex's own toolchain
fingerprint, mint transform or capability authority, or bypass LLP 0028's
one-transform-authority principle.** Ibex remains the sole authority for
its own fingerprint domain and its own in-process transforms; a
registration is a host-authorized statement of identity, consumed by
admission, never a source of new capability.

## Terminology

- **Ibex-configured fingerprint**: the `TransformFingerprintV1` value
  derived from `config/module-transform.json` for a source goal —
  `configured_transform_fingerprint_for_goal_v1`. Unchanged by this RFC.
- **External fingerprint**: a `TransformFingerprintV1` value whose
  `producer` is not an ibex-reserved producer id. Today's concrete
  instance: `exact-vite-prepared-graph-producer` /
  `exact-compat-loader-cjs-8` (Exact's arms E/F producer).
- **Registration**: one `ibex/registered-transform-fingerprint/1` record
  (schema below) binding an external fingerprint to open, named semantic
  dimensions.
- **Registered set**: the registrations live for one runtime: the armed
  snapshot's section (production) or the session credential's facet
  (development). There is no ambient, file-configured, or cache-resident
  registered set.

## Design principles

1. **Identity, not authority.** A registration changes what admission can
   *verify*, never what code can *do*. It widens no capability decision,
   authorizes no source, and admits no bytes by itself; those remain the
   business of the deployment graph, the prepared-graph commitment
   (LLP 0042), and the armed policy.
2. **The two fingerprint classes never alias.** An external fingerprint
   must not be able to validate as the ibex-configured fingerprint, and
   vice versa. Registration validation refuses any record whose
   `producer` uses a reserved ibex id (`ibex-` prefix: today
   `ibex-oxc-module-producer`, `ibex-rolldown-module-preparer`) and any
   record whose fingerprint digest equals the active ibex-configured
   digest for any source goal. LLP 0028's "one engine, one fingerprint
   domain" claim is scoped to ibex's in-process runtime transforms and
   survives intact: this registry adds a second *named* class, not a
   second authority over the first class.
3. **Open dimensions, closed wire.** `ModuleArtifactV1` and
   `TransformFingerprintV1` do not change (LLP 0028 non-goal; LLP 0027 v1
   stability). The new semantic dimensions live in the registration in the
   open, and the fingerprint's two producer-defined digests
   (`typescript_jsx_options_digest`, `output_options_digest`) are
   **derived deterministically from the declared dimensions** — the
   derivation is recomputed at registration validation, so a producer
   cannot declare one thing and digest another.
4. **Trust enters the way it already enters.** Production registrations
   ride the arming ceremony; development registrations ride the session
   commitment credential. No new signing mechanism, no new transport, and
   nothing under a writable cache directory contributes.
5. **Staleness is the feature, not a failure mode.** Any dimension change
   produces a different registration digest, and publications carrying the
   old fingerprint refuse. Refusal falls back per LLP 0042:
   refuse-then-cold-rebuild (or re-produce upstream), never
   accept-with-warning, never version-range matching.

## Registration schema

`ibex/registered-transform-fingerprint/1`, strict I-JSON, canonical JCS,
closed fields (`deny_unknown_fields`), digested in the domain
`ibex:registered-transform-fingerprint:1`:

```text
RegisteredTransformFingerprintV1 {
  schema                    // exactly "ibex/registered-transform-fingerprint/1"
  producer {
    id                      // e.g. "exact-vite-prepared-graph-producer";
                            // reserved ibex ids refuse at validation
    identityDigest          // digest of the producer's own implementation
                            // (see Open question 3: binary digest is not
                            // well-defined for a JS-hosted producer)
  }
  toolchain[]               // per-tool identity table, sorted by id:
                            // { id, version } — e.g. vite, esbuild,
                            // es-module-lexer, cjs-module-lexer, node/bun
  artifactFingerprint       // the EXACT TransformFingerprintV1 value every
                            // admitted record of this producer must carry,
                            // verbatim (all ten fields)
  dimensions {
    defineTable             // the full define/env replacement table applied
                            // upstream (import.meta.env.*, process.env.*,
                            // __DEV__, ...), canonically sorted; digested
                            // into output_options_digest via the derivation
    jsxRuntime {            // "automatic" | "classic", importSource,
      mode, importSource, development
    }                       // (D2: ibex pins classic; Vite runs automatic
                            // through a shim that appears as a graph module)
    conditionSet[]          // ordered resolution condition set, including
                            // custom conditions (e.g. "native")
    platformSuffixRules[]   // ordered suffix resolution list per target
                            // (e.g. ["mac", "native", ""]) — inexpressible
                            // in ibex-native resolution, so declared here
    contractCompiler {      // identity of the Contract compiler whose output
      id, identity          // entered the pipeline (version or content
    }                       // digest — Open question 2); null when no
                            // .contract source is in scope
    forOfRepairPass {       // the Hermes AOT for-of repair applied after
      id, identity          // lowering — the canonical LLP 0019 tier-1 pass
    }                       // or a declared vendored copy, identified by
                            // content digest, not by version string
  }
}
```

Validation, beyond closed-structure/JCS rules:

- reserved-producer refusal and ibex-digest-collision refusal (principle 2);
- **derivation recompute**: `artifactFingerprint.typescript_jsx_options_digest`
  and `.output_options_digest` must equal the digests derived from
  `dimensions` under a versioned derivation recipe published with this
  schema (`ibex:registered-fingerprint-derivation:1`). A registration whose
  open dimensions do not produce its claimed closed digests refuses — the
  dimensions cannot be decorative;
- `artifactFingerprint.producer == producer.id`;
- `hermes_target` must be consistent with the runtime target the registered
  set is bound to (snapshot `engine.target` in production).

A registered set is an array of these records, canonically sorted and
unique by registration digest, with at most one registration per
`producer.id` (v1 simplification; see Open question 4).

## Authorization surfaces (mirroring LLP 0042)

### Production: an armed-snapshot section

A new additive optional section `registeredTransformFingerprints` under
`ibex/capsec-armed/1`, an array of `RegisteredTransformFingerprintV1`,
validated by `ArmedSnapshot::load` (crates/capsec-semantics/src/arming.rs)
next to `preparedGraphs` and authenticated by the existing snapshot digest
— the same binding-surface story as `PreparedGraphCommitmentV1`
(commit 1a9e8234): no new signing mechanism, unavailable to the writable
cache by construction, absence means no external fingerprint is
verifiable.

Cross-link to the commitment: a `preparedGraphs` commitment whose
`producer.id` is not an ibex-reserved id is valid only when the same
snapshot registers that producer's fingerprint; `ArmedSnapshot::load`
refuses the dangling case so a deployment cannot ship a committed external
publication that is guaranteed to refuse at admission step 6.

### Development: a session-commitment facet

Development registrations are a facet of the dev session commitment —
`ibex/prepared-graph-commitment-dev/1` per LLP 0042, whose transport is
the deliberately separate work item
`issues/20260729-prepared-graph-development-session-commitment.md`. The
producing session mints registrations alongside the commitment, covers
them with the same session MAC, and delivers them over the same
authenticated dev/session channel — **never** as files in the cache
directory or the publication directory. Lifetime and revocation are the
credential's: `runId` match, generation advance supersedes, restart
revokes. This RFC adds no transport of its own and inherits that ticket's
open transport decision wholesale; until it lands, development has no
registered-external admission, exactly as it has no dev committed
admission.

Production admission structurally refuses dev-carried registrations
(unknown schema position, not policy), and the snapshot section refuses
any record arriving via a non-arming channel: a caller-provided lookalike
is not authority, per the arming.rs doc rule.

## Verification semantics

`verify_current_transform_fingerprint_v1` is **unchanged**: it answers
"was this artifact produced by ibex's active configuration?" and continues
to refuse everything else. Registered-external records are handled by a
new admission-level dispatch:

```text
verify_admissible_transform_fingerprint_v1(semantics, registered_set):
  1. if fingerprint digest == ibex-configured digest for the record's
     source goal            -> OK (class: ibex-configured)
  2. else find a registration whose artifactFingerprint digest equals the
     record's fingerprint digest exactly
       - none               -> refuse IBEX_FINGERPRINT_UNREGISTERED
       - found              -> require semantics.transform_fingerprint ==
                               registration.artifactFingerprint verbatim
                               (field-level, not just digest) and
                               fingerprint.producer == registration
                               .producer.id -> OK (class: registered-
                               external, naming the registration digest)
```

No prefix, range, or "compatible" matching exists at any step. The
admission receipt names the class; a startup that admitted any
registered-external record says so in diagnostics, in the spirit of
LLP 0042's authority-class line.

What this explicitly does **not** do: step 2 never feeds
`configured_transform_fingerprint_for_goal_v1`, never marks the artifact
as ibex-produced, never relaxes producer-binary or deployment-graph
checks, and never applies to inline (in-process) artifacts — inline
admission still requires the expected in-process producer binary
(LLP 0027). Registered-external is a prepared-publication posture only.

## Staleness and the cache-key story

Every dimension change — a Vite or esbuild bump, one define-table entry, a
JSX-runtime flip, a condition-set or suffix-rule edit, a Contract-compiler
or for-of-pass content change — changes the derived option digests, hence
the `artifactFingerprint` digest, hence the registration digest. Old
publications carry the old fingerprint and refuse at step 2. That refusal
is the design working: the D2 measurement showed these dimensions carry
observable meaning (`import.meta.env.DEV` divergence, automatic-vs-classic
JSX), so "stale publication silently admitted under a moved toolchain" is
the bug this registry exists to prevent.

Interaction with LLP 0027's cache key: the cache-key digest already covers
the transform-fingerprint digest, so external publications' cache
identities rotate with the fingerprint automatically; no new cache-key
input is added. In production the registered set is part of the armed
snapshot, so authority rotation and deployment rotation are atomic. A
publication refused for fingerprint staleness follows LLP 0042's rule:
discard, cold-rebuild (ibex-produced) or re-produce upstream and
re-register (external) — never rejoin-accept, never mid-run fallback.

## Adversarial fixtures

Fixture family `registered-fingerprint-authority`, extending the LLP 0027
tamper matrix and LLP 0042's substitution family; all refuse before any
factory evaluation:

1. **Unregistered honest producer.** The D2 adapter-1 publication admitted
   with its registration present; the identical publication refuses when
   the registration is absent (`IBEX_FINGERPRINT_UNREGISTERED`).
2. **Impersonation.** A registration claiming `producer.id`
   `ibex-oxc-module-producer`, and a registration whose fingerprint digest
   equals the ibex-configured digest, both refuse at validation — in the
   snapshot loader and in the dev-credential mint path.
3. **Decorative dimensions.** A registration whose declared `dimensions`
   do not derive its claimed option digests refuses at validation.
4. **Stale dimension.** Register, publish, admit green; change one define
   entry; re-register; the old publication refuses with a diagnostic
   naming fingerprint mismatch, distinct from corruption.
5. **Field-level splice.** A record whose fingerprint digest matches a
   registration but whose fields differ (a second-preimage stand-in test
   using a corrupted registration) refuses at the verbatim compare.
6. **Class confusion.** A dev-minted registration presented to production
   admission refuses structurally; a snapshot section containing a
   dev-facet shape refuses at `ArmedSnapshot::load`; a dangling external
   `preparedGraphs.producer` with no registration refuses at load.

## Migration

- **From the D2 harness.** M2/M4 drove admission with harness-supplied
  expectations and deliberately did not assert fingerprint currency
  (tournament ticket finding 4). Those harnesses migrate to constructing
  an explicit test-only registered set from the publication's declared
  fingerprint — the same bytes, but flowing through
  `verify_admissible_transform_fingerprint_v1`, so the bypass becomes a
  typed test authority and the currency check runs in CI instead of being
  skipped.
- **What the Exact producer starts emitting.** Alongside each publication:
  a `RegisteredTransformFingerprintV1` with real values — tool versions
  read from the lockfile/package metadata rather than the current
  hard-coded strings (`es-module-lexer/2.1.0+esbuild-vite-lowering` etc.
  in prepared-graph-producer.ts); the lane's actual define table as Vite
  resolved it; the actual JSX runtime mode; the resolver's condition set
  and platform-suffix order for the target; the `@exact/contract` compiler
  identity when any `.contract` module is in the graph; and the content
  identity of the vendored `fixForOfScoping` pass (which should be pinned
  against ibex's canonical LLP 0019 tier-1 pass so drift between the two
  copies is visible as a fingerprint change, not a silent divergence).
  Deployment tooling copies the registration into the armed snapshot next
  to `preparedGraphs`; the dev producer folds it into the session
  credential once the transport ticket lands.
- **Coexistence.** Ibex-produced publications (adapter 2, the dependency-
  principal end-state) are untouched: they pass step 1 by construction
  (940/940 in the D2 slice) and need no registration. Rejoin/source-mode
  admission is unaffected.

## Open questions

1. **Dimension granularity vs churn.** Is the tool-version table
   (vite/esbuild/lexers) the right cut, or must the ordered Vite plugin
   pipeline join the identity? Every added dimension buys refusal
   precision and costs re-registration churn (a patch bump refuses all
   publications — intended, but the dev loop must absorb it cheaply).
2. **Contract compiler identity: version or content digest?** Phase 0
   reality is that the compiler changes without version bumps, arguing for
   a content digest; but a source-tree digest churns per commit and makes
   registrations short-lived. A compiled-output corpus digest is a middle
   ground nobody has built. Decision-blocking for the field's definition.
3. **Producer `identityDigest` for a JS-hosted producer.** Exact's
   producer is TypeScript executed by a dev server; "binary digest" in the
   LLP 0027/0042 sense has no single honest referent (node/bun binary?
   producer bundle? source closure?). The schema reserves `identityDigest`
   but its derivation needs a decision before production registrations
   exist. Decision-blocking for production; the dev lane can start with
   the session credential carrying the burden.
4. **Multi-producer publications.** The D2 split (adapter 1 for the root
   principal, adapter 2 for dependency principals) implies one publication
   whose carriers come from two producers, while the LLP 0042 commitment
   carries one `producer`. Does the commitment grow per-carrier producer
   attribution, or do split-producer graphs ship as two publications? V1
   of this registry assumes per-record dispatch (step 1 vs step 2 per
   artifact), which works either way, but the commitment-side answer is
   needed before the split lands.
5. **Dev-lane sequencing.** Development registered-external admission is
   gated on the dev commitment transport
   (issues/20260729-prepared-graph-development-session-commitment.md).
   Should the production-shaped snapshot section land first and CI drive
   it via LLP 0038 synthesized-cells arming (the LLP 0042 pattern), with
   the dev facet following? Recommended, but stated for the record.
