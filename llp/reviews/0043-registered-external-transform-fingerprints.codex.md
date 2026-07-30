# Reviews of LLP 0043 — Registered External Transform Fingerprints (OpenAI/Codex family)

Review artifacts for `llp/0043-registered-external-transform-fingerprints.rfc.md`,
recorded per
[LLP 0005](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).
One `## Round N` section per round, appended, never overwritten.

---

## Round 1 — 2026-07-30

**Provenance**

- **Reviewer family:** OpenAI (Codex)
- **Provider / runtime:** `codex exec` CLI 0.146.0, read-only sandbox,
  `model_reasoning_effort="high"`, default (strongest available) model —
  the exact model id as reported by the runner is recorded with the review
  body below.
- **Date:** 2026-07-30
- **Revision under review:** `eba133b97e83`
  (`shasum -a 256 llp/0043-registered-external-transform-fingerprints.rfc.md | cut -c1-12`)
- **Status transition:** the document was authored today as `Draft` from
  `issues/20260729-transform-fingerprint-registry-contract.md` and set to
  `Review` at loop start — the one pre-authorized transition.
- **Authorization:** The directing author (Charlie Cheever) invoked
  `/llp-super-refine` on this target in the orchestrating session; the
  external send is made under that direction, with the outbound inventory
  being exactly the capsule described below — consistent with the four
  prior recorded loops in this corpus.
- **Capsule:** faithful copy of the tracked working tree plus the untracked
  target, with `llp/reviews/0043-*` structurally excluded and the two
  external Exact documents under `context-exact/`. Content hash
  `100d1a54ecc3` (sorted per-file sha256, sha256'd, first 12). No
  redaction of the target; context redaction: none.
- **Independence:** separate vendor runtime and model family from the
  orchestrator; run against the capsule with no access to the
  orchestrator's conversation, the concurrent Fable review, or any prior
  0043 review artifact (structural exclusion in the capsule). Instructed
  additionally not to read scratchpad or orchestrator notes (that part
  self-attested).
- **Method:** `codex exec` with the round-1 brief on stdin
  (`sr0043/brief-r1.md`, sha256 prefix `fa9d913541b4`) — same brief as the
  concurrent Fable round-1 review.
- **Topology:** single-target loop; no cluster.
- **Sealing:** this review was recorded verbatim on receipt and sealed
  from the Fable reviewer until both round-1 reviews landed.

**Launch log**

- Launch 1 (2026-07-30 01:32): failed before any review content —
  `codex exec` refused the capsule directory ("Not inside a trusted
  directory and --skip-git-repo-check was not specified", exit 1).
  Recorded as a failed response; not counted.
- Launch 2 (2026-07-30 01:35): relaunched identically plus
  `--skip-git-repo-check`, same capsule `100d1a54ecc3`, same brief
  `fa9d913541b4`.

**Model (as reported by runner):** `gpt-5.6-sol`; 152,590 tokens used.

**Review (verbatim)**

Revision `eba133b97e83` has a sound commitment-root and digest-separation direction, but it is not ready: the proposed contract permits authority mislabeling and mixed-authority downgrade, while its downstream identity can accept stale Ibex lowering.

1. **MATERIAL — “Fingerprint wire evolution” / “Fail-closed currency.”** `DownstreamLoweringIdentityV1` omits output-affecting Ibex components that actually process external input. It includes the handwritten-pass version, runner ABI, Hermes compatibility, target, and output-options digest, but not the Oxc locked-set/parser identity or relevant parser/semantic options. LLP 0028 §1 requires that locked set and full effective configuration to rotate atomically; current code carries them through `parser_version`, `typescript_jsx_options_digest`, and the effective configuration identity generated from `config/module-transform.json`. Adapter 1 still requires Ibex to parse and lower the external ESM output. An Oxc parser/semantic/source-map dependency rotation could therefore leave the registration’s downstream value unchanged and admit artifacts produced by the old lowering stack. Resolve this by deriving the downstream identity mechanically from every applicable field of the authored effective manifest, including the locked dependency closure, with rotation tests for each component.

2. **MATERIAL — “Summary” / Design principle 2 / “Admission change.”** Domain separation does not enforce the claim that an external producer can never claim the `ibex-toolchain` arm. The current Ibex fingerprint is public and reproducible; an external publisher can serialize `authority: "ibex-toolchain"` with the current V1 fields. Admission step 1 then accepts it without consulting a registration. The proposed verifier receives semantics, principal, and the recognized set, but no evidence that Ibex actually performed the transform. The prepared artifact’s producer identity binds the publication preparer, not the transform route. Rejecting `ibex-` prefixes inside `ExternalTransformStageV1` is irrelevant because the forged artifact never takes that arm. The Ibex arm needs trusted provenance bound into the commitment or an exclusive authority assignment that an external publication producer cannot relabel.

3. **MATERIAL — “Registration record and scope” / “Refusal matrix” / “What registration does not claim.”** Registration scope is additive, not exclusive. For a scoped `(principal, source goal)`, the recognized set still contains the Ibex fingerprint as well as the external fingerprint. Consequently both authorities admit, and nothing checks that all applicable records in a principal or carrier use the selected external authority. The refusal-matrix claim that a mixed-authority principal “cannot arise” is contradicted by the algorithm and code: `render_prepared_source_graph_v2` groups every record by principal, and `PreparedModuleCarrierV2` checks principal agreement only. Builtins are additionally placed in the root carrier while being required to use the Ibex arm. Define a closed authority assignment—probably per `(principal, goal)` with an explicit builtin rule—where an external assignment replaces the Ibex default, and validate carrier/record occupancy against it.

4. **MATERIAL — Design principle 5 / “Admission change” / “Migration and coexistence.”** The inherited LLP 0042 failure path creates a semantic downgrade. `prepare_authenticated_module_graph` currently responds to any committed-admission refusal or missing publication by rebuilding from authenticated source with Ibex’s producer. That was safe when prepared and cold paths shared one transform truth. It is not safe for adapter 1: Exact LLP 0416 D2 establishes that Contract compilation, environment replacement, platform suffixes, and automatic JSX are deliberately absent or divergent in Ibex’s native path. Cache deletion, substitution, or a stale registration can therefore switch an armed startup to different program semantics rather than fail closed. A commitment requiring external authority must either fail startup or obtain a fresh publication from that same authorized authority before evaluation; it must not fall back to the Ibex transform.

5. **minor — “Fingerprint wire evolution” / “Migration and coexistence.”** The RFC intentionally replaces the fixed fingerprint object in accepted `ibex/module-artifact/1` with an incompatible tagged union, while also adding a field to strict `ibex/prepared-graph-commitment/1`, but does not explicitly rotate either containing schema. The codec-casing correction cited as precedent restored conformance to an existing schema; it was not an intentional schema change. The assertion that cache entries rotate through the fingerprint digest is also false for the Ibex arm, whose digest deliberately remains unchanged. The implementation contract should name the containing schema/domain rotations or explicitly justify and specify nested-version negotiation.

6. **minor — “Authority surface.”** `ArmedSnapshot::load` cannot validate that scoped principals belong to “the commitment’s principal set”: `PreparedGraphCommitmentV1` carries only `principalSetDigest`, while the actual principal set is derived from the independently committed index later. The CapSec layer also does not currently own the authored transform manifest needed for downstream equality. These checks should be assigned to committed admission after the root check, or the commitment must carry the authenticated facts required to perform them earlier.

This verdict applies specifically to revision `eba133b97e83` in capsule `100d1a54ecc3`.

VERDICT: NOT READY

---

## Round 2 — 2026-07-30 (delta round)

**Round-1 revision (orchestrator), applied before this round**

Revision `eba133b97e83` → `93f1f44ddb3b`. The full concern-by-concern
disposition ledger for both families is recorded in the round-2 section of
the Fable-family artifact; it applies identically here.

**Provenance**

- **Reviewer family:** OpenAI (Codex); `codex exec` CLI 0.146.0,
  read-only sandbox, `--skip-git-repo-check`,
  `model_reasoning_effort="high"`, default model (round 1 reported
  `gpt-5.6-sol`; this round's reported model recorded with the body).
- **Date:** 2026-07-30
- **Revision under review:** `93f1f44ddb3b`
- **Capsule:** `c6cdba88e473` — tracked tree + revised target, target
  review artifacts structurally excluded, Exact LLP 0413/0416 under
  `context-exact/`. No redaction.
- **Independence:** as round 1; structural exclusion of this target's
  artifacts verified in the capsule build.
- **Method:** round-2 delta brief on stdin (`sr0043/brief-r2.md`, sha256
  prefix `40d187806882`) — same brief as the concurrent Fable round-2
  review; delta enumerated; IN-DELTA vs PRE-EXISTING required.
- **Sealing:** recorded verbatim on receipt; sealed until both round-2
  reviews land.

**Model (as reported by runner):** `gpt-5.6-sol`.

**Review (verbatim)**

Revision `93f1f44ddb3b` materially improves the authority model: unique per-cell assignments prevent record-selected masquerading, and the complete downstream fingerprint closes the prior subsetting risk. However, revision `93f1f44ddb3b` in capsule `c6cdba88e473` is not ready because three material delta defects remain.

1. **MATERIAL — IN-DELTA — Design principle 6; “Refusal disposition: no substitute authority”; migration.** The no-downgrade rule is enforceable only while a commitment containing the external assignment is present. LLP 0042 explicitly selects rejoin or cold preparation when an entry has no commitment, and the revised sibling requirements do not change that absence behavior. Consequently, an omitted production commitment—or an unavailable development credential—erases the only fact saying the entry requires an external authority, allowing Ibex source preparation with the divergent Contract/define/JSX/suffix semantics this RFC says must never be substituted. The “deleted publication” fixture retains the commitment and therefore does not cover this case. External-required authority must be authenticated independently of the optional publication commitment, or the relevant entry/lane must require committed admission so a missing commitment or credential refuses before source fallback.

2. **MATERIAL — IN-DELTA — “Fingerprint wire evolution”; “Required sibling revisions”; migration.** The containing-schema rotation is incomplete. `ibex/prepared-module-graph/2` embeds an artifact through `prepared-module-graph-v1.schema.json`, which references `module-artifact-v1.schema.json`; `ibex/module-carrier/2` directly references the v1 artifact semantics. Both therefore embed the `TransformFingerprintV1` shape. Replacing that shape with `TransformFingerprintV2` while rotating only the artifact and commitment schemas would silently change two closed accepted schemas in place. The RFC must name rotations for the prepared-graph index and module-carrier manifest, update LLP 0027 accordingly, and specify their refusal/rebuild migration.

3. **MATERIAL — IN-DELTA — “Currency, per lane.”** The claim that every production downstream rotation is rejected at arming through `engine.binaryDigest` is not generally true. `src/engine/mod.rs` derives that digest from `ex_hermes_engine_binary_path`, explicitly identifying and hashing the loaded Hermes artifact. On framework/dylib configurations that artifact can remain unchanged while Ibex’s compiled transform configuration changes. The commitment’s producer digest authenticates the publication’s preparer; it is not an arming-time comparison with the current consumer transform manifest. Thus an old snapshot can arm and reach the leg-2 `STALE` check, making that check operative—not expected-unreachable—in production. Either arming must additionally pin the current Ibex transform configuration/module-producer identity, or the production currency semantics and fixtures must treat admission-time `STALE` as an ordinary expected refusal.

4. **minor — IN-DELTA — “Validation and admission.”** Admission rejects an assignment only when its principal is absent, not when its exact `(principal, sourceGoal)` cell is absent. A publication can therefore carry a principal with only JSON records and an external module-goal assignment, leaving the registration semantically unused while still activating the entry-wide terminal-refusal disposition. Cross-check the assignment keys against the publication’s actual `(principal, sourceGoal)` inventory and refuse zero-record assignments.

5. **minor — PRE-EXISTING — Summary.** The statement that Exact LLP 0416’s “D2 resolution proceeds adapter 1” overstates the cited decision record. LLP 0416 records D2 as “decision deferred”; its final adapter-1/split conclusion is explicitly a recommendation whose decision remains Charlie’s. Describe this RFC as satisfying the recommendation’s prerequisite unless a separate author decision can be cited.

VERDICT: NOT READY


---

## Round 3 — 2026-07-30 (delta round; final budgeted round)

**Round-2 revision (orchestrator), applied before this round**

Revision `93f1f44ddb3b` → `b4b3ad472da4`. The full disposition ledger
for both families is in the round-3 section of the Fable-family artifact;
it applies identically here.

**Provenance**

- **Reviewer family:** OpenAI (Codex); `codex exec` CLI 0.146.0,
  read-only sandbox, `--skip-git-repo-check`,
  `model_reasoning_effort="high"`, default model (rounds 1–2 reported
  `gpt-5.6-sol`).
- **Date:** 2026-07-30
- **Revision under review:** `b4b3ad472da4`
- **Capsule:** `eb7eca7f53f0` — as described in the Fable round-3
  record. No redaction.
- **Independence:** as prior rounds; structural exclusion verified.
- **Method:** round-3 delta brief on stdin (`sr0043/brief-r3.md`, sha256
  prefix `11bd3fea3df2`) — same brief as the concurrent Fable round-3 review.
- **Sealing:** recorded verbatim on receipt; sealed until both round-3
  reviews land.

**Model (as reported by runner):** `gpt-5.6-sol`.

**Review (verbatim)**

Revision `b4b3ad472da4` in capsule `eb7eca7f53f0` substantially improves goal matching, stale handling, schema rotation, and refusal behavior, but two round-2 changes remain materially incomplete: development cannot enforce committed-only consistency at the specified validation site, and the claimed complete migration omits governing contracts affected by the wire rotations.

1. **MATERIAL — IN-DELTA — “Validation and admission” / “Committed-only entries and refusal disposition.”** Development committed-only consistency is assigned to dev-credential minting, but the RFC explicitly places the authoritative marking in consuming-app host configuration and says it cannot ride the credential. The producer minting the credential therefore cannot establish that the eventual consumer has marked the entry. Even if the producer receives an assertion, the credential could still be consumed by an unmarked embedder unless the consumer rechecks its own standing configuration. This contradicts the refusal-matrix and fixture claim that an external assignment without marking is structurally refused, and permits the exact downgrade sequence principle 6 intends to prevent: accept an external assignment while a credential is present, then select LLP 0042’s source fallback when the credential is later absent. Require a consumer-side, entry-bound marking check before development committed admission; mint-time validation may remain additional defense but cannot be the enforcement boundary.

2. **MATERIAL — IN-DELTA — “Fingerprint wire evolution” / “Required sibling revisions” / “Migration and coexistence.”** The asserted complete sibling and migration set omits two governing contracts changed by the global wire rotation. LLP 0026 still states that only the in-process producer and build-time Rolldown/Oxc producer are trusted, which conflicts with this RFC’s new host-authorized Vite authority. LLP 0029 makes accepted carrier schemas part of `StubContractV1`; both `schemas/stub-contract-v1.schema.json` and `src/compiled_contract.rs` pin `ibex/module-carrier/2`. Rotating every carrier to `/3` therefore rotates the compiled-stub compatibility contract and catalog artifacts even for all-Ibex executables. Naming only LLP 0027, 0028, and 0042 leaves either broken compiled executables or undocumented contract drift. Add LLP 0026 and LLP 0029 to the required sibling revisions, including the `/3` accepted-schema pin, stub-contract/catalog digest migration, and old-stub/new-carrier refusal and rebuild fixtures.

3. **minor — IN-DELTA — Design principle 5 / “External stage declaration” (altitude).** `pipelineToolsDigest` is now said to make resolved configuration coverage a “schema obligation,” but the field is an opaque digest and the RFC does not name its canonical preimage or digest domain. Under the RFC’s naming-not-blessing trust model, admission cannot verify that configuration was actually included. Clarify that this is a producer-conformance obligation and require an auditable canonical recipe or receipt during implementation; the underlying trust decision is otherwise coherent.

VERDICT: NOT READY


---

## Close-out — 2026-07-30 (loop terminal; escalated to the author)

Terminal state, final-revision labeling (`dab6bd9a7a3b` UNREVIEWED; last
reviewed revision `b4b3ad472da4`), the complete round-3 disposition
ledger, the growth-budget overrun record, and the escalation proposals are
recorded in the close-out section of the Fable-family artifact; they apply
identically here. This family's final verdict is its round-3 review above:
**NOT READY** on `b4b3ad472da4` (2 MATERIAL, both IN-DELTA, both
dispositioned in the unreviewed close-out revision; no PRE-EXISTING
MATERIAL in rounds 2–3).
