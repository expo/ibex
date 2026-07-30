# Reviews of LLP 0043 — Registered External Transform Fingerprints (Claude/Fable family)

Review artifacts for `llp/0043-registered-external-transform-fingerprints.rfc.md`,
recorded per
[LLP 0005](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).
One `## Round N` section per round, appended, never overwritten.

---

## Round 1 — 2026-07-30

**Provenance**

- **Reviewer family:** Claude (Fable)
- **Provider / runtime:** Fresh Claude agent session (`claude-fable-5`)
  spawned by the orchestrating Claude Code session running
  `/llp-super-refine`; the orchestrator (who authored and will revise the
  document) did not perform this review.
- **Date:** 2026-07-30
- **Revision under review:** `eba133b97e83`
  (`shasum -a 256 llp/0043-registered-external-transform-fingerprints.rfc.md | cut -c1-12`)
- **Status transition:** the document was authored today as `Draft` from
  `issues/20260729-transform-fingerprint-registry-contract.md` and set to
  `Review` at loop start — the one pre-authorized transition.
- **Authorization:** The directing author (Charlie Cheever) invoked
  `/llp-super-refine` on this target in the orchestrating session.
  Outbound inventory for the external (Codex) send: the review capsule
  described below — the Ibex tracked working tree plus the target document
  and two referenced Exact-repo LLPs (0413, 0416) — consistent with the
  four prior recorded loops in this corpus.
- **Capsule:** faithful copy of the tracked working tree plus the untracked
  target, with `llp/reviews/0043-*` structurally excluded and the two
  external Exact documents under `context-exact/`. Content hash
  `100d1a54ecc3` (sorted per-file sha256, sha256'd, first 12). No
  redaction of the target; context redaction: none.
- **Independence:** Fresh agent session with no access to the
  orchestrator's conversation, the concurrent Codex review, or any prior
  0043 review artifact (none exist — this is round 1; exclusion is
  structural in the capsule). Instructed additionally not to read
  scratchpad or orchestrator notes (that part self-attested).
- **Method:** agent-runner, round-1 brief verbatim
  (`sr0043/brief-r1.md`, sha256 prefix `fa9d913541b4`) — same brief as the
  concurrent Codex round-1 review.
- **Topology:** single-target loop; no cluster.
- **Sealing:** this review was recorded verbatim on receipt and sealed
  from the Codex reviewer until both round-1 reviews landed.

**Review (verbatim)**

# Review — LLP 0043 (Registered External Transform Fingerprints), Round 1

**Revision under review:** `eba133b97e83` · **Capsule:** `100d1a54ecc3`

## Summary

The document is the right shape for the problem the D2 record filed: it correctly refuses to make admission a semantic-equivalence oracle ("naming, not blessing"), rides the LLP 0042 commitment rather than inventing a second authority channel, separates digest domains, reserves the producer namespace, and states the fail-closed rotation posture in both directions. Its code citations check out exactly: `verify_current_transform_fingerprint_v1` / `configured_transform_fingerprint_for_goal_v1` are as described (`src/module_loader/producer_spike.rs:70-136`, generated from `config/module-transform.json`), the two call sites are rejoin and committed admission (`src/module_loader/runner_pipeline.rs:3792`, `:3428`), the digest domain and `TransformFingerprintV1` shape match `src/module_loader/artifact.rs:19-92`, and the D2 dimension list faithfully reflects Exact LLP 0416 §D2.2/§D2.3. The open-questions register is honest (notably OQ3 on replay/retention). However, four defects block acceptance at this revision: a validation assigned to `ArmedSnapshot::load` that is uncomputable there as LLP 0042 stands; a rotation-staleness story whose specified mechanism contradicts its stated disposition (and is largely unreachable in armed production given engine-binary pinning); a refusal-matrix row (mixed-authority principal) that the specified admission algorithm does not actually produce; and a downstream-identity field set that omits the Oxc toolchain identity even though the document's own composition account says ibex passes run on external bytes.

## Concerns

**1. MATERIAL — Authority surface: the principal-scope validation cannot run where it is specified.**
The document requires `ArmedSnapshot::load` to validate, per registration, "principal ids present in the commitment's principal set." But `PreparedGraphCommitmentV1` carries only `principalSetDigest` — a digest over the canonically sorted set (LLP 0042 schema; `crates/capsec-semantics/src/arming.rs:48-57`) — and LLP 0042 design principle 2(b) explicitly requires the arming ceremony to validate the commitment *without opening the cache*. Membership of an id in a set is not checkable against a digest of the whole sorted set. As written the check is impossible at load: either the commitment must carry the explicit principal list (a change to LLP 0042's schema this document does not propose), or the check must move to admission, where the principal set is recomputed from the carrier inventory (`runner_pipeline.rs:3322`). The document must pick one; right now it specifies a mechanism that cannot exist.

**2. MATERIAL — Design principle 5 / Authority surface / Refusal matrix: the downstream-currency check's site and disposition are incoherent.**
The same condition — registration `downstream` equals the current authored manifest — is assigned to `ArmedSnapshot::load` (Authority surface) *and* to admission step 2 (`STALE`), and the refusal matrix gives it the disposition "refuse `STALE`; publication is cold-rebuild material after re-registration." These do not cohere:
- `ArmedSnapshot::load` already requires `engine.binaryDigest` to equal the loaded engine binary (`arming.rs:363-367`), and the authored manifest is compiled into that binary (generated `transform_config` constants). A real ibex downstream rotation therefore refuses the *entire snapshot* at engine authentication — before any registration is examined. The matrix's "ibex rotated → `STALE` → cold rebuild" path never executes in armed production; the actual production behavior on rotation is a whole-host arming failure requiring re-arming, not a localized cold rebuild.
- Conversely, if the load-time downstream check is the operative one, its failure disposition (refuse the snapshot? drop the section?) is unstated, and refusing the snapshot contradicts the matrix's localized cold-rebuild disposition.
The `STALE` leg appears reachable only in lanes where the consumer binary is not snapshot-pinned to the registration's minting context (the dev credential's cross-process warm start; LLP 0042 OQ1). The document's headline claim ("fail-closed currency, both directions") is directionally safe — the failure is over-broad, not absent — but the specified mechanics and the stated disposition disagree, and an implementer could resolve the ambiguity either way. The document must say where downstream currency actually bites per lane and what fails there.

**3. MATERIAL — Refusal matrix row 8 / Admission change: the mixed-authority-principal refusal is claimed but not produced by the specified algorithm.**
Row 8 asserts "a mixed-authority principal refuses `SCOPE`," and "What registration does not claim" rests on "one observable meaning per module" — the exact Exact LLP 0413 §9.5 principle this document claims to preserve. But the admission algorithm is strictly per-record: an `ibex-toolchain`-arm record is checked by digest equality alone (step 1) and consults no scope; a `composed-external` record checks its own registration (step 2). A single-principal carrier for a registered principal can therefore mix ibex-arm and external-arm records, and every record passes its own leg — nothing specified refuses the mixture. "Carriers are single-principal and scope is per principal" is a non-sequitur as justification. Making the row true requires an exclusivity rule the algorithm does not contain (e.g., an `ibex-toolchain` record whose (goal, principal) is covered by any registration refuses `SCOPE`, or a per-principal same-arm cross-record check). Relatedly, the overlapping-scope refusal ("registering two producers whose scopes overlap on the same principal and goal is validation-refused") appears in prose and in fixture 2 but is absent from the Authority-surface enumeration of what `ArmedSnapshot::load` validates. Because this is the load-bearing single-source-of-semantics guarantee, the gap between claim and mechanism is a security-relevant coherence defect, not a detail request.

**4. MATERIAL — Fingerprint wire evolution: `DownstreamLoweringIdentityV1` omits the toolchain the document says runs on external input.**
The Terminology section defines the downstream stage as "ibex's own module-runner factory and Hermes-compat lowering, which runs on the external producer's output exactly as it runs on ibex-parsed source," and the identity includes a *codegen output options digest* — both of which entail that ibex parses (Oxc), transforms, and re-emits the external bytes. Yet the field list (handwritten-pass version, module-runner ABI, Hermes-compat version, Hermes target, codegen options digest) omits the Oxc identity that `TransformFingerprintV1` carries as `parser_version`/`transform_version` (`artifact.rs:74-75`; the LLP 0028 §1 locked-set digest). Under the document's own account, an Oxc pin rotation changes downstream output bytes while every `DownstreamLoweringIdentityV1` field stays constant — registrations and artifacts remain "current" while stale relative to the executing toolchain, defeating design principle 5 in exactly the direction the contract exists to close. Either the Oxc locked-set identity joins `DownstreamLoweringIdentityV1`, or the composition account is wrong (adapter-1 lowering is parse-free on ibex's side and the codegen-options field is spurious) and must be corrected. One of the two normative statements is defective as written.

**5. minor — Summary: "it never lets an external producer claim ibex's fingerprint" overstates what admission enforces.**
The reserved namespace refuses `ibex-`-prefixed *registrations*, and domain separation prevents cross-domain digest collision — but nothing prevents a mendacious external pipeline from stamping records with the literal `ibex-toolchain` arm and the publicly derivable configured fingerprint value; committed admission accepts on digest equality, and no re-rendering exists to catch it. This is coherent within the trust model (a lying producer means a compromised publication pipeline, and the commitment vouches for the whole publication), and "naming, not blessing" gestures at it, but the Summary's absolute phrasing reads as an admission-enforced property. Scope the claim: arm tags are commitment-vouched declarations, not admission-verified provenance. (Note the interaction with concern 3: arm masquerade is precisely the escape from scope limits until the exclusivity rule exists.)

**6. minor — Coherence with LLP 0028's acceptance criteria.**
LLP 0028 pins "Snapback's claim — 'one engine, one fingerprint domain' — is true in LLP 0027's fingerprint vocabulary" as an acceptance criterion. This RFC introduces a second fingerprint domain into that vocabulary. The Summary defends the "one engine" scope but does not reconcile the "one fingerprint domain" acceptance line. The inline/in-process lane genuinely stays single-domain, so a scoped revision to LLP 0028 (or an explicit reconciliation sentence here) suffices — but per corpus practice it should land with this change, and the RFC should name it.

**7. minor (altitude) — External stage declaration: `ecmascriptOutputTarget` "must be expressible in ibex's downstream target" is undefined.**
What "expressible" means and where it is checked (registration validation vs. admission) is unspecified. Implementation-phase, but the doc should at least name the validation site.

**8. minor — Admission change / Refusal matrix wording.**
"Rejoin admission and inline production keep calling the current ibex-only check unchanged" is not literally true post-rotation: `verify_current_transform_fingerprint_v1` must decode the V2 `ibex-toolchain` arm (even if its digest is V1-stable). Likewise, row 9's parenthetical "byte-compare against ibex's rendering fails first" asserts a check ordering the rejoin path does not guarantee (the per-record fingerprint check at `runner_pipeline.rs:3792` can fire first); the refusal is correct either way, so drop the ordering claim.

**9. minor — Dev-lane dependency should be named.**
The development registration lane rides the dev commitment, whose transport and admission are explicitly unimplemented and open (LLP 0042 OQ1 and its 2026-07-29 checkpoint: "Development-session credential transport and admission remain separate follow-up work"). The RFC treats the dev array as available surface; a one-line dependency note would prevent a reader from assuming the dev lane is landable independently of that resolution.

## Verdict

Concerns 1–4 are unresolved MATERIAL defects: one impossible-as-specified validation, one incoherent currency-disposition story, one claimed refusal the algorithm does not produce, and one fail-closed gap (or mis-described composition) in the downstream identity. The design direction is sound and none of these look structurally expensive to fix, but each requires an author decision, not implementation-phase elaboration.

VERDICT: NOT READY (revision `eba133b97e83`, capsule `100d1a54ecc3`)

---

## Round 2 — 2026-07-30 (delta round)

**Round-1 revision (orchestrator), applied before this round**

Revision `eba133b97e83` → `93f1f44ddb3b` (483 lines; net growth +30% over
the loop-entering revision — past the ~20% guideline, recorded here;
subsequent revisions target net-zero growth). Dispositions of round-1
concerns, both families:

- Fable 1 / Codex 6 (validation site) → revised: validation-site split;
  `ArmedSnapshot::load` checks only self-contained facts; principal
  membership and downstream currency move to committed admission.
- Fable 2 (staleness incoherence) → revised: per-lane currency section
  (armed production: snapshot refuses at arming, admission STALE =
  defense-in-depth tripwire; development: admission STALE operative).
- Fable 3 / Codex 3 (exclusivity) → revised: closed per-(principal, goal)
  authority assignment, unique key; mixed authority refuses `AUTHORITY`.
- Fable 4 / Codex 1 (downstream omits Oxc) → revised: `downstream` is the
  complete current `TransformFingerprintV1` value embedded verbatim; no
  subsetting; per-component rotation fixtures.
- Fable 5 / Codex 2 (ibex-arm masquerade) → revised: assignment makes arm
  labels enforced per cell (masquerade refuses `AUTHORITY` in external
  cells); Summary claim rescoped to commitment-vouched declarations.
- Codex 4 (fallback downgrade) → revised: new design principle 6 +
  "no substitute authority" disposition (production terminal refusal;
  development reproduce-from-live-producer); LLP 0042 sibling revision.
- Codex 5 (schema rotation) → revised: explicit `ibex/module-artifact/2`
  and commitment `/2` rotations; cache-key claim corrected (rotates via
  schema component).
- Fable 6 (LLP 0028 acceptance line) → revised: Required sibling
  revisions section.
- Fable 7 (`ecmascriptOutputTarget`) → revised: check site + v1 equality.
- Fable 8 (ordering claim / wire wording) → revised: ordering claim
  dropped; union-decoding note.
- Fable 9 (dev-lane dependency) → revised: named in Currency + OQ5.

**Provenance**

- **Reviewer family:** Claude (Fable); fresh agent session
  (`claude-fable-5`), orchestrator did not review.
- **Date:** 2026-07-30
- **Revision under review:** `93f1f44ddb3b`
- **Capsule:** `c6cdba88e473` — tracked tree + revised target, target
  review artifacts structurally excluded, Exact LLP 0413/0416 under
  `context-exact/`. No redaction.
- **Independence:** as round 1; structural exclusion of this target's
  artifacts verified in the capsule build.
- **Method:** agent-runner, round-2 delta brief verbatim
  (`sr0043/brief-r2.md`, sha256 prefix `40d187806882`) — same brief as
  the concurrent Codex round-2 review; delta enumerated in the brief;
  IN-DELTA vs PRE-EXISTING classification required.
- **Sealing:** recorded verbatim on receipt; sealed until both round-2
  reviews land.

**Review (verbatim)**

# Review — LLP 0043 rev `93f1f44ddb3b` (Round 2, delta round)

**Summary.** The revision delivers what it claims: the additive "recognized set" is genuinely gone, replaced by a closed unique-keyed per-(principal, sourceGoal) authority assignment with masquerade refusals in both directions; the downstream identity is the complete `TransformFingerprintV1` value embedded verbatim (verified against the actual struct in `src/module_loader/artifact.rs` — `parser_version`/`transform_version` carry the config digest, so any manifest change rotates every composed fingerprint by construction); the validation-site split is consistent with the code (commitment validation in `crates/capsec-semantics/src/arming.rs` has no transform-manifest access — confirmed no reference exists in that crate — while both admission call sites in `src/module_loader/runner_pipeline.rs` have the carrier→principal map needed to resolve assignments); the containing-schema rotation claim is code-accurate (`ArtifactCacheKeyV1` includes `schema`, so cache keys rotate on the `/1`→`/2` bump); the armed-production currency argument is structurally sound (the manifest is compiled constants in `transform_config_generated.rs`, in the binary the snapshot's `engine.binaryDigest` pins, so a rotation refuses at arming and admission `STALE` is correctly characterized as a tripwire); and the new no-semantic-downgrade principle correctly makes the whole-entry refusal terminal in production even for refusals in ibex-assigned cells, which is the right call since a cold rebuild cannot be partial. The provenance-honesty rescope (names-not-blesses, commitment-vouched declarations, arming ceremony as the defense against a lying pipeline) is the correct trust statement and matches LLP 0042's model. Remaining concerns are all minor.

## Concerns

**1. minor / PRE-EXISTING — External stage declaration (`pipelineToolsDigest`) vs. design principle 5.** Principle 5 claims "When the external pipeline changes anything output-affecting, its stage digest changes." As specified, `pipelineToolsDigest` covers tool *identity* ("with source/version/checksum — the external analogue of LLP 0028 §1's Oxc locked-set digest"), and the enumerated tables cover the D2-measured dimensions (define, JSX, conditions, aliases, suffixes, Contract options, sourcemap policy, target). But LLP 0028 §1's manifest covers locked set **and** the full option set; the external analogue of the option set is only the enumerated tables. Output-affecting tool *configuration* outside them — e.g. a Vite plugin's own options (`@vitejs/plugin-react` babel config), `optimizeDeps`/chunking settings — has no declared home, so a config-only change rotates nothing and principle 5's fail-closed guarantee does not hold as literally specified. This is not attacker-exploitable (config change on the host side is within the trust model's host-honesty boundary) and OQ1 already holds the digest's audit unit open, so this is a spec-coverage tightening, not a defective architecture: state explicitly that the *resolved output-affecting configuration* of the tool closure joins `pipelineToolsDigest` (or a sibling digest), so the principle-5 property is a schema obligation rather than host folklore.

**2. minor / IN-DELTA — Refusal disposition, development bullet.** "A consumer that cannot reach a live producer has no committed admission and fails the warm path; **it does not fall back to an ibex transform of externally-owned source**." Without a commitment there is no assignment, so ibex has no structural knowledge that any source is "externally owned"; nothing in this contract prevents a commitment-less cold start from ibex-transforming the same tree (the no-downgrade fixtures, item 3, correctly test only the assignment-present case). The sentence asserts host-integration behavior as if it were a contract-enforced invariant. Rewrite to scope the enforceable guarantee to "when an assignment is in hand" and name the commitment-less case as host responsibility.

**3. minor / IN-DELTA — Required sibling revisions omits LLP 0027.** The section says landing this contract "revises two governing documents" (LLP 0042, LLP 0028). But LLP 0027 is the spec that owns the artifact envelope (its text pins `schema // exactly "ibex/module-artifact/1"`), the `transform_fingerprint` field description, the digest-domain inventory, and the cache-key composition — all changed by this RFC (fingerprint union, `/2` rotation, two new domains, two new schema ids). By the same corpus rule the section invokes, LLP 0027's revision is required in the same change; the enumeration presents itself as complete and is not.

**4. minor / PRE-EXISTING — D2 status overstated relative to the citable record.** The Summary states "Exact's LLP 0416 D2 resolution proceeds **adapter 1** for the root/app principal" and that "the D2 record names this contract as the non-negotiable precondition." In the capsule's copy of Exact LLP 0416, the Decision record (2026-07-29) marks D2 "MEASUREMENT ORDERED, decision deferred," and the M3 recommendation — which is where the adapter-1 split and the "non-negotiable" registry precondition appear — closes with "This is a recommendation under §6; the decision remains Charlie's." If the acceptance has since been recorded in the Exact repo, cite that entry; as citable from this tree the premise is a recommendation, not a resolution. (The RFC's motivation survives either way — adapter-1 publications structurally cannot admit today regardless.)

**5. minor / IN-DELTA (altitude) — Registrations are goal-typed only implicitly.** A registration's `downstream` embeds one per-goal fingerprint value (module/json options digests differ, per `configured_transform_fingerprint_for_goal_v1`), but nothing binds a registration to a goal. Assigning a module-downstream registration to a `json`-goal cell refuses — fail-closed, good — but as `STALE`, a misleading diagnostic for what is a configuration error, and it is not distinguishable from a real rotation. Relatedly, the dev reproduce-from-producer disposition becomes a persistent `STALE` loop under cross-process producer/consumer binary skew; the document honestly names this lane's dependence on LLP 0042 OQ1 and OQ5, so both points are implementation-phase diagnostics/shape detail, recorded here per the altitude rule.

**6. minor / IN-DELTA (wording) — "impossible by construction rather than refused by rule."** The Registration section claims competing authorities for one cell are impossible by construction; on the wire a duplicate (principal, goal) key is entirely possible and is *refused at commitment validation* — the document's own refusal matrix says so. The map is unique-keyed only post-validation. The intended contrast (closed map vs. pattern search at admission) is right; the phrasing overstates it.

## Verdict

No unresolved MATERIAL concern: the closed-assignment model, domain separation, complete-embedded-downstream currency, validation-site split, per-lane currency analysis, and no-downgrade disposition all check out against the corpus (LLP 0027/0028/0042, Exact 0413 §9.5, 0416 §D2) and the code at the cited sites, and the delta introduces no defect at decision altitude.

VERDICT: READY — bound to document revision `93f1f44ddb3b` in capsule `c6cdba88e473`.


---

## Round 3 — 2026-07-30 (delta round; final budgeted round)

**Round-2 revision (orchestrator), applied before this round**

Revision `93f1f44ddb3b` → `b4b3ad472da4` (539 lines; net growth +45%
over the loop-entering revision — past the ~20% guideline; all growth is
reviewer-demanded mechanism, recorded for the close-out). Dispositions:

- Codex r2-1 (no-downgrade unenforceable without commitment; Fable r2-2
  is the same finding at lower severity) → revised: committed-only entry
  marking on standing authority surfaces (production
  `committedOnlyEntries` snapshot section; development host embedding
  configuration); missing commitment/credential refuses; unmarked
  commitment-less case honestly scoped as host responsibility.
- Codex r2-2 / Fable r2-3 (incomplete schema rotation; LLP 0027 sibling)
  → revised: `ibex/prepared-module-graph/3` + `ibex/module-carrier/3`
  rotations named; LLP 0027 added to Required sibling revisions.
- Codex r2-3 (production STALE reachable — orchestrator verified against
  `src/engine/mod.rs`: `engine.binaryDigest` hashes the loaded Hermes
  engine artifact, not the ibex loader binary; the round-2 Fable review's
  contrary endorsement was wrong on this point) → revised: STALE is an
  ordinary, operative refusal in every lane; single-file configs refuse
  earlier at arming as an additional refusal.
- Codex r2-4 (zero-record assignment cells) → revised: uninhabited-cell
  admission cross-check.
- Codex r2-5 / Fable r2-4 (D2 recommendation vs decision) → revised:
  Summary cites D2 as a recommendation, decision the author's.
- Fable r2-1 (pipelineToolsDigest configuration coverage) → revised:
  covers resolved output-affecting configuration; principle 5 is a schema
  obligation.
- Fable r2-5 (goal-typing, altitude) → revised anyway: registrations gain
  `sourceGoal`; goal mismatch refuses at validation, never as STALE.
- Fable r2-6 (wording) → revised: validated-schema phrasing.

**Provenance**

- **Reviewer family:** Claude (Fable); fresh agent session
  (`claude-fable-5`), orchestrator did not review.
- **Date:** 2026-07-30
- **Revision under review:** `b4b3ad472da4`
- **Capsule:** `eb7eca7f53f0` — tracked tree + revised target, target
  review artifacts structurally excluded, Exact LLP 0413/0416 under
  `context-exact/`. No redaction.
- **Independence:** as prior rounds; structural exclusion verified.
- **Method:** agent-runner, round-3 delta brief verbatim
  (`sr0043/brief-r3.md`, sha256 prefix `11bd3fea3df2`) — same brief as the
  concurrent Codex round-3 review.
- **Sealing:** recorded verbatim on receipt; sealed until both round-3
  reviews land.

**Review (verbatim)**

# Review — LLP 0043 (Registered External Transform Fingerprints), Round 3

**Target:** `llp/0043-registered-external-transform-fingerprints.rfc.md` at revision `b4b3ad472da4`, reviewed against capsule `eb7eca7f53f0`.

## Summary

The document is in strong shape. I verified its load-bearing factual claims against the capsule: `verify_current_transform_fingerprint_v1` (`src/module_loader/producer_spike.rs:130`) does digest-compare against the generated per-goal configuration from `config/module-transform.json` (es2022, classic JSX — matching the D2 divergence claims), and it runs in both admission paths (`src/module_loader/runner_pipeline.rs:3428, 3792`). The delta's most security-relevant correction — that admission-time `STALE` is an ordinary, operative refusal in every lane — is accurate to the code: the armed snapshot's `engine.binaryDigest` is captured from `loaded_engine_artifact_path` (`src/engine/mod.rs:146-161`, the mapped Hermes artifact), `ProtectedArtifactRole` (`crates/capsec-semantics/src/arming.rs:250`) has no loader-binary role, so on framework/dylib configurations an old snapshot indeed remains armable across an ibex toolchain rotation and the admission check is the operative gate. The containing-schema rotation list is complete against the checked-in schemas: only `module-carrier-v2` and `prepared-module-graph-v2` (via the v1 record defs) embed the artifact/fingerprint *shape*; the computed-candidates sidecar and the diagnostic schemas carry digests only and need no rotation. The committed-only entry marking is the right fix for the round-2 gap it targets — principle 6 correctly observes that a rule riding an optional commitment cannot survive that commitment's absence — and its production mechanics (snapshot-digest-covered section, validated at `ArmedSnapshot::load`, missing-commitment-refuses-startup) are sound and fail-closed. The validation-site split is coherently reasoned (e.g., the `ecmascriptOutputTarget` equality genuinely cannot run at commitment validation because the target lives inside option digests in `TransformFingerprintV1`, readable only against the loader's manifest constants). The D2 framing matches Exact LLP 0416 exactly (recommendation under §6, decision record shows D2 measurement ordered / decision deferred), and the masquerade, uninhabited-cell, and domain-separation analyses hold up under adversarial reading: carrier-principal reshuffles, arm-tag masquerades in both directions, and forgotten assignments all land on refusals, never on silent substitution. The concerns below are all minor.

## Concerns

**1. Dev-lane validation site for the committed-only consistency rule — minor, IN-DELTA (§Validation and admission / §Committed-only entries).** The commitment-validation list places "committed-only consistency: a commitment carrying any external assignment is valid only for an entry marked committed-only" at "`ArmedSnapshot::load` / dev-credential mint". In production both facts are in the snapshot, so the check is self-contained at load. In development they are split across processes: the marking is "host embedding configuration supplied by the consuming app," while the mint happens in the *producing* session, which in the cross-process warm start (LLP 0042 open question 1) cannot see the consumer's embedding configuration. The check as specified is only well-defined at the consumer's acceptance of the credential, not at mint. This does not undermine the guarantee — the operative enforcement (a marked entry refuses cold start) lives in the consumer regardless, and the document already declares the dev registration lane "not independently landable" pending OQ1 — but the validation-site assignment should name the consumer-side acceptance point when that transport design lands. Minor because the dependency is acknowledged and the defense does not rest on the mint-site check.

**2. Per-entry granularity of `committedOnlyEntries` — minor, IN-DELTA (§Committed-only entries and refusal disposition).** The marking is keyed by `entrySourceId`, but the property it protects (external transform ownership) attaches to source/principals, not entries. A production snapshot carrying a marked entry A and a second, unmarked, commitment-less entry B over the same Vite-owned tree would let B cold-build that source through ibex with the divergent semantics principle 6 exists to prevent. The document states the analogous honest-scoping ("host responsibility, guarantee begins at the marking") only for the development lane; the production multi-entry case is unstated. This is not a defective decision — the snapshot is the host's deliberate, ceremony-authenticated authorization surface, entry is the unit LLP 0042 commits at, and multi-entry snapshots are themselves an LLP 0042 open question — but one sentence extending the honest-scoping to production multi-entry snapshots would close the gap in the prose.

**3. Whether `sourceGoal` joins the registration's digested identity is unspecified — minor/altitude, IN-DELTA (§Registration and authority assignment / §Fingerprint wire evolution).** Assignments name registrations by "composed digest," defined as the digest "over the canonical composed value (both stages)" — which excludes the new `sourceGoal` field. Two registrations differing only in `sourceGoal` would therefore share a composed digest and collide on the uniqueness rule. Today the per-goal option digests make identical stage+downstream across goals effectively impossible, and even in the degenerate case the outcome is a validation refusal (fail-closed) plus the goal-match rule, so there is no unsoundness — but the implementation must pin which bytes the registration identity covers, and the document currently leaves the natural reading ambiguous (registration-value digest vs. composed-arm digest). Implementation-phase detail; recording as minor per the altitude rule.

**4. "Needed however the decision lands" slightly overstates — minor, PRE-EXISTING (§Summary; the delta touched the framing but the claim predates it).** The registry is a precondition for any outcome that keeps root-principal transforms Vite-owned — which is every live option, since D2 established there is no seam for Contract/suffix/env/automatic-JSX in ibex short of architectural work the measurement recommends against. But an author decision to reject the split entirely (e.g., pursue Contract-in-ibex or stay on the legacy path) would not need this contract. The operative, proven claim — adapter-1 publications structurally cannot admit today (0416 D2.3, 940/940 counter-evidence for adapter 2) — carries the document fine; the universal quantifier is rhetorical surplus.

**5. Fixture item 3's dev legs ride an unresolved transport — minor, IN-DELTA (§Fixtures and adversarial gate).** The no-downgrade fixtures include dev-harness legs ("trigger reproduce-from-producer") whose transport is LLP 0042 open question 1, inherited and acknowledged in §Currency. The fixture plan should not gate landing the production-shaped suite on the dev legs; a one-line sequencing note would prevent that misreading. Consistent with the document's own "not independently landable" statement, so minor.

## Verdict

All concerns are minor; none identifies a defective decision. The delta items enumerated in the brief are each present, internally coherent, and verified against the corpus and code where checkable; the round-2 revision resolved what it claims (authority-independent no-downgrade via the committed-only marking, completed schema rotations, honest `STALE` classification, goal-typed registrations) without introducing a material defect.

Binding this verdict to revision `b4b3ad472da4` of `llp/0043-registered-external-transform-fingerprints.rfc.md` and capsule `eb7eca7f53f0`.

VERDICT: READY


---

## Close-out — 2026-07-30 (loop terminal; escalated to the author)

**Terminal state.** The round budget (3/document) is exhausted. Round-3
verdicts on revision `b4b3ad472da4` / capsule `eb7eca7f53f0`: **Fable
READY**, **Codex NOT READY** (2 MATERIAL, both IN-DELTA; no PRE-EXISTING
MATERIAL from either family in rounds 2–3). Two terminal conditions hold
simultaneously: budget exhaustion with open MATERIAL concerns, and
sustained asymmetry (Fable READY on `93f1f44ddb3b` and `b4b3ad472da4`;
Codex NOT READY on both). Per the delta-convergence rule, remaining
in-delta fixes were applied as a final revision **labeled unreviewed**.

**Final revision:** `dab6bd9a7a3b` (post-round-3, UNREVIEWED — no verdict
binds to it). The last reviewed revision is `b4b3ad472da4`.

**Round-3 concern dispositions (applied in `dab6bd9a7a3b`):**

- Codex r3-1 (MATERIAL, IN-DELTA; Fable r3-1 is the same finding rated
  minor): dev committed-only consistency cannot be enforced at
  dev-credential mint → revised: the consumer's entry-bound marking check
  before any dev committed admission (and any cold start) is the
  enforcement boundary; mint-time checking demoted to defense in depth.
- Codex r3-2 (MATERIAL, IN-DELTA): sibling/migration set incomplete —
  orchestrator verified `schemas/stub-contract-v1.schema.json:120` and
  `src/compiled_contract.rs:105` pin `ibex/module-carrier/2`, and LLP 0026
  enumerates two trusted producers → revised: LLP 0026 (third trusted
  producer class) and LLP 0029 (`StubContractV1` carrier-pin `/3`
  migration, stub/catalog digest migration, refusal-and-rebuild fixtures)
  join Required sibling revisions (now five documents).
- Codex r3-3 (minor, altitude): `pipelineToolsDigest` preimage
  auditability → revised: named as a producer-conformance obligation with
  an implementation-pinned canonical preimage recipe and domain.
- Fable r3-2 (minor): production multi-entry honest-scoping sentence
  added to the committed-only section.
- Fable r3-3 (minor, altitude): registration identity pinned — digest of
  the whole registration value (covering `sourceGoal`) in
  `ibex:external-transform-registration:1`, distinct from the
  artifact-side composed fingerprint digest.
- Fable r3-4 (minor): Summary quantifier tightened to "any outcome that
  keeps root-principal transforms Vite-owned."
- Fable r3-5 (minor): fixture sequencing note — production-shaped suite
  lands with the contract; dev-harness legs gated on LLP 0042 OQ1.

**Growth budget:** entering revision 372 lines → final 587 (+58% net;
guideline ~20%). Every increment was reviewer-demanded mechanism
(authority assignment, committed-only marking, schema-rotation
completeness, sibling-revision enumeration); recorded as a bound
overrun, not hidden.

**Escalation to the author (proposals, author applies):**

1. **Stay `Review`** (recommended): the two round-3 MATERIALs are
   addressed in `dab6bd9a7a3b` but that revision is unreviewed; either
   accept after an author read, or authorize one additional delta round
   (exceeding the default budget) to convert it to a reviewed revision.
2. **Revert to `Draft`**: if the author wants the committed-only marking
   or the five-document sibling-revision footprint reconsidered before
   further review investment.

Fundamental-redesign feedback: none from either family in any round; both
families endorse the architecture (closed assignment, domain separation,
committed-only marking, naming-not-blessing trust model).
