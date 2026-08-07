# Reviews — LLP 0021 scoped-advertisement amendment (Codex/OpenAI family)

The LLP 0049 Phase 1 review package: the `## Amendment: scoped advertisement
(2026-08-06)` section of LLP 0021 (A1–A10, join matrix M1–M26) plus the
LLP 0032/0036 amendment deltas. Loop bound: 3 rounds (LLP 0049 §9), then
the disagreement ledger goes to the author.

## Round 1 — 2026-08-06

- **Family:** OpenAI Codex (gpt-5.6-sol)
- **Provider/runtime:** `codex exec` CLI 0.146.1,
  `-c model_reasoning_effort="high"`, `--sandbox read-only`,
  `--skip-git-repo-check`, brief on stdin
- **Date:** 2026-08-06
- **Redacted:** no (public-repo content only)
- **Method:** package at `90aafc67`; executed all mandated matrix-row
  checks (exceeding the 10-row minimum) plus independent completeness
  sweeps over both advertisement schema strings, both report schemas,
  `target_cells`, the lineage verifier, `new_armed_with_target_cells`,
  and `ibex/capsec-armed/1`; targeted questions Q1–Q5 per the round-1
  brief
- **Verdict:** NOT READY (2 BLOCKER, 4 MATERIAL, 1 MINOR; six-item flip
  set)

### Review body (verbatim from codex exec stdout)

## 1. Execution-pass results

Revision check: `git rev-parse HEAD` returned `90aafc6715ac607f0c9d511d04c579ef93a9b189`; the requested package has not moved. The amendment’s internal code citations remain pinned to the older `6416114d`, as disclosed in `llp/0021-capsec-effect-model-migration.plan.md:3493-3499`; code observations below are from current HEAD.

| Row/check | Result | Observation |
|---|---|---|
| M1 / `scopeDigest` | PASS | Exact repository-wide search over `src/`, `crates/`, `packages/ibex-devtools/src/`, `scripts/`, `build_support/`, and `tools/` returned zero `scopeDigest` hits. The blank-page claim is accurate (`llp/0021-capsec-effect-model-migration.plan.md:3493-3498`, `3922-3927`). |
| M2 / recipe completeness | PASS | The present assertion is global: it requires executable + internally verified = required and `unresolvedFixtures === 0` (`packages/ibex-devtools/src/scripts/capsec-conformance-recipes.mjs:5154-5166`). |
| M3 / public execution evidence | FAIL — incomplete consumer account | The rich artifact has a closed field set with no scope binding and still enforces global residual/missing counts (`capsec-public-surface-evidence.mjs:9600-9631`, `9701-9724`). More importantly, M3 omits the portable execution-binding digest and two strict Rust plan consumers discussed under Q1. |
| M4 / reports | PASS | The rich report is `ibex/capsec-conformance/1`, derives whole-inventory counts, and refuses advertisement unless every cell and fixture is complete (`capsec-conformance.mjs:570-609`, `612-640`). |
| M6 / bundle cell invariant | PASS | `exactTargetCells` rejects any exact-target row whose disposition is `unsupported` or whose fixtures/branches are malformed (`capsec-portable-promotion-bundle.mjs:149-179`). `validateSourceClosure` also requires the exact reviewed edge inventory and per-edge source-derived disposition/fixtures (`:262-325`). |
| M7 / admission | PASS | Admission requires the exact ordered coverage inventory, equality with independently derived authority, `Complete`/`Closed` dispositions, and full equality of required, passed, and execution fixture unions (`src/host/portable_target_admission.rs:1443-1527`). This verifies the behavior the amendment proposes to replace. |
| M11 / Option A blast radius | FAIL — incomplete and imprecisely classified | The cited direct SFE pins are real (`crates/sfe-format/src/lib.rs:780-790`; `crates/sfe-format/src/app_bound.rs:378-390`; `crates/sfe-catalog/src/lib.rs:700-711`), as is the digest-contract pin (`capsec-contract.mjs:494-499`). The ABI and embedder citations are generic parser/ingestion routes rather than literal schema pins (`src/host/abi.rs:1376-1392`; `src/host/embedder_artifacts.rs:690-705`). Literal grep also found omitted pins in `crates/capsec-semantics/src/canonical.rs:262-271`, `generate-capsec-runtime-projection.mjs:129-138`, `schemas/stub-contract-v1.schema.json:115-125`, `schemas/stub-contract-v3.schema.json:117-127`, `schemas/app-bound-common-v1.schema.json:223-235`, and `schemas/capsec-runtime-projection-v1.schema.json:18-30`. |
| M12/M13 / Host delivery | PASS on current-state description; FAIL on amendment coherence | Today `Host::new_armed` obtains one map from admission and passes it to the private constructor (`src/host/mod.rs:723-737`). The constructor accepts `BTreeMap<String, TargetCellDisposition>`, requires every value to be `Complete` or `Closed`, and stores the map separately on Host (`:781-845`, `872-877`). This confirms the cited current behavior but exposes the amendment’s missing host-level disposition type. |
| M14 / typed decision path | FAIL — open design is not yet implementable as written | The typed path emits `TargetCellIncomplete` with the coverage edge when `TargetCellDisposition::Incomplete` is reached (`crates/capsec-semantics/src/decision.rs:609-621`). The semantic enum presently has only `Complete`, `Closed`, and `Incomplete` (`:393-399`), and Host passes that exact type into every `EffectGate` (`src/host/mod.rs:2341-2349`). A host-only distinction is possible, but only after defining a separate host disposition/projection and a concrete telemetry envelope; neither exists in A3/M13. |
| M15 / synthetic constructors | PASS | Dev, insecure, and observer constructors synthesize complete maps and `CompleteAdvertised` (`src/host/mod.rs:655-682`, `695-718`, `745-772`). F11 is an appropriate negative invariant. |
| M17 / v2 reader | PASS | The sole authority-bearing portable validator pins v2 advertisement/report schemas and performs field-by-field publication joins (`capsec-portable-engine-evidence-contract.mjs:46-53`, `1037-1116`). |
| M18 / v1 ownership conflict | PASS — conflict is real | The registry generator builds non-empty v1 advertisements from committed promotions and writes them to the generated path (`generate-capsec-registry.mjs:1056-1082`, `1375-1381`). The lineage verifier requires the artifact-source copy at that path to be empty v1 (`portable-engine-promotion-lineage.mjs:816-826`). The build selector requires the tracked path to contain v2 bytes (`build_support/portable_engine_promotion_report.rs:23-30`, `314-336`). “V2 publication owns the path” is the correct semantic resolution because the verified bundle graph already requires the published bytes to equal its v2 advertisement member (`portable-engine-promotion-lineage.mjs:914-926`). |
| M19 / lineage | FAIL — incomplete artifact/consumer chain | The current verifier permits exactly one active catalog admission (`portable-engine-promotion-lineage.mjs:677-687`), requires a disabled/empty source authority (`:804-826`), and verifies one exact two-parent promotion merge (`:1064-1087`). M19 says it will expose the predecessor scope, but the checked admission artifact currently has no scope field in its schema, producer, or Rust parser (`schemas/portable-engine-checked-promotion-admission-v1.schema.json:7-18`; `portable-engine-promotion-lineage.mjs:1185-1199`; `src/host/portable_target_admission.rs:613-628`). That carrier is absent from the matrix. |
| M20 / build selector | PASS on current behavior | It selects one checked report and joins it to the tracked advertisement (`build_support/portable_engine_promotion_report.rs:286-360`, `362-450`); `build.rs` embeds the resulting bytes (`build.rs:864-880`). |
| M21/M22 / cells and authority | PASS | Target-cell candidate generation covers the complete edge inventory and refuses unpromotable dispositions (`generate-capsec-portable-promotion-target-cells.mjs:90-129`). Admission independently rebuilds report authority from checked coverage and implementation data (`portable_target_admission.rs:1144-1175`). |
| M26 / Go verifier | PASS | The Go verifier’s constants and trust surface concern artifact provenance/Sigstore, not CapSec reports, advertisements, or cell schemas (`tools/portable-engine-attestation-verifier/verifier.go:30-63`). Scope-transparent is correct. |

This exceeds the requested ten-row spot check and includes every mandated row.

## 2. Overall assessment

The package has the right claim-boundary model and Option B is directionally preferable, but it is not yet a complete, implementable security design. Two defects are blocking: the authenticated lineage result has no specified artifact path from M19 into runtime admission, and A3/M13 require an explicit uncertified host disposition while M14 simultaneously preserves a semantic type that cannot represent it. The matrix also misses strict consumers that will either reject or fail to bind the new scope identity. These gaps can produce either non-armable releases or a Host whose advertised/introspected scope is not mechanically inseparable from the map it enforces.

## 3. Strengths

- A7 preserves the essential per-invocation, non-compositional boundary and expressly withholds refusal/absence/safety claims for the remainder (`llp/0021-capsec-effect-model-migration.plan.md:3782-3814`). That faithfully carries LLP 0044’s normative threat model (`llp/0044-scoped-advertisement-and-evidence-cost-collapse.rfc.md:186-213`).

- A2 preserves complete-cell indivisibility and retains the honest out-of-scope rows rather than deleting or reclassifying them (`llp/0021-capsec-effect-model-migration.plan.md:3562-3587`).

- Option B correctly identifies report admission as the only component positioned to independently rederive expansion and closure (`llp/0021-capsec-effect-model-migration.plan.md:3714-3737`). Avoiding a derivative snapshot field is sound in principle.

- M18 catches a real, otherwise release-breaking three-way ownership conflict and recommends the correct semantic owner (`llp/0021-capsec-effect-model-migration.plan.md:4126-4155`).

- A1 gives the scope, expansion diff, and cell mapping distinct schemas and digest domains and binds both companion digests into the scope artifact (`llp/0021-capsec-effect-model-migration.plan.md:3507-3538`).

## 4. Concerns

### BLOCKER — M19/M7: no authenticated predecessor carrier or evolvable lineage algorithm

M19 promises that the verifier will “resolve and expose” the current scope for M7 (`llp/0021-capsec-effect-model-migration.plan.md:4157-4167`), but the authoritative matrix has no row for the checked promotion-admission artifact that actually crosses the build/runtime boundary. Its schema, producer, build carrier, and Rust parser all have closed field sets without a scope or predecessor field (`schemas/portable-engine-checked-promotion-admission-v1.schema.json:7-18`; `portable-engine-promotion-lineage.mjs:1185-1199`; `build_support/portable_engine_build_consumption.rs:130-139`; `portable_target_admission.rs:613-628`).

The current lineage topology is also one-shot: one active admission, empty source foundation, one exact promotion merge (`portable-engine-promotion-lineage.mjs:677-687`, `804-826`, `1064-1087`). A5’s “each expansion is a new promotion” therefore lacks an algorithm for discovering and authenticating the prior scope across promotions (`llp/0021-capsec-effect-model-migration.plan.md:3641-3659`).

Resolution: add a matrix row for the checked lineage/admission result and every producer/carrier/parser; specify its revised schema, exact predecessor/current fields, and how the verifier finds the prior admitted scope in authenticated Git history. Define whether whole-checkout rollback is out of scope or bind to an external monotonic anchor.

### BLOCKER — A3/A6/M13/M14: scope identity, host disposition, and enforced map are not one defined object

A3 requires an explicit uncertified cell-map disposition while saying decision semantics remain unchanged (`llp/0021-capsec-effect-model-migration.plan.md:3599-3619`). Current Host stores `TargetCellDisposition` directly, and that semantic enum has no uncertified variant (`src/host/mod.rs:236-239`; `decision.rs:393-407`). Passing a new variant through `EffectGate` necessarily changes `decision.rs`; keeping M14 transparent requires a separate host-only disposition that projects `Uncertified → Incomplete`.

A6 also says the digest “never travels alone,” but does not require an opaque admitted aggregate tying scope identity, expanded set, and exhaustive map together. A10 permits a parallel Host record without specifying the constructor recheck (`llp/0021-capsec-effect-model-migration.plan.md:4265-4270`).

Resolution: define an opaque `AdmittedScopedTargetCells`-equivalent, constructible only by M7, containing the rederived scope identity, expansion, and exhaustive host-level dispositions. M12/M13 must consume it atomically, recheck the in-scope/out-of-scope partition, and derive both introspection and `EffectGate` projection from that same retained object. Specify the host telemetry schema and central emission point.

### MATERIAL — A9/M3/M11/M19/M25: the consumer matrix is incomplete

In addition to M11’s missing literal pins, the following load-bearing consumers lack explicit rows:

- `portableExecutionBindingDigest` enumerates report/cell/evidence bindings but would ignore an added `scopeDigest` unless amended (`capsec-portable-engine-evidence-contract.mjs:216-235`).
- The portable public-batch Rust parser rejects unknown binding fields (`src/bin/ibex/engine/capsec_portable_public_batch.rs:183-204`).
- The exact-fixture portable plan parser has the same closed binding list (`capsec_exact_fixture_evidence_batch.rs:489-508`).
- The generated Rust include is the advertisement carrier into runtime (`src/capsec_registry_generated.rs:10-12`).
- The physical-promotion workflow derives cells, invokes the bundle-producing run, verifies the bundle, and uploads it, so its scope inputs/outputs must be classified at least scope-transparent (`.github/workflows/portable-engine-physical-promotion.yml:372-443`).

Resolution: add rows or explicitly expand M3/M19/M25 to enumerate and classify these consumers. Repeat the literal-schema sweep in M11.

### MATERIAL — A5: rename/split/merge totality does not prevent semantic narrowing

A1 requires mapping entries to be total “on both sides,” but does not require scope preservation across the mapping (`llp/0021-capsec-effect-model-migration.plan.md:3533-3538`). A split can therefore map one in-scope predecessor to several successors without saying all successors remain in scope; a merge does not say the successor stays in scope when any predecessor was in scope. Live-inventory absence alone also cannot distinguish a true retirement from inventory drift (`:3527-3535`, `3651-3657`).

Resolution: normatively require:

- rename of an in-scope cell → successor in scope;
- split of an in-scope cell → every successor in scope;
- merge with any in-scope predecessor → successor in scope;
- mapped predecessors cannot simultaneously count as retired;
- predecessor/current inventory digests and the mapping relation are bound and independently regenerated;
- genesis checks search retained history for the canonical tuple, including an explicit policy for feature/tuple renames.

### MATERIAL — A7: two sentences overstate or contradict the boundary

“Every surface outside the scope … remains callable” is a universal availability assertion (`llp/0021-capsec-effect-model-migration.plan.md:3789-3797`). Some out-of-scope target surfaces can be absent or otherwise unavailable; the intended claim is only that scoped certification adds no universal physical-refusal guarantee.

The next paragraph says every generated cell, including a zero-decision cell, participates in startup map exhaustiveness, then says the zero-decision remainder has “neither layer” (`:3799-3808`). That conflates metadata admission with an execution-refusal property.

Resolution: replace “it remains callable” with “the certification does not constrain its availability; no universal physical-refusal claim is made.” Describe startup admission as protecting scope/map integrity, not as refusing zero-decision execution, and say zero-decision surfaces have no typed-gate or physical-entrypoint refusal.

### MATERIAL — A8: substitution fixtures are not exhaustive enough for A6’s argument

F1 names paired S1/S2 substitution but does not explicitly cover stale advertisement + fresh report, two tuple artifacts crossed, or a direct scope-identity/map crossing at the Host constructor (`llp/0021-capsec-effect-model-migration.plan.md:3827-3830`). F6 covers stale predecessors and false genesis but not rollback of the checked lineage root (`:3846-3849`). F11 checks only absence of synthetic scope introspection, not positive equality between introspection and enforced map (`:3865-3869`).

Resolution: add explicit subcases for each attack in Q2, including a positive invariant that introspection and every Host disposition derive from the same opaque admitted aggregate.

### MATERIAL — M18/A10.2: path ownership should be settled, not left as an equal alternative

The v1 generator, empty-v1 source rule, and v2 build reader cannot all own the same bytes. V2 publication already has the runtime and verified-bundle semantics (`portable-engine-promotion-lineage.mjs:914-926`; `portable_engine_promotion_report.rs:314-336`). The remaining choice is only where diagnostic v1 output moves.

Resolution: normatively assign `capsec/generated/target-advertisements.json` to v2/v3 publication and move or retire the v1 diagnostic emission.

### MINOR — M11 terminology

`src/host/abi.rs:1381-1392` and `src/host/embedder_artifacts.rs:690-705` are transitive ingestion routes, not literal schema pins. Distinguish direct schema pins, generated mirrors, and transitively affected callers when pricing Option A.

## 5. Answers to Q1–Q5

### Q1 — Matrix completeness

No. I swept, excluding `target/`, `.git/`, and LLP prose:

- both advertisement schema strings: 7 non-LLP files each;
- both report schema strings: 9 v1 files and 7 v2 files;
- `target_cells|targetCells|target-cells`;
- `portable-engine-promotion-lineage`;
- `new_armed_with_target_cells`;
- `ibex/capsec-armed/1`: 17 non-LLP files.

Missing load-bearing consumers are the checked promotion-admission schema/producer/build carrier/Rust parser, portable execution-binding digest, two strict Rust evidence-plan parsers, the generated Rust advertisement carrier, and physical-promotion workflow. Their concrete locations are cited in the concerns above. M11 also misses multiple direct schema pins.

### Q2 — Option B substitution resistance

- **Stale advertisement + fresh report:** closed by the intended M7 rederivation and advertisement/report/bundle equality, with a second build-time join in M20 (`llp/0021…:3744-3748`, `4170-4179`). F1 should explicitly instantiate this crossing; it currently does not.

- **Two tuples’ artifacts crossed:** structurally closed because the scope includes the canonical tuple, advertisement selection is tuple-unique, and admission authenticates target/artifact identity (`llp/0021…:3511-3526`, `3749-3754`; current checks at `portable_target_admission.rs:702-715`). No A8 fixture explicitly pins the cross-tuple case.

- **Re-admission after lineage rollback:** F6 closes a stale predecessor relative to an intact authenticated lineage (`llp/0021…:3846-3849`). It does not close rollback of the lineage/check-out root itself, and the present verifier authenticates only the currently checked revision/topology (`portable-engine-promotion-lineage.mjs:1041-1087`). The threat boundary must be stated.

- **Snapshot from a differently scoped run:** under Option B, same-tuple snapshots are intentionally scope-neutral, so “differently scoped snapshot” is not a meaningful identity class. A different-tuple snapshot remains constrained by tuple and loaded-engine authentication (`llp/0021…:3722-3727`, `3749-3754`). This should have an explicit fixture.

- **Introspection digest disagrees with enforced map:** not fully closed as written. A6’s construction story intends one admission result, but no opaque type or constructor invariant makes the scope/map/introspection relationship inseparable.

The Option A/B trade is honest in its central insight: putting a derivative digest in the snapshot adds consistency work without an independent authority. Option B does relocate all claim integrity to admission, but that is the correct authority boundary because admission alone rederives the scope. The phrase “digest never travels alone” becomes sound only after the opaque admission aggregate and checked-lineage carrier are normative.

### Q3 — Claim wording versus rule 8

No sentence makes the forbidden positive assertion that out-of-scope surfaces are refused, absent, or safe. Every actual refusal statement names startup admission or reached typed-gate refusal (`llp/0021…:3799-3808`, `3831-3837`), and A3 correctly limits its behavior claim to a reached typed gate (`:3608-3619`).

Two edits are nevertheless required:

1. “it remains callable” is an overbroad universal availability claim (`:3789-3797`);
2. the zero-decision “neither layer” sentence contradicts the immediately preceding exhaustive-map admission statement (`:3799-3808`).

The 0032/0036 deltas do not add an out-of-scope safety claim (`llp/0032…:825-829`; `llp/0036…:421-439`).

### Q4 — Monotone lineage

As written, narrowing can be laundered through insufficiently specified inventory and mapping transitions:

- retirement passes on current live-inventory absence without a separately stated completeness/history proof;
- split/merge totality does not force every successor of an in-scope predecessor to remain in scope;
- genesis is safe only if M19 searches retained history for the canonical tuple, which the current one-admission verifier does not yet do;
- changing the feature vector creates a different tuple and therefore a fresh genesis unless a tuple-migration rule exists.

The expansion diff and mapping do have genuinely separate proposed schema/digest domains, and both are bound into the scope artifact (`llp/0021…:3527-3538`). The defect is transition semantics and lineage delivery, not domain separation.

### Q5 — A10 open questions

1. **Telemetry placement:** a genuine implementation/author choice, but the admissible host-layer design must be specified before item 5. “Host annotation” alone is insufficient.

2. **V1-path ownership:** not a genuine equal security choice. V2/v3 publication must own the production path; only the diagnostic-v1 destination is discretionary.

3. **Bundle versus repository placement:** a genuine architecture decision, but it directly determines M19/M20/M7 authentication and must be settled before approving Option B.

4. **`TargetArmState` payload versus parallel record:** implementation representation can vary, but only an opaque admission aggregate with atomic construction is acceptable. An independently mutable parallel Host record is not security-equivalent.

Missing from both A6 and A10 are:

- the schema and carrier for M19’s authenticated predecessor/current-scope result;
- the multi-promotion lineage/history algorithm and whole-repository rollback boundary;
- semantic-preservation rules for rename/split/merge and tuple migrations;
- whether portable execution bindings carry `scopeDigest` directly or are formally scope-transparent through a named transitive digest.

## 6. Open questions for the author beyond A10

1. Is rollback of the entire authenticated checkout/release channel in scope? If not, what external authority is assumed to supply freshness?

2. What exact mapping invariant proves that a rename, split, or merge preserves every formerly in-scope obligation rather than merely accounting for identifiers?

3. Does a feature-name or tuple migration inherit the predecessor scope, or intentionally create a new lineage? What authenticated mapping governs that transition?

4. Must every execution-plan binding carry `scopeDigest` directly, or is transitive binding through `recipeCatalogDigest` acceptable? Whichever rule is chosen should be uniform and machine-checked.

5. What exact machine-readable telemetry object carries `uncertified` without changing `DecisionReason`, and which centralized Host path guarantees that every reached-gate refusal receives it?

## 7. Verdict

**NOT READY** for the author’s LLP 0044 item-5 decision.

Minimal flip set:

1. Add the checked-lineage admission artifact/carrier/parser and omitted execution/workflow/schema consumers to A9.
2. Define an opaque admitted scope+expansion+cell-map aggregate, its host-only uncertified disposition, its projection to `Incomplete`, and its telemetry/introspection invariants.
3. Specify the evolvable lineage/history algorithm and narrowing-preserving rename/split/merge/retirement rules.
4. Expand A8 with stale/fresh artifact crossings, cross-tuple crossings, direct map/digest crossings, positive introspection coherence, and the decided rollback boundary.
5. Correct A7’s universal callability and zero-decision-layer wording.
6. Settle v2/v3 production-path ownership and scope-artifact placement.
