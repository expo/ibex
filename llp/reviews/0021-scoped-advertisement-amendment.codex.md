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

## Round 2 (delta) — 2026-08-06

- **Family:** OpenAI Codex (gpt-5.6-sol)
- **Provider/runtime:** `codex exec` CLI 0.146.1,
  `-c model_reasoning_effort="high"`, `--sandbox read-only`,
  `--skip-git-repo-check`, brief on stdin
- **Date:** 2026-08-06
- **Redacted:** no (public-repo content only)
- **Method:** delta round at commit `38c382d2`, document revision
  `9565a3cb8f30`; executed all mandated delta checks including a
  `git grep` sweep against the committed tree and a git-history
  reconstruction of the catalog foundation (`afad4af9`) to test genesis
  admissibility; full disposition table over both families' round-1
  findings
- **Verdict:** NOT READY (2 new IN-DELTA BLOCKERs; three-item flip set)

### Review body (verbatim from codex exec stdout)

## 1. Delta-verification results

- **PASS — revision identity.** `git rev-parse --verify 38c382d2^{commit}` returned `38c382d2eab6227c8abfc318635a61422f3a5f21`; `git show 38c382d2:llp/0021-capsec-effect-model-migration.plan.md | shasum -a 256` returned `9565a3cb8f30530f…`. The requested package matches.

- **FAIL — M27 lineage topology and discovery walk.** The four current pins are accurate: the checked schema is closed (`schemas/portable-engine-checked-promotion-admission-v1.schema.json:6-18`), the producer freezes the same fields (`scripts/portable-engine-promotion-lineage.mjs:1185-1199`), the build carrier writes those exact bytes (`build_support/portable_engine_build_consumption.rs:118-139`), and Rust rejects any other key set before verifying the domain digest (`src/host/portable_target_admission.rs:587-628,639-668`). But M27’s walk does not work as specified. Today an active catalog is valid only when the examined revision itself is the exact two-parent promotion merge, its first parent is `sourceRevision`, its topic is one direct child, and that source revision contains a disabled, empty catalog and empty-v1 advertisement (`portable-engine-promotion-lineage.mjs:804-826,1064-1087`). A later ordinary first-parent commit continues to “carry an admission” but is not that merge, so M27 step 2 can select it and step 1 will reject it. Repeated promotion also conflicts with M18 pin 2: the previous promoted revision owns v2/v3 bytes, while unchanged `assertSourceAuthorityClosed` requires the next source revision’s copy to be empty v1. No enable→disable/reset lifecycle or exact “promotion revision” predicate is specified (`llp/0021…:4538-4568`). Genesis is under-specified too: `git log 38c382d2 --first-parent -- …catalog…` shows the catalog was introduced disabled at `afad4af9`; its parent lacks the path, while M27 says the walk runs to exhaustion without defining how pre-foundation absence is authenticated. `git log 38c382d2 --all -S'"enabled":true"' -- …catalog…` found no historical active admission, so this repository is a legitimate genesis only if that missing-path rule is supplied.

- **FAIL — A3 aggregate/projection against real Host entry points.** The proposed Rust type placement is mechanically viable: `portable_target_admission` is a private child module (`src/host/mod.rs:14-24`), so a `pub(super)` opaque type with private fields can be returned by M7 and moved into Host without other production modules constructing it. The production cell map currently comes from `authenticated_report_target_cells` (`src/host/portable_target_admission.rs:1307-1322`); five synthetic complete-map constructors and two test-only direct calls also exist (`src/host/mod.rs:655-718,745-772,880-953,8151-8157,8979-8985`) and are correctly assigned to M15/F11. `HostCellDisposition::Uncertified → TargetCellDisposition::Incomplete` can occur in `Host::target_cell` and leave `decision.rs` unchanged (`src/host/mod.rs:956-961,2840-2851`; `crates/capsec-semantics/src/decision.rs:393-407,609-621`). However, the aggregate does **not** currently make every gate disposition map-derived: the C ABI accepts caller-supplied serialized `EffectGate.targetCell` (`src/host/abi.rs:5823-5839`; `src/host/mod.rs:3942-3981`), and `EffectGate` exposes that field publicly (`decision.rs:401-407`). There is also a direct production `TargetCellDisposition::Complete` construction for runtime-extension gates (`src/host/mod.rs:1266-1310`). Additionally, telemetry has three separate evaluation paths, not the claimed single receiver (`src/host/mod.rs:3794-3839,3844-3872,3874-3903`). Thus an out-of-scope ABI gate can bypass the retained aggregate and reached-gate refusal unless every ingress is rebound or checked.

- **FAIL — M11 sweep and count.** Against the committed tree,  
  `git grep -n -F '"ibex/capsec-armed/1"' 38c382d2 -- . ':!llp/**' ':!target/**' ':!node_modules/**'`  
  returns **21 matching lines in 17 files**, and `git grep -o … | wc -l` returns **23 literal occurrences**. Excluding `vendored-generated/**` yields the amendment’s 20 lines/16 files, but still 21 literal occurrences because `crates/capsec-semantics/src/arming.rs:3679` contains the string twice. The omitted seventeenth file is `vendored-generated/capsec-runtime-projection.canonical.json:1`, itself generated and embedded through `generate-capsec-runtime-projection.mjs:31,156` and `src/capsec_runtime_projection_generated.rs:14`. Fable’s 21-hit observation was correct for the 16-file set; the revision’s recorded command does not exclude the additional generated mirror.

- **FAIL — M18 eight-pin disposition.** All eight named pins are real (`llp/0021…:4342-4408`), including the three contrary assertions at `src/host/portable_target_admission.rs:1866-1879`, `scripts/hermes-artifacts-workflow-security.test.mjs:375-384`, and `scripts/package-portable-hermes-macos.test.mjs:773-782`. Retiring them or converting them to artifact-source fixtures is workable and fixes their HEAD-copy assertions. The settled owner is also correct for one promotion: the generator emits v1 (`generate-capsec-registry.mjs:1056-1082,1375-1381`), while the build selector requires v2 (`build_support/portable_engine_promotion_report.rs:23-30,314-336`). But pin 2 cannot remain unchanged under M27’s repeated-promotion story without a specified depublication/reset phase: `assertSourceAuthorityClosed` still requires empty-v1 source bytes (`portable-engine-promotion-lineage.mjs:804-826`), whereas the preceding promoted revision contains the v2/v3-owned path. Therefore the per-pin disposition is not yet coherent across multiple promotions.

- **PASS — M28 strict parsers and carriage choice.** Both Rust parsers compare the binding object’s exact sorted key set and therefore reject an unknown `scopeDigest` today (`src/bin/ibex/engine/capsec_portable_public_batch.rs:96-104,183-204`; `src/bin/ibex/engine/capsec_exact_fixture_evidence_batch.rs:175-183,489-508`). Both recompute the digest over the accepted whole binding object (`capsec_portable_public_batch.rs:213-220`; `capsec_exact_fixture_evidence_batch.rs:537-545`). Direct carriage is viable by revising all three lists; transitive carriage is also a real choice because `portableExecutionBindingDigest` already binds `recipeCatalogDigest` (`capsec-portable-engine-evidence-contract.mjs:216-235`) and the recipe-catalog digest commits its complete object (`:238-241`). The transitive option must retain M28’s proposed digest-reachability check.

- **PASS — M7 scoped equalities.** Today admission constructs full-inventory fixture unions and requires `required == passed == executions`, exact summary counts, and zero missing/failed/incomplete (`src/host/portable_target_admission.rs:1443-1527`). M7 preserves that equation over the independently rederived in-scope set S, keeps the report exhaustive over the full inventory, and adds an explicit refusal for any out-of-scope authoritative fixture or execution (`llp/0021…:4140-4179`). Relative to scoped certification, this is equivalent on S and stronger at the diagnostic/authoritative boundary because of the zero-contribution rule.

## 2. Round-1 disposition table

The Codex artifact’s header says four MATERIAL findings, but its body contains five MATERIAL headings (`llp/reviews/0021-scoped-advertisement-amendment.codex.md:86,98,111,119,125`). All five are included below to satisfy “every finding.”

| Family / finding | Disposition | Exact resolving or failing location |
|---|---|---|
| Codex BLOCKER 1 — authenticated predecessor carrier and evolvable lineage | **PARTIAL** | Carrier/schema/parser and rollback boundary added in M27 and M7 (`llp/0021…:4180-4191,4510-4576`), but M27’s “most recent revision carrying an admission” is not an exact promotion-revision predicate and conflicts with today’s source-empty topology (`portable-engine-promotion-lineage.mjs:804-826,1064-1087`). |
| Codex BLOCKER 2 — opaque scope/map aggregate, host disposition, telemetry | **PARTIAL** | `AdmittedScopedTargetCells`, `HostCellDisposition`, atomic Host retention, projection, envelope, M12/M13, and F11 were added (`llp/0021…:3607-3666,3992-4003,4269-4309`). Caller-supplied ABI gates and the direct runtime-extension `Complete` gate remain outside that invariant (`src/host/abi.rs:5823-5839`; `src/host/mod.rs:1266-1310,3942-3981`). |
| Codex MATERIAL — consumer matrix incomplete | **PARTIAL** | M27–M31 now cover the checked carrier, execution bindings, workflow, report restamps, and installer (`llp/0021…:4510-4651`), while M18 includes the generated advertisement carrier. M11 still omits the checked-in runtime-projection mirror and misstates its executed count (`vendored-generated/capsec-runtime-projection.canonical.json:1`). |
| Codex MATERIAL — rename/split/merge and retirement narrowing | **PARTIAL** | Preservation rules, disjoint retirement/mapping sets, and independently regenerated inventory digests are now normative (`llp/0021…:3706-3728`). Feature-list/tuple migration remains undecided in A10 #7 (`:4718-4725`), and the history walk on which genesis depends remains incomplete. |
| Codex MATERIAL — A7 overbroad callability/zero-decision wording | **RESOLVED** | A7 now says certification does not constrain availability, describes startup as scope/map-integrity only, and excludes typed/physical refusal for zero-decision surfaces (`llp/0021…:3881-3904`). |
| Codex MATERIAL — substitution fixtures incomplete | **RESOLVED** | F1a–F1c cover stale/fresh, cross-tuple, and direct map/identity crossings; F6 states the whole-checkout rollback boundary; F11 adds positive introspection/map coherence (`llp/0021…:3926-3946,3967-3976,3992-4003`). |
| Codex MATERIAL — M18 ownership left open | **PARTIAL** | A10 #2 assigns the path to v2/v3 and M18 dispositions all eight named pins (`llp/0021…:4342-4408,4677-4687`). The unchanged source-empty pin is not reconciled with repeated promotions, as described above. |
| Codex MINOR — M11 terminology | **RESOLVED** | M11 separates direct schema pins, generated mirrors/emission sites/vectors, and transitive callers (`llp/0021…:4231-4261`). |
| Fable MATERIAL 1 — missing M18 path pins | **PARTIAL** | The four requested missing pins plus the v1 schema are present with dispositions in M18 pins 4–8 (`llp/0021…:4377-4408`), but pin 2’s unchanged source-empty rule conflicts with M27’s repeated-promotion topology. |
| Fable MATERIAL 2 — M11 enumeration/count | **PARTIAL** | Most missing pins were added (`llp/0021…:4231-4255`), but the recorded sweep actually returns 21 lines/17 files and omits `vendored-generated/capsec-runtime-projection.canonical.json:1`. |
| Fable MATERIAL 3 — report-schema restamp chain | **PARTIAL** | M30 now enumerates both closed JSON Schemas and the four v1 digest-contract pins (`llp/0021…:4618-4638`; LLP 0032 delta `:810-822`). The requested rev-vs-evolve decision remains open in A10 #6 (`llp/0021…:4713-4717`). |
| Fable MATERIAL 4 — scoped M7 equalities and zero contribution | **RESOLVED** | Normative equalities and zero-authoritative-contribution refusal are explicit in M7 and F4 (`llp/0021…:4162-4179,3954-3963`). |
| Fable MATERIAL 5 — runtime lineage-anchor carrier unnamed | **PARTIAL** | M7/M20/M27 now name the build-embedded checked admission as anchor, script verifier as authority, and bundle-carried scope as the other input (`llp/0021…:4180-4191,4432-4441,4510-4576`). The carrier is specified, but the history algorithm that stamps it is not operationally complete. |
| Fable MATERIAL 6 — uncertified type placement | **RESOLVED** | Host-side `HostCellDisposition`, projection at Host gate construction, and unchanged `decision.rs` are settled in A3/M13/M14/A10 (`llp/0021…:3628-3642,4285-4309,4657-4661`). |
| Fable MINOR 7 — installer and v1-schema consumers | **RESOLVED** | Installer is M31 (`llp/0021…:4640-4651`); v1 schema is M18 pin 8 (`:4404-4407`). |
| Fable MINOR 8 — denominator drift | **PARTIAL** | LLP 0036 now marks 3,922 as superseded by 3,927/73 (`llp/0036…:426-434`), but LLP 0049 still describes 610/536/74 and “the 74” (`llp/0049…:150-156,428-449`) while its evidence index says 610/537/73 (`:714`). The corpus still disagrees. |

## 3. New findings

### IN-DELTA — BLOCKER: M27 does not identify an authentic historical promotion revision

M27 searches for the newest revision whose catalog “carries an admission,” but catalog contents persist into descendants; carrying the bytes is not proof that the revision is the promotion merge. Today that proof is tied to the examined checkout itself and requires the exact merge parents/tree (`portable-engine-promotion-lineage.mjs:1041-1087`). The algorithm also refers to `R_prev`’s `admittedScopeDigest`, although that value exists only in the proposed build-output checked admission; the tracked admission’s closed fields contain no such property (`portable-engine-promotion-lineage.mjs:691-704`; `llp/0021…:4530-4568`).

**Exact resolution:** define a historical promotion-revision predicate and tracked source for its scope digest; specify the enabled/disabled catalog lifecycle between promotions; validate each selected promotion directly from commit/tree/blob objects; define behavior before the catalog foundation exists; then fixture genesis, promotion→ordinary commits/reset→second promotion, stale predecessor, and false genesis.

### IN-DELTA — BLOCKER: scoped gate disposition remains caller-controlled through the Host ABI

The revision says every per-gate disposition derives from the retained aggregate and that divergence is unrepresentable (`llp/0021…:3617-3627,3997-4003`). In reality, `ex_host_evaluate_typed_decision` accepts serialized gates from its caller (`src/host/abi.rs:5823-5839`), Host deserializes their public `targetCell` field and evaluates them unchanged (`src/host/mod.rs:3963-3981`; `crates/capsec-semantics/src/decision.rs:401-407`). An out-of-scope edge supplied as `complete` therefore bypasses the promised projection. The direct runtime-extension gate also manufactures `Complete` locally (`src/host/mod.rs:1266-1310`).

**Exact resolution:** under `ScopedAdvertised`, every evaluator ingress must discard/recompute or equality-check `targetCell` against `AdmittedScopedTargetCells` by `coverageEdgeId`; eliminate or explicitly scope the runtime-extension exception; centralize the three evaluation/evidence paths for telemetry; add ABI-level F1c/F3 fixtures proving caller-supplied `complete` cannot override an uncertified cell.

No additional PRE-EXISTING finding beyond issues already present in the round-1 artifacts.

## 4. Verdict

**NOT READY** for the author’s LLP 0044 item-5 decision.

Minimal flip set:

1. Replace M27’s discovery sketch with an implementable authenticated multi-promotion algorithm, including the catalog reset/persistence lifecycle, exact historical promotion predicate, tracked source of the prior scope digest, and pre-foundation genesis semantics; reconcile M18 pin 2 with that lifecycle.
2. Make the scoped aggregate authoritative at **every** `EffectGate` ingress, including the C ABI/public JSON evaluators and the runtime-extension direct-`Complete` path, and identify one complete telemetry emission path covering all evaluator variants.
3. Correct M11’s recorded sweep/count and include the checked-in generated runtime-projection mirror in the Option-A blast radius.

## Round 3 (final round) — 2026-08-06

- **Family:** OpenAI Codex (gpt-5.6-sol)
- **Provider/runtime:** `codex exec` CLI 0.146.1,
  `-c model_reasoning_effort="high"`, `--sandbox read-only`,
  `--skip-git-repo-check`, brief on stdin
- **Date:** 2026-08-06
- **Redacted:** no (public-repo content only)
- **Method:** final delta round at commit `8def7e20`, document revision
  `a770c2f95e9b`; executed the mandated checks including direct AJV
  execution against both v1 schemas, git-object verification of the
  lineage floor and its parent, and both M11 sweep commands
- **Verdict:** NOT READY (1 IN-DELTA BLOCKER, 2 IN-DELTA MATERIAL,
  1 PRE-EXISTING MATERIAL; two-item flip set)

### Review body (verbatim from codex exec stdout)

## 1. Delta-verification results

- **PASS — revision identity.** `git rev-parse HEAD` and `git rev-parse --verify 8def7e20^{commit}` both returned `8def7e20c363274b3228491df6dcbdf736754465`; `git show 8def7e20:llp/0021-capsec-effect-model-migration.plan.md | shasum -a 256` returned `a770c2f95e9b2360…`.

- **PASS — A3/M32 closes caller-supplied `targetCell`.** There are exactly five caller-supplied-gate doors: four public Rust methods at `src/host/mod.rs:3776,3844,3942,3963` plus `ex_host_evaluate_typed_decision` at `src/host/abi.rs:5823-5839`; the two JSON methods delegate to the two typed methods (`src/host/mod.rs:3960,3981`). A3 normatively requires discard-and-recompute before every `evaluate_decision_set*` call (`llp/0021…:3683-3751`), and M32 carries the implementation work (`:5350-5412`). The private path-projection evaluator at `src/host/mod.rs:3874-3903` receives only Host-constructed gates, so it is not a sixth caller ingress.

- **PASS — runtime-extension scoping.** Although the ABI supplies `effect_semantics`, Host rejects it unless it exactly equals the authenticated capsule operation’s semantics (`src/host/mod.rs:1202-1217`) before copying it into `coverage_edge_id` (`:1266`). A3/M32 then require an inventory-edge collision to use the aggregate disposition, while a genuinely non-inventory extension semantic remains explicitly `extension-declared` (`llp/0021…:3752-3774,5383-5412`). That boundary is sound.

- **PASS — F3a pins recomputation, not min-of-two.** F3a-1/2 reject caller-presented `complete` for an uncertified edge, while F3a-3 requires caller-presented `incomplete` on an in-scope Complete edge to evaluate as Complete (`llp/0021…:4146-4164`). A min rule cannot pass both directions.

- **FAIL — M27’s historical promotion predicate is not exact against the current verifier.** M27 lifts only the merge-shape checks corresponding to `portable-engine-promotion-lineage.mjs:1064-1074` (`llp/0021…:5059-5083`). Current authorization additionally collects the source tree, runs `assertSourceAuthorityClosed`, and runs `verifyChangedArtifacts` (`portable-engine-promotion-lineage.mjs:1075-1087`), which ties catalog artifact rows to actual tree blobs, raw digests, the exact changed-path set, and the verified bundle graph (`:930-995`). M27 explicitly omits those checks for historical hops (`llp/0021…:5129-5142`).

- **PARTIAL — tracked `admittedScopeDigest`.** Adding it to `validateAdmissionShape`, the catalog schema, and `admissionDigest` would content-bind the declaration (`llp/0021…:5085-5107`; current digest recomputation at `portable-engine-promotion-lineage.mjs:757-758`). It does not prove the value equals a scope artifact in R’s tree. It also does not identify the canonical tuple: A1 defines tuple identity as triple plus sorted features (`llp/0021…:3531-3534`), while M27 searches only by `targetTriple` (`:5081-5083`) and adds no feature field to the tracked admission (`:5091-5099`).

- **FAIL — reduced per-hop authentication is insufficient.** `parseCatalog`/`validateAdmissionShape` check canonical form, field shape, role counts, and the self-digest (`portable-engine-promotion-lineage.mjs:673-759`), but do not require the named blobs—or any scope artifact—to occur in R’s tree. A correctly shaped two-parent merge can therefore insert an arbitrary self-consistent `admittedScopeDigest`, which a later walk accepts as the predecessor anchor. `admissionDigest` is an unkeyed semantic digest, not evidence that the full ceremony ran (`:757-758`; contrary wording at `llp/0021…:5139-5142`).

- **PARTIAL — enable/disable/RESET lifecycle.** The reset makes `assertSourceAuthorityClosed`’s empty-v1 rule coherent for promotion 2+ (`llp/0021…:5144-5187`; current rule at `portable-engine-promotion-lineage.mjs:804-826`). Its cost is real: a disabled checked admission causes the build selector to embed `null` (`build_support/portable_engine_promotion_report.rs:453-465`), so the reset revision cannot advertise or arm from the promoted report. The repository’s push-triggered publisher creates diagnostic artifact caches, not product releases (`.github/workflows/hermes-artifacts.yml:20-25,35-40`), so no present automation falsely publishes the claim; however, M27 supplies no mechanical tag/release gate enforcing its statement that the reset commit “must not be treated as release-able” (`llp/0021…:5177-5183`).

- **PASS — lineage floor and truncated-history precondition.** `afad4af9f4257eb8262cf8348e5fbb0a3c082ecf` is a first-parent ancestor of `8def7e20`; its catalog is present, disabled, and empty, while `git cat-file -e afad4af9^:<catalog>` exits 128. Both `git log --all -S'"enabled":true'` and `-S'"enabled": true'` return zero commits. Requiring non-shallow history, no grafts/replace refs, and exact first-parent reachability to that object closes the truncated-history genesis bypass (`llp/0021…:5189-5235`; F6e at `:4220-4226`).

- **PASS — M11 re-adjudication.** The new path-anchored command at `llp/0021…:4545-4555` returned **21 lines / 17 files / 23 occurrences**. The old `grep … | grep -v target/` pipeline returned **20 lines / 16 files**. The missing line is `vendored-generated/capsec-runtime-projection.canonical.json:1`, whose content includes `"/target/triple"`; applying the old content filter to the complete hit set reproduces the undercount exactly.

- **FAIL — M18 pin 9 recommendation is incomplete.** The release-breaking claim is true: `capsec-contract.mjs` reads the HEAD advertisement (`:3514-3517`) and validates it against the v1 schema (`:130-131,3680-3685`); direct AJV execution produced `current_v1=true` and `promoted_v2_under_v1=false` with `/targetAdvertisementSchema must be equal to constant`. But moving only advertisements to the artifact-source copy is insufficient: the same runner reads HEAD target attestations (`:3518-3520`), validates them against v1 (`:132-133,3686-3690`), and requires advertisement/attestation target-set equality (`:4212-4229`). Promotion already emits v2 attestations at that tracked path (`capsec-portable-promotion-bundle.mjs:1089-1099`; v1 const at `capsec/schema/target-attestations.schema.json:8`). The recommendation must move both foundation documents together or version-dispatch both.

## 2. Disposition tables

### Round-2 findings

| Family / finding | Disposition | Exact section or row |
|---|---|---|
| Codex BLOCKER — historical promotion-revision identification | **PARTIAL** | M27 (i)–(vi) fixes persistence, the tracked digest source, reset lifecycle, floor, and truncated history (`llp/0021…:5059-5273`), but M27 (iii) does not authenticate the historical scope/artifact binding; New Finding 1. |
| Codex BLOCKER — caller-controlled gate disposition | **RESOLVED** | A3 ingress rule (`:3683-3774`), F1c/F3a (`:4119-4133,4146-4176`), M13/M32 (`:4662-4666,5350-5412`). |
| Codex flip item — M11 undercount | **RESOLVED** | M11’s new command and 21/17/23 result (`:4508-4616`), independently reproduced above. |
| Fable MATERIAL — nonexistent central refusal path | **RESOLVED** | A3 acknowledges three bodies and makes the funnel new work (`:3794-3820`); M13 carries it (`:4652-4661`); F3 covers all three (`:4137-4145`). |
| Fable MATERIAL — incomplete M18 inventory/pin 8 | **RESOLVED as asked** | M18 requalifies completeness, records a 19-line/15-file sweep, and adds/corrects pins 9, 10, and 12 (`:4746-4903`). The adjacent attestation defect is a new finding. |
| Fable MATERIAL — M27 algorithm/reset collision | **PARTIAL** | M27 (iii) and (iv) state the reduced set and reset lifecycle (`:5109-5187`), but the reduced set is not sufficient to authenticate a hop. |
| Fable MATERIAL — genesis via truncated history | **RESOLVED** | A5 precondition (`:3883-3904`), M27 (v)/(vi) (`:5189-5235`), F6a/F6e (`:4203-4206,4220-4226`). |
| Fable MINOR — global vs per-tuple cardinality | **RESOLVED** | M27 retains today’s global one-admission rule (`:5251-5263`). |
| Fable MINOR — pin 4 cannot perform a source-revision check | **RESOLVED** | M18 pin 4 limits disposition to retirement/replacement (`:4798-4812`). |
| Fable MINOR — “no test constructor” overclaim | **RESOLVED** | A3 narrows the type-system boundary (`:3622-3637`); F11 repeats it (`:4243-4255`). |
| Fable MINOR — M7 zero-contribution ambiguity | **RESOLVED** | M7 explicitly distinguishes authoritative unions from row content (`:4441-4462`). |
| Fable PRE-EXISTING MINOR — stale M2/A2 pins | **RESOLVED by disclosure** | Dated pin-drift note at `llp/0021…:3509-3519`; implementation still must re-pin. |

### Round-1 carry-forward

| Family / finding | Final disposition | Exact location |
|---|---|---|
| Codex B1 — predecessor carrier/evolvable lineage | **PARTIAL** | Carrier resolved by M27/M7 (`:5016-5107,4463-4474`); historical authentication remains unresolved. |
| Codex B2 — opaque aggregate/host disposition | **RESOLVED** | A3 (`:3622-3682`) plus M12/M13/M32 (`:4618-4666,5350-5412`). |
| Codex M1 — consumer matrix omissions | **RESOLVED for named omissions** | M27–M31 and M18 pin 7 (`:5016-5348,4823-4830`). |
| Codex M2 — rename/split/merge narrowing | **RESOLVED** | A5 semantic-preservation rules (`:3860-3904`). |
| Codex M3 — A7 overstatement | **RESOLVED** | A7 (`:4050-4090`). |
| Codex M4 — substitution fixtures | **RESOLVED** | F1a–F1c, F6, F11 (`:4104-4133,4190-4227,4243-4266`). |
| Codex M5 — M18 owner unsettled | **PARTIAL** | Owner is settled (`:5497-5524`), but pin 9’s recommended implementation omits the coupled attestation document. |
| Codex minor — M11 terminology | **RESOLVED** | Direct/generated/transitive classification (`:4565-4607`). |
| Fable M1 — missing M18 path pins | **RESOLVED** | Sweep-recorded thirteen-pin disposition (`:4746-4914`). |
| Fable M2 — M11 enumeration/count | **RESOLVED** | M11 (`:4508-4616`). |
| Fable M3 — report restamp chain | **RESOLVED** | M30 and LLP 0032 delta (`:5315-5335`; `llp/0032…:810-822`). |
| Fable M4 — scoped M7 equations | **RESOLVED** | M7 (`:4429-4462`). |
| Fable M5 — runtime lineage carrier unnamed | **RESOLVED** | M7 runtime anchor and M20 (`:4463-4474,4932-4947`). |
| Fable M6 — uncertified type placement | **RESOLVED** | A3/M14 (`:3654-3682,4668-4695`). |
| Fable minor — installer/v1-schema consumers | **RESOLVED** | M31 and M18 pin 8 (`:5337-5348,4831-4843`). |
| Fable minor — denominator drift | **RESOLVED** | LLP 0036 amendment delta (`llp/0036…:414-446`). |

## 3. New findings

### IN-DELTA — BLOCKER — M27 authenticates a catalog declaration, not a historical promotion hop

M27’s selected-hop predicate checks canonical catalog shape and merge topology but deliberately omits `assertSourceAuthorityClosed` and `verifyChangedArtifacts` (`llp/0021…:5059-5083,5109-5142`). Consequently, it never proves that the historical admission’s artifact rows match R’s tree, that the named scope artifact exists, or that recomputing that artifact yields `admittedScopeDigest`. `validateAdmissionShape` only validates field syntax and a self-digest (`portable-engine-promotion-lineage.mjs:691-759`); the omitted checks perform the actual tree/blob/bundle joins (`:930-995,1075-1087`).

A shaped merge can therefore insert an arbitrary self-consistent predecessor digest without rewriting old history, and later promotions treat it as authoritative. That defeats the new monotone-lineage claim.

**Exact resolution:** for every selected R, collect R/source leaves and verify at least the scope-critical subset of `verifyChangedArtifacts`: exactly one scope artifact row, row blob ID/size/raw digest equal to R’s tree, recomputed `scopeDigest == admission.admittedScopeDigest`, scope artifact canonical tuple equality, and source/current changed-path consistency. Full version-dispatched `assertSourceAuthorityClosed` plus `verifyChangedArtifacts` is stronger and preferable. Remove the statement that `admissionDigest` “attests” the prior ceremony unless a real attestation authority is added.

### IN-DELTA — MATERIAL — M27 cannot identify a per-feature tuple

The scope’s canonical tuple is triple plus sorted features (`llp/0021…:3531-3534`), and A10 explicitly says a feature-list change creates a fresh tuple (`:5555-5562`). M27’s historical selection filters only `targetTriple` (`:5081-5083`); its tracked admission work adds only `admittedScopeDigest` (`:5091-5107`). Promotions for two feature vectors on the same triple are therefore indistinguishable: the walk either incorrectly forces cross-feature ancestry or cannot validate genesis.

**Exact resolution:** add the canonical feature list—or one closed canonical `target` object—to the tracked admission, checked admission, catalog schema, digest projection, historical predicate, and fixtures. Rev the tracked admission schema/domain rather than silently changing the closed `/1` contract, or derive and verify the full tuple from the historically authenticated scope artifact.

### IN-DELTA — MATERIAL — reset revisions lack a mechanical non-release gate

M27 acknowledges that reset-to-empty-v1 withdraws the advertisement and that the reset revision must not be releaseable (`llp/0021…:5164-5183`). Disabled admission embeds no promoted report (`build_support/portable_engine_promotion_report.rs:461-465`). The reset reconciles M18 pin 2 safely, but “reset and promotion as a single reviewed sequence” is not atomic in the required Git topology: the reset must first exist as the next promotion’s first parent.

**Exact resolution:** add a release/tag/product-publication gate that refuses a disabled/reset catalog, or perform the reset in a non-release staging ref and promote atomically into the release ref. Keep ordinary diagnostic per-SHA artifact caches explicitly outside that gate (`.github/workflows/hermes-artifacts.yml:20-25,35-40`).

### PRE-EXISTING — MATERIAL — M18 pin 9’s recommended fix ignores the coupled target-attestation publication

The contract runner reads and v1-validates both HEAD publications (`capsec-contract.mjs:130-133,3514-3520,3680-3690`) and requires their advertised target sets to match (`:4212-4229`). Promotion emits v2 target attestations now (`capsec-portable-promotion-bundle.mjs:1089-1099`), while the amendment proposes v3 in M5 (`llp/0021…:4380-4388`). Moving only target advertisements to their artifact-source v1 copy therefore still fails schema validation and, if validation were version-dispatched, produces a foundation-advertisement/current-attestation set mismatch.

**Exact resolution:** the recommended frozen-contract option must read both target advertisements and target attestations from the same authenticated artifact-source revision. The alternative must version-dispatch and restamp both documents together.

## 4. Verdict

**NOT READY.**

The ledger-worthy findings are:

1. **M27 does not authenticate the historical scope artifact behind `admittedScopeDigest`**; this is a direct defect in the newly claimed monotone lineage.
2. **M27 lacks full tuple identity**, colliding with the author-facing tuple-migration decision in A10 #7.

The reset release gate and paired target-attestation correction are implementer-correctable: both fail closed and will surface immediately during gate implementation.

Minimal flip set:

1. Make each historical M27 hop prove the tracked `admittedScopeDigest` against an actual content-hashed scope artifact in that promotion tree, with scope-critical source/tree/artifact joins.
2. Carry and verify the full canonical tuple, including features, through the tracked and checked admission schemas and historical predicate.
