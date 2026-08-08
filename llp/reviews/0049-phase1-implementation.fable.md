# Reviews — LLP 0049 Phase 1 implementation (Claude/Fable family)

The independent adversarial review of the **merged Phase 1 gate code**,
required by LLP 0049 §3 rule 11. This is distinct from the reviews of the
LLP 0021 scoped-advertisement amendment (the design package) and of
LLP 0049 itself (the plan).

## Round 1 — 2026-08-07

- **Family:** Claude (Fable 5)
- **Provider/runtime:** fresh general-purpose subagent via Claude Code Agent
  tool, independent context
- **Independence:** the reviewer wrote none of the code under review and
  did not participate in authoring LLP 0049 or the LLP 0021 amendment
- **Reviewed revision:** `1c3806832` (`git diff 5e41aca0..HEAD`, 79 files,
  ~9,551 insertions / 1,073 deletions), on branch `phase1/integration`
- **Date:** 2026-08-07
- **Redacted:** no (public-repo content only)
- **Method:** read against the LLP 0021 amendment as authority; executed
  the suites; and — per rule 11's break-test requirement — **reverted three
  defects in a scratch tree and confirmed the fixtures fail**, restoring
  the tree afterwards (`git status --short` empty on exit)
- **Break-tests performed (all reverted):**
  1. `src/host/mod.rs:1067` — dropped discard-and-recompute, trusting the
     caller's `target_cell` → **3 failures**
     (`all_four_public_ingresses_discard_and_recompute_scoped_cells`,
     `c_abi_discards_presented_complete_for_an_uncertified_cell`,
     `scoped_refusal_funnel_covers_all_three_evaluator_bodies_once`)
  2. `src/host/mod.rs:1084-1088` — restored hard-coded `Complete` for
     runtime-extension gates → **1 failure**
     (`runtime_extension_resolver_separates_collisions_from_extension_declared`)
  3. `scripts/portable-engine-promotion-lineage.mjs:1037` and `:1044` —
     removed both M27(i) scope joins → **2 failures** (F6f, F6f-4)
- **Verdict:** NOT READY at the reviewed revision — 1 BLOCKER
  (the scope artifact's two incompatible canonical forms), 6 MATERIAL,
  9 MINOR
- **Disposition of findings:** BLOCKER-1 and MATERIAL M-1 fixed and merged
  in `caac9ecd5` / `e11071717`, with the cross-language vector
  `schemas/vectors/capsec-scope-v1.valid.json` consumed from both
  languages and the F6f variant-(a) break-test re-run to confirm it now
  refuses at the intended layer. **The remaining MATERIAL and MINOR
  findings are NOT yet dispositioned** — see LLP 0049 §5.3.

### Review body (verbatim)

# Independent adversarial review — LLP 0049 Phase 1 gate code

**Target:** `1c3806832` ("fix(capsec): LLP 0049 Phase 1 integration reconciliation (S7)"), `git diff 5e41aca0..HEAD`, 79 files.
**Authority:** `llp/0021-capsec-effect-model-migration.plan.md` §§A1–A9 (`Amendment: scoped advertisement (2026-08-06)`, lines 3485–6386) + `scratchpad/a10-decisions.md`.
**Tree state on exit:** clean. Every edit I made was reverted (`git status --short` empty). Note: during the session another agent committed `d604d116b` (LLP 0050 lockdown restamp) on top of the review target; `1c3806832` is now `HEAD~1`.

---

## 1. Verdict: **NOT READY to merge to main**

The security core is genuinely good. The ingress rule, the opaque aggregate, and the scoped admission arithmetic all do what §A3/§A7 say, and I could not construct a bypass. Three break-tests confirmed the Rust and JS fixtures pin real defects.

But the chain does not connect end to end: **the only generator of the scope artifact emits a document the only consumers of the scope artifact cannot parse**, and no test crosses that seam. §A9's M7 and M20 are implemented against two mutually incompatible definitions of `ibex/capsec-scope/1`.

**Minimal blocking set: BLOCKER-1 only.** Everything else is MATERIAL/MINOR and can land as follow-ups, but MATERIAL-2 should be fixed in the same change because it is a fixture that reads as proof and is not.

---

## 2. Findings

### BLOCKER

**B1 — The scope artifact has two incompatible canonical forms sharing one schema id and one digest domain. M7/M20 cannot execute.**

Producer and schema of record (JS names):
- `packages/ibex-devtools/src/scripts/capsec-scope-artifact.mjs:667-681` — `buildScopeArtifact` emits `scopeSchema`, `expandedCellIds`, `closureEdges` (7 fields each), `predecessor: {kind[,scopeDigest]}`, `scopeExpansionDiffDigest`, `scopeCellMappingDigest`, `scopeDigest`.
- `schemas/capsec-scope-v1.schema.json` — `required` = exactly those ten names; `$defs/closureEdge` has `additionalProperties: false` and `required: [fromEdgeId, toEdgeId, dependencyKind, implementationBranchId, terminalObservedKey, proofPaths, sourceRefs]`.
- `scripts/portable-engine-promotion-lineage.mjs:936` (`SCOPE_DIGEST_FORMATS[scope.scopeSchema]`), `:942-956` (`scope.predecessor.kind`), `:1263` (`"scope-artifact": ["scopeSchema", SCOPE_SCHEMA]`) — the lineage verifier reads the JS names.

Consumers (Rust names):
- `src/host/portable_target_admission.rs:66-79` — `struct CapsecScopeArtifact`, `#[serde(rename_all="camelCase", deny_unknown_fields)]`, fields `schema`, `profile`, `target`, `intensional_definition`, `expanded_cells`, `closure_edges`, `predecessor_scope_digest`, `expansion_diff_digest`, `cell_mapping_digest`, `scope_digest`.
- `src/host/portable_target_admission.rs:59-64` — `struct ScopeClosureEdge`, `deny_unknown_fields`, **two** fields only.
- `build_support/portable_engine_promotion_report.rs:443` — `scope_root.get("schema")`.

Five of ten top-level names differ, plus the closure-edge shape. Both sides declare the *same* schema id `ibex/capsec-scope/1` (`capsec-scope-artifact.mjs:12` / `portable_target_admission.rs:36`) and the *same* digest domain `ibex:capsec:scope:1` (`capsec-scope-artifact.mjs:13` / `portable_target_admission.rs:37`). §A1 requires one canonical artifact in one digest domain; a digest in that domain currently does not identify a unique document type.

Effect: a real generator artifact is rejected at `parse_scope_artifact` (`portable_target_admission.rs:1572`, "invalid promoted scope artifact model") before any of the M7 re-derivation at `:1656-1726` runs, and independently fails the build-time join at `portable_engine_promotion_report.rs:443-446`.

Why no test caught it: each side builds its own fixture in its own dialect — `portable_target_admission.rs:2161` (`"schema": SCOPE_SCHEMA_V1`) and `:2168`-region `"expandedCells"`; `portable_engine_promotion_report.rs:658,665` (`"schema"`, `"expandedCells"`); the JS tests use `buildScopeArtifact` output. Unlike every other CapSec artifact there is **no cross-language vector**: `ls schemas/vectors/ | grep -i scope` returns nothing.

Currently latent, not exploitable: with the promotion catalog still disabled, `select_embedded_report` short-circuits to `scope_bytes: b"null\n"` (`build_support/portable_engine_promotion_report.rs:489-495, 500-505`) and `authenticated_report_target_cells_with_authority` refuses on `report_text == "null\n"` (`portable_target_admission.rs:1755-1759`). It fails closed. But Phase 3's first genesis promotion cannot succeed, and the claim "admission re-derives the promoted scope and compares" is unsupported end to end.

**Resolves it:** choose one field set, restamp the other side, and add `schemas/vectors/capsec-scope-v1.valid.json` consumed by *both* the JS schema validator and a Rust `parse_scope_artifact` test — the same cross-language vector discipline the other CapSec artifacts already have (e.g. `schemas/vectors/portable-engine-provenance-v1.valid.json`, used at `portable_target_admission.rs:2415-2420`).

### MATERIAL

**M-1 — F6f variant (a) refuses at the wrong layer; it does not exercise the tree-backing join.**
`scripts/portable-engine-promotion-lineage.test.mjs:336-341`: the `missing-scope-row` variant demotes the scope row's `role` to `conformance-evidence`, so the admission is refused by `validateAdmissionShape` (`scripts/portable-engine-promotion-lineage.mjs:788`, `roleCounts.get(SCOPE_ROLE) === 1`, reached at `:1117`) — *admission-shape validation*, not the M27(i) join at `:1030-1037`. §A8 F6f explicitly specifies "an admission that passes `validateAdmissionShape`". **Confirmed by break-test:** with the join at `.mjs:1037` neutered, the F6f test still passed variants (a) and (b) and failed only on `scope-digest-mismatch`. Also, `.mjs:1032` (`missing reserved scope artifact`) is consequently unreachable dead code.
Related gap: variant (b) mutates only `blobObjectId` (`test:346-350`); §A8 also names size, digest, and blob-absence — untested.
**Resolves it:** keep `role: "scope-artifact"` and make the blob genuinely absent from the merge tree, or relabel the variant to what it actually tests.

**M-2 — Two structurally different report schemas now share the id `ibex/capsec-conformance/3`.**
Before: rich report id `/1` + domain `ibex:capsec:conformance:1`; portable report id `/2` + domain `:2` (`git show 5e41aca0:capsec/schema/conformance-report.schema.json:17`, `git show 5e41aca0:schemas/capsec-conformance-report-v2.schema.json:18,104`). After M30's restamp both are `/3` (`capsec/schema/conformance-report.schema.json:17`, `schemas/capsec-conformance-report-v2.schema.json:18`) while the domains stayed apart — `:1` (`crates/capsec-semantics/src/digest.rs:15`, `canonical.rs:277`) vs `:3` (`src/host/portable_target_admission.rs:35`, `capsec-portable-engine-evidence-contract.mjs:48`). The id is no longer a discriminator between them. It fails closed (the domain separates them), but A10 #6's own rationale — "evolving `/1` in place mutates the meaning of an already-published schema id, which this corpus treats as dishonest versioning" — argues equally against minting a colliding one. **Resolves it:** give the rich report a distinct id (e.g. `ibex/capsec-conformance-rich/2`).

**M-3 — F6f-5's "only" and its negative-control claim are unasserted narrative.**
`test:1473-1491`. The positive half is genuine: `resolveHistory` succeeding proves the `SCOPE_ROLE` branch at `.mjs:1023` and `:1412` landed. But (a) the "old HEAD refused this" assertion is `git cat-file -e` on the *fixture's own* source revision (`test:1477-1486`) — a fixture property restated in an assert message as a claim about superseded code, which reads true regardless of what old HEAD did; (b) the "only at the reserved path" half is `scopePath.endsWith("/capsec-scope.json")`, a construction tautology. `assertArtifactRolePath` (`.mjs:851-854`, "scope-artifact must use the reserved evidence-prefix path") has zero coverage repo-wide. **Resolves it:** add a `scope-artifact` row at a non-reserved path and assert its refusal; drop the historical claim.

**M-4 — F4's zero-authoritative-contribution assertion is tautological in JS.**
`packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.test.mjs:4473ff`: `expect(canonicalJson(authoritative)).toBe(authoritativeBytes)` snapshots the bytes one line earlier and `buildPublicSurfaceDiagnosticArtifact` never receives `authoritative`, so nothing between them could mutate it. The real §A8 F4 claim ("zero out-of-scope fixtures in the required, passed, or execution unions") *is* enforced and tested on the Rust side (`portable_target_admission.rs:1951-1952, 1978-1980, 2571-2593`). **Resolves it:** assert the union arithmetic in JS, or record that the Rust test is F4's authority.

**M-5 — F6h-b tests text, not behaviour.**
`scripts/assert-releasable-checked-admission.test.mjs:95` and `scripts/portable-engine-physical-promotion-workflow.test.mjs:398` assert exclusion-list membership and YAML greps. §A8 F6h(b)'s substance — "every artifact-source-revision ceremony output still succeeds there", the anti-circularity property the gate depends on — is not executed anywhere. F6h-a's input is the static `vectors.checkedDiagnostic`, not an admission produced at a reset revision, so `build_support/portable_engine_promotion_report.rs:500-505` is never exercised.

**M-6 — F6b's admit direction is tautological, and the "regression test" claim is against a model.**
`test:1373-1394`: `assert.equal(promotion2.scope.predecessor.scopeDigest, prior.admittedScopeDigest)` compares a value the fixture itself set; the admit half never calls `verifyPortableEngineScopePredecessor` with a matching digest (only the refusal direction, in F6c/F6d, goes through production code). Separately, `SCOPE_ROLE`, `verifyScopeCriticalPromotionRevision` and the advertisement join all landed in one commit (`816490184`) — there is no round-2 implementation in this repo, so §A8's "it is a regression test in fact, not only in intent" rests on `roundTwoShapeOnlyAccepts` (`test:402-408`), a six-line hand-written model of the superseded prose.

### MINOR

- **m1** `src/host/abi.rs:2670-2677` — the sole `abi.rs` change is a comment claiming the ingress rule, placed inside `private_vfs_open_read_typed`, ~3150 lines from `ex_host_evaluate_typed_decision` (`:5828`) that it describes. Move it.
- **m2** `src/host/mod.rs:4111-4126` — `record_scoped_refusal` uses `.find(...)`, emitting one envelope per *decision*, not per refused gate. Correct today only because `evaluate_decision_set` returns on the first `TargetCellIncomplete` (`crates/capsec-semantics/src/decision.rs:612-621`). The envelope's completeness is a property of the evaluator's early return, not of the emitter — worth an `@ref`ed comment.
- **m3** `src/host/mod.rs:4136-4141` — the `Certified(Complete | Closed) ⇒ IncompleteDefect` arm is unreachable through any recomputing ingress (a certified cell never yields `TargetCellIncomplete`). The funnel test reaches it only via the private `evaluate_typed_decision_inner` with a hand-built `Incomplete` gate (`portable_target_admission.rs:2736-2743`). `incomplete-defect` has no production producer, which is exactly what §A3 says; document it at the enum rather than leaving it looking live.
- **m4** `src/host/portable_target_admission.rs:174-204` — `is_coherent()` re-derives precisely the invariants `new()` already enforces at `:117-142`, so the `HostTargetCells::Scoped(admitted) if admitted.is_coherent()` guard at `src/host/mod.rs:915` can never be false and its refusal branch is untestable. Harmless, but it is not the independent construction-time re-check A3 asks for.
- **m5** `src/host/portable_target_admission.rs:2643-2699` — `non_advertisement_constructors_remain_scope_incapable` scrapes `mod.rs` as a string with hand-rolled body delimiters. It would not catch a constructor reaching `Scoped` through a helper, and it breaks on reformatting. The real F11 negative half is the module boundary (`mod.rs:23` + private `fn new`); the scrape adds little.
- **m6** `schemas/capsec-scope-introspection-v1.schema.json` and `schemas/capsec-scope-diagnostic-record-v1.schema.json` are referenced by nothing — no validator, no test, no Rust round-trip (grep over `src crates packages scripts` returns only self-references). The refusal envelope alone has an equivalent pin (exact key-set assertion, `portable_target_admission.rs:2768-2785`). Add the same for the other two.
- **m7** `packages/ibex-devtools/src/scripts/capsec-public-surface-evidence.mjs:9798-9812` — `assertPublicSurfaceExecutionComplete` requires `options.closureEdgeIds` but never uses it; the real F8 enforcement is in `validatePublicSurfaceExecutionArtifact` (`:9744-9745` → `assertObservedScopeClosure`, `:9757`). Also, callers pass `scopeArtifact.expandedCellIds` as `closureEdgeIds` (`run-capsec-conformance.mjs:953, 1053, 1986`) — semantically right (closure targets are folded into the expansion at `portable_target_admission.rs:1648`) but misnamed.
- **m8** Unpinned §A9 rows: **M26** (Go attestation verifier) has no test at all; **M11** has no test pinning the schema-string pin inventory; **M10** is pinned only transitively via `scoped_host_keeps_scope_out_of_the_frozen_armed_snapshot`.
- **m9** Process: the brief states the code "is NOT on main". `1c3806832` is `HEAD~1` of the local `main` branch, and the local `origin/main` ref points at `7e1e1cd85` — slice S1 of this very work. Worth confirming with a fetch before anyone concludes none of the gate code is on the shared branch.

---

## 3. Answers to Q1–Q6

### Q1 — Does the ingress rule actually close the ABI hole? **Yes, for `ScopedAdvertised`. I could not construct a bypass.**

- All four `pub` gate-taking methods route through `prepare_external_gates`: `src/host/mod.rs:3927` (`evaluate_typed_decision`, :3922), `:4005` (`_with_evidence`, :4000), `:4226` (`_json`, :4208), `:4255` (`_json_with_evidence`, :4237). I enumerated the `pub fn` surface taking `gates: &[EffectGate]` and those four are exhaustive.
- `prepare_external_gates` (`:1047-1075`) **overwrites** unconditionally — `gate.target_cell = self.target_cell(...)` at `:1067`. There is no equality check anywhere in the file. The discarded value is kept only as `presented_target_cells` for telemetry (`:1057`, `:4144-4146`).
- Absent edge does **not** inherit the caller's value: `target_cell` (`:1036-1042`) maps `Some(Uncertified) | None ⇒ Incomplete`. §A3's explicitly forbidden reconciliation is absent, and `all_four_public_ingresses_discard_and_recompute_scoped_cells` (`portable_target_admission.rs:2833-2844`) asserts refusal + `AbsentEdge` for `"extension.absent.scope-edge"`.
- The C symbol needed no change: `ex_host_evaluate_typed_decision` (`abi.rs:5828`) calls `evaluate_typed_decision_json_with_evidence` (`abi.rs:5840`), which recomputes. Directly proven by `c_abi_discards_presented_complete_for_an_uncertified_cell` (`portable_target_admission.rs:2862-2897`), which drives the real `#[no_mangle]` symbol.
- Runtime-extension path: `authorize_runtime_extension_operation` builds its gate via `resolve_runtime_extension_gate` (`mod.rs:1077-1107`) and hands it to the **private** `evaluate_typed_decision_inner` at `mod.rs:1457` — not the `pub` ingress. This is exactly §A3's round-4 correction, and the conditional rule is right: inventory edge ⇒ aggregate's disposition wins (refuses if `Uncertified`); non-inventory ⇒ literal `Complete` + `extension-declared` in the *diagnostic* record (`mod.rs:1090-1095`), not in the refusal envelope. `scoped_refusal_funnel_covers_all_three_evaluator_bodies_once:2785` asserts `hostDisposition != "extension-declared"`.
- The third evaluator body, `evaluate_typed_path_decision_with_evidence` (`mod.rs:4045`), is private; its only callers (`mod.rs:2487`, `portable_target_admission.rs:2724`) build gates internally. It still emits the envelope (`mod.rs:4069`).

**Residual worth stating plainly:** under `CompleteAdvertised`, `prepare_external_gates` returns the caller's gates verbatim (`mod.rs:1051-1056`). That is F3a-5 by design, but it means the ABI hole remains fully open for every non-scoped armed build — i.e. every build shipping today. Nothing in the code overclaims here; release notes must not.

### Q2 — Is `AdmittedScopedTargetCells` genuinely inseparable? **Yes, within the boundary §A3 itself draws.**

- Constructor `fn new` is module-private (`portable_target_admission.rs:110`); all five fields private (`:101-107`); no `Default`; `mod portable_target_admission` is a private child of `src/host` (`mod.rs:23`). The single production construction site is `:1994`.
- Host consumes it atomically: the map is not a Host field at all — `target_cells: Arc<HostTargetCells>` with `HostTargetCells::Scoped(AdmittedScopedTargetCells)` (`mod.rs:238-244`), taken by `new_armed_with_target_cells` (`mod.rs:855`). No parallel record.
- One source for both surfaces: `fn target_cell` (`mod.rs:1036-1042`) and `capsec_scope_introspection` (`mod.rs:4097-4110`) both read the *same* `self.target_cells` payload. There is no second copy of the digest, expansion, or map anywhere.
- The map cannot be mutated beside the digest: only `scope_digest()`, `disposition()`, `uncertified_remainder()`, `uncertified_edge_ids()`, `is_coherent()` are exposed (`:156-204`), all read-only; no `&mut` accessor exists.
- Partition exactness is enforced at construction (`:117-142`): exhaustive over `CAPSEC_COVERAGE_EDGE_IDS`, expansion ⊆ inventory, and `in-expansion ⇔ Certified(Complete|Closed)` / `out ⇔ Uncertified`. `admitted_aggregate_is_atomic_exhaustive_and_partitioned` (`:2469-2509`) exercises all three rejections.
- Exceptions, both named by §A3 and correctly not papered over: the in-file `#[cfg(test)] mod tests` (`:2032`) is a descendant with private access and does construct aggregates (`:2380, 2481, 2492, 2502`) — review-constrained, not type-constrained.
- Weakness: see MINOR m4 — the "re-check at construction" the Host performs is `is_coherent()`, which is `new()`'s own postcondition restated.

### Q3 — Is the scoped admission arithmetic right? **Yes, on both sides. This is the strongest part of the change.**

Rust (`portable_target_admission.rs:1895-1993`):
- Row content is **not** emptied: `cell.required_fixtures != expected_authority.required_fixtures` refuses for **every** cell, in-scope or not (`:1916-1923`). Out-of-scope rows therefore keep their honest source-derived `required_fixtures`.
- Zero authoritative contribution: `required_fixtures.extend` / `passed_fixtures.extend` occur only inside the in-scope branch (`:1951-1952`). The out-of-scope branch requires `status == "uncertified"` and empty `passed`/`missing`/`failed` (`:1958-1966`).
- No out-of-scope execution can enter the authoritative set: `passed_fixtures != execution_fixtures` (`:1980`) forces the executions union to equal the in-scope passed set exactly.
- Summary equalities at `:1981-1988` match M7's normative list term for term (`conformant_cells == |expansion|`, `uncertified_cells == |inventory| − |expansion|`, `incomplete == 0`, `missing == 0`, `failed == 0`).
- Pinned by `out_of_scope_rows_keep_honest_required_fixtures_without_authoritative_credit` (`:2571-2593`), which asserts `requiredFixtures` retained, `passedFixtures == []`, and no execution row carrying the out-of-scope fixture id.

JS:
- Report builder mirrors it: `capsec-conformance.mjs:570-583` — out-of-scope cells keep `requiredFixtures` via `...publicCell` and get empty `passed`/`missing`/`failed` with `status: "uncertified"`.
- A2 completeness is exactly as written: `assertRecipeCatalogComplete` (`capsec-conformance-recipes.mjs:5441-5468`) requires the scope binding to be present, then `unresolvedFixturesInScope === 0` and `fullyExecutableInScope + internallyVerifiedInScope === requiredFixturesInScope`; per-recipe validation runs only over `inScope` (`:5470-5500`). Out-of-scope rows are retained and counted separately (`scopedSummary`, `:4826-4850`).
- A shared fixture is in-scope when **any** in-scope cell requires it (`:4818-4821`), counted once — the conservative direction, consistent with A2's "no partial-cell credit".

### Q4 — Do the fixtures test what their names claim? **Mostly yes; three do not. I broke three defects and confirmed the fixtures.**

Break-tests executed (all reverted):

| # | Defect reverted | Result |
|---|---|---|
| 1 | `src/host/mod.rs:1067` — dropped the discard-and-recompute, trusting the caller's `target_cell` | **3 failures**: `all_four_public_ingresses_discard_and_recompute_scoped_cells`, `c_abi_discards_presented_complete_for_an_uncertified_cell`, `scoped_refusal_funnel_covers_all_three_evaluator_bodies_once` (`Allow` where `RefuseArming` expected) |
| 2 | `src/host/mod.rs:1084-1088` — restored hard-coded `Complete` for every runtime-extension gate | **1 failure**: `runtime_extension_resolver_separates_collisions_from_extension_declared` (`left: Complete, right: Incomplete`) |
| 3 | `scripts/portable-engine-promotion-lineage.mjs:1037` and `:1044` — removed both M27(i) scope joins | **2 failures**: F6f (`Missing expected exception: scope-digest-mismatch`) and F6f-4 (`advertisement scopeDigest differs` not raised). F6f-5 still passed, correctly |

Per-fixture verdicts on the ones named in the brief:

- **F6f (a) tree-unbacked, no `scope-artifact` row** — **fails its claim.** See MATERIAL M-1. Break-test 3 corroborates: variant (a) passed with the join removed.
- **F6f (b) blob mismatch** — sound. Admission digest is recomputed after mutation (`test:364`), so the fixture is self-consistent and refuses inside `verifyScopeCriticalPromotionRevision` (`.mjs:1017`), ahead of the ceremony. Incomplete against §A8 (only `blobObjectId` mutated, `test:348`).
- **F6f (c) recomputed digest mismatch** — sound, and break-test-proven.
- **F6f-4 advertisement contradicting admitted scope** — **sound and break-test-proven.** The advertisement's `scopeDigest` is mutated before `git add`, so every artifact row still matches the tree; the refusal is the sixth-clause join at `.mjs:1044`, not a byte check.
- **F6f-5 role predicate at the reserved evidence path** — positive control genuine; the "only" and the historical claim are not asserted. MATERIAL M-3.
- **F6e truncation** — **sound and correctly scoped.** Three real conditions (an actual `--depth 1` clone, a real `.git/info/grafts`, a real `git replace` ref), each matched to a distinct message. "Before the walk" is structurally true: `assertCompleteLineageHistory` runs at `.mjs:1094`, the walk loop opens at `:1096`. It does **not** claim reconstruction resistance — the disclaimer rides in the assert message itself (`test:1431`).
- **`all_four_public_ingresses_discard_and_recompute_scoped_cells`** (`:2789-2859`) — sound. Covers F3a-2 (all four), F3a-3 (the converse honesty check at `:2825-2831`, which does distinguish recompute from `min()`), the absent-edge default, and F3a-5 (`CompleteAdvertised` unchanged, `:2846-2858`). One softness: F3a-3 uses `assert_ne!(evidence.first().reason, TargetCellIncomplete)` rather than asserting `Allow`, so it would pass vacuously if the set failed earlier — it does not here, because the same set reaches `TargetCellIncomplete` in the sibling assertions.
- **`scoped_refusal_funnel_covers_all_three_evaluator_bodies_once`** (`:2702-2786`) — sound. Drives all three evaluation bodies plus the private inner, asserts exactly four envelopes in order, the correct `hostDisposition` per case, `presentedTargetCell` present only for external ingresses, and the envelope's **exact closed key set** (`:2775-2784`) plus `hostDisposition != "extension-declared"`.
- **`scoped_projection_and_introspection_share_one_aggregate`** (`:2597-2640`) — sound. Sweeps every generated edge comparing `host.target_cell(edge)` against an *independently re-admitted* aggregate, and asserts introspection is `None` for both the test-armed and unarmed hosts. Note it covers §A8 F11's `fn target_cell` half; the "as the evaluator sees them" half is covered by the two tests above rather than here.

Not found anywhere, JS or Rust: **F1a** (stale advertisement × fresh report crossing) and **F1b** (cross-tuple crossing) as named subcases. `scope_is_canonical_source_rederived_and_single_per_tuple` (`:2512-2568`) covers F1's re-derivation and §A4's uniqueness, and F5's first half ("two advertisements for one tuple refuse selection") is there at `:2556-2567` — but the byte-binding crossing subcases §A8 enumerates have no dedicated fixture.

### Q5 — Matrix coverage (M1–M33)

I verified M7, M12, M13, M15, M16, M19, M27, M32 myself against the code; the remainder is a mapped survey I directed and spot-checked.

**Scope-validating rows with corresponding code: all 24.** M1 (`capsec-scope-artifact.mjs:619,684`; `generate-capsec-scope-artifact.mjs:107`), M2 (`capsec-conformance-recipes.mjs:4826, 5441`), M3 (`capsec-public-surface-evidence.mjs:9798, 9939`), M4 (`capsec-conformance.mjs:656,662,706`), M5 (`capsec-portable-engine-evidence-contract.mjs:1426`), M6 (`capsec-portable-promotion-bundle.mjs:152,185,589`), M7 (`portable_target_admission.rs:1597,1656,1748`), M12 (`mod.rs:799,7005`), M13 (`mod.rs:855,1029,1047,4111`), M16 (`mod.rs:4097`), M17 (`portable_target_admission.rs:703`; `schemas/capsec-target-advertisements-v3.schema.json`), M19 (`portable-engine-promotion-lineage.mjs:82-85,1023,1412`), M20 (`build.rs:877-885`; `portable_engine_promotion_report.rs:41,200,443,550`), M21 (`generate-capsec-portable-promotion-target-cells.mjs`), M22 (pinned by `capsec-scope-artifact.test.mjs:459`), M23 (`capsec-portable-engine-evidence-contract.mjs:690`), M24 (`verify-capsec-portable-promotion-bundle.mjs`), M25 (`run-capsec-conformance.mjs:1973-1999`), M27 (`portable_target_admission.rs:761,815`; lineage `:1063-1080,1100`), M28 (`capsec-portable-engine-evidence-contract.mjs:434,444`, called in production at `:1623`), M30, M31, M32, M33 (`assert-releasable-checked-admission.mjs:83,130,207`; `.github/workflows/ci.yml:38-41`).

**No row is missing code.** M7 and M20 exist but cannot execute against the M1 generator's output — that is BLOCKER-1, and it is a wiring defect, not an absent row.

**PROOF-no-change rows and their pins:**

| Row | Pinned? |
|---|---|
| M8 (armed-snapshot producer) | `portable_target_admission.rs:2962` `scoped_host_keeps_scope_out_of_the_frozen_armed_snapshot` |
| M9 (`ibex/capsec-armed/1` parser + digest contract) | same test; `arming.rs` untouched, `digest.rs` diff touches only the conformance projection |
| M10 (`ExpectedArmingIdentity`) | **only transitively** — no test names it |
| M11 (armed/1 schema pins) | **UNPINNED** — no test pins the pin inventory |
| M14 (typed decision path) | `decision.rs:1936` `scoped_arm_marker_preserves_incomplete_gate_semantics`. Caveat: the amendment's "decision.rs untouched" is now literally false (`decision.rs:54`, `:227-233` add and admit `ScopedAdvertised`). The *narrow* claim — the reached-gate algorithm and `TargetCellDisposition` are unchanged — holds. A10 #4 explicitly blesses the bare-marker representation. |
| M15 (dev/insecure/observer/test constructors) | `portable_target_admission.rs:2643`, but by source-text scrape — see MINOR m5 |
| M22 (full-inventory catalog derivation) | `capsec-scope-artifact.test.mjs:459` |
| M26 (Go attestation verifier) | **UNPINNED — no test anywhere** |
| M29 (physical-promotion workflow) | `portable-engine-physical-promotion-workflow.test.mjs` (incl. `:398`), text-grep only |

### Q6 — Honesty sweep

**Clean where it matters most.** A grep of the new Rust for out-of-scope/uncertified × refuse/absent/safe returns exactly one hit — the refusal-envelope doc comment at `src/host/mod.rs:379-383` — and it is accurate. No comment or message anywhere asserts that out-of-scope surfaces are refused, absent, or safe. The one user-visible claim string, `schemas/capsec-target-advertisements-v3.schema.json:5` ("no claim is made for the uncertified remainder"), is honest and A7-conformant. The `fail closed` strings in `assert-releasable-checked-admission.mjs`/`.test.mjs` are about the release-gate exclusion list, not about the uncertified remainder, so A7's layer-naming rule does not bite.

Specific sweep items:
- **Weakened/special-cased assertions:** M-1 (F6f (a) refuses at a shallower layer than claimed), M-3 (`endsWith` tautology and a fixture property presented as a claim about old code), M-4 (self-comparison standing in for the zero-contribution rule), M-6 (comparing a fixture-authored value to itself).
- **Happy-path-only tests:** M-5 (F6h-b asserts nothing runs).
- **Schema admitting fields the validator ignores:** the reverse, and worse — `schemas/capsec-scope-v1.schema.json` requires seven `closureEdge` fields with `additionalProperties: false` while the Rust model accepts exactly two with `deny_unknown_fields` (BLOCKER-1). Separately, `capsec-scope-introspection-v1` and `capsec-scope-diagnostic-record-v1` are validated by nothing at all (m6).
- **Unnamed layer:** none found.
- **Dead/unreachable code presented as live:** m3 (`incomplete-defect` has no production producer), m4 (`is_coherent()` cannot be false), `.mjs:1032` (unreachable after `validateAdmissionShape`).

---

## 4. Required by the amendment, missing entirely

1. **A working producer→consumer path for the scope artifact** (BLOCKER-1) and the cross-language vector that would keep it working.
2. **§A8 F1a and F1b** — stale-advertisement × fresh-report crossing, and cross-tuple crossing, as named fixtures. F1's re-derivation mismatch and §A4 uniqueness are covered; these two byte-binding subcases are not.
3. **§A7's normative published wording** is emitted by nothing. Grepping `src crates packages scripts schemas capsec` for its distinctive phrases ("certified for the declared scope", "no statement is made") returns zero hits. Phase 1 has no publication step, so this is arguably Phase 2/3 work — but the amendment calls the wording normative and nothing in this change is on a path to producing it, so it should be tracked rather than assumed.
4. **§A5's rename/split/merge narrowing half of F7** — `capsec-scope-artifact.test.mjs:278` covers "a retired cell still in the live inventory fails"; "a rename not covered by the authenticated mapping fails as narrowing" is not asserted.
5. **A pin for M11's schema-string inventory and any pin at all for M26.**

---

## 5. What is genuinely good

Worth recording, because the blocking finding is a wiring defect and not a design failure. The ingress rule is implemented the strong way §A3 argues for — total, no comparison to invert, no flag threaded through, the runtime-extension resolver structurally separate and entering through the private door. `AdmittedScopedTargetCells` is a real opaque type on a real module boundary, and the amendment's honest note about the in-file test module is respected rather than papered over. The scoped admission arithmetic (`portable_target_admission.rs:1895-1993`) is the most careful code in the change: it preserves out-of-scope row content, contributes zero to every authoritative union, and closes the execution set by equality rather than by containment. F6e is a model of a fixture that asserts the lane it closes and explicitly declines the lane it does not. And three separate break-tests confirmed that the headline fixtures fail when their defects return.
