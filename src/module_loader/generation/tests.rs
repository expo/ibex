use super::*;
use crate::module_loader::artifact::{
    source_integrity, ArtifactAdmissionV1, CanonicalSourceId, CommonJsExportsV1,
    ExportDescriptorV1, ModuleSemanticsV1, ProducerIdentityV1, SourceDialectV1, SourceGoalV1,
    SourceMapV1, TransformFingerprintV1, MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
};
use crate::module_loader::identity::{ResolutionKind, SourceId};
use capsec_semantics::model::{NonEmptyString, PathComponent, SafeUint};

#[derive(Clone)]
struct Policy {
    digest: Digest,
    generations: SnapshotGenerations,
}

impl GraphImportPolicy for Policy {
    fn snapshot_digest(&self) -> &Digest {
        &self.digest
    }
    fn snapshot_generations(&self) -> SnapshotGenerations {
        self.generations
    }
    fn authenticates_module_edge(
        &self,
        _importer: &Principal,
        _request_specifier: &str,
        _imported: &Principal,
        _resolution_kind: &str,
        _conditions: &[String],
        _attributes: &BTreeMap<String, String>,
    ) -> bool {
        true
    }
}

fn digest(label: &str) -> Digest {
    digest_bytes("generation-test", label.as_bytes()).unwrap()
}

fn policy(label: &str) -> Policy {
    Policy {
        digest: digest(label),
        generations: SnapshotGenerations {
            policy: SafeUint::new(1).unwrap(),
            negative: SafeUint::new(1).unwrap(),
            dynamic: SafeUint::new(1).unwrap(),
            handle: SafeUint::new(1).unwrap(),
        },
    }
}

fn root() -> Principal {
    Principal::Root {
        identity: NonEmptyString::new("project").unwrap(),
    }
}

fn package() -> Principal {
    Principal::Package {
        name: NonEmptyString::new("dep").unwrap(),
        integrity: digest("package-integrity"),
        locator: capsec_semantics::model::PackageLocator::new("dep@1.0.0").unwrap(),
    }
}

fn source(principal: Principal, name: &str) -> SourceId {
    SourceId::file(principal, vec![PathComponent::utf8(name).unwrap()]).unwrap()
}

fn artifact(source_id: SourceId, value: u32) -> ModuleArtifactV1 {
    artifact_with_shape(
        source_id,
        value,
        SourceGoalV1::Module,
        &[("value", "value")],
    )
}

fn artifact_with_shape(
    source_id: SourceId,
    value: u32,
    source_goal: SourceGoalV1,
    exports: &[(&str, &str)],
) -> ModuleArtifactV1 {
    let factory = format!(
        "function($export){{return{{declare:function(){{}},execute:function(){{$export('value',{value});}}}};}}"
    );
    let export_descriptors = exports
        .iter()
        .map(|(exported, local)| ExportDescriptorV1::Local {
            exported: NonEmptyString::new(*exported).unwrap(),
            local: NonEmptyString::new(*local).unwrap(),
        })
        .collect();
    let commonjs_exports = (source_goal == SourceGoalV1::CommonJs).then(|| CommonJsExportsV1 {
        detector: NonEmptyString::new("detector").unwrap(),
        detector_version: NonEmptyString::new("1").unwrap(),
        names: vec![NonEmptyString::new("value").unwrap()],
        reexports: Vec::new(),
    });
    ModuleArtifactV1::new_inline(
        ModuleSemanticsV1 {
            source_id: CanonicalSourceId(source_id.clone()),
            source_goal,
            dialect: Some(SourceDialectV1::Js),
            source_integrity: source_integrity(factory.as_bytes()).unwrap(),
            transform_fingerprint: TransformFingerprintV1 {
                producer: NonEmptyString::new("generation-test").unwrap(),
                parser_version: NonEmptyString::new("1").unwrap(),
                transform_version: NonEmptyString::new("1").unwrap(),
                hermes_target: NonEmptyString::new("test").unwrap(),
                typescript_jsx_options_digest: digest("options"),
                module_runner_abi: NonEmptyString::new("1").unwrap(),
                hermes_compat_version: NonEmptyString::new("1").unwrap(),
                commonjs_detector: NonEmptyString::new("detector").unwrap(),
                commonjs_detector_version: NonEmptyString::new("1").unwrap(),
                output_options_digest: digest("output"),
            },
            static_edges: Vec::new(),
            dynamic_edges: Vec::new(),
            export_descriptors,
            commonjs_exports,
            has_top_level_await: false,
            factory_digest: digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory.as_bytes())
                .unwrap(),
            source_map: SourceMapV1 {
                version: 3,
                source_ids: vec![CanonicalSourceId(source_id)],
                names: Vec::new(),
                mappings: String::new(),
            },
        },
        factory,
        ProducerIdentityV1::InProcess {
            producer_id: NonEmptyString::new("generation-test").unwrap(),
            producer_binary_digest: digest("producer"),
        },
    )
    .unwrap()
}

fn commonjs_artifact(source_id: SourceId, value: u32) -> ModuleArtifactV1 {
    artifact_with_shape(source_id, value, SourceGoalV1::CommonJs, &[])
}

fn verified(artifact: &ModuleArtifactV1) -> VerifiedModuleArtifactV1<'_> {
    artifact
        .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
            expected_source_id: artifact.semantics.source_id.0.clone(),
            expected_source_integrity: artifact.semantics.source_integrity.clone(),
            expected_producer_id: NonEmptyString::new("generation-test").unwrap(),
            producer_binary_digest: digest("producer"),
            transform_fingerprint_digest: artifact
                .semantics
                .transform_fingerprint
                .digest()
                .unwrap(),
        })
        .unwrap()
}

fn graph(artifacts: &[ModuleArtifactV1]) -> AuthenticatedGenerationGraphV1 {
    AuthenticatedGenerationGraphV1::from_verified(
        artifacts
            .iter()
            .map(|artifact| (verified(artifact), BTreeMap::new())),
    )
    .unwrap()
}

#[derive(Clone, Default)]
struct TypedFacts {
    bindings: BTreeMap<GraphEdgeKey, SourceId>,
    candidate_sites: BTreeMap<u64, CandidateSitePinV1>,
    deferred_dynamic: BTreeSet<GraphEdgeKey>,
    deferred_commonjs_require: BTreeSet<GraphEdgeKey>,
    bootstrap_internal_commonjs: BTreeSet<String>,
}

fn edge(specifier: &str, resolution_kind: ResolutionKind) -> GraphEdgeKey {
    GraphEdgeKey::new(specifier, resolution_kind)
}

fn facts(bindings: impl IntoIterator<Item = (GraphEdgeKey, SourceId)>) -> TypedFacts {
    TypedFacts {
        bindings: bindings.into_iter().collect(),
        ..TypedFacts::default()
    }
}

fn self_facts(source_id: &SourceId) -> TypedFacts {
    facts([(edge("./self", ResolutionKind::EsmStatic), source_id.clone())])
}

fn typed_record(artifact: &ModuleArtifactV1, facts: TypedFacts) -> GenerationRecordV2 {
    assert!(!facts.bindings.is_empty());
    GenerationRecordV2::from_verified(
        verified(artifact),
        facts.bindings,
        facts.candidate_sites,
        facts.deferred_dynamic,
        facts.deferred_commonjs_require,
        facts.bootstrap_internal_commonjs,
    )
    .unwrap()
}

fn typed_graph(
    rows: impl IntoIterator<Item = (ModuleArtifactV1, TypedFacts)>,
) -> AuthenticatedGenerationGraphV2 {
    let rows: Vec<_> = rows.into_iter().collect();
    assert!(rows.iter().all(|(_, facts)| !facts.bindings.is_empty()));
    AuthenticatedGenerationGraphV2::from_verified(rows.iter().map(|(artifact, facts)| {
        (
            verified(artifact),
            facts.bindings.clone(),
            facts.candidate_sites.clone(),
            facts.deferred_dynamic.clone(),
            facts.deferred_commonjs_require.clone(),
            facts.bootstrap_internal_commonjs.clone(),
        )
    }))
    .unwrap()
}

fn publication_kinds() -> [GenerationPublicationKind; 6] {
    [
        GenerationPublicationKind::Evaluation,
        GenerationPublicationKind::TopLevelAwait,
        GenerationPublicationKind::DynamicImport,
        GenerationPublicationKind::Error,
        GenerationPublicationKind::CommonJsCache,
        GenerationPublicationKind::ArtifactCache,
    ]
}

fn begin_staged_revision(
    generations: &ModuleExecutionGenerationsV2,
    current_policy: &Policy,
    origin: HmrOrigin,
    invalidated: impl IntoIterator<Item = SourceId>,
    replacements: impl IntoIterator<Item = GenerationRecordV2>,
) -> HotRevisionTransactionV1 {
    let mut transaction = generations
        .begin_revision(
            current_policy,
            origin,
            (
                generations.current_generation(),
                generations.current_revision(),
            ),
            invalidated,
        )
        .unwrap();
    transaction.stage_replacements(replacements).unwrap();
    transaction
}

fn live_snapshot(
    generations: &ModuleExecutionGenerationsV2,
) -> (Digest, HotRevision, BTreeMap<SourceId, HotRevision>) {
    (
        generations.graph_digest().clone(),
        generations.current_revision(),
        generations.current.install_revisions.clone(),
    )
}

#[test]
fn exact_and_vite_updates_publish_coherent_monotonic_generations() {
    let source_id = source(root(), "entry.mjs");
    let initial = artifact(source_id.clone(), 1);
    let current_policy = policy("authority");
    let mut generations = ModuleExecutionGenerationsV1::new(
        GenerationMode::Development,
        &current_policy,
        graph(&[initial]),
    )
    .unwrap();
    let old_token = generations.publication_token(&source_id).unwrap();
    let updated = artifact(source_id.clone(), 2);
    let mut exact = generations
        .begin_update(&current_policy, HmrOrigin::Exact, [source_id.clone()])
        .unwrap();
    exact.stage_graph(graph(&[updated])).unwrap();
    let first = generations.commit(&current_policy, exact).unwrap();
    assert_eq!(first.previous.get(), 1);
    assert_eq!(first.generation.get(), 2);
    assert_eq!(
        generations.incarnation(&source_id).unwrap().generation,
        first.generation
    );
    for kind in [
        GenerationPublicationKind::Evaluation,
        GenerationPublicationKind::TopLevelAwait,
        GenerationPublicationKind::DynamicImport,
        GenerationPublicationKind::Error,
        GenerationPublicationKind::CommonJsCache,
        GenerationPublicationKind::ArtifactCache,
    ] {
        assert!(generations.publish(&old_token, kind).is_err());
    }

    let updated_again = artifact(source_id.clone(), 3);
    let mut vite = generations
        .begin_update(&current_policy, HmrOrigin::Vite, [source_id.clone()])
        .unwrap();
    vite.stage_graph(graph(&[updated_again])).unwrap();
    let second = generations.commit(&current_policy, vite).unwrap();
    assert_eq!(second.generation.get(), 3);
    assert_eq!(second.origin, HmrOrigin::Vite);
}

#[test]
fn concurrent_update_package_edit_authority_drift_and_widening_refuse() {
    let root_id = source(root(), "entry.mjs");
    let package_id = source(package(), "index.mjs");
    let initial_root = artifact(root_id.clone(), 1);
    let initial_package = artifact(package_id.clone(), 1);
    let current_policy = policy("authority");
    let mut generations = ModuleExecutionGenerationsV1::new(
        GenerationMode::Development,
        &current_policy,
        graph(&[initial_root.clone(), initial_package.clone()]),
    )
    .unwrap();

    let mut winner = generations
        .begin_update(&current_policy, HmrOrigin::Exact, [root_id.clone()])
        .unwrap();
    let mut loser = generations
        .begin_update(&current_policy, HmrOrigin::Vite, [root_id.clone()])
        .unwrap();
    winner
        .stage_graph(graph(&[
            artifact(root_id.clone(), 2),
            initial_package.clone(),
        ]))
        .unwrap();
    loser
        .stage_graph(graph(&[
            artifact(root_id.clone(), 3),
            initial_package.clone(),
        ]))
        .unwrap();
    generations.commit(&current_policy, winner).unwrap();
    assert!(generations.commit(&current_policy, loser).is_err());

    let mut package_edit = generations
        .begin_update(&current_policy, HmrOrigin::Exact, [package_id.clone()])
        .unwrap();
    package_edit
        .stage_graph(graph(&[
            artifact(root_id.clone(), 2),
            artifact(package_id.clone(), 2),
        ]))
        .unwrap();
    assert!(generations
        .commit(&current_policy, package_edit)
        .unwrap_err()
        .to_string()
        .contains("restart"));

    let foreign_id = source(root(), "new.mjs");
    assert!(generations
        .begin_update(&current_policy, HmrOrigin::Exact, [foreign_id])
        .is_err());
    let changed_policy = policy("widened-authority");
    assert!(generations
        .begin_update(&changed_policy, HmrOrigin::Exact, [root_id.clone()])
        .unwrap_err()
        .to_string()
        .contains("restart"));
}

#[test]
fn production_graph_remains_one_generation() {
    let source_id = source(root(), "entry.mjs");
    let initial = artifact(source_id.clone(), 1);
    let current_policy = policy("authority");
    let generations = ModuleExecutionGenerationsV1::new(
        GenerationMode::Production,
        &current_policy,
        graph(&[initial]),
    )
    .unwrap();
    assert_eq!(
        generations.current_generation(),
        ExecutionGeneration::INITIAL
    );
    assert!(generations
        .begin_update(&current_policy, HmrOrigin::Exact, [source_id])
        .is_err());
}

#[test]
fn native_graph_owner_swaps_only_after_the_complete_candidate_is_valid() {
    let source_id = source(root(), "entry.mjs");
    let initial = artifact(source_id.clone(), 1);
    let current_policy = policy("authority");
    let generations = ModuleExecutionGenerationsV1::new(
        GenerationMode::Development,
        &current_policy,
        graph(&[initial]),
    )
    .unwrap();
    let mut slot = ModuleExecutionGenerationSlotV1::new(generations, "native-graph-1");
    let mut update = slot
        .generations()
        .begin_update(&current_policy, HmrOrigin::Vite, [source_id.clone()])
        .unwrap();
    assert_eq!(update.candidate_generation().unwrap().get(), 2);
    update
        .stage_graph(graph(&[artifact(source_id, 2)]))
        .unwrap();
    let (commit, retired) = slot
        .commit(&current_policy, update, "native-graph-2")
        .unwrap();
    assert_eq!(commit.generation.get(), 2);
    assert_eq!(retired, "native-graph-1");
    assert_eq!(*slot.current(), "native-graph-2");
}

#[test]
fn f1_per_slot_publication_fences_only_the_replaced_incarnation() {
    let a = source(root(), "a.mjs");
    let b = source(root(), "b.mjs");
    let a_artifact = artifact(a.clone(), 1);
    let b_boot = artifact(b.clone(), 1);
    let b_revision = artifact(b.clone(), 2);
    let a_facts = facts([(edge("./b", ResolutionKind::EsmStatic), b.clone())]);
    let b_facts = self_facts(&b);
    let current_policy = policy("authority");
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        &current_policy,
        typed_graph([(a_artifact, a_facts.clone()), (b_boot, b_facts.clone())]),
    )
    .unwrap();
    let a_boot_token = generations.publication_token(&a).unwrap();
    let b_boot_token = generations.publication_token(&b).unwrap();
    let transaction = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [b.clone()],
        [typed_record(&b_revision, b_facts)],
    );
    let commit = generations
        .commit_revision(&current_policy, transaction)
        .unwrap();
    assert_eq!(commit.previous_revision, HotRevision::BOOT);
    assert_eq!(commit.revision.get(), 1);
    assert_eq!(generations.install_revision(&a).unwrap(), HotRevision::BOOT);
    assert_eq!(generations.install_revision(&b).unwrap().get(), 1);

    for kind in publication_kinds() {
        assert!(generations.publish(&a_boot_token, kind).is_ok());
        assert!(generations
            .publish(&b_boot_token, kind)
            .unwrap_err()
            .to_string()
            .contains("stale module-revision completion cannot publish"));
    }
    let b_revision_token = generations.publication_token(&b).unwrap();
    for kind in publication_kinds() {
        assert!(generations.publish(&b_revision_token, kind).is_ok());
    }
}

#[test]
fn f1_shadow_publications_are_transaction_local_and_drop_whole() {
    let a = source(root(), "a.mjs");
    let b = source(root(), "b.mjs");
    let a_artifact = artifact(a.clone(), 1);
    let b_boot = artifact(b.clone(), 1);
    let b_revision = artifact(b.clone(), 2);
    let a_facts = facts([(edge("./b", ResolutionKind::EsmStatic), b.clone())]);
    let b_facts = self_facts(&b);
    let current_policy = policy("authority");
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        &current_policy,
        typed_graph([(a_artifact, a_facts), (b_boot, b_facts.clone())]),
    )
    .unwrap();
    let live_b = generations.publication_token(&b).unwrap();
    let before = live_snapshot(&generations);
    let mut transaction = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Vite,
        [b.clone()],
        [typed_record(&b_revision, b_facts)],
    );
    let shadow_b = transaction.shadow_publication_token(&b).unwrap();
    assert_eq!(shadow_b.install_revision.get(), 1);
    transaction
        .shadow_publish(&shadow_b, GenerationPublicationKind::TopLevelAwait)
        .unwrap();
    assert_eq!(transaction.shadow_publication_count(), 1);
    assert!(transaction.shadow_publication_token(&a).is_err());
    assert!(generations
        .publish(&live_b, GenerationPublicationKind::Evaluation)
        .is_ok());
    drop(transaction);

    assert_eq!(live_snapshot(&generations), before);
    assert!(generations
        .publish(&live_b, GenerationPublicationKind::ArtifactCache)
        .is_ok());

    let mut committed = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Vite,
        [b.clone()],
        [typed_record(&b_revision, self_facts(&b))],
    );
    let committed_token = committed.shadow_publication_token(&b).unwrap();
    let shadow_receipt = committed
        .shadow_publish(&committed_token, GenerationPublicationKind::DynamicImport)
        .unwrap();
    let commit = generations
        .commit_revision(&current_policy, committed)
        .unwrap();
    assert_eq!(commit.shadow_publications, [shadow_receipt]);
}

#[test]
fn f2_stale_begin_refuses_and_same_base_commit_has_one_winner() {
    let source_id = source(root(), "entry.mjs");
    let boot = artifact(source_id.clone(), 1);
    let winner_artifact = artifact(source_id.clone(), 2);
    let loser_artifact = artifact(source_id.clone(), 3);
    let row_facts = self_facts(&source_id);
    let current_policy = policy("authority");
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        &current_policy,
        typed_graph([(boot, row_facts.clone())]),
    )
    .unwrap();
    let base = (
        generations.current_generation(),
        generations.current_revision(),
    );
    let mut winner = generations
        .begin_revision(&current_policy, HmrOrigin::Exact, base, [source_id.clone()])
        .unwrap();
    let mut loser = generations
        .begin_revision(&current_policy, HmrOrigin::Vite, base, [source_id.clone()])
        .unwrap();
    winner
        .stage_replacements([typed_record(&winner_artifact, row_facts.clone())])
        .unwrap();
    loser
        .stage_replacements([typed_record(&loser_artifact, row_facts)])
        .unwrap();
    generations
        .commit_revision(&current_policy, winner)
        .unwrap();
    let winner_state = live_snapshot(&generations);
    let winner_digest = winner_artifact.semantic_digest.clone();
    assert_eq!(
        generations
            .current
            .graph
            .record(&source_id)
            .unwrap()
            .artifact
            .semantic_digest,
        winner_digest
    );
    assert_eq!(
        generations
            .commit_revision(&current_policy, loser)
            .unwrap_err()
            .to_string(),
        "hot revision commit-time base compare failed after begin; invariant violation"
    );
    assert_eq!(live_snapshot(&generations), winner_state);
    assert_eq!(
        generations
            .current
            .graph
            .record(&source_id)
            .unwrap()
            .artifact
            .semantic_digest,
        winner_artifact.semantic_digest
    );

    let stale_begin_state = live_snapshot(&generations);
    let stale_error = generations
        .begin_revision(&current_policy, HmrOrigin::Exact, base, [source_id.clone()])
        .unwrap_err()
        .to_string();
    assert!(stale_error.contains("committed coordinates are generation 1 revision 1"));
    assert_eq!(live_snapshot(&generations), stale_begin_state);

    let generation_error = generations
        .begin_revision(
            &current_policy,
            HmrOrigin::Exact,
            (ExecutionGeneration(2), HotRevision::at(1)),
            [source_id.clone()],
        )
        .unwrap_err()
        .to_string();
    assert_eq!(
        generation_error,
        "HMR revision base generation does not match the live execution generation"
    );
    assert_eq!(live_snapshot(&generations), stale_begin_state);

    let authority_compare = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [source_id.clone()],
        [typed_record(
            &artifact(source_id.clone(), 4),
            self_facts(&source_id),
        )],
    );
    assert_eq!(
        generations
            .commit_revision(&policy("changed-authority"), authority_compare)
            .unwrap_err()
            .to_string(),
        "hot revision commit-time authority compare failed after begin; invariant violation"
    );
    assert_eq!(live_snapshot(&generations), stale_begin_state);

    let mut authority_stamp = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [source_id.clone()],
        [typed_record(
            &artifact(source_id.clone(), 4),
            self_facts(&source_id),
        )],
    );
    authority_stamp.authority_digest = digest("changed-authority-stamp");
    assert_eq!(
        generations
            .commit_revision(&current_policy, authority_stamp)
            .unwrap_err()
            .to_string(),
        "hot revision commit-time authority stamp compare failed after begin; invariant violation"
    );
    assert_eq!(live_snapshot(&generations), stale_begin_state);
}

#[test]
fn no_op_replacement_refuses_without_requesting_full_reload() {
    let source_id = source(root(), "entry.mjs");
    let boot = artifact(source_id.clone(), 1);
    let row_facts = self_facts(&source_id);
    let current_policy = policy("authority");
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        &current_policy,
        typed_graph([(boot.clone(), row_facts.clone())]),
    )
    .unwrap();
    let transaction = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [source_id],
        [typed_record(&boot, row_facts)],
    );
    let before = live_snapshot(&generations);
    let error = generations
        .commit_revision(&current_policy, transaction)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "hot revision changed nothing; nothing to apply");
    assert!(!error.contains("full reload"));
    assert_eq!(live_snapshot(&generations), before);
}

#[test]
fn f2_mixed_closure_advances_unchanged_importer_install_revision() {
    let a = source(root(), "a.mjs");
    let b = source(root(), "b.mjs");
    let a_boot = artifact(a.clone(), 1);
    let b_boot = artifact(b.clone(), 1);
    let b_revision = artifact(b.clone(), 2);
    let a_facts = facts([(edge("./b", ResolutionKind::EsmStatic), b.clone())]);
    let b_facts = self_facts(&b);
    let current_policy = policy("authority");
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        &current_policy,
        typed_graph([(a_boot.clone(), a_facts.clone()), (b_boot, b_facts.clone())]),
    )
    .unwrap();
    let old_a_token = generations.publication_token(&a).unwrap();
    let transaction = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [a.clone(), b.clone()],
        [
            typed_record(&a_boot, a_facts),
            typed_record(&b_revision, b_facts),
        ],
    );

    let commit = generations
        .commit_revision(&current_policy, transaction)
        .unwrap();
    assert_eq!(commit.changed, [b.clone()].into_iter().collect());
    assert_eq!(generations.install_revision(&a).unwrap().get(), 1);
    assert_eq!(generations.install_revision(&b).unwrap().get(), 1);
    assert_eq!(
        generations
            .publish(&old_a_token, GenerationPublicationKind::TopLevelAwait)
            .unwrap_err()
            .to_string(),
        "stale module-revision completion cannot publish"
    );
}

#[test]
fn f3_integrity_pinned_package_replacement_requires_restart() {
    let package_id = source(package(), "index.mjs");
    let boot = artifact(package_id.clone(), 1);
    let replacement = artifact(package_id.clone(), 2);
    let row_facts = self_facts(&package_id);
    let current_policy = policy("authority");
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        &current_policy,
        typed_graph([(boot, row_facts.clone())]),
    )
    .unwrap();
    let transaction = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [package_id],
        [typed_record(&replacement, row_facts)],
    );
    assert!(generations
        .commit_revision(&current_policy, transaction)
        .unwrap_err()
        .to_string()
        .contains("restart"));
}

#[test]
fn f4_typed_digest_and_ceiling_cover_every_v2_shape_fact() {
    let a = source(root(), "a.mjs");
    let b = source(root(), "b.mjs");
    let c = source(root(), "c.mjs");
    let a_boot = artifact(a.clone(), 1);
    let a_revision = artifact(a.clone(), 2);
    let b_artifact = artifact(b.clone(), 1);
    let c_artifact = artifact(c.clone(), 1);
    let static_key = edge("./same", ResolutionKind::EsmStatic);
    let dynamic_key = edge("./same", ResolutionKind::DynamicImport);
    let both = facts([
        (static_key.clone(), b.clone()),
        (dynamic_key.clone(), b.clone()),
    ]);
    let static_only = facts([(static_key.clone(), b.clone())]);
    let dynamic_only = facts([(dynamic_key.clone(), b.clone())]);
    let b_facts = self_facts(&b);
    let c_facts = self_facts(&c);
    let both_graph = typed_graph([
        (a_boot.clone(), both.clone()),
        (b_artifact.clone(), b_facts.clone()),
        (c_artifact.clone(), c_facts.clone()),
    ]);
    let static_graph = typed_graph([
        (a_boot.clone(), static_only),
        (b_artifact.clone(), b_facts.clone()),
        (c_artifact.clone(), c_facts.clone()),
    ]);
    let dynamic_graph = typed_graph([
        (a_boot.clone(), dynamic_only),
        (b_artifact.clone(), b_facts.clone()),
        (c_artifact.clone(), c_facts.clone()),
    ]);
    assert_ne!(both_graph.digest(), static_graph.digest());
    assert_ne!(both_graph.digest(), dynamic_graph.digest());
    assert_ne!(static_graph.digest(), dynamic_graph.digest());

    let current_policy = policy("authority");
    let mut generations =
        ModuleExecutionGenerationsV2::new(GenerationMode::Development, &current_policy, both_graph)
            .unwrap();
    let widened = facts([(static_key.clone(), b), (dynamic_key.clone(), c)]);
    let transaction = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [a.clone()],
        [typed_record(&a_revision, widened)],
    );
    assert!(generations
        .commit_revision(&current_policy, transaction)
        .unwrap_err()
        .to_string()
        .contains("restart"));

    let site_source = source(root(), "site.mjs");
    let site_boot = artifact(site_source.clone(), 1);
    let site_revision = artifact(site_source.clone(), 2);
    let mut site_facts = self_facts(&site_source);
    site_facts.candidate_sites.insert(
        7,
        CandidateSitePinV1 {
            digest: digest("site-a"),
            attributes_digest: digest("attributes-a"),
        },
    );
    let site_graph = typed_graph([(site_boot, site_facts.clone())]);
    let site_admission =
        ImmutableGenerationAdmissionV2::from_initial(&current_policy, &site_graph).unwrap();
    for (candidate_digest, attributes_digest) in [
        (digest("site-b"), digest("attributes-a")),
        (digest("site-a"), digest("attributes-b")),
    ] {
        let mut changed = self_facts(&site_source);
        changed.candidate_sites.insert(
            7,
            CandidateSitePinV1 {
                digest: candidate_digest,
                attributes_digest,
            },
        );
        let candidate = typed_graph([(site_revision.clone(), changed)]);
        assert!(site_admission
            .validate_graph(&candidate)
            .unwrap_err()
            .to_string()
            .contains("restart"));
    }

    let deferred_source = source(root(), "deferred.mjs");
    let deferred_boot = artifact(deferred_source.clone(), 1);
    let deferred_revision = artifact(deferred_source.clone(), 2);
    let deferred_key = edge("./later", ResolutionKind::DynamicImport);
    let mut deferred_facts = facts([(deferred_key.clone(), deferred_source.clone())]);
    deferred_facts.deferred_dynamic.insert(deferred_key.clone());
    let deferred_graph = typed_graph([(deferred_boot, deferred_facts)]);
    let deferred_admission =
        ImmutableGenerationAdmissionV2::from_initial(&current_policy, &deferred_graph).unwrap();
    let eager = facts([(deferred_key.clone(), deferred_source.clone())]);
    assert!(deferred_admission
        .validate_graph(&typed_graph([(deferred_revision, eager)]))
        .unwrap_err()
        .to_string()
        .contains("restart"));

    let invalid_deferred = GenerationRecordV2::from_verified(
        verified(&artifact(deferred_source.clone(), 3)),
        facts([(deferred_key, deferred_source.clone())]).bindings,
        BTreeMap::new(),
        [edge("./wrong-kind", ResolutionKind::EsmStatic)]
            .into_iter()
            .collect(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    assert!(invalid_deferred.is_err());

    let absent_target = source(root(), "absent.mjs");
    let orphan = artifact(source(root(), "orphan.mjs"), 1);
    assert!(AuthenticatedGenerationGraphV2::from_verified([(
        verified(&orphan),
        [(edge("./absent", ResolutionKind::EsmStatic), absent_target,)]
            .into_iter()
            .collect(),
        BTreeMap::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    )])
    .is_err());

    let bootstrap_source = source(root(), "bootstrap.mjs");
    let bootstrap_boot = artifact(bootstrap_source.clone(), 1);
    let bootstrap_revision = artifact(bootstrap_source.clone(), 2);
    let mut bootstrap_facts = self_facts(&bootstrap_source);
    bootstrap_facts
        .bootstrap_internal_commonjs
        .insert("internal-a".to_owned());
    let bootstrap_graph = typed_graph([(bootstrap_boot, bootstrap_facts)]);
    let bootstrap_admission =
        ImmutableGenerationAdmissionV2::from_initial(&current_policy, &bootstrap_graph).unwrap();
    let mut changed_bootstrap = self_facts(&bootstrap_source);
    changed_bootstrap
        .bootstrap_internal_commonjs
        .insert("internal-b".to_owned());
    assert!(bootstrap_admission
        .validate_graph(&typed_graph([(bootstrap_revision, changed_bootstrap)]))
        .unwrap_err()
        .to_string()
        .contains("restart"));
}

#[test]
fn f6_export_shape_changes_refuse_but_factory_only_replacement_commits() {
    let source_id = source(root(), "entry.mjs");
    let current_policy = policy("authority");
    let boot = artifact(source_id.clone(), 1);
    let row_facts = self_facts(&source_id);
    let changed_shapes = [
        artifact_with_shape(
            source_id.clone(),
            2,
            SourceGoalV1::Module,
            &[("value", "value"), ("extra", "extra")],
        ),
        artifact_with_shape(source_id.clone(), 2, SourceGoalV1::Module, &[]),
        artifact_with_shape(
            source_id.clone(),
            2,
            SourceGoalV1::Module,
            &[("renamed", "value")],
        ),
    ];
    for replacement in changed_shapes {
        let mut generations = ModuleExecutionGenerationsV2::new(
            GenerationMode::Development,
            &current_policy,
            typed_graph([(boot.clone(), row_facts.clone())]),
        )
        .unwrap();
        let transaction = begin_staged_revision(
            &generations,
            &current_policy,
            HmrOrigin::Exact,
            [source_id.clone()],
            [typed_record(&replacement, row_facts.clone())],
        );
        assert_eq!(
            generations
                .commit_revision(&current_policy, transaction)
                .unwrap_err()
                .to_string(),
            "hot revision changed the module export shape; full reload required"
        );
    }

    let replacement = artifact(source_id.clone(), 9);
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        &current_policy,
        typed_graph([(boot, row_facts.clone())]),
    )
    .unwrap();
    let transaction = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Vite,
        [source_id],
        [typed_record(&replacement, row_facts)],
    );
    assert_eq!(
        generations
            .commit_revision(&current_policy, transaction)
            .unwrap()
            .revision
            .get(),
        1
    );
}

#[test]
fn f7_ceiling_and_converse_refusals_leave_live_state_unchanged() {
    let a = source(root(), "a.mjs");
    let b = source(root(), "b.mjs");
    let c = source(root(), "c.mjs");
    let a_boot = artifact(a.clone(), 1);
    let b_boot = artifact(b.clone(), 1);
    let c_boot = artifact(c.clone(), 1);
    let a_revision = artifact(a.clone(), 2);
    let current_policy = policy("authority");
    let a_facts = facts([(edge("./target", ResolutionKind::EsmStatic), b.clone())]);
    let b_facts = self_facts(&b);
    let c_facts = self_facts(&c);
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        &current_policy,
        typed_graph([
            (a_boot.clone(), a_facts.clone()),
            (b_boot.clone(), b_facts.clone()),
            (c_boot.clone(), c_facts),
        ]),
    )
    .unwrap();
    let before_ceiling = live_snapshot(&generations);
    let widened = facts([(edge("./target", ResolutionKind::EsmStatic), c)]);
    let ceiling = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [a.clone()],
        [typed_record(&a_revision, widened)],
    );
    assert!(generations
        .commit_revision(&current_policy, ceiling)
        .is_err());
    assert_eq!(live_snapshot(&generations), before_ceiling);

    let missing = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [a.clone()],
        [],
    );
    let before_converse = live_snapshot(&generations);
    assert!(generations
        .commit_revision(&current_policy, missing)
        .unwrap_err()
        .to_string()
        .contains("missing an invalidated replacement"));
    assert_eq!(live_snapshot(&generations), before_converse);

    let b_revision = artifact(b.clone(), 2);
    let extra = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [a.clone()],
        [
            typed_record(&a_revision, a_facts.clone()),
            typed_record(&b_revision, b_facts.clone()),
        ],
    );
    let before_extra = live_snapshot(&generations);
    assert_eq!(
        generations
            .commit_revision(&current_policy, extra)
            .unwrap_err()
            .to_string(),
        "HMR candidate changed a module outside its invalidation set"
    );
    assert_eq!(live_snapshot(&generations), before_extra);

    let unchanged_extra = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [a.clone()],
        [
            typed_record(&a_revision, a_facts),
            typed_record(&b_boot, b_facts),
        ],
    );
    let before_unchanged_extra = live_snapshot(&generations);
    assert_eq!(
        generations
            .commit_revision(&current_policy, unchanged_extra)
            .unwrap_err()
            .to_string(),
        "hot revision transaction contains a replacement outside its invalidation set"
    );
    assert_eq!(live_snapshot(&generations), before_unchanged_extra);
}

#[test]
fn f10_commonjs_cross_boundary_refuses_for_any_outside_edge_kind() {
    let consumer = source(root(), "consumer.mjs");
    let boundary = source(root(), "boundary.cjs");
    let current_policy = policy("authority");
    for resolution_kind in [ResolutionKind::CommonJsRequire, ResolutionKind::EsmStatic] {
        let consumer_boot = artifact(consumer.clone(), 1);
        let boundary_boot = commonjs_artifact(boundary.clone(), 1);
        let boundary_revision = commonjs_artifact(boundary.clone(), 2);
        let consumer_facts = facts([(edge("./boundary", resolution_kind), boundary.clone())]);
        let boundary_facts = self_facts(&boundary);
        let mut generations = ModuleExecutionGenerationsV2::new(
            GenerationMode::Development,
            &current_policy,
            typed_graph([
                (consumer_boot, consumer_facts),
                (boundary_boot, boundary_facts.clone()),
            ]),
        )
        .unwrap();
        let transaction = begin_staged_revision(
            &generations,
            &current_policy,
            HmrOrigin::Exact,
            [boundary.clone()],
            [typed_record(&boundary_revision, boundary_facts)],
        );
        assert_eq!(
            generations
                .commit_revision(&current_policy, transaction)
                .unwrap_err()
                .to_string(),
            "hot revision boundary is consumed across the closure through CommonJS; full reload required"
        );
    }

    let consumer_boot = artifact(consumer.clone(), 1);
    let consumer_revision = artifact(consumer.clone(), 2);
    let boundary_boot = commonjs_artifact(boundary.clone(), 1);
    let boundary_revision = commonjs_artifact(boundary.clone(), 2);
    let consumer_facts = facts([(
        edge("./boundary", ResolutionKind::CommonJsRequire),
        boundary.clone(),
    )]);
    let boundary_facts = self_facts(&boundary);
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        &current_policy,
        typed_graph([
            (consumer_boot, consumer_facts.clone()),
            (boundary_boot, boundary_facts.clone()),
        ]),
    )
    .unwrap();
    let transaction = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [consumer.clone(), boundary.clone()],
        [
            typed_record(&consumer_revision, consumer_facts),
            typed_record(&boundary_revision, boundary_facts),
        ],
    );
    let commit = generations
        .commit_revision(&current_policy, transaction)
        .unwrap();
    assert_eq!(commit.changed, [consumer, boundary].into_iter().collect());
}

#[test]
fn hot_revisions_are_monotonic_production_closed_and_overflow_checked() {
    let source_id = source(root(), "entry.mjs");
    let boot = artifact(source_id.clone(), 1);
    let revision_one = artifact(source_id.clone(), 2);
    let revision_two = artifact(source_id.clone(), 3);
    let row_facts = self_facts(&source_id);
    let current_policy = policy("authority");
    let initial_graph = typed_graph([(boot.clone(), row_facts.clone())]);
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        &current_policy,
        initial_graph.clone(),
    )
    .unwrap();
    assert_eq!(generations.current_revision(), HotRevision::BOOT);
    for (expected, replacement) in [(1, revision_one), (2, revision_two)] {
        let transaction = begin_staged_revision(
            &generations,
            &current_policy,
            HmrOrigin::Exact,
            [source_id.clone()],
            [typed_record(&replacement, row_facts.clone())],
        );
        assert_eq!(
            generations
                .commit_revision(&current_policy, transaction)
                .unwrap()
                .revision
                .get(),
            expected
        );
    }

    let production = ModuleExecutionGenerationsV2::new(
        GenerationMode::Production,
        &current_policy,
        initial_graph,
    )
    .unwrap();
    assert_eq!(
        production
            .begin_revision(
                &current_policy,
                HmrOrigin::Exact,
                (ExecutionGeneration::INITIAL, HotRevision::BOOT),
                [source_id.clone()],
            )
            .unwrap_err()
            .to_string(),
        "production module graphs have exactly one execution generation and revision"
    );
    assert!(HotRevision::at(u64::MAX)
        .next()
        .unwrap_err()
        .to_string()
        .contains("full reload"));
    generations.current.revision = HotRevision::at(u64::MAX);
    assert!(generations
        .begin_revision(
            &current_policy,
            HmrOrigin::Exact,
            (
                generations.current_generation(),
                generations.current_revision(),
            ),
            [source_id],
        )
        .unwrap_err()
        .to_string()
        .contains("full reload"));
}

#[test]
fn hot_revision_slot_swaps_owner_value_only_with_a_successful_revision() {
    let source_id = source(root(), "entry.mjs");
    let boot = artifact(source_id.clone(), 1);
    let replacement = artifact(source_id.clone(), 2);
    let row_facts = self_facts(&source_id);
    let current_policy = policy("authority");
    let generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        &current_policy,
        typed_graph([(boot, row_facts.clone())]),
    )
    .unwrap();
    let mut slot = HotRevisionSlotV1::new(generations, "native-revision-0");
    let transaction = begin_staged_revision(
        slot.generations(),
        &current_policy,
        HmrOrigin::Exact,
        [source_id],
        [typed_record(&replacement, row_facts)],
    );
    let (commit, retired) = slot
        .commit_revision(&current_policy, transaction, "native-revision-1")
        .unwrap();
    assert_eq!(commit.revision.get(), 1);
    assert_eq!(retired, "native-revision-0");
    assert_eq!(*slot.current(), "native-revision-1");
}
