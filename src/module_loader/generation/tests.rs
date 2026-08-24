use super::*;
use crate::module_loader::artifact::{
    source_integrity, ArtifactAdmissionV1, CanonicalSourceId, CommonJsExportsV1, DynamicEdgeV1,
    ExportDescriptorV1, ModulePayloadV1, ModuleSemanticsV1, ProducerIdentityV1, SourceDialectV1,
    SourceGoalV1, SourceMapV1, StaticEdgeV1, TransformFingerprintV1,
    MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
};
use crate::module_loader::identity::{ImportAttributes, ResolutionKind, SourceId};
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

fn execution_generation() -> ExecutionGeneration {
    ExecutionGeneration::new(41).unwrap()
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
    let commonjs_exports = matches!(source_goal, SourceGoalV1::CommonJs | SourceGoalV1::Builtin)
        .then(|| CommonJsExportsV1 {
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

fn rebuild_inline_artifact(
    artifact: &ModuleArtifactV1,
    semantics: ModuleSemanticsV1,
) -> ModuleArtifactV1 {
    let factory_source = match &artifact.payload {
        ModulePayloadV1::Inline { factory_source, .. } => factory_source.clone(),
        ModulePayloadV1::Carrier { .. } => panic!("generation fixtures use inline artifacts"),
    };
    ModuleArtifactV1::new_inline(semantics, factory_source, artifact.producer.clone()).unwrap()
}

fn artifact_with_export_descriptors(
    source_id: SourceId,
    value: u32,
    source_goal: SourceGoalV1,
    export_descriptors: Vec<ExportDescriptorV1>,
) -> ModuleArtifactV1 {
    let artifact = artifact_with_shape(source_id, value, source_goal, &[]);
    let mut semantics = artifact.semantics.clone();
    semantics.export_descriptors = export_descriptors;
    rebuild_inline_artifact(&artifact, semantics)
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

fn commonjs_self_facts(source_id: &SourceId) -> TypedFacts {
    facts([(
        edge("./self", ResolutionKind::CommonJsRequire),
        source_id.clone(),
    )])
}

fn artifact_with_typed_facts(artifact: &ModuleArtifactV1, facts: &TypedFacts) -> ModuleArtifactV1 {
    let mut semantics = artifact.semantics.clone();
    semantics.static_edges.clear();
    semantics.dynamic_edges.clear();
    for key in facts.bindings.keys() {
        match key.resolution_kind {
            ResolutionKind::EsmStatic => {
                semantics.static_edges.push(StaticEdgeV1::SideEffect {
                    specifier: NonEmptyString::new(key.specifier.clone()).unwrap(),
                    attributes: ImportAttributes::default(),
                });
            }
            ResolutionKind::DynamicImport => {
                semantics.dynamic_edges.push(DynamicEdgeV1::Literal {
                    specifier: NonEmptyString::new(key.specifier.clone()).unwrap(),
                    attributes: ImportAttributes::default(),
                });
            }
            ResolutionKind::CommonJsRequire => {
                semantics.static_edges.push(StaticEdgeV1::CommonJsRequire {
                    specifier: NonEmptyString::new(key.specifier.clone()).unwrap(),
                });
            }
            ResolutionKind::Entry => {}
        }
    }
    for site in facts.candidate_sites.keys() {
        semantics.dynamic_edges.push(DynamicEdgeV1::Computed {
            site: u32::try_from(*site).unwrap(),
        });
    }
    for specifier in &facts.bootstrap_internal_commonjs {
        if !semantics.static_edges.iter().any(|edge| {
            matches!(edge, StaticEdgeV1::CommonJsRequire { specifier: declared }
                if declared.as_str() == specifier)
        }) {
            semantics.static_edges.push(StaticEdgeV1::CommonJsRequire {
                specifier: NonEmptyString::new(specifier.clone()).unwrap(),
            });
        }
    }
    semantics.static_edges.sort_by_key(|edge| {
        capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(edge).unwrap()).unwrap()
    });
    semantics.dynamic_edges.sort_by_key(|edge| {
        capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(edge).unwrap()).unwrap()
    });
    rebuild_inline_artifact(artifact, semantics)
}

fn typed_record(artifact: &ModuleArtifactV1, facts: TypedFacts) -> GenerationRecordV2 {
    let artifact = artifact_with_typed_facts(artifact, &facts);
    GenerationRecordV2::from_verified(
        verified(&artifact),
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
    let declared = rows
        .iter()
        .map(|(artifact, facts)| (artifact_with_typed_facts(artifact, facts), facts))
        .collect::<Vec<_>>();
    AuthenticatedGenerationGraphV2::from_verified(declared.iter().map(|(artifact, facts)| {
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
        execution_generation(),
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
        execution_generation(),
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
    for kind in publication_kinds() {
        transaction.shadow_publish(&shadow_b, kind).unwrap();
    }
    assert_eq!(transaction.shadow_publication_count(), 6);
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
    assert_ne!(shadow_b.transaction_nonce, committed.transaction_nonce);
    assert_eq!(live_b.install_revision, HotRevision::BOOT);
    assert_ne!(live_b.install_revision, shadow_b.install_revision);
    assert_eq!(
        committed
            .shadow_publish(&shadow_b, GenerationPublicationKind::Evaluation)
            .unwrap_err()
            .to_string(),
        "shadow publication token belongs to another hot revision transaction"
    );
    let committed_token = committed.shadow_publication_token(&b).unwrap();
    let shadow_receipts = publication_kinds()
        .into_iter()
        .map(|kind| committed.shadow_publish(&committed_token, kind).unwrap())
        .collect::<Vec<_>>();
    let commit = generations
        .commit_revision(&current_policy, committed)
        .unwrap();
    assert_eq!(commit.shadow_publications, shadow_receipts);
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
        execution_generation(),
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
    let winner_digest =
        artifact_with_typed_facts(&winner_artifact, &self_facts(&source_id)).semantic_digest;
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
        winner_digest
    );

    let stale_begin_state = live_snapshot(&generations);
    let stale_error = generations
        .begin_revision(&current_policy, HmrOrigin::Exact, base, [source_id.clone()])
        .unwrap_err()
        .to_string();
    assert_eq!(
        stale_error,
        "hot update base is stale; committed coordinates are generation 41 revision 1"
    );
    assert_eq!(live_snapshot(&generations), stale_begin_state);

    let generation_error = generations
        .begin_revision(
            &current_policy,
            HmrOrigin::Exact,
            (ExecutionGeneration::new(42).unwrap(), HotRevision::at(1)),
            [source_id.clone()],
        )
        .unwrap_err()
        .to_string();
    assert_eq!(
        generation_error,
        "hot update base is stale; committed coordinates are generation 41 revision 1"
    );
    assert_eq!(live_snapshot(&generations), stale_begin_state);

    assert_eq!(generations.current_generation().get(), 41);
    assert_eq!(
        ExecutionGeneration::new(0).unwrap_err().to_string(),
        "module execution generation must be nonzero"
    );
    assert_eq!(
        generations
            .begin_revision(
                &current_policy,
                HmrOrigin::Exact,
                (
                    generations.current_generation(),
                    generations.current_revision(),
                ),
                [],
            )
            .unwrap_err()
            .to_string(),
        "HMR update must invalidate at least one module"
    );
    assert_eq!(
        generations
            .begin_revision(
                &current_policy,
                HmrOrigin::Exact,
                (
                    generations.current_generation(),
                    generations.current_revision(),
                ),
                [source(root(), "absent.mjs")],
            )
            .unwrap_err()
            .to_string(),
        "HMR invalidation widened the authenticated source graph; full reload required"
    );
    assert_eq!(
        generations
            .begin_revision(
                &policy("begin-authority-drift"),
                HmrOrigin::Exact,
                (
                    generations.current_generation(),
                    generations.current_revision(),
                ),
                [source_id.clone()],
            )
            .unwrap_err()
            .to_string(),
        "HMR authority changed; regenerate policy and restart the runtime"
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
        execution_generation(),
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
        execution_generation(),
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
        execution_generation(),
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
    let before = live_snapshot(&generations);
    assert_eq!(
        generations
            .commit_revision(&current_policy, transaction)
            .unwrap_err()
            .to_string(),
        "HMR changed integrity-pinned package/runtime source; restart required"
    );
    assert_eq!(live_snapshot(&generations), before);
}

#[test]
fn typed_metadata_must_agree_with_the_verified_artifact_at_every_seam() {
    const DISAGREEMENT: &str = "hot update typed metadata disagrees with the verified artifact";
    let source_id = source(root(), "typed.mjs");
    let boot = artifact(source_id.clone(), 1);
    let replacement = artifact(source_id.clone(), 2);
    let row_facts = self_facts(&source_id);

    let undeclared = GenerationRecordV2::from_verified(
        verified(&replacement),
        row_facts.bindings.clone(),
        BTreeMap::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    assert_eq!(undeclared.unwrap_err().to_string(), DISAGREEMENT);

    let current_policy = policy("authority");
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        typed_graph([(boot, row_facts.clone())]),
    )
    .unwrap();
    let base = (
        generations.current_generation(),
        generations.current_revision(),
    );

    let mut stage_refusal = generations
        .begin_revision(&current_policy, HmrOrigin::Exact, base, [source_id.clone()])
        .unwrap();
    let mut tampered = typed_record(&replacement, row_facts.clone());
    tampered.bindings.insert(
        edge("./undeclared", ResolutionKind::EsmStatic),
        source_id.clone(),
    );
    assert_eq!(
        stage_refusal
            .stage_replacements([tampered])
            .unwrap_err()
            .to_string(),
        DISAGREEMENT
    );

    let mut clone_and_swap = generations
        .begin_revision(&current_policy, HmrOrigin::Exact, base, [source_id.clone()])
        .unwrap();
    clone_and_swap
        .stage_replacements([typed_record(&replacement, row_facts)])
        .unwrap();
    clone_and_swap
        .replacements
        .as_mut()
        .unwrap()
        .get_mut(&source_id)
        .unwrap()
        .bindings
        .insert(edge("./undeclared", ResolutionKind::EsmStatic), source_id);
    assert_eq!(
        generations
            .commit_revision(&current_policy, clone_and_swap)
            .unwrap_err()
            .to_string(),
        DISAGREEMENT
    );
}

#[test]
fn principal_less_members_admit_are_integrity_pinned_and_cannot_hot_reload() {
    let root_source = source(root(), "entry.mjs");
    let builtin_source = SourceId::builtin("ibex-runtime", "generation-member-test").unwrap();
    let root_facts = facts([(
        edge("ibex:member", ResolutionKind::EsmStatic),
        builtin_source.clone(),
    )]);
    let mut builtin_facts = TypedFacts::default();
    builtin_facts
        .bootstrap_internal_commonjs
        .insert("internal/test/binding".to_owned());
    let builtin_artifact =
        artifact_with_shape(builtin_source.clone(), 1, SourceGoalV1::Builtin, &[]);
    let current_policy = policy("authority");
    let generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        typed_graph([
            (artifact(root_source, 1), root_facts),
            (builtin_artifact, builtin_facts),
        ]),
    )
    .unwrap();
    assert!(generations
        .admission
        .pinned_integrities
        .contains_key(&builtin_source));
    let before = live_snapshot(&generations);
    assert_eq!(
        generations
            .begin_revision(
                &current_policy,
                HmrOrigin::Exact,
                (
                    generations.current_generation(),
                    generations.current_revision(),
                ),
                [builtin_source],
            )
            .unwrap_err()
            .to_string(),
        "builtin/synthetic sources cannot hot-reload; regenerate policy and restart the runtime"
    );
    assert_eq!(live_snapshot(&generations), before);

    let file_source = source(root(), "bootstrap.cjs");
    let mut file_facts = commonjs_self_facts(&file_source);
    file_facts
        .bootstrap_internal_commonjs
        .insert("internal/test/binding".to_owned());
    let file_artifact = artifact_with_typed_facts(&commonjs_artifact(file_source, 1), &file_facts);
    assert_eq!(
        GenerationRecordV2::from_verified(
            verified(&file_artifact),
            file_facts.bindings,
            file_facts.candidate_sites,
            file_facts.deferred_dynamic,
            file_facts.deferred_commonjs_require,
            file_facts.bootstrap_internal_commonjs,
        )
        .unwrap_err()
        .to_string(),
        "hot update typed metadata disagrees with the verified artifact"
    );
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
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        both_graph,
    )
    .unwrap();
    let widened = facts([(static_key.clone(), b.clone()), (dynamic_key.clone(), c)]);
    let transaction = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [a.clone()],
        [typed_record(&a_revision, widened)],
    );
    assert_eq!(
        generations
            .commit_revision(&current_policy, transaction)
            .unwrap_err()
            .to_string(),
        "HMR graph edge widened; regenerate policy and restart the runtime"
    );

    let removed = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [a.clone()],
        [typed_record(
            &a_revision,
            facts([(static_key.clone(), b.clone())]),
        )],
    );
    assert_eq!(
        generations
            .commit_revision(&current_policy, removed)
            .unwrap_err()
            .to_string(),
        "HMR graph edge widened; regenerate policy and restart the runtime"
    );

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
    let site_graph = typed_graph([(site_boot.clone(), site_facts.clone())]);
    let mut changed_pin = site_facts.clone();
    changed_pin.candidate_sites.get_mut(&7).unwrap().digest = digest("site-b");
    assert_ne!(
        site_graph.digest(),
        typed_graph([(site_boot.clone(), changed_pin)]).digest()
    );
    let mut site_generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        site_graph,
    )
    .unwrap();
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
        let transaction = begin_staged_revision(
            &site_generations,
            &current_policy,
            HmrOrigin::Exact,
            [site_source.clone()],
            [typed_record(&site_revision, changed)],
        );
        assert_eq!(
            site_generations
                .commit_revision(&current_policy, transaction)
                .unwrap_err()
                .to_string(),
            "HMR candidate site changed; regenerate policy and restart the runtime"
        );
    }
    let removed_site = begin_staged_revision(
        &site_generations,
        &current_policy,
        HmrOrigin::Exact,
        [site_source.clone()],
        [typed_record(&site_revision, self_facts(&site_source))],
    );
    assert_eq!(
        site_generations
            .commit_revision(&current_policy, removed_site)
            .unwrap_err()
            .to_string(),
        "HMR candidate site changed; regenerate policy and restart the runtime"
    );

    let mut added_site_generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        typed_graph([(site_boot, self_facts(&site_source))]),
    )
    .unwrap();
    let added_site = begin_staged_revision(
        &added_site_generations,
        &current_policy,
        HmrOrigin::Exact,
        [site_source.clone()],
        [typed_record(&site_revision, site_facts)],
    );
    assert_eq!(
        added_site_generations
            .commit_revision(&current_policy, added_site)
            .unwrap_err()
            .to_string(),
        "HMR candidate site changed; regenerate policy and restart the runtime"
    );

    let deferred_source = source(root(), "deferred.mjs");
    let deferred_boot = artifact(deferred_source.clone(), 1);
    let deferred_revision = artifact(deferred_source.clone(), 2);
    let deferred_key = edge("./later", ResolutionKind::DynamicImport);
    let mut deferred_facts = facts([(deferred_key.clone(), deferred_source.clone())]);
    deferred_facts.deferred_dynamic.insert(deferred_key.clone());
    let eager = facts([(deferred_key.clone(), deferred_source.clone())]);
    let deferred_graph = typed_graph([(deferred_boot.clone(), deferred_facts.clone())]);
    assert_ne!(
        deferred_graph.digest(),
        typed_graph([(deferred_boot, eager.clone())]).digest()
    );
    let mut deferred_generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        deferred_graph,
    )
    .unwrap();
    let eager_transaction = begin_staged_revision(
        &deferred_generations,
        &current_policy,
        HmrOrigin::Exact,
        [deferred_source.clone()],
        [typed_record(&deferred_revision, eager)],
    );
    assert_eq!(
        deferred_generations
            .commit_revision(&current_policy, eager_transaction)
            .unwrap_err()
            .to_string(),
        "HMR deferred membership changed; regenerate policy and restart the runtime"
    );

    let wrong_kind_artifact = artifact_with_typed_facts(
        &artifact(deferred_source.clone(), 3),
        &self_facts(&deferred_source),
    );
    let invalid_deferred = GenerationRecordV2::from_verified(
        verified(&wrong_kind_artifact),
        self_facts(&deferred_source).bindings,
        BTreeMap::new(),
        [edge("./self", ResolutionKind::EsmStatic)]
            .into_iter()
            .collect(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    assert_eq!(
        invalid_deferred.unwrap_err().to_string(),
        "hot update typed metadata disagrees with the verified artifact"
    );

    let deferred_cjs_source = source(root(), "deferred.cjs");
    let deferred_cjs_boot = commonjs_artifact(deferred_cjs_source.clone(), 1);
    let deferred_cjs_revision = commonjs_artifact(deferred_cjs_source.clone(), 2);
    let deferred_cjs_key = edge("./self", ResolutionKind::CommonJsRequire);
    let mut deferred_cjs_facts = commonjs_self_facts(&deferred_cjs_source);
    deferred_cjs_facts
        .deferred_commonjs_require
        .insert(deferred_cjs_key);
    let mut deferred_cjs_generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        typed_graph([(deferred_cjs_boot, deferred_cjs_facts)]),
    )
    .unwrap();
    let eager_cjs = begin_staged_revision(
        &deferred_cjs_generations,
        &current_policy,
        HmrOrigin::Exact,
        [deferred_cjs_source.clone()],
        [typed_record(
            &deferred_cjs_revision,
            commonjs_self_facts(&deferred_cjs_source),
        )],
    );
    assert_eq!(
        deferred_cjs_generations
            .commit_revision(&current_policy, eager_cjs)
            .unwrap_err()
            .to_string(),
        "HMR deferred membership changed; regenerate policy and restart the runtime"
    );

    let absent_target = source(root(), "absent.mjs");
    let orphan = artifact(source(root(), "orphan.mjs"), 1);
    let orphan_facts = facts([(edge("./absent", ResolutionKind::EsmStatic), absent_target)]);
    let declared_orphan = artifact_with_typed_facts(&orphan, &orphan_facts);
    assert_eq!(
        AuthenticatedGenerationGraphV2::from_verified([(
            verified(&declared_orphan),
            orphan_facts.bindings,
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        )])
        .unwrap_err()
        .to_string(),
        "typed module generation edge targets an absent SourceId"
    );

    let bootstrap_source = SourceId::builtin("ibex-runtime", "generation-bootstrap-test").unwrap();
    let bootstrap_boot =
        artifact_with_shape(bootstrap_source.clone(), 1, SourceGoalV1::Builtin, &[]);
    let bootstrap_revision = bootstrap_boot.clone();
    let mut bootstrap_facts = TypedFacts::default();
    bootstrap_facts
        .bootstrap_internal_commonjs
        .insert("internal/test/binding".to_owned());
    let mut changed_bootstrap = TypedFacts::default();
    changed_bootstrap
        .bootstrap_internal_commonjs
        .insert("internal/util".to_owned());
    assert_ne!(
        typed_graph([(bootstrap_boot.clone(), bootstrap_facts.clone())]).digest(),
        typed_graph([(bootstrap_revision.clone(), changed_bootstrap.clone())]).digest()
    );

    let root_source = source(root(), "bootstrap-root.mjs");
    let root_boot = artifact(root_source.clone(), 1);
    let root_facts = self_facts(&root_source);
    let mut bootstrap_generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        typed_graph([
            (root_boot.clone(), root_facts.clone()),
            (bootstrap_boot, bootstrap_facts),
        ]),
    )
    .unwrap();
    let mut bootstrap_change = bootstrap_generations
        .begin_revision(
            &current_policy,
            HmrOrigin::Exact,
            (
                bootstrap_generations.current_generation(),
                bootstrap_generations.current_revision(),
            ),
            [root_source.clone()],
        )
        .unwrap();
    // The public begin path refuses builtin targets. Mutating the private test
    // transaction exercises the clone-and-swap ceiling backstop directly.
    bootstrap_change
        .invalidated
        .insert(bootstrap_source.clone());
    bootstrap_change
        .stage_replacements([
            typed_record(&root_boot, root_facts),
            typed_record(&bootstrap_revision, changed_bootstrap),
        ])
        .unwrap();
    assert_eq!(
        bootstrap_generations
            .commit_revision(&current_policy, bootstrap_change)
            .unwrap_err()
            .to_string(),
        "HMR bootstrap-internal CommonJS set changed; regenerate policy and restart the runtime"
    );
}

#[test]
fn f6_export_shape_changes_refuse_but_factory_only_replacement_commits() {
    let source_id = source(root(), "entry.mjs");
    let current_policy = policy("authority");
    let boot = artifact(source_id.clone(), 1);
    let row_facts = self_facts(&source_id);
    let changed_shapes = vec![
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
        artifact_with_export_descriptors(
            source_id.clone(),
            2,
            SourceGoalV1::Module,
            vec![ExportDescriptorV1::Indirect {
                exported: NonEmptyString::new("value").unwrap(),
                specifier: NonEmptyString::new("./dep").unwrap(),
                imported: NonEmptyString::new("value").unwrap(),
            }],
        ),
        artifact_with_export_descriptors(
            source_id.clone(),
            2,
            SourceGoalV1::Module,
            vec![ExportDescriptorV1::Star {
                specifier: NonEmptyString::new("./dep").unwrap(),
            }],
        ),
    ];
    for replacement in changed_shapes {
        let mut generations = ModuleExecutionGenerationsV2::new(
            GenerationMode::Development,
            execution_generation(),
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
        let before = live_snapshot(&generations);
        assert_eq!(
            generations
                .commit_revision(&current_policy, transaction)
                .unwrap_err()
                .to_string(),
            "hot revision changed the module export shape; full reload required"
        );
        assert_eq!(live_snapshot(&generations), before);
    }

    for (boot, boot_facts, replacement, replacement_facts) in [
        (
            artifact_with_shape(source_id.clone(), 1, SourceGoalV1::Module, &[]),
            self_facts(&source_id),
            commonjs_artifact(source_id.clone(), 2),
            commonjs_self_facts(&source_id),
        ),
        (
            commonjs_artifact(source_id.clone(), 1),
            commonjs_self_facts(&source_id),
            artifact_with_shape(source_id.clone(), 2, SourceGoalV1::Module, &[]),
            self_facts(&source_id),
        ),
    ] {
        let mut generations = ModuleExecutionGenerationsV2::new(
            GenerationMode::Development,
            execution_generation(),
            &current_policy,
            typed_graph([(boot, boot_facts)]),
        )
        .unwrap();
        let transaction = begin_staged_revision(
            &generations,
            &current_policy,
            HmrOrigin::Exact,
            [source_id.clone()],
            [typed_record(&replacement, replacement_facts)],
        );
        let before = live_snapshot(&generations);
        assert_eq!(
            generations
                .commit_revision(&current_policy, transaction)
                .unwrap_err()
                .to_string(),
            "hot revision changed the module export shape; full reload required"
        );
        assert_eq!(live_snapshot(&generations), before);
    }

    let cjs_boot = commonjs_artifact(source_id.clone(), 1);
    let cjs_replacement_base = commonjs_artifact(source_id.clone(), 2);
    let mut cjs_semantics = cjs_replacement_base.semantics.clone();
    cjs_semantics.commonjs_exports.as_mut().unwrap().names = vec![
        NonEmptyString::new("extra").unwrap(),
        NonEmptyString::new("value").unwrap(),
    ];
    let cjs_replacement = rebuild_inline_artifact(&cjs_replacement_base, cjs_semantics);
    let cjs_facts = commonjs_self_facts(&source_id);
    let mut cjs_generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        typed_graph([(cjs_boot, cjs_facts.clone())]),
    )
    .unwrap();
    let cjs_shape_change = begin_staged_revision(
        &cjs_generations,
        &current_policy,
        HmrOrigin::Exact,
        [source_id.clone()],
        [typed_record(&cjs_replacement, cjs_facts)],
    );
    assert_eq!(
        cjs_generations
            .commit_revision(&current_policy, cjs_shape_change)
            .unwrap_err()
            .to_string(),
        "hot revision changed the module export shape; full reload required"
    );

    let replacement = artifact(source_id.clone(), 9);
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        typed_graph([(boot, row_facts.clone())]),
    )
    .unwrap();
    let transaction = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Vite,
        [source_id.clone()],
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

    let duplicate_descriptor = ExportDescriptorV1::Local {
        exported: NonEmptyString::new("value").unwrap(),
        local: NonEmptyString::new("value").unwrap(),
    };
    let duplicate_replacement = artifact_with_export_descriptors(
        source_id.clone(),
        10,
        SourceGoalV1::Module,
        vec![duplicate_descriptor.clone(), duplicate_descriptor],
    );
    let duplicate_boot = artifact(source_id.clone(), 1);
    let mut duplicate_generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        typed_graph([(duplicate_boot, self_facts(&source_id))]),
    )
    .unwrap();
    let duplicate_collapse = begin_staged_revision(
        &duplicate_generations,
        &current_policy,
        HmrOrigin::Exact,
        [source_id.clone()],
        [typed_record(&duplicate_replacement, self_facts(&source_id))],
    );
    assert_eq!(
        duplicate_generations
            .commit_revision(&current_policy, duplicate_collapse)
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
        execution_generation(),
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

    // An outside CommonJS require snapshots even an ESM namespace boundary.
    let consumer_boot = commonjs_artifact(consumer.clone(), 1);
    let boundary_boot = artifact(boundary.clone(), 1);
    let boundary_revision = artifact(boundary.clone(), 2);
    let consumer_facts = facts([(
        edge("./boundary", ResolutionKind::CommonJsRequire),
        boundary.clone(),
    )]);
    let boundary_facts = self_facts(&boundary);
    let mut esm_boundary = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        typed_graph([
            (consumer_boot, consumer_facts),
            (boundary_boot, boundary_facts.clone()),
        ]),
    )
    .unwrap();
    let transaction = begin_staged_revision(
        &esm_boundary,
        &current_policy,
        HmrOrigin::Exact,
        [boundary.clone()],
        [typed_record(&boundary_revision, boundary_facts)],
    );
    let before = live_snapshot(&esm_boundary);
    assert_eq!(
        esm_boundary
            .commit_revision(&current_policy, transaction)
            .unwrap_err()
            .to_string(),
        "hot revision boundary is consumed across the closure through CommonJS; full reload required"
    );
    assert_eq!(live_snapshot(&esm_boundary), before);

    // A CommonJS live/replacement row refuses every outside binding kind.
    for resolution_kind in [ResolutionKind::CommonJsRequire, ResolutionKind::EsmStatic] {
        let consumer_boot = if resolution_kind == ResolutionKind::CommonJsRequire {
            commonjs_artifact(consumer.clone(), 1)
        } else {
            artifact(consumer.clone(), 1)
        };
        let boundary_boot = commonjs_artifact(boundary.clone(), 1);
        let boundary_revision = commonjs_artifact(boundary.clone(), 2);
        let consumer_facts = facts([(edge("./boundary", resolution_kind), boundary.clone())]);
        let boundary_facts = commonjs_self_facts(&boundary);
        let mut generations = ModuleExecutionGenerationsV2::new(
            GenerationMode::Development,
            execution_generation(),
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
        let before = live_snapshot(&generations);
        assert_eq!(
            generations
                .commit_revision(&current_policy, transaction)
                .unwrap_err()
                .to_string(),
            "hot revision boundary is consumed across the closure through CommonJS; full reload required"
        );
        assert_eq!(live_snapshot(&generations), before);
    }

    let consumer_boot = commonjs_artifact(consumer.clone(), 1);
    let consumer_revision = commonjs_artifact(consumer.clone(), 2);
    let boundary_boot = commonjs_artifact(boundary.clone(), 1);
    let boundary_revision = commonjs_artifact(boundary.clone(), 2);
    let consumer_facts = facts([(
        edge("./boundary", ResolutionKind::CommonJsRequire),
        boundary.clone(),
    )]);
    let boundary_facts = commonjs_self_facts(&boundary);
    let mut generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
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
    assert_eq!(
        commit.changed,
        [consumer.clone(), boundary.clone()].into_iter().collect()
    );

    // A CJS-to-ESM goal flip is both a CJS boundary defect and an export-shape
    // defect; LLP 0055 §5.2.5 requires the shape diagnostic to win.
    let consumer_boot = artifact(consumer.clone(), 1);
    let boundary_boot = commonjs_artifact(boundary.clone(), 1);
    let boundary_revision = artifact_with_shape(boundary.clone(), 2, SourceGoalV1::Module, &[]);
    let consumer_facts = facts([(
        edge("./boundary", ResolutionKind::EsmStatic),
        boundary.clone(),
    )]);
    let mut flip_generations = ModuleExecutionGenerationsV2::new(
        GenerationMode::Development,
        execution_generation(),
        &current_policy,
        typed_graph([
            (consumer_boot, consumer_facts),
            (boundary_boot, commonjs_self_facts(&boundary)),
        ]),
    )
    .unwrap();
    let flip = begin_staged_revision(
        &flip_generations,
        &current_policy,
        HmrOrigin::Exact,
        [boundary.clone()],
        [typed_record(&boundary_revision, self_facts(&boundary))],
    );
    let before = live_snapshot(&flip_generations);
    assert_eq!(
        flip_generations
            .commit_revision(&current_policy, flip)
            .unwrap_err()
            .to_string(),
        "hot revision changed the module export shape; full reload required"
    );
    assert_eq!(live_snapshot(&flip_generations), before);
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
        execution_generation(),
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
        execution_generation(),
        &current_policy,
        initial_graph,
    )
    .unwrap();
    assert_eq!(
        production
            .begin_revision(
                &current_policy,
                HmrOrigin::Exact,
                (execution_generation(), HotRevision::BOOT),
                [source_id.clone()],
            )
            .unwrap_err()
            .to_string(),
        "production module graphs have exactly one execution generation and revision"
    );
    assert_eq!(
        HotRevision::at(u64::MAX).next().unwrap_err().to_string(),
        "hot revision space is exhausted; full reload required"
    );
    generations.current.revision = HotRevision::at(u64::MAX);
    assert_eq!(
        generations
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
            .to_string(),
        "hot revision space is exhausted; full reload required"
    );
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
        execution_generation(),
        &current_policy,
        typed_graph([(boot.clone(), row_facts.clone())]),
    )
    .unwrap();
    let refused = begin_staged_revision(
        &generations,
        &current_policy,
        HmrOrigin::Exact,
        [source_id.clone()],
        [typed_record(&boot, row_facts.clone())],
    );
    let mut slot = HotRevisionSlotV1::new(generations, "native-revision-0");
    assert_eq!(
        slot.commit_revision(&current_policy, refused, "must-not-publish")
            .unwrap_err()
            .to_string(),
        "hot revision changed nothing; nothing to apply"
    );
    assert_eq!(*slot.current(), "native-revision-0");
    assert_eq!(slot.generations().current_revision(), HotRevision::BOOT);
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
