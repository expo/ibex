//! Typed, owner-thread staging surface for intra-generation hot revisions.

use std::cell::Cell;
use std::rc::Rc;

use anyhow::{bail, Result};
use capsec_semantics::model::Digest;

use super::generation::{
    ExecutionGeneration, GenerationMode, GenerationPublicationKind, GenerationPublicationReceipt,
    GenerationPublicationToken, HmrOrigin, HotRevision, HotRevisionCommitV1,
    HotRevisionTransactionV1, ModuleExecutionGenerationsV2, ShadowPublicationToken,
};
use super::identity::SourceId;
use super::runner_pipeline::SourceModuleGraphV1;
use super::security::GraphImportPolicy;

/// Owner-thread host API for one generation's single-flight revision chain.
// @ref LLP 0055#52-hotrevisionsurfacev1--single-flight-typed-states-no-fallible-check-after-an-effect
// — consuming state values keep staged records private until ReadyToPublish.
pub struct HotRevisionSurfaceV1 {
    generations: ModuleExecutionGenerationsV2,
    in_flight: Rc<Cell<bool>>,
}

impl HotRevisionSurfaceV1 {
    pub fn new(generations: ModuleExecutionGenerationsV2) -> Self {
        Self {
            generations,
            in_flight: Rc::new(Cell::new(false)),
        }
    }

    pub fn for_source_graph(
        mode: GenerationMode,
        execution_generation: ExecutionGeneration,
        graph: &SourceModuleGraphV1,
    ) -> Result<Self> {
        let initial = graph.generation_graph_v2()?;
        Ok(Self::new(ModuleExecutionGenerationsV2::new(
            mode,
            execution_generation,
            graph.snapshot(),
            initial,
        )?))
    }

    pub fn current_generation(&self) -> ExecutionGeneration {
        self.generations.current_generation()
    }

    pub fn current_revision(&self) -> HotRevision {
        self.generations.current_revision()
    }

    pub fn current_coordinates(&self) -> (ExecutionGeneration, HotRevision) {
        (self.current_generation(), self.current_revision())
    }

    pub fn graph_digest(&self) -> &Digest {
        self.generations.graph_digest()
    }

    pub fn install_revision(&self, source_id: &SourceId) -> Result<HotRevision> {
        self.generations.install_revision(source_id)
    }

    pub fn publication_token(&self, source_id: &SourceId) -> Result<GenerationPublicationToken> {
        self.generations.publication_token(source_id)
    }

    pub fn publish(
        &self,
        token: &GenerationPublicationToken,
        kind: GenerationPublicationKind,
    ) -> Result<GenerationPublicationReceipt> {
        self.generations.publish(token, kind)
    }

    /// S4 seam: envelope verification + replay table mount here, before begin.
    ///
    /// This slice accepts inputs whose envelope/session checks already
    /// succeeded; S4 will mount those checks ahead of the algebra call below.
    // @ref LLP 0055#1-the-hotrevision-counter-and-successor-law — the live
    // manager coordinate is authoritative and commit has exactly one successor.
    pub fn begin<P: GraphImportPolicy>(
        &self,
        policy: &P,
        origin: HmrOrigin,
        base: (ExecutionGeneration, HotRevision),
        invalidated: impl IntoIterator<Item = SourceId>,
    ) -> Result<HotRevisionBegunV1> {
        if self.in_flight.get() {
            bail!("hot revision surface is busy");
        }
        let transaction = self
            .generations
            .begin_revision(policy, origin, base, invalidated)?;
        let guard = HotRevisionFlightGuardV1 {
            in_flight: Rc::clone(&self.in_flight),
        };
        self.in_flight.set(true);
        Ok(HotRevisionBegunV1 {
            state: HotRevisionStateV1 {
                transaction,
                _guard: guard,
            },
        })
    }

    /// Commit-bundle mount points for the engine slice (`LLP 0055#53`):
    /// 3. slot retargets/binding relinks mount after algebraic graph adoption;
    /// 5. loader-cache surgery and 6. carrier retirement mount after the
    /// activation flip. They execute in the same owner-thread fence.
    ///
    /// A commit-time validation error is an item-8 invariant backstop. This
    /// library returns it so the caller can quarantine and recreate.
    /// @ref LLP 0055#53-the-commit-bundle-atomic-owner-thread-no-fail
    pub fn commit<P: GraphImportPolicy>(
        &mut self,
        policy: &P,
        ready: HotRevisionReadyToPublishV1,
    ) -> Result<HotRevisionCommitV1> {
        let HotRevisionReadyToPublishV1 {
            state,
            activation_token,
        } = ready;
        let HotRevisionStateV1 {
            transaction,
            _guard,
        } = state;

        let commit = self.generations.commit_revision(policy, transaction)?;
        // Engine §5.3 step 3 mounts immediately before this activation flip.
        activation_token.apply();
        // Engine §5.3 steps 5 and 6 mount immediately after this flip.
        Ok(commit)
    }
}

struct HotRevisionFlightGuardV1 {
    in_flight: Rc<Cell<bool>>,
}

impl Drop for HotRevisionFlightGuardV1 {
    fn drop(&mut self) {
        self.in_flight.set(false);
    }
}

struct HotRevisionStateV1 {
    transaction: HotRevisionTransactionV1,
    _guard: HotRevisionFlightGuardV1,
}

pub struct HotRevisionBegunV1 {
    state: HotRevisionStateV1,
}

impl HotRevisionBegunV1 {
    pub fn stage(
        mut self,
        records: impl IntoIterator<Item = super::generation::GenerationRecordV2>,
    ) -> Result<HotRevisionStagedV1> {
        self.state.transaction.stage_replacements(records)?;
        Ok(HotRevisionStagedV1 { state: self.state })
    }
}

pub struct HotRevisionStagedV1 {
    state: HotRevisionStateV1,
}

impl HotRevisionStagedV1 {
    pub fn preflight(self, surface: &HotRevisionSurfaceV1) -> Result<HotRevisionPreflightedV1> {
        surface
            .generations
            .preflight_revision(&self.state.transaction)?;
        Ok(HotRevisionPreflightedV1 { state: self.state })
    }
}

pub struct HotRevisionPreflightedV1 {
    state: HotRevisionStateV1,
}

impl HotRevisionPreflightedV1 {
    pub fn shadow_publication_token(&self, source_id: &SourceId) -> Result<ShadowPublicationToken> {
        self.state.transaction.shadow_publication_token(source_id)
    }

    pub fn shadow_publish(
        &mut self,
        token: &ShadowPublicationToken,
        kind: GenerationPublicationKind,
    ) -> Result<GenerationPublicationReceipt> {
        self.state.transaction.shadow_publish(token, kind)
    }

    pub fn evaluated(self) -> Result<HotRevisionEvaluatedV1> {
        let transaction = &self.state.transaction;
        let settled = transaction.invalidated().iter().all(|source_id| {
            transaction.shadow_publications().iter().any(|receipt| {
                &receipt.incarnation.source_id == source_id
                    && matches!(
                        receipt.kind,
                        GenerationPublicationKind::Evaluation
                            | GenerationPublicationKind::CommonJsCache
                    )
            })
        });
        if !settled {
            bail!("staged evaluation has not settled");
        }
        Ok(HotRevisionEvaluatedV1 { state: self.state })
    }
}

pub struct HotRevisionEvaluatedV1 {
    state: HotRevisionStateV1,
}

impl HotRevisionEvaluatedV1 {
    pub fn prepare_activation(
        self,
        activation_token: ActivationTokenV1,
    ) -> HotRevisionActivationPreparedV1 {
        HotRevisionActivationPreparedV1 {
            state: self.state,
            activation_token,
        }
    }
}

pub struct HotRevisionActivationPreparedV1 {
    state: HotRevisionStateV1,
    activation_token: ActivationTokenV1,
}

impl HotRevisionActivationPreparedV1 {
    pub fn ready(self) -> HotRevisionReadyToPublishV1 {
        HotRevisionReadyToPublishV1 {
            state: self.state,
            activation_token: self.activation_token,
        }
    }
}

pub struct HotRevisionReadyToPublishV1 {
    state: HotRevisionStateV1,
    activation_token: ActivationTokenV1,
}

/// Linear, transaction-bound consumer activation prepared before publication.
/// The action is private so it can run only from [`HotRevisionSurfaceV1::commit`].
pub struct ActivationTokenV1 {
    action: ActivationActionV1,
}

enum ActivationActionV1 {
    Trivial,
    Flip(Box<dyn FnOnce()>),
}

impl ActivationTokenV1 {
    pub fn trivial() -> Self {
        Self {
            action: ActivationActionV1::Trivial,
        }
    }

    pub fn flip(action: impl FnOnce() + 'static) -> Self {
        Self {
            action: ActivationActionV1::Flip(Box::new(action)),
        }
    }

    fn apply(self) {
        if let ActivationActionV1::Flip(action) = self.action {
            action();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use capsec_semantics::arming::SnapshotGenerations;
    use capsec_semantics::model::{NonEmptyString, PathComponent, Principal, SafeUint};

    use super::*;
    use crate::module_loader::artifact::{
        digest_bytes, source_integrity, ArtifactAdmissionV1, CanonicalSourceId, ExportDescriptorV1,
        ModuleArtifactV1, ModuleSemanticsV1, ProducerIdentityV1, SourceDialectV1, SourceGoalV1,
        SourceMapV1, TransformFingerprintV1, VerifiedModuleArtifactV1,
        MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
    };
    use crate::module_loader::generation::{AuthenticatedGenerationGraphV2, GenerationRecordV2};

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
        digest_bytes("hot-revision-surface-test", label.as_bytes()).unwrap()
    }

    fn policy() -> Policy {
        Policy {
            digest: digest("authority"),
            generations: SnapshotGenerations {
                policy: SafeUint::new(1).unwrap(),
                negative: SafeUint::new(1).unwrap(),
                dynamic: SafeUint::new(1).unwrap(),
                handle: SafeUint::new(1).unwrap(),
            },
        }
    }

    fn source(name: &str) -> SourceId {
        SourceId::file(
            Principal::Root {
                identity: NonEmptyString::new("project").unwrap(),
            },
            vec![PathComponent::utf8(name).unwrap()],
        )
        .unwrap()
    }

    fn artifact(source_id: SourceId, value: u32) -> ModuleArtifactV1 {
        let factory = format!(
            "function($export){{return{{declare:function(){{}},execute:function(){{$export('value',{value});}}}};}}"
        );
        ModuleArtifactV1::new_inline(
            ModuleSemanticsV1 {
                source_id: CanonicalSourceId(source_id.clone()),
                source_goal: SourceGoalV1::Module,
                dialect: Some(SourceDialectV1::Js),
                source_integrity: source_integrity(factory.as_bytes()).unwrap(),
                transform_fingerprint: TransformFingerprintV1 {
                    producer: NonEmptyString::new("hot-revision-surface-test").unwrap(),
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
                export_descriptors: vec![ExportDescriptorV1::Local {
                    exported: NonEmptyString::new("value").unwrap(),
                    local: NonEmptyString::new("value").unwrap(),
                }],
                commonjs_exports: None,
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
                producer_id: NonEmptyString::new("hot-revision-surface-test").unwrap(),
                producer_binary_digest: digest("producer"),
            },
        )
        .unwrap()
    }

    fn verified(artifact: &ModuleArtifactV1) -> VerifiedModuleArtifactV1<'_> {
        artifact
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: artifact.semantics.source_id.0.clone(),
                expected_source_integrity: artifact.semantics.source_integrity.clone(),
                expected_producer_id: NonEmptyString::new("hot-revision-surface-test").unwrap(),
                producer_binary_digest: digest("producer"),
                transform_fingerprint_digest: artifact
                    .semantics
                    .transform_fingerprint
                    .digest()
                    .unwrap(),
            })
            .unwrap()
    }

    fn record(artifact: &ModuleArtifactV1) -> GenerationRecordV2 {
        GenerationRecordV2::from_verified(
            verified(artifact),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .unwrap()
    }

    fn graph(artifacts: &[ModuleArtifactV1]) -> AuthenticatedGenerationGraphV2 {
        AuthenticatedGenerationGraphV2::from_verified(artifacts.iter().map(|artifact| {
            (
                verified(artifact),
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            )
        }))
        .unwrap()
    }

    fn surface(artifacts: &[ModuleArtifactV1], current_policy: &Policy) -> HotRevisionSurfaceV1 {
        HotRevisionSurfaceV1::new(
            ModuleExecutionGenerationsV2::new(
                GenerationMode::Development,
                ExecutionGeneration::new(41).unwrap(),
                current_policy,
                graph(artifacts),
            )
            .unwrap(),
        )
    }

    fn preflighted(
        surface: &HotRevisionSurfaceV1,
        current_policy: &impl GraphImportPolicy,
        source_id: &SourceId,
        replacement: &ModuleArtifactV1,
    ) -> HotRevisionPreflightedV1 {
        surface
            .begin(
                current_policy,
                HmrOrigin::Exact,
                surface.current_coordinates(),
                [source_id.clone()],
            )
            .unwrap()
            .stage([record(replacement)])
            .unwrap()
            .preflight(surface)
            .unwrap()
    }

    fn ready_revision(
        surface: &HotRevisionSurfaceV1,
        current_policy: &impl GraphImportPolicy,
        source_id: &SourceId,
        replacement: &ModuleArtifactV1,
        activation_token: ActivationTokenV1,
    ) -> HotRevisionReadyToPublishV1 {
        let mut preflighted = preflighted(surface, current_policy, source_id, replacement);
        let token = preflighted.shadow_publication_token(source_id).unwrap();
        preflighted
            .shadow_publish(&token, GenerationPublicationKind::Evaluation)
            .unwrap();
        preflighted
            .evaluated()
            .unwrap()
            .prepare_activation(activation_token)
            .ready()
    }

    #[test]
    fn single_flight_drop_releases_the_surface() {
        let source_id = source("entry.mjs");
        let current_policy = policy();
        let surface = surface(&[artifact(source_id.clone(), 1)], &current_policy);

        let first = surface
            .begin(
                &current_policy,
                HmrOrigin::Exact,
                surface.current_coordinates(),
                [source_id.clone()],
            )
            .unwrap();
        let error = surface
            .begin(
                &current_policy,
                HmrOrigin::Vite,
                surface.current_coordinates(),
                [source_id.clone()],
            )
            .err()
            .expect("a second begin must refuse while the first is live");
        assert_eq!(error.to_string(), "hot revision surface is busy");

        drop(first);
        let next = surface
            .begin(
                &current_policy,
                HmrOrigin::Vite,
                surface.current_coordinates(),
                [source_id],
            )
            .unwrap();
        drop(next);
    }

    #[test]
    fn full_happy_path_advances_only_invalidated_slots_and_flips_at_commit() {
        let a = source("a.mjs");
        let b = source("b.mjs");
        let a_boot = artifact(a.clone(), 1);
        let b_boot = artifact(b.clone(), 1);
        let a_revision = artifact(a.clone(), 2);
        let current_policy = policy();
        let mut surface = surface(&[a_boot, b_boot], &current_policy);
        let flip_count = Rc::new(Cell::new(0));
        let observed = Rc::clone(&flip_count);

        let ready = ready_revision(
            &surface,
            &current_policy,
            &a,
            &a_revision,
            ActivationTokenV1::flip(move || observed.set(observed.get() + 1)),
        );
        assert_eq!(flip_count.get(), 0);
        assert_eq!(surface.current_revision(), HotRevision::BOOT);

        let commit = surface.commit(&current_policy, ready).unwrap();
        assert_eq!(commit.previous_revision, HotRevision::BOOT);
        assert_eq!(commit.revision.get(), 1);
        assert_eq!(surface.current_revision().get(), 1);
        assert_eq!(surface.install_revision(&a).unwrap().get(), 1);
        assert_eq!(surface.install_revision(&b).unwrap(), HotRevision::BOOT);
        assert_eq!(flip_count.get(), 1);
    }

    #[test]
    fn preflight_refusal_drops_staged_rows_and_frees_the_surface() {
        let source_id = source("entry.mjs");
        let replacement = artifact(source_id.clone(), 2);
        let current_policy = policy();
        let mut surface = surface(&[artifact(source_id.clone(), 1)], &current_policy);
        let before = (
            surface.current_coordinates(),
            surface.graph_digest().clone(),
            surface.install_revision(&source_id).unwrap(),
        );

        let staged = surface
            .begin(
                &current_policy,
                HmrOrigin::Exact,
                surface.current_coordinates(),
                [source_id.clone()],
            )
            .unwrap()
            .stage(std::iter::empty())
            .unwrap();
        let error = staged
            .preflight(&surface)
            .err()
            .expect("a missing replacement must fail preflight");
        assert_eq!(
            error.to_string(),
            "hot revision transaction is missing an invalidated replacement"
        );
        assert_eq!(
            (
                surface.current_coordinates(),
                surface.graph_digest().clone(),
                surface.install_revision(&source_id).unwrap(),
            ),
            before
        );

        let ready = ready_revision(
            &surface,
            &current_policy,
            &source_id,
            &replacement,
            ActivationTokenV1::trivial(),
        );
        surface.commit(&current_policy, ready).unwrap();
        assert_eq!(surface.current_revision().get(), 1);
    }

    #[test]
    fn evaluated_requires_a_successful_shadow_evaluation_publication() {
        let source_id = source("entry.mjs");
        let replacement = artifact(source_id.clone(), 2);
        let current_policy = policy();
        let surface = surface(&[artifact(source_id.clone(), 1)], &current_policy);

        let without_publication = preflighted(&surface, &current_policy, &source_id, &replacement);
        let error = without_publication
            .evaluated()
            .err()
            .expect("evaluation cannot settle without a shadow publication");
        assert_eq!(error.to_string(), "staged evaluation has not settled");

        let mut with_publication = preflighted(&surface, &current_policy, &source_id, &replacement);
        let token = with_publication
            .shadow_publication_token(&source_id)
            .unwrap();
        with_publication
            .shadow_publish(&token, GenerationPublicationKind::Evaluation)
            .unwrap();
        let evaluated = with_publication.evaluated().unwrap();
        drop(evaluated);
    }

    #[test]
    fn ready_from_a_foreign_surface_preserves_manager_identity_refusal() {
        let source_id = source("entry.mjs");
        let boot = artifact(source_id.clone(), 1);
        let replacement = artifact(source_id.clone(), 2);
        let current_policy = policy();
        let first = surface(std::slice::from_ref(&boot), &current_policy);
        let mut second = surface(&[boot], &current_policy);

        let ready = ready_revision(
            &first,
            &current_policy,
            &source_id,
            &replacement,
            ActivationTokenV1::trivial(),
        );
        let error = second
            .commit(&current_policy, ready)
            .expect_err("a foreign surface must reject the ready transaction");
        assert_eq!(
            error.to_string(),
            "hot revision transaction belongs to another hot revision surface"
        );
        assert_eq!(second.current_revision(), HotRevision::BOOT);

        let begun_again = first
            .begin(
                &current_policy,
                HmrOrigin::Exact,
                first.current_coordinates(),
                [source_id],
            )
            .unwrap();
        drop(begun_again);
    }

    #[cfg(unix)]
    #[test]
    fn f8_runtime_recreate_derives_a_fresh_boot_ceiling_from_the_same_content() {
        let project = tempfile::tempdir().unwrap();
        let source_text = "export const value = 1;\n";
        let graph_one = crate::module_loader::runner_pipeline::tests::build_test_source_graph(
            project.path(),
            source_text,
        )
        .unwrap();
        let graph_two = crate::module_loader::runner_pipeline::tests::build_test_source_graph(
            project.path(),
            source_text,
        )
        .unwrap();
        assert_eq!(graph_one.snapshot().digest(), graph_two.snapshot().digest());
        let original_boot_digest = graph_one.generation_graph_v2().unwrap().digest().clone();
        assert_eq!(
            graph_two.generation_graph_v2().unwrap().digest(),
            &original_boot_digest
        );

        let entry = graph_one.entry().clone();
        let mut revised = HotRevisionSurfaceV1::for_source_graph(
            GenerationMode::Development,
            graph_one.execution_generation(),
            &graph_one,
        )
        .unwrap();
        assert_eq!(revised.graph_digest(), &original_boot_digest);
        let replacement = artifact(entry.clone(), 2);
        let ready = ready_revision(
            &revised,
            graph_one.snapshot(),
            &entry,
            &replacement,
            ActivationTokenV1::trivial(),
        );
        revised.commit(graph_one.snapshot(), ready).unwrap();
        assert_eq!(revised.current_revision().get(), 1);
        assert_ne!(revised.graph_digest(), &original_boot_digest);

        let recreate_generation =
            ExecutionGeneration::new(graph_one.execution_generation().get() + 1).unwrap();
        let recreated = HotRevisionSurfaceV1::for_source_graph(
            GenerationMode::Development,
            recreate_generation,
            &graph_two,
        )
        .unwrap();
        assert_eq!(recreated.current_generation(), recreate_generation);
        assert_eq!(recreated.current_revision(), HotRevision::BOOT);
        assert_eq!(recreated.graph_digest(), &original_boot_digest);
    }
}
