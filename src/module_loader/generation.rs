//! Atomic development graph generations and HMR publication isolation.
//!
//! A generation transition replaces one complete authenticated graph. It can
//! reuse immutable artifacts, but never live records, cells, namespaces,
//! promises, errors, or CommonJS exports from another generation.
//! @ref LLP 0026#8-development-hmr-and-invalidation

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Result};
use capsec_semantics::arming::SnapshotGenerations;
use capsec_semantics::model::{Digest, Principal};

use super::artifact::{digest_bytes, ModuleArtifactV1, VerifiedModuleArtifactV1};
use super::graph::SynchronousGraphPlan;
use super::identity::SourceId;
use super::security::GraphImportPolicy;

pub const GENERATION_GRAPH_DIGEST_DOMAIN_V1: &str = "ibex/module-generation-graph/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExecutionGeneration(u64);

impl ExecutionGeneration {
    pub const INITIAL: Self = Self(1);

    pub fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .filter(|value| *value != 0)
            .map(Self)
            .ok_or_else(|| anyhow!("module execution generation space is exhausted"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleIncarnationKey {
    pub source_id: SourceId,
    pub generation: ExecutionGeneration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationMode {
    Development,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmrOrigin {
    Exact,
    Vite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationPublicationKind {
    Evaluation,
    TopLevelAwait,
    DynamicImport,
    Error,
    CommonJsCache,
    ArtifactCache,
}

#[derive(Debug, Clone)]
pub struct GenerationPublicationToken {
    generation: ExecutionGeneration,
    source_id: SourceId,
    semantic_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationPublicationReceipt {
    pub incarnation: ModuleIncarnationKey,
    pub kind: GenerationPublicationKind,
    pub semantic_digest: Digest,
}

#[derive(Debug, Clone)]
struct GenerationRecordV1 {
    artifact: ModuleArtifactV1,
    bindings: BTreeMap<String, SourceId>,
}

/// One complete graph candidate built only from admitted artifact tokens.
#[derive(Debug, Clone)]
pub struct AuthenticatedGenerationGraphV1 {
    records: BTreeMap<SourceId, GenerationRecordV1>,
    digest: Digest,
}

impl AuthenticatedGenerationGraphV1 {
    pub fn from_verified<'artifact>(
        records: impl IntoIterator<
            Item = (
                VerifiedModuleArtifactV1<'artifact>,
                BTreeMap<String, SourceId>,
            ),
        >,
    ) -> Result<Self> {
        let records: Vec<_> = records.into_iter().collect();
        if records.is_empty() {
            bail!("module generation graph cannot be empty");
        }
        // Reuse the link-plan validator so every binding corresponds to typed
        // artifact metadata and every target has one admitted record.
        SynchronousGraphPlan::new(
            records
                .iter()
                .map(|(artifact, bindings)| (*artifact, bindings.clone())),
        )?;
        let mut owned = BTreeMap::new();
        for (verified, bindings) in records {
            let artifact = verified.artifact().clone();
            let source_id = artifact.semantics.source_id.0.clone();
            if owned
                .insert(source_id, GenerationRecordV1 { artifact, bindings })
                .is_some()
            {
                bail!("module generation graph contains a duplicate SourceId");
            }
        }
        let digest = graph_digest(&owned)?;
        Ok(Self {
            records: owned,
            digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn source_ids(&self) -> impl Iterator<Item = &SourceId> {
        self.records.keys()
    }

    fn record(&self, source_id: &SourceId) -> Result<&GenerationRecordV1> {
        self.records
            .get(source_id)
            .ok_or_else(|| anyhow!("SourceId is absent from the generation graph"))
    }
}

fn graph_digest(records: &BTreeMap<SourceId, GenerationRecordV1>) -> Result<Digest> {
    let mut rows = Vec::with_capacity(records.len());
    for (source_id, record) in records {
        rows.push(serde_json::json!({
            "sourceId": source_id.encode()?,
            "semanticDigest": record.artifact.semantic_digest,
            "bindings": record.bindings.iter().map(|(specifier, target)| {
                Ok(serde_json::json!({
                    "specifier": specifier,
                    "target": target.encode()?,
                }))
            }).collect::<Result<Vec<_>>>()?,
        }));
    }
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&serde_json::Value::Array(rows))
        .map_err(|error| anyhow!("cannot canonicalize module generation graph: {error}"))?;
    digest_bytes(GENERATION_GRAPH_DIGEST_DOMAIN_V1, &canonical)
}

/// Immutable HMR ceiling derived from the armed policy and initial graph.
/// It has no API for adding sources, edges, or mutable authority generations.
#[derive(Debug, Clone)]
pub struct ImmutableGenerationAdmissionV1 {
    authority_digest: Digest,
    authority_generations: SnapshotGenerations,
    defining_principals: BTreeMap<SourceId, Principal>,
    pinned_integrities: BTreeMap<SourceId, Digest>,
    authorized_edges: BTreeSet<(SourceId, String, SourceId)>,
}

impl ImmutableGenerationAdmissionV1 {
    pub fn from_initial<P: GraphImportPolicy>(
        policy: &P,
        graph: &AuthenticatedGenerationGraphV1,
    ) -> Result<Self> {
        let mut defining_principals = BTreeMap::new();
        let mut pinned_integrities = BTreeMap::new();
        let mut authorized_edges = BTreeSet::new();
        for (source_id, record) in &graph.records {
            let principal = source_id
                .defining_principal()
                .ok_or_else(|| anyhow!("HMR requires a SourceId with a defining principal"))?
                .clone();
            if !matches!(principal, Principal::Root { .. }) {
                pinned_integrities.insert(
                    source_id.clone(),
                    record.artifact.semantics.source_integrity.clone(),
                );
            }
            defining_principals.insert(source_id.clone(), principal);
            for (specifier, target) in &record.bindings {
                authorized_edges.insert((source_id.clone(), specifier.clone(), target.clone()));
            }
        }
        Ok(Self {
            authority_digest: policy.snapshot_digest().clone(),
            authority_generations: policy.snapshot_generations(),
            defining_principals,
            pinned_integrities,
            authorized_edges,
        })
    }

    fn validate_authority<P: GraphImportPolicy>(&self, policy: &P) -> Result<()> {
        if policy.snapshot_digest() != &self.authority_digest
            || policy.snapshot_generations() != self.authority_generations
        {
            bail!("HMR authority changed; regenerate policy and restart the runtime");
        }
        Ok(())
    }

    fn validate_graph(&self, graph: &AuthenticatedGenerationGraphV1) -> Result<()> {
        for (source_id, record) in &graph.records {
            let expected_principal = self.defining_principals.get(source_id).ok_or_else(|| {
                anyhow!("HMR graph widened; regenerate policy and restart the runtime")
            })?;
            if source_id.defining_principal() != Some(expected_principal) {
                bail!("HMR changed a module defining principal");
            }
            if let Some(integrity) = self.pinned_integrities.get(source_id) {
                if &record.artifact.semantics.source_integrity != integrity {
                    bail!("HMR changed integrity-pinned package/runtime source; restart required");
                }
            }
            for (specifier, target) in &record.bindings {
                if !self.authorized_edges.contains(&(
                    source_id.clone(),
                    specifier.clone(),
                    target.clone(),
                )) {
                    bail!("HMR graph edge widened; regenerate policy and restart the runtime");
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct PublishedGenerationV1 {
    generation: ExecutionGeneration,
    graph: AuthenticatedGenerationGraphV1,
}

pub struct ModuleExecutionGenerationsV1 {
    mode: GenerationMode,
    admission: ImmutableGenerationAdmissionV1,
    current: PublishedGenerationV1,
}

impl ModuleExecutionGenerationsV1 {
    pub fn new<P: GraphImportPolicy>(
        mode: GenerationMode,
        policy: &P,
        initial: AuthenticatedGenerationGraphV1,
    ) -> Result<Self> {
        let admission = ImmutableGenerationAdmissionV1::from_initial(policy, &initial)?;
        admission.validate_authority(policy)?;
        admission.validate_graph(&initial)?;
        Ok(Self {
            mode,
            admission,
            current: PublishedGenerationV1 {
                generation: ExecutionGeneration::INITIAL,
                graph: initial,
            },
        })
    }

    pub fn current_generation(&self) -> ExecutionGeneration {
        self.current.generation
    }

    pub fn incarnation(&self, source_id: &SourceId) -> Result<ModuleIncarnationKey> {
        self.current.graph.record(source_id)?;
        Ok(ModuleIncarnationKey {
            source_id: source_id.clone(),
            generation: self.current.generation,
        })
    }

    pub fn publication_token(&self, source_id: &SourceId) -> Result<GenerationPublicationToken> {
        let record = self.current.graph.record(source_id)?;
        Ok(GenerationPublicationToken {
            generation: self.current.generation,
            source_id: source_id.clone(),
            semantic_digest: record.artifact.semantic_digest.clone(),
        })
    }

    pub fn publish(
        &self,
        token: &GenerationPublicationToken,
        kind: GenerationPublicationKind,
    ) -> Result<GenerationPublicationReceipt> {
        if token.generation != self.current.generation {
            bail!("stale module-generation completion cannot publish");
        }
        let record = self.current.graph.record(&token.source_id)?;
        if record.artifact.semantic_digest != token.semantic_digest {
            bail!("module-generation completion semantic digest is stale");
        }
        Ok(GenerationPublicationReceipt {
            incarnation: ModuleIncarnationKey {
                source_id: token.source_id.clone(),
                generation: token.generation,
            },
            kind,
            semantic_digest: token.semantic_digest.clone(),
        })
    }

    pub fn begin_update<P: GraphImportPolicy>(
        &self,
        policy: &P,
        origin: HmrOrigin,
        invalidated: impl IntoIterator<Item = SourceId>,
    ) -> Result<ModuleGenerationTransactionV1> {
        if self.mode == GenerationMode::Production {
            bail!("production module graphs have exactly one execution generation");
        }
        self.admission.validate_authority(policy)?;
        let invalidated: BTreeSet<_> = invalidated.into_iter().collect();
        if invalidated.is_empty() {
            bail!("HMR update must invalidate at least one module");
        }
        if invalidated
            .iter()
            .any(|source_id| !self.current.graph.records.contains_key(source_id))
        {
            bail!("HMR invalidation widened the authenticated source graph");
        }
        Ok(ModuleGenerationTransactionV1 {
            origin,
            base_generation: self.current.generation,
            authority_digest: self.admission.authority_digest.clone(),
            authority_generations: self.admission.authority_generations,
            invalidated,
            candidate: None,
        })
    }

    pub fn commit<P: GraphImportPolicy>(
        &mut self,
        policy: &P,
        transaction: ModuleGenerationTransactionV1,
    ) -> Result<GenerationCommitV1> {
        self.admission.validate_authority(policy)?;
        if transaction.authority_digest != self.admission.authority_digest
            || transaction.authority_generations != self.admission.authority_generations
        {
            bail!("HMR transaction authority stamp is stale");
        }
        if transaction.base_generation != self.current.generation {
            bail!("HMR transaction lost the generation publication race");
        }
        let candidate = transaction
            .candidate
            .ok_or_else(|| anyhow!("HMR transaction has no complete graph candidate"))?;
        self.admission.validate_graph(&candidate)?;
        let changed = changed_sources(&self.current.graph, &candidate);
        if changed
            .iter()
            .any(|source_id| !transaction.invalidated.contains(source_id))
        {
            bail!("HMR candidate changed a module outside its invalidation set");
        }
        let previous = self.current.generation;
        let generation = previous.next()?;
        // Single assignment is the publication point. No candidate record or
        // completion is visible through `current` before every check succeeds.
        self.current = PublishedGenerationV1 {
            generation,
            graph: candidate,
        };
        Ok(GenerationCommitV1 {
            origin: transaction.origin,
            previous,
            generation,
            invalidated: transaction.invalidated,
            changed,
            graph_digest: self.current.graph.digest.clone(),
        })
    }
}

fn changed_sources(
    current: &AuthenticatedGenerationGraphV1,
    candidate: &AuthenticatedGenerationGraphV1,
) -> BTreeSet<SourceId> {
    current
        .records
        .keys()
        .chain(candidate.records.keys())
        .filter(|source_id| {
            match (
                current.records.get(*source_id),
                candidate.records.get(*source_id),
            ) {
                (Some(left), Some(right)) => {
                    left.artifact.semantic_digest != right.artifact.semantic_digest
                        || left.bindings != right.bindings
                }
                _ => true,
            }
        })
        .cloned()
        .collect()
}

#[derive(Debug)]
pub struct ModuleGenerationTransactionV1 {
    origin: HmrOrigin,
    base_generation: ExecutionGeneration,
    authority_digest: Digest,
    authority_generations: SnapshotGenerations,
    invalidated: BTreeSet<SourceId>,
    candidate: Option<AuthenticatedGenerationGraphV1>,
}

impl ModuleGenerationTransactionV1 {
    /// Generation that every staged native factory/context/record must use.
    /// The value is not published until `commit` succeeds.
    pub fn candidate_generation(&self) -> Result<ExecutionGeneration> {
        self.base_generation.next()
    }

    pub fn stage_graph(&mut self, graph: AuthenticatedGenerationGraphV1) -> Result<()> {
        if self.candidate.is_some() {
            bail!("HMR transaction already has a staged graph");
        }
        self.candidate = Some(graph);
        Ok(())
    }
}

/// Couples the metadata publication gate to an arbitrary complete native graph
/// owner. Exclusive `&mut` access makes the manager update and graph swap one
/// observable publication point; a failed transaction drops the staged value
/// without disturbing the current generation.
pub struct ModuleExecutionGenerationSlotV1<T> {
    generations: ModuleExecutionGenerationsV1,
    current: T,
}

impl<T> ModuleExecutionGenerationSlotV1<T> {
    pub fn new(generations: ModuleExecutionGenerationsV1, initial: T) -> Self {
        Self {
            generations,
            current: initial,
        }
    }

    pub fn generations(&self) -> &ModuleExecutionGenerationsV1 {
        &self.generations
    }

    pub fn current(&self) -> &T {
        &self.current
    }

    pub fn commit<P: GraphImportPolicy>(
        &mut self,
        policy: &P,
        transaction: ModuleGenerationTransactionV1,
        staged: T,
    ) -> Result<(GenerationCommitV1, T)> {
        let commit = self.generations.commit(policy, transaction)?;
        let retired = std::mem::replace(&mut self.current, staged);
        Ok((commit, retired))
    }
}

#[derive(Debug, Clone)]
pub struct GenerationCommitV1 {
    pub origin: HmrOrigin,
    pub previous: ExecutionGeneration,
    pub generation: ExecutionGeneration,
    pub invalidated: BTreeSet<SourceId>,
    pub changed: BTreeSet<SourceId>,
    pub graph_digest: Digest,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_loader::artifact::{
        source_integrity, ArtifactAdmissionV1, CanonicalSourceId, ExportDescriptorV1,
        ModuleSemanticsV1, ProducerIdentityV1, SourceDialectV1, SourceGoalV1, SourceMapV1,
        TransformFingerprintV1, MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
    };
    use crate::module_loader::identity::SourceId;
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
                producer_id: NonEmptyString::new("generation-test").unwrap(),
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
}
