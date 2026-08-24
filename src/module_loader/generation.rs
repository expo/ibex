//! Atomic development graph generations and HMR publication isolation.
//!
//! A generation transition replaces one complete authenticated graph. It can
//! reuse immutable artifacts, but never live records, cells, namespaces,
//! promises, errors, or CommonJS exports from another generation.
//! @ref LLP 0026#8-development-hmr-and-invalidation

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Result};
use capsec_semantics::arming::SnapshotGenerations;
use capsec_semantics::model::{Digest, Principal};

use super::artifact::{
    digest_bytes, DynamicEdgeV1, ExportDescriptorV1, ModuleArtifactV1, SourceGoalV1, StaticEdgeV1,
    VerifiedModuleArtifactV1,
};
use super::graph::{GraphEdgeKey, SynchronousGraphPlan};
use super::identity::{ResolutionKind, SourceId};
use super::security::GraphImportPolicy;

pub const GENERATION_GRAPH_DIGEST_DOMAIN_V1: &str = "ibex/module-generation-graph/1";
pub const GENERATION_GRAPH_DIGEST_DOMAIN_V2: &str = "ibex/module-generation-graph/2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExecutionGeneration(u64);

impl ExecutionGeneration {
    pub const INITIAL: Self = Self(1);

    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            bail!("module execution generation must be nonzero");
        }
        Ok(Self(value))
    }

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

/// Monotonic transaction coordinate within one execution generation.
// @ref LLP 0055#1-the-hotrevision-counter-and-successor-law — revision zero is boot and
// every accepted transaction advances by exactly one without wrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HotRevision(u64);

impl HotRevision {
    pub const BOOT: Self = Self(0);

    pub fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| anyhow!("hot revision space is exhausted; full reload required"))
    }

    #[cfg(test)]
    fn at(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleIncarnationKey {
    pub source_id: SourceId,
    pub generation: ExecutionGeneration,
    pub install_revision: HotRevision,
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
    install_revision: HotRevision,
    semantic_digest: Digest,
}

/// Transaction-local publication authority. It is intentionally a distinct
/// type from [`GenerationPublicationToken`], so a shadow completion cannot be
/// supplied to the live [`ModuleExecutionGenerationsV2::publish`] path.
#[derive(Debug, Clone)]
pub struct ShadowPublicationToken {
    source_id: SourceId,
    install_revision: HotRevision,
    semantic_digest: Digest,
    transaction_nonce: u64,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSitePinV1 {
    pub digest: Digest,
    pub attributes_digest: Digest,
}

/// One authenticated V2 graph row. Construction authenticates every typed row
/// against the verified artifact before it can enter a graph or transaction.
// @ref LLP 0055#4-the-typed-authenticated-graph-obligation-4 — edge identity includes
// resolution kind and the digest covers candidate/deferred/bootstrap facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationRecordV2 {
    artifact: ModuleArtifactV1,
    bindings: BTreeMap<GraphEdgeKey, SourceId>,
    candidate_sites: BTreeMap<u64, CandidateSitePinV1>,
    deferred_dynamic: BTreeSet<GraphEdgeKey>,
    deferred_commonjs_require: BTreeSet<GraphEdgeKey>,
    bootstrap_internal_commonjs: BTreeSet<String>,
}

impl GenerationRecordV2 {
    pub fn from_verified(
        verified: VerifiedModuleArtifactV1<'_>,
        bindings: BTreeMap<GraphEdgeKey, SourceId>,
        candidate_sites: BTreeMap<u64, CandidateSitePinV1>,
        deferred_dynamic: BTreeSet<GraphEdgeKey>,
        deferred_commonjs_require: BTreeSet<GraphEdgeKey>,
        bootstrap_internal_commonjs: BTreeSet<String>,
    ) -> Result<Self> {
        let record = Self {
            artifact: verified.artifact().clone(),
            bindings,
            candidate_sites,
            deferred_dynamic,
            deferred_commonjs_require,
            bootstrap_internal_commonjs,
        };
        record.validate_typed_metadata_agreement()?;
        Ok(record)
    }

    pub fn artifact(&self) -> &ModuleArtifactV1 {
        &self.artifact
    }

    fn source_id(&self) -> &SourceId {
        &self.artifact.semantics.source_id.0
    }

    fn validate_typed_metadata_agreement(&self) -> Result<()> {
        const DISAGREEMENT: &str = "hot update typed metadata disagrees with the verified artifact";

        let mut declared_bindings = BTreeSet::new();
        let mut declared_dynamic = BTreeSet::new();
        let mut declared_commonjs_require = BTreeSet::new();
        for edge in &self.artifact.semantics.static_edges {
            let (specifier, resolution_kind) = match edge {
                StaticEdgeV1::CommonJsRequire { specifier } => {
                    (specifier.as_str(), ResolutionKind::CommonJsRequire)
                }
                StaticEdgeV1::SideEffect { specifier, .. }
                | StaticEdgeV1::Default { specifier, .. }
                | StaticEdgeV1::Namespace { specifier, .. }
                | StaticEdgeV1::Named { specifier, .. }
                | StaticEdgeV1::ReExportNamed { specifier, .. }
                | StaticEdgeV1::ReExportStar { specifier, .. }
                | StaticEdgeV1::ReExportNamespace { specifier, .. } => {
                    (specifier.as_str(), ResolutionKind::EsmStatic)
                }
            };
            let key = GraphEdgeKey::new(specifier, resolution_kind);
            if resolution_kind == ResolutionKind::CommonJsRequire {
                declared_commonjs_require.insert(key.clone());
            }
            declared_bindings.insert(key);
        }

        let mut declared_computed_sites = BTreeSet::new();
        for edge in &self.artifact.semantics.dynamic_edges {
            match edge {
                DynamicEdgeV1::Literal { specifier, .. } => {
                    let key = GraphEdgeKey::new(specifier.as_str(), ResolutionKind::DynamicImport);
                    declared_dynamic.insert(key.clone());
                    declared_bindings.insert(key);
                }
                DynamicEdgeV1::Computed { site } => {
                    declared_computed_sites.insert(u64::from(*site));
                }
            }
        }

        if self
            .bindings
            .keys()
            .any(|key| !declared_bindings.contains(key))
            || !self
                .candidate_sites
                .keys()
                .copied()
                .eq(declared_computed_sites.iter().copied())
            || !self.deferred_dynamic.is_subset(&declared_dynamic)
            || !self
                .deferred_commonjs_require
                .is_subset(&declared_commonjs_require)
        {
            bail!(DISAGREEMENT);
        }

        let declared_bootstrap_internal = if self.source_id().defining_principal().is_none() {
            declared_commonjs_require
                .iter()
                .filter(|key| super::is_bootstrap_internal_module_specifier(&key.specifier))
                .map(|key| key.specifier.clone())
                .collect()
        } else {
            BTreeSet::new()
        };
        if self.bootstrap_internal_commonjs != declared_bootstrap_internal {
            bail!(DISAGREEMENT);
        }
        Ok(())
    }

    fn typed_rows_equal(&self, other: &Self) -> bool {
        self.artifact.semantic_digest == other.artifact.semantic_digest
            && self.bindings == other.bindings
            && self.candidate_sites == other.candidate_sites
            && self.deferred_dynamic == other.deferred_dynamic
            && self.deferred_commonjs_require == other.deferred_commonjs_require
            && self.bootstrap_internal_commonjs == other.bootstrap_internal_commonjs
    }
}

/// One complete authenticated graph over typed edge rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedGenerationGraphV2 {
    records: BTreeMap<SourceId, GenerationRecordV2>,
    digest: Digest,
}

impl AuthenticatedGenerationGraphV2 {
    #[allow(clippy::type_complexity)]
    pub fn from_verified<'artifact>(
        records: impl IntoIterator<
            Item = (
                VerifiedModuleArtifactV1<'artifact>,
                BTreeMap<GraphEdgeKey, SourceId>,
                BTreeMap<u64, CandidateSitePinV1>,
                BTreeSet<GraphEdgeKey>,
                BTreeSet<GraphEdgeKey>,
                BTreeSet<String>,
            ),
        >,
    ) -> Result<Self> {
        let mut owned = Vec::new();
        for (
            artifact,
            bindings,
            candidate_sites,
            deferred_dynamic,
            deferred_commonjs_require,
            bootstrap_internal_commonjs,
        ) in records
        {
            owned.push(GenerationRecordV2::from_verified(
                artifact,
                bindings,
                candidate_sites,
                deferred_dynamic,
                deferred_commonjs_require,
                bootstrap_internal_commonjs,
            )?);
        }
        Self::from_records(owned)
    }

    fn from_records(records: impl IntoIterator<Item = GenerationRecordV2>) -> Result<Self> {
        let mut owned = BTreeMap::new();
        for record in records {
            // Clone-and-swap candidates must authenticate their stored typed
            // rows again rather than trusting a prior construction site.
            record.validate_typed_metadata_agreement()?;
            let source_id = record.source_id().clone();
            if owned.insert(source_id, record).is_some() {
                bail!("module generation graph contains a duplicate SourceId");
            }
        }
        if owned.is_empty() {
            bail!("module generation graph cannot be empty");
        }

        // SynchronousGraphPlan additionally requires artifact-derived edge
        // completeness and graph-global candidate/deferred inputs. V2 accepts
        // already authenticated typed rows, so its fitting validation is the
        // direct invariant needed here: every target names exactly one row.
        for record in owned.values() {
            for target in record.bindings.values() {
                if !owned.contains_key(target) {
                    bail!("typed module generation edge targets an absent SourceId");
                }
            }
        }

        let digest = graph_digest_v2(&owned)?;
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

    fn record(&self, source_id: &SourceId) -> Result<&GenerationRecordV2> {
        self.records
            .get(source_id)
            .ok_or_else(|| anyhow!("SourceId is absent from the generation graph"))
    }
}

fn edge_digest_row(key: &GraphEdgeKey, target: Option<&SourceId>) -> Result<serde_json::Value> {
    let mut row = serde_json::Map::new();
    row.insert(
        "specifier".to_owned(),
        serde_json::Value::String(key.specifier.clone()),
    );
    row.insert(
        "resolutionKind".to_owned(),
        serde_json::Value::String(key.resolution_kind.wire_name().to_owned()),
    );
    if let Some(target) = target {
        row.insert(
            "target".to_owned(),
            serde_json::Value::String(target.encode()?),
        );
    }
    Ok(serde_json::Value::Object(row))
}

fn graph_digest_v2(records: &BTreeMap<SourceId, GenerationRecordV2>) -> Result<Digest> {
    let mut rows = Vec::with_capacity(records.len());
    for (source_id, record) in records {
        rows.push(serde_json::json!({
            "sourceId": source_id.encode()?,
            "semanticDigest": record.artifact.semantic_digest,
            "bindings": record.bindings.iter().map(|(key, target)| {
                edge_digest_row(key, Some(target))
            }).collect::<Result<Vec<_>>>()?,
            "candidateSites": record.candidate_sites.iter().map(|(ordinal, pin)| {
                serde_json::json!({
                    "ordinal": ordinal,
                    "digest": pin.digest,
                    "attributesDigest": pin.attributes_digest,
                })
            }).collect::<Vec<_>>(),
            "deferredDynamic": record.deferred_dynamic.iter().map(|key| {
                edge_digest_row(key, None)
            }).collect::<Result<Vec<_>>>()?,
            "deferredCommonJsRequire": record.deferred_commonjs_require.iter().map(|key| {
                edge_digest_row(key, None)
            }).collect::<Result<Vec<_>>>()?,
            "bootstrapInternalCommonJs": record.bootstrap_internal_commonjs.iter().collect::<Vec<_>>(),
        }));
    }
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&serde_json::Value::Array(rows))
        .map_err(|error| anyhow!("cannot canonicalize typed module generation graph: {error}"))?;
    digest_bytes(GENERATION_GRAPH_DIGEST_DOMAIN_V2, &canonical)
}

/// Immutable authority and graph-shape ceiling inherited from the boot graph.
// @ref LLP 0055#4-the-typed-authenticated-graph-obligation-4 — no hot revision may
// widen or alter any pinned typed shape fact; all breaches require re-arming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableGenerationAdmissionV2 {
    authority_digest: Digest,
    authority_generations: SnapshotGenerations,
    members: BTreeSet<SourceId>,
    defining_principals: BTreeMap<SourceId, Principal>,
    pinned_integrities: BTreeMap<SourceId, Digest>,
    authorized_edges: BTreeSet<(SourceId, GraphEdgeKey, SourceId)>,
    candidate_sites: BTreeMap<(SourceId, u64), CandidateSitePinV1>,
    deferred_dynamic: BTreeMap<SourceId, BTreeSet<GraphEdgeKey>>,
    deferred_commonjs_require: BTreeMap<SourceId, BTreeSet<GraphEdgeKey>>,
    bootstrap_internal_commonjs: BTreeMap<SourceId, BTreeSet<String>>,
}

impl ImmutableGenerationAdmissionV2 {
    pub fn from_initial<P: GraphImportPolicy>(
        policy: &P,
        graph: &AuthenticatedGenerationGraphV2,
    ) -> Result<Self> {
        let mut members = BTreeSet::new();
        let mut defining_principals = BTreeMap::new();
        let mut pinned_integrities = BTreeMap::new();
        let mut authorized_edges = BTreeSet::new();
        let mut candidate_sites = BTreeMap::new();
        let mut deferred_dynamic = BTreeMap::new();
        let mut deferred_commonjs_require = BTreeMap::new();
        let mut bootstrap_internal_commonjs = BTreeMap::new();

        for (source_id, record) in &graph.records {
            members.insert(source_id.clone());
            match source_id.defining_principal() {
                Some(principal) => {
                    if !matches!(principal, Principal::Root { .. }) {
                        pinned_integrities.insert(
                            source_id.clone(),
                            record.artifact.semantics.source_integrity.clone(),
                        );
                    }
                    defining_principals.insert(source_id.clone(), principal.clone());
                }
                None => {
                    pinned_integrities.insert(
                        source_id.clone(),
                        record.artifact.semantics.source_integrity.clone(),
                    );
                }
            }
            for (key, target) in &record.bindings {
                authorized_edges.insert((source_id.clone(), key.clone(), target.clone()));
            }
            for (ordinal, pin) in &record.candidate_sites {
                candidate_sites.insert((source_id.clone(), *ordinal), pin.clone());
            }
            deferred_dynamic.insert(source_id.clone(), record.deferred_dynamic.clone());
            deferred_commonjs_require
                .insert(source_id.clone(), record.deferred_commonjs_require.clone());
            bootstrap_internal_commonjs.insert(
                source_id.clone(),
                record.bootstrap_internal_commonjs.clone(),
            );
        }

        Ok(Self {
            authority_digest: policy.snapshot_digest().clone(),
            authority_generations: policy.snapshot_generations(),
            members,
            defining_principals,
            pinned_integrities,
            authorized_edges,
            candidate_sites,
            deferred_dynamic,
            deferred_commonjs_require,
            bootstrap_internal_commonjs,
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

    fn validate_graph(&self, graph: &AuthenticatedGenerationGraphV2) -> Result<()> {
        if !graph.records.keys().eq(self.members.iter()) {
            bail!("HMR graph membership changed; regenerate policy and restart the runtime");
        }

        let mut candidate_edges = BTreeSet::new();
        let mut candidate_sites = BTreeMap::new();
        let mut deferred_dynamic = BTreeMap::new();
        let mut deferred_commonjs_require = BTreeMap::new();
        let mut bootstrap_internal_commonjs = BTreeMap::new();

        for (source_id, record) in &graph.records {
            if let Some(expected_principal) = self.defining_principals.get(source_id) {
                if source_id.defining_principal() != Some(expected_principal) {
                    bail!(
                        "HMR changed a module defining principal; regenerate policy and restart the runtime"
                    );
                }
            } else if source_id.defining_principal().is_some() {
                bail!(
                    "HMR changed a module defining principal; regenerate policy and restart the runtime"
                );
            }
            if let Some(integrity) = self.pinned_integrities.get(source_id) {
                if &record.artifact.semantics.source_integrity != integrity {
                    bail!("HMR changed integrity-pinned package/runtime source; restart required");
                }
            }
            for (key, target) in &record.bindings {
                candidate_edges.insert((source_id.clone(), key.clone(), target.clone()));
            }
            for (ordinal, pin) in &record.candidate_sites {
                candidate_sites.insert((source_id.clone(), *ordinal), pin.clone());
            }
            deferred_dynamic.insert(source_id.clone(), record.deferred_dynamic.clone());
            deferred_commonjs_require
                .insert(source_id.clone(), record.deferred_commonjs_require.clone());
            bootstrap_internal_commonjs.insert(
                source_id.clone(),
                record.bootstrap_internal_commonjs.clone(),
            );
        }

        if candidate_edges != self.authorized_edges {
            bail!("HMR graph edge widened; regenerate policy and restart the runtime");
        }
        if candidate_sites != self.candidate_sites {
            bail!("HMR candidate site changed; regenerate policy and restart the runtime");
        }
        if deferred_dynamic != self.deferred_dynamic
            || deferred_commonjs_require != self.deferred_commonjs_require
        {
            bail!("HMR deferred membership changed; regenerate policy and restart the runtime");
        }
        if bootstrap_internal_commonjs != self.bootstrap_internal_commonjs {
            bail!(
                "HMR bootstrap-internal CommonJS set changed; regenerate policy and restart the runtime"
            );
        }
        Ok(())
    }
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
            install_revision: HotRevision::BOOT,
        })
    }

    pub fn publication_token(&self, source_id: &SourceId) -> Result<GenerationPublicationToken> {
        let record = self.current.graph.record(source_id)?;
        Ok(GenerationPublicationToken {
            generation: self.current.generation,
            source_id: source_id.clone(),
            install_revision: HotRevision::BOOT,
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
                install_revision: HotRevision::BOOT,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublishedHotRevisionV1 {
    generation: ExecutionGeneration,
    revision: HotRevision,
    graph: AuthenticatedGenerationGraphV2,
    install_revisions: BTreeMap<SourceId, HotRevision>,
}

/// Development graph owner for intra-generation replacement transactions.
#[derive(Debug, PartialEq, Eq)]
pub struct ModuleExecutionGenerationsV2 {
    mode: GenerationMode,
    admission: ImmutableGenerationAdmissionV2,
    current: PublishedHotRevisionV1,
    next_transaction_nonce: Cell<u64>,
}

impl ModuleExecutionGenerationsV2 {
    pub fn new<P: GraphImportPolicy>(
        mode: GenerationMode,
        generation: ExecutionGeneration,
        policy: &P,
        initial: AuthenticatedGenerationGraphV2,
    ) -> Result<Self> {
        let admission = ImmutableGenerationAdmissionV2::from_initial(policy, &initial)?;
        admission.validate_authority(policy)?;
        admission.validate_graph(&initial)?;
        let install_revisions = initial
            .source_ids()
            .cloned()
            .map(|source_id| (source_id, HotRevision::BOOT))
            .collect();
        Ok(Self {
            mode,
            admission,
            current: PublishedHotRevisionV1 {
                generation,
                revision: HotRevision::BOOT,
                graph: initial,
                install_revisions,
            },
            next_transaction_nonce: Cell::new(1),
        })
    }

    pub fn current_generation(&self) -> ExecutionGeneration {
        self.current.generation
    }

    pub fn current_revision(&self) -> HotRevision {
        self.current.revision
    }

    pub fn graph_digest(&self) -> &Digest {
        self.current.graph.digest()
    }

    pub fn install_revision(&self, source_id: &SourceId) -> Result<HotRevision> {
        self.current
            .install_revisions
            .get(source_id)
            .copied()
            .ok_or_else(|| anyhow!("SourceId is absent from the generation graph"))
    }

    pub fn incarnation(&self, source_id: &SourceId) -> Result<ModuleIncarnationKey> {
        self.current.graph.record(source_id)?;
        Ok(ModuleIncarnationKey {
            source_id: source_id.clone(),
            generation: self.current.generation,
            install_revision: self.install_revision(source_id)?,
        })
    }

    pub fn publication_token(&self, source_id: &SourceId) -> Result<GenerationPublicationToken> {
        let record = self.current.graph.record(source_id)?;
        Ok(GenerationPublicationToken {
            generation: self.current.generation,
            source_id: source_id.clone(),
            install_revision: self.install_revision(source_id)?,
            semantic_digest: record.artifact.semantic_digest.clone(),
        })
    }

    // @ref LLP 0055#22-per-slot-incarnation-predicate-exact-0417-h1-entry-obligation-1 —
    // unchanged slots retain their install revision while replaced slots fence old completions.
    pub fn publish(
        &self,
        token: &GenerationPublicationToken,
        kind: GenerationPublicationKind,
    ) -> Result<GenerationPublicationReceipt> {
        if token.generation != self.current.generation {
            bail!("stale module-generation completion cannot publish");
        }
        if token.install_revision != self.install_revision(&token.source_id)? {
            bail!("stale module-revision completion cannot publish");
        }
        let record = self.current.graph.record(&token.source_id)?;
        if record.artifact.semantic_digest != token.semantic_digest {
            bail!("module-generation completion semantic digest is stale");
        }
        Ok(GenerationPublicationReceipt {
            incarnation: ModuleIncarnationKey {
                source_id: token.source_id.clone(),
                generation: token.generation,
                install_revision: token.install_revision,
            },
            kind,
            semantic_digest: token.semantic_digest.clone(),
        })
    }

    pub fn begin_revision<P: GraphImportPolicy>(
        &self,
        policy: &P,
        origin: HmrOrigin,
        base: (ExecutionGeneration, HotRevision),
        invalidated: impl IntoIterator<Item = SourceId>,
    ) -> Result<HotRevisionTransactionV1> {
        if self.mode == GenerationMode::Production {
            bail!("production module graphs have exactly one execution generation and revision");
        }
        self.admission.validate_authority(policy)?;
        // @ref LLP 0055#5.2 — check 3 requires the supplied base to equal the live
        // committed coordinates.
        if base.0 != self.current.generation || base.1 != self.current.revision {
            bail!(
                "hot update base is stale; committed coordinates are generation {} revision {}",
                self.current.generation.get(),
                self.current.revision.get()
            );
        }
        base.1.next()?;
        let invalidated: BTreeSet<_> = invalidated.into_iter().collect();
        if invalidated.is_empty() {
            bail!("HMR update must invalidate at least one module");
        }
        if invalidated
            .iter()
            .any(|source_id| !self.current.graph.records.contains_key(source_id))
        {
            bail!("HMR invalidation widened the authenticated source graph; full reload required");
        }
        if invalidated
            .iter()
            .any(|source_id| source_id.defining_principal().is_none())
        {
            bail!(
                "builtin/synthetic sources cannot hot-reload; regenerate policy and restart the runtime"
            );
        }
        let transaction_nonce = self.next_transaction_nonce.get();
        let next_transaction_nonce = transaction_nonce
            .checked_add(1)
            .ok_or_else(|| anyhow!("hot revision transaction nonce space is exhausted"))?;
        self.next_transaction_nonce.set(next_transaction_nonce);
        Ok(HotRevisionTransactionV1 {
            origin,
            base_generation: base.0,
            base_revision: base.1,
            authority_digest: self.admission.authority_digest.clone(),
            authority_generations: self.admission.authority_generations,
            transaction_nonce,
            invalidated,
            replacements: None,
            shadow_publications: Vec::new(),
        })
    }

    pub fn commit_revision<P: GraphImportPolicy>(
        &mut self,
        policy: &P,
        transaction: HotRevisionTransactionV1,
    ) -> Result<HotRevisionCommitV1> {
        if policy.snapshot_digest() != &self.admission.authority_digest
            || policy.snapshot_generations() != self.admission.authority_generations
        {
            bail!(
                "hot revision commit-time authority compare failed after begin; invariant violation"
            );
        }
        if transaction.authority_digest != self.admission.authority_digest
            || transaction.authority_generations != self.admission.authority_generations
        {
            bail!(
                "hot revision commit-time authority stamp compare failed after begin; invariant violation"
            );
        }
        // @ref LLP 0055#1-the-hotrevision-counter-and-successor-law — the only
        // publication successor is exactly the transaction's live base plus one.
        if transaction.base_generation != self.current.generation
            || transaction.base_revision != self.current.revision
        {
            bail!("hot revision commit-time base compare failed after begin; invariant violation");
        }
        let revision = transaction.base_revision.next()?;
        let replacements = transaction
            .replacements
            .ok_or_else(|| anyhow!("hot revision transaction has no staged replacements"))?;

        let mut candidate_records = self.current.graph.records.clone();
        for (source_id, record) in &replacements {
            candidate_records.insert(source_id.clone(), record.clone());
        }
        let candidate_graph =
            AuthenticatedGenerationGraphV2::from_records(candidate_records.into_values())?;

        let changed = changed_sources_v2(&self.current.graph, &candidate_graph);
        if changed
            .iter()
            .any(|source_id| !transaction.invalidated.contains(source_id))
        {
            bail!("HMR candidate changed a module outside its invalidation set");
        }
        if replacements
            .keys()
            .any(|source_id| !transaction.invalidated.contains(source_id))
        {
            bail!("hot revision transaction contains a replacement outside its invalidation set");
        }
        if transaction
            .invalidated
            .iter()
            .any(|source_id| !replacements.contains_key(source_id))
        {
            bail!("hot revision transaction is missing an invalidated replacement");
        }
        if changed.is_empty() {
            bail!("hot revision changed nothing; nothing to apply");
        }

        // @ref LLP 0055#23-stable-logical-slots-every-cross-module-use-resolves-through-the-slot
        // — stable namespace shape is a structural eligibility condition.
        for source_id in &transaction.invalidated {
            let current = self.current.graph.record(source_id)?;
            let replacement = replacements.get(source_id).ok_or_else(|| {
                anyhow!("hot revision transaction is missing an invalidated replacement")
            })?;
            if export_shape(&current.artifact)? != export_shape(&replacement.artifact)? {
                bail!("hot revision changed the module export shape; full reload required");
            }
        }

        // @ref LLP 0055#23-stable-logical-slots-every-cross-module-use-resolves-through-the-slot
        // — v1 cannot safely retain a CommonJS object across an invalidation boundary.
        for source_id in &transaction.invalidated {
            let current_is_commonjs = self
                .current
                .graph
                .record(source_id)?
                .artifact
                .semantics
                .source_goal
                == SourceGoalV1::CommonJs;
            let replacement_is_commonjs = replacements.get(source_id).is_some_and(|record| {
                record.artifact.semantics.source_goal == SourceGoalV1::CommonJs
            });
            let crosses_boundary = candidate_graph.records.iter().any(|(requester, record)| {
                !transaction.invalidated.contains(requester)
                    && record.bindings.iter().any(|(key, target)| {
                        target == source_id
                            && (key.resolution_kind == ResolutionKind::CommonJsRequire
                                || current_is_commonjs
                                || replacement_is_commonjs)
                    })
            });
            if crosses_boundary {
                bail!(
                    "hot revision boundary is consumed across the closure through CommonJS; full reload required"
                );
            }
        }

        // @ref LLP 0055#5.2
        // — specific preflight refusals precede the ceiling backstop.
        self.admission.validate_graph(&candidate_graph)?;

        let mut install_revisions = self.current.install_revisions.clone();
        for source_id in &transaction.invalidated {
            install_revisions.insert(source_id.clone(), revision);
        }
        let commit = HotRevisionCommitV1 {
            origin: transaction.origin,
            generation: self.current.generation,
            previous_revision: self.current.revision,
            revision,
            invalidated: transaction.invalidated,
            changed,
            graph_digest: candidate_graph.digest.clone(),
            shadow_publications: transaction.shadow_publications,
        };

        // @ref LLP 0055#53-the-commit-bundle-atomic-owner-thread-no-fail — every
        // check and allocation precedes this sole live-state assignment.
        self.current = PublishedHotRevisionV1 {
            generation: commit.generation,
            revision,
            graph: candidate_graph,
            install_revisions,
        };
        Ok(commit)
    }
}

fn changed_sources_v2(
    current: &AuthenticatedGenerationGraphV2,
    candidate: &AuthenticatedGenerationGraphV2,
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
                (Some(left), Some(right)) => !left.typed_rows_equal(right),
                _ => true,
            }
        })
        .cloned()
        .collect()
}

fn export_descriptor_set(descriptors: &[ExportDescriptorV1]) -> Result<BTreeSet<Vec<u8>>> {
    descriptors
        .iter()
        .map(|descriptor| {
            let value = serde_json::to_value(descriptor)?;
            capsec_semantics::canonical::to_jcs_bytes(&value)
                .map_err(|error| anyhow!("cannot canonicalize module export descriptor: {error}"))
        })
        .collect()
}

fn export_shape(artifact: &ModuleArtifactV1) -> Result<(SourceGoalV1, BTreeSet<Vec<u8>>, Vec<u8>)> {
    let commonjs_exports = capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(
        &artifact.semantics.commonjs_exports,
    )?)
    .map_err(|error| anyhow!("cannot canonicalize CommonJS export shape: {error}"))?;
    Ok((
        artifact.semantics.source_goal,
        export_descriptor_set(&artifact.semantics.export_descriptors)?,
        commonjs_exports,
    ))
}

#[derive(Debug)]
pub struct HotRevisionTransactionV1 {
    origin: HmrOrigin,
    base_generation: ExecutionGeneration,
    base_revision: HotRevision,
    authority_digest: Digest,
    authority_generations: SnapshotGenerations,
    transaction_nonce: u64,
    invalidated: BTreeSet<SourceId>,
    replacements: Option<BTreeMap<SourceId, GenerationRecordV2>>,
    shadow_publications: Vec<GenerationPublicationReceipt>,
}

impl HotRevisionTransactionV1 {
    pub fn candidate_revision(&self) -> Result<HotRevision> {
        self.base_revision.next()
    }

    pub fn stage_replacements(
        &mut self,
        records: impl IntoIterator<Item = GenerationRecordV2>,
    ) -> Result<()> {
        if self.replacements.is_some() {
            bail!("hot revision transaction already has staged replacements");
        }
        let mut replacements = BTreeMap::new();
        for record in records {
            record.validate_typed_metadata_agreement()?;
            let source_id = record.source_id().clone();
            if replacements.insert(source_id, record).is_some() {
                bail!("hot revision transaction repeats a replacement SourceId");
            }
        }
        self.replacements = Some(replacements);
        Ok(())
    }

    // @ref LLP 0055#22-per-slot-incarnation-predicate-exact-0417-h1-entry-obligation-1 —
    // staged completions are transaction-local and use the candidate install revision.
    pub fn shadow_publication_token(&self, source_id: &SourceId) -> Result<ShadowPublicationToken> {
        if !self.invalidated.contains(source_id) {
            bail!("shadow publication source is outside the invalidation set");
        }
        let record = self
            .replacements
            .as_ref()
            .and_then(|records| records.get(source_id))
            .ok_or_else(|| anyhow!("shadow publication source has no staged replacement"))?;
        Ok(ShadowPublicationToken {
            source_id: source_id.clone(),
            install_revision: self.candidate_revision()?,
            semantic_digest: record.artifact.semantic_digest.clone(),
            transaction_nonce: self.transaction_nonce,
        })
    }

    pub fn shadow_publish(
        &mut self,
        token: &ShadowPublicationToken,
        kind: GenerationPublicationKind,
    ) -> Result<GenerationPublicationReceipt> {
        if token.transaction_nonce != self.transaction_nonce {
            bail!("shadow publication token belongs to another hot revision transaction");
        }
        if token.install_revision != self.candidate_revision()? {
            bail!("stale shadow module-revision completion cannot publish");
        }
        if !self.invalidated.contains(&token.source_id) {
            bail!("shadow publication source is outside the invalidation set");
        }
        let record = self
            .replacements
            .as_ref()
            .and_then(|records| records.get(&token.source_id))
            .ok_or_else(|| anyhow!("shadow publication source has no staged replacement"))?;
        if record.artifact.semantic_digest != token.semantic_digest {
            bail!("shadow module-revision completion semantic digest is stale");
        }
        let receipt = GenerationPublicationReceipt {
            incarnation: ModuleIncarnationKey {
                source_id: token.source_id.clone(),
                generation: self.base_generation,
                install_revision: token.install_revision,
            },
            kind,
            semantic_digest: token.semantic_digest.clone(),
        };
        self.shadow_publications.push(receipt.clone());
        Ok(receipt)
    }

    #[cfg(test)]
    fn shadow_publication_count(&self) -> usize {
        self.shadow_publications.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotRevisionCommitV1 {
    pub origin: HmrOrigin,
    pub generation: ExecutionGeneration,
    pub previous_revision: HotRevision,
    pub revision: HotRevision,
    pub invalidated: BTreeSet<SourceId>,
    pub changed: BTreeSet<SourceId>,
    pub graph_digest: Digest,
    pub shadow_publications: Vec<GenerationPublicationReceipt>,
}

/// Couples revision metadata publication to an arbitrary native owner value.
pub struct HotRevisionSlotV1<T> {
    generations: ModuleExecutionGenerationsV2,
    current: T,
}

impl<T> HotRevisionSlotV1<T> {
    pub fn new(generations: ModuleExecutionGenerationsV2, initial: T) -> Self {
        Self {
            generations,
            current: initial,
        }
    }

    pub fn generations(&self) -> &ModuleExecutionGenerationsV2 {
        &self.generations
    }

    pub fn current(&self) -> &T {
        &self.current
    }

    pub fn commit_revision<P: GraphImportPolicy>(
        &mut self,
        policy: &P,
        transaction: HotRevisionTransactionV1,
        staged: T,
    ) -> Result<(HotRevisionCommitV1, T)> {
        let commit = self.generations.commit_revision(policy, transaction)?;
        let retired = std::mem::replace(&mut self.current, staged);
        Ok((commit, retired))
    }
}

#[cfg(test)]
mod tests;
