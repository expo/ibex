//! Authenticated synchronous ESM graph planning.
//!
//! This layer resolves namespace exports and checks graph shape before any
//! factory executes. Hermes owns live cells; Rust owns these authenticated
//! SourceId edges and the ambiguity decision.
//! @ref LLP 0026#4-native-graph-owner-and-hermes-runner
//! @ref LLP 0026#5-esm-record-lifecycle

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use super::artifact::{
    ExportDescriptorV1, ModulePayloadV1, SourceGoalV1, StaticEdgeV1, VerifiedModuleArtifactV1,
};
use super::identity::{ResolutionKind, SourceId};
use super::security::{
    AuthorizedGraphOperation, GraphAuthorityContext, GraphDecisionSet, GraphImportPolicy,
    GraphOperationKind, ModuleGraphAuthorizer,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExportTarget {
    pub record: SourceId,
    /// `*` denotes the stable namespace object; other values denote cells.
    pub binding: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImportBindingPlan {
    pub specifier: String,
    pub imported: String,
    pub target: ExportTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicImportBindingPlan {
    /// `None` identifies an authored literal site; computed candidates retain
    /// their producer-owned site ordinal so equal spellings at different sites
    /// never collapse into one authority decision.
    pub site: Option<u32>,
    pub specifier: String,
    pub target: SourceId,
    pub attributes: super::identity::ImportAttributes,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DynamicImportBindingKey {
    pub site: Option<u32>,
    pub specifier: String,
}

impl DynamicImportBindingPlan {
    fn key(&self) -> DynamicImportBindingKey {
        DynamicImportBindingKey {
            site: self.site,
            specifier: self.specifier.clone(),
        }
    }
}

pub struct DynamicAuthorizationPlan {
    pub receipts: Vec<AuthorizedGraphOperation>,
    pub allowed_bindings: BTreeMap<SourceId, BTreeSet<DynamicImportBindingKey>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputedCandidateBinding {
    pub target: SourceId,
    pub attributes: super::identity::ImportAttributes,
}

pub type ComputedCandidateSiteMap =
    BTreeMap<SourceId, BTreeMap<(u32, String), ComputedCandidateBinding>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphErrorCode {
    ModuleLink,
    RequireAsyncModule,
}

impl GraphErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModuleLink => "ERR_MODULE_LINK",
            Self::RequireAsyncModule => "ERR_REQUIRE_ASYNC_MODULE",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("{code}: {detail}", code = .code.as_str())]
pub struct GraphError {
    pub code: GraphErrorCode,
    pub detail: String,
}

impl GraphError {
    fn link(detail: impl Into<String>) -> Self {
        Self {
            code: GraphErrorCode::ModuleLink,
            detail: detail.into(),
        }
    }

    fn asynchronous(source_id: &SourceId) -> Self {
        Self {
            code: GraphErrorCode::RequireAsyncModule,
            detail: format!("synchronous graph contains top-level await in {source_id:?}"),
        }
    }
}

struct PlannedRecord<'artifact> {
    artifact: VerifiedModuleArtifactV1<'artifact>,
    edges: BTreeMap<GraphEdgeKey, SourceId>,
}

/// Exact authenticated lookup key for one authored dependency edge. The same
/// spelling may resolve differently under ESM, dynamic-import, and CommonJS
/// package conditions, so specifier text alone is not a graph identity.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GraphEdgeKey {
    pub specifier: String,
    pub resolution_kind: ResolutionKind,
}

impl GraphEdgeKey {
    pub fn new(specifier: impl Into<String>, resolution_kind: ResolutionKind) -> Self {
        Self {
            specifier: specifier.into(),
            resolution_kind,
        }
    }
}

/// Immutable link plan for one synchronous graph generation.
pub struct SynchronousGraphPlan<'artifact> {
    records: BTreeMap<SourceId, PlannedRecord<'artifact>>,
    computed_candidate_sites: ComputedCandidateSiteMap,
    deferred_dynamic_sources: BTreeSet<SourceId>,
    deferred_commonjs_require_sources: BTreeSet<SourceId>,
    bootstrap_internal_commonjs_requires: BTreeMap<SourceId, BTreeSet<String>>,
}

/// Data-only ordered composition roots with an explicitly named main root.
// @ref LLP 0056#72-the-authorized-composition-linker-module_runnerrs — import.meta.main belongs to the named app root, never a positional guess.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionRootPlan {
    roots: Vec<SourceId>,
    main_root: SourceId,
}

impl CompositionRootPlan {
    /// Construct a non-empty, duplicate-free root plan containing `main_root`.
    pub fn new(roots: Vec<SourceId>, main_root: &SourceId) -> anyhow::Result<Self> {
        if roots.is_empty() {
            anyhow::bail!("composition root plan must contain at least one root");
        }
        let mut seen = BTreeSet::new();
        for root in &roots {
            if !seen.insert(root) {
                anyhow::bail!("composition root plan contains a duplicate root");
            }
        }
        if !seen.contains(main_root) {
            anyhow::bail!("composition main root is absent from the ordered roots");
        }
        Ok(Self {
            roots,
            main_root: main_root.clone(),
        })
    }

    /// Return the declaration-ordered composition roots.
    pub fn roots(&self) -> &[SourceId] {
        &self.roots
    }

    /// Return the explicitly named main (application) root.
    pub fn main_root(&self) -> &SourceId {
        &self.main_root
    }
}

/// One strongly connected component in dependency-first order. Records inside
/// a component preserve the graph's deterministic DFS evaluation order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsyncEvaluationScc {
    pub records: Vec<SourceId>,
    pub dependencies: Vec<usize>,
    pub contains_top_level_await: bool,
    pub async_tainted: bool,
}

/// Immutable scheduling metadata for one asynchronous entry closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsyncEvaluationPlan {
    pub evaluation_order: Vec<SourceId>,
    pub sccs: Vec<AsyncEvaluationScc>,
    record_scc: BTreeMap<SourceId, usize>,
}

impl AsyncEvaluationPlan {
    pub fn scc_for(&self, source_id: &SourceId) -> Option<usize> {
        self.record_scc.get(source_id).copied()
    }

    pub fn is_async_tainted(&self, source_id: &SourceId) -> Option<bool> {
        self.scc_for(source_id)
            .map(|index| self.sccs[index].async_tainted)
    }
}

impl<'artifact> SynchronousGraphPlan<'artifact> {
    /// Build a plan from admitted artifacts and authenticated resolution edges.
    /// The edge map must exactly match the artifact's static and literal
    /// dynamic specifier set. A computed import may add a finite candidate
    /// map; disagreement fails before factory compilation or evaluation.
    pub fn new(
        records: impl IntoIterator<
            Item = (
                VerifiedModuleArtifactV1<'artifact>,
                BTreeMap<String, SourceId>,
            ),
        >,
    ) -> Result<Self, GraphError> {
        let records = records
            .into_iter()
            .map(|(artifact, edges)| {
                let mut typed = BTreeMap::new();
                for (specifier, target) in edges {
                    let mut matched = false;
                    for key in artifact_edge_keys(artifact) {
                        if key.specifier == specifier {
                            typed.insert(key, target.clone());
                            matched = true;
                        }
                    }
                    if !matched {
                        typed.insert(
                            GraphEdgeKey::new(specifier, ResolutionKind::DynamicImport),
                            target,
                        );
                    }
                }
                (artifact, typed)
            })
            .collect::<Vec<_>>();
        Self::new_typed(records)
    }

    pub fn new_typed(
        records: impl IntoIterator<
            Item = (
                VerifiedModuleArtifactV1<'artifact>,
                BTreeMap<GraphEdgeKey, SourceId>,
            ),
        >,
    ) -> Result<Self, GraphError> {
        Self::new_typed_with_computed_candidates(records, BTreeMap::new())
    }

    pub fn new_typed_with_computed_candidates(
        records: impl IntoIterator<
            Item = (
                VerifiedModuleArtifactV1<'artifact>,
                BTreeMap<GraphEdgeKey, SourceId>,
            ),
        >,
        computed_candidate_sites: ComputedCandidateSiteMap,
    ) -> Result<Self, GraphError> {
        let records = records.into_iter().collect::<Vec<_>>();
        let mut bootstrap_internal_commonjs_requires = BTreeMap::new();
        for (artifact, _) in &records {
            let semantics = &artifact.artifact().semantics;
            if semantics.source_goal != SourceGoalV1::Builtin {
                continue;
            }
            let specifiers = semantics
                .static_edges
                .iter()
                .filter_map(|edge| match edge {
                    StaticEdgeV1::CommonJsRequire { specifier }
                        if super::is_bootstrap_internal_module_specifier(specifier.as_str()) =>
                    {
                        Some(specifier.as_str().to_owned())
                    }
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            if !specifiers.is_empty() {
                bootstrap_internal_commonjs_requires
                    .insert(semantics.source_id.0.clone(), specifiers);
            }
        }
        // Release envelopes authenticate the builtin artifact semantics and
        // runtime identity, so the sealed bootstrap-only edge set is derived
        // here instead of being serialized as an application graph binding.
        // @ref LLP 0004#one-source-many-specifiers
        Self::new_typed_with_private_commonjs_edges(
            records,
            computed_candidate_sites,
            BTreeSet::new(),
            BTreeSet::new(),
            bootstrap_internal_commonjs_requires,
        )
    }

    /// Build the static closure while retaining authenticated dynamic-site
    /// semantics without requiring a target record. The caller supplies the
    /// exact requester identities whose dynamic edges are deferred; every
    /// static edge remains mandatory and complete.
    // @ref LLP 0026#6-top-level-await-and-dynamic-import
    pub fn new_typed_with_call_time_deferred(
        records: impl IntoIterator<
            Item = (
                VerifiedModuleArtifactV1<'artifact>,
                BTreeMap<GraphEdgeKey, SourceId>,
            ),
        >,
        computed_candidate_sites: ComputedCandidateSiteMap,
        deferred_dynamic_sources: BTreeSet<SourceId>,
    ) -> Result<Self, GraphError> {
        Self::new_typed_with_call_time_deferred_edges(
            records,
            computed_candidate_sites,
            deferred_dynamic_sources,
            BTreeSet::new(),
        )
    }

    /// Build a static closure while retaining both asynchronous `import()`
    /// declarations and synchronous authored CommonJS `require()` spellings
    /// as exact call-time edges. Generated builtin `require()` fan-out is
    /// never deferred through this path.
    // @ref LLP 0026#7-commonjs-interop
    pub fn new_typed_with_call_time_deferred_edges(
        records: impl IntoIterator<
            Item = (
                VerifiedModuleArtifactV1<'artifact>,
                BTreeMap<GraphEdgeKey, SourceId>,
            ),
        >,
        computed_candidate_sites: ComputedCandidateSiteMap,
        deferred_dynamic_sources: BTreeSet<SourceId>,
        deferred_commonjs_require_sources: BTreeSet<SourceId>,
    ) -> Result<Self, GraphError> {
        Self::new_typed_with_private_commonjs_edges(
            records,
            computed_candidate_sites,
            deferred_dynamic_sources,
            deferred_commonjs_require_sources,
            BTreeMap::new(),
        )
    }

    /// Build a graph that additionally retains exact generated-builtin
    /// `require()` spellings resolved by the sealed bootstrap closure. These
    /// private object edges have no ModuleRecord target and are never available
    /// to authored CommonJS activation.
    // @ref LLP 0004#one-source-many-specifiers
    pub fn new_typed_with_private_commonjs_edges(
        records: impl IntoIterator<
            Item = (
                VerifiedModuleArtifactV1<'artifact>,
                BTreeMap<GraphEdgeKey, SourceId>,
            ),
        >,
        computed_candidate_sites: ComputedCandidateSiteMap,
        deferred_dynamic_sources: BTreeSet<SourceId>,
        deferred_commonjs_require_sources: BTreeSet<SourceId>,
        bootstrap_internal_commonjs_requires: BTreeMap<SourceId, BTreeSet<String>>,
    ) -> Result<Self, GraphError> {
        let mut planned = BTreeMap::new();
        for (artifact, edges) in records {
            let semantics = &artifact.artifact().semantics;
            let source_id = semantics.source_id.0.clone();
            let mut expected: BTreeSet<_> = artifact_edge_keys(artifact).collect();
            if deferred_dynamic_sources.contains(&source_id) {
                expected.retain(|key| key.resolution_kind != ResolutionKind::DynamicImport);
            }
            if deferred_commonjs_require_sources.contains(&source_id) {
                if semantics.source_goal == SourceGoalV1::Builtin {
                    return Err(GraphError::link(format!(
                        "generated builtin require edges cannot be deferred for {source_id:?}"
                    )));
                }
                expected.retain(|key| key.resolution_kind != ResolutionKind::CommonJsRequire);
            }
            if let Some(specifiers) = bootstrap_internal_commonjs_requires.get(&source_id) {
                if semantics.source_goal != SourceGoalV1::Builtin || specifiers.is_empty() {
                    return Err(GraphError::link(format!(
                        "bootstrap-internal require declarations belong to a non-builtin or empty record {source_id:?}"
                    )));
                }
                for specifier in specifiers {
                    let key = GraphEdgeKey::new(specifier, ResolutionKind::CommonJsRequire);
                    if !expected.remove(&key) {
                        return Err(GraphError::link(format!(
                            "bootstrap-internal require {specifier:?} is not declared by {source_id:?}"
                        )));
                    }
                }
            }
            let observed: BTreeSet<_> = edges.keys().cloned().collect();
            let has_computed_dynamic_import = semantics
                .dynamic_edges
                .iter()
                .any(|edge| matches!(edge, super::artifact::DynamicEdgeV1::Computed { .. }))
                && !deferred_dynamic_sources.contains(&source_id);
            let agrees = if has_computed_dynamic_import {
                expected.is_subset(&observed)
                    && observed
                        .difference(&expected)
                        .all(|key| key.resolution_kind == ResolutionKind::DynamicImport)
            } else {
                expected == observed
            };
            if !agrees {
                return Err(GraphError::link(format!(
                    "artifact/resolver graph disagreement for {source_id:?}: expected {expected:?}, observed {observed:?}"
                )));
            }
            if planned
                .insert(source_id.clone(), PlannedRecord { artifact, edges })
                .is_some()
            {
                return Err(GraphError::link(format!(
                    "duplicate ModuleRecord identity {source_id:?}"
                )));
            }
        }
        for (source_id, record) in &planned {
            for target in record.edges.values() {
                if !planned.contains_key(target) {
                    return Err(GraphError::link(format!(
                        "{source_id:?} resolves a static edge to absent record {target:?}"
                    )));
                }
            }
        }
        for (requester, rows) in &computed_candidate_sites {
            if deferred_dynamic_sources.contains(requester) {
                return Err(GraphError::link(format!(
                    "deferred dynamic requester has an eagerly resolved candidate table: {requester:?}"
                )));
            }
            let record = planned.get(requester).ok_or_else(|| {
                GraphError::link(format!(
                    "computed-candidate requester is absent from graph: {requester:?}"
                ))
            })?;
            let admitted_sites = record
                .artifact
                .artifact()
                .semantics
                .dynamic_edges
                .iter()
                .filter_map(|edge| match edge {
                    super::artifact::DynamicEdgeV1::Computed { site } => Some(*site),
                    super::artifact::DynamicEdgeV1::Literal { .. } => None,
                })
                .collect::<BTreeSet<_>>();
            for ((site, specifier), binding) in rows {
                if !admitted_sites.contains(site) || !planned.contains_key(&binding.target) {
                    return Err(GraphError::link(format!(
                        "computed-candidate site {site} spelling {specifier:?} disagrees with the authenticated artifact graph"
                    )));
                }
            }
        }
        Ok(Self {
            records: planned,
            computed_candidate_sites,
            deferred_dynamic_sources,
            deferred_commonjs_require_sources,
            bootstrap_internal_commonjs_requires,
        })
    }

    pub fn computed_candidate_sites(&self) -> &ComputedCandidateSiteMap {
        &self.computed_candidate_sites
    }

    pub fn defers_dynamic_edges(&self, source_id: &SourceId) -> bool {
        self.deferred_dynamic_sources.contains(source_id)
    }

    pub fn defers_commonjs_require_edges(&self, source_id: &SourceId) -> bool {
        self.deferred_commonjs_require_sources.contains(source_id)
    }

    pub fn bootstrap_internal_commonjs_requires(&self, source_id: &SourceId) -> BTreeSet<String> {
        self.bootstrap_internal_commonjs_requires
            .get(source_id)
            .cloned()
            .unwrap_or_default()
    }

    fn is_bootstrap_internal_commonjs_require(
        &self,
        source_id: &SourceId,
        specifier: &str,
    ) -> bool {
        self.bootstrap_internal_commonjs_requires
            .get(source_id)
            .is_some_and(|specifiers| specifiers.contains(specifier))
    }

    pub fn artifact(
        &self,
        source_id: &SourceId,
    ) -> Result<VerifiedModuleArtifactV1<'artifact>, GraphError> {
        Ok(self.record(source_id)?.artifact)
    }

    pub fn contains_record(&self, source_id: &SourceId) -> bool {
        self.records.contains_key(source_id)
    }

    /// Refuse production-native plans that would need an authored call-time
    /// edge before the runtime has a private in-drive loader capability.
    ///
    /// The source-graph ingress applies the same boundary before resolving a
    /// deferred target. Keep this independent check at the authenticated
    /// linker boundary so a prepared graph or another internal caller cannot
    /// reintroduce eager authorization through the prelinked lookup tables.
    /// Exact manifest-owned builtin fan-out is a private synchronous
    /// initialization dependency; native code separately proves that its
    /// `require` closure cannot be used after that initialization returns.
    // @ref LLP 0024#3-source-goal
    // @ref LLP 0021#module-initialization-and-trusted-source-acquisition
    pub fn ensure_native_call_time_edges_supported(&self) -> Result<(), GraphError> {
        for (source_id, record) in &self.records {
            let semantics = &record.artifact.artifact().semantics;
            if !semantics.dynamic_edges.is_empty() {
                return Err(GraphError::link(format!(
                    "native call-time dynamic-import activation is unavailable for {source_id:?}"
                )));
            }
            for edge in &semantics.static_edges {
                let StaticEdgeV1::CommonJsRequire { specifier } = edge else {
                    continue;
                };
                if self.defers_commonjs_require_edges(source_id) {
                    continue;
                }
                if self.is_bootstrap_internal_commonjs_require(source_id, specifier.as_str()) {
                    continue;
                }
                if semantics.source_goal != SourceGoalV1::Builtin {
                    return Err(GraphError::link(format!(
                        "native call-time CommonJS require activation is unavailable for {source_id:?}"
                    )));
                }
                let target =
                    self.edge_target(record, specifier.as_str(), ResolutionKind::CommonJsRequire)?;
                if self.artifact(target)?.artifact().semantics.source_goal != SourceGoalV1::Builtin
                {
                    return Err(GraphError::link(format!(
                        "manifest builtin private dependency {specifier:?} from {source_id:?} is not a builtin record"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Dependency-first execution order for the entry's eager ESM closure.
    /// CommonJS require targets are linked but excluded from this traversal
    /// because `require()` reaches and evaluates them only when invoked. A CJS
    /// record reached by an ESM edge is scheduled before its importer.
    /// A visiting record is reused, so cycles append each record exactly once.
    /// @ref LLP 0026#7-commonjs-interop
    pub fn evaluation_order(&self, entry: &SourceId) -> Result<Vec<SourceId>, GraphError> {
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut order = Vec::new();
        self.visit_for_evaluation(entry, &mut visiting, &mut visited, &mut order)?;
        Ok(order)
    }

    /// Deterministic record-materialization order including authenticated
    /// literal and computed-candidate dynamic targets. These records are
    /// linked but remain unevaluated until a static or dynamic entry reaches
    /// them.
    pub fn linkage_order(&self, entry: &SourceId) -> Result<Vec<SourceId>, GraphError> {
        let allowed: BTreeMap<_, _> = self
            .records
            .keys()
            .map(|source_id| {
                Ok((
                    source_id.clone(),
                    self.dynamic_import_bindings(source_id)?
                        .into_iter()
                        .map(|binding| binding.key())
                        .collect(),
                ))
            })
            .collect::<Result<_, GraphError>>()?;
        self.linkage_order_for_authorized(entry, &allowed)
    }

    /// Deterministic dependency-first materialization order for an ordered
    /// root list. A record belongs to the first root closure that reaches it.
    // @ref LLP 0056#71-synchronousgraphplan-graphrs — entry-plan order and cross-root dedup place shared records in the agent segment.
    pub fn linkage_order_for_roots(&self, roots: &[SourceId]) -> Result<Vec<SourceId>, GraphError> {
        let allowed: BTreeMap<_, _> = self
            .records
            .keys()
            .map(|source_id| {
                Ok((
                    source_id.clone(),
                    self.dynamic_import_bindings(source_id)?
                        .into_iter()
                        .map(|binding| binding.key())
                        .collect(),
                ))
            })
            .collect::<Result<_, GraphError>>()?;
        self.linkage_order_for_authorized_roots(roots, &allowed)
    }

    pub(crate) fn linkage_order_for_authorized_roots(
        &self,
        roots: &[SourceId],
        allowed_dynamic_bindings: &BTreeMap<SourceId, BTreeSet<DynamicImportBindingKey>>,
    ) -> Result<Vec<SourceId>, GraphError> {
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut order = Vec::new();
        for root in roots {
            self.visit_for_linkage(
                root,
                allowed_dynamic_bindings,
                &mut visiting,
                &mut visited,
                &mut order,
            )?;
        }
        Ok(order)
    }

    pub fn linkage_order_for_authorized(
        &self,
        entry: &SourceId,
        allowed_dynamic_bindings: &BTreeMap<SourceId, BTreeSet<DynamicImportBindingKey>>,
    ) -> Result<Vec<SourceId>, GraphError> {
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut order = Vec::new();
        self.visit_for_linkage(
            entry,
            allowed_dynamic_bindings,
            &mut visiting,
            &mut visited,
            &mut order,
        )?;
        Ok(order)
    }

    /// Dependency-first order for a synchronous caller. Async taint is checked
    /// over only the entry's reachable closure and before native records are
    /// created, so an unrelated TLA record neither poisons the request nor
    /// begins executing as a side effect of refusal.
    pub fn synchronous_evaluation_order(
        &self,
        entry: &SourceId,
    ) -> Result<Vec<SourceId>, GraphError> {
        let order = self.evaluation_order(entry)?;
        if let Some(source_id) = order.iter().find(|source_id| {
            self.records
                .get(*source_id)
                .expect("evaluation order contains only planned records")
                .artifact
                .artifact()
                .semantics
                .has_top_level_await
        }) {
            return Err(GraphError::asynchronous(source_id));
        }
        Ok(order)
    }

    /// Dependency-first synchronous evaluation segments for ordered roots.
    /// Cross-root dedup is retained between segments, so each record appears
    /// exactly once under the first root that reaches it.
    // @ref LLP 0056#71-synchronousgraphplan-graphrs — the segment boundary is the descriptor executor's invoke point.
    pub fn synchronous_evaluation_order_for_roots(
        &self,
        roots: &[SourceId],
    ) -> Result<Vec<Vec<SourceId>>, GraphError> {
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut segments = Vec::with_capacity(roots.len());
        for root in roots {
            let mut segment = Vec::new();
            self.visit_for_evaluation(root, &mut visiting, &mut visited, &mut segment)?;
            if let Some(source_id) = segment.iter().find(|source_id| {
                self.records
                    .get(*source_id)
                    .expect("evaluation order contains only planned records")
                    .artifact
                    .artifact()
                    .semantics
                    .has_top_level_await
            }) {
                return Err(GraphError::asynchronous(source_id));
            }
            segments.push(segment);
        }
        Ok(segments)
    }

    pub fn has_top_level_await(&self, source_id: &SourceId) -> Result<bool, GraphError> {
        Ok(self
            .record(source_id)?
            .artifact
            .artifact()
            .semantics
            .has_top_level_await)
    }

    pub fn source_goal(&self, source_id: &SourceId) -> Result<SourceGoalV1, GraphError> {
        Ok(self
            .record(source_id)?
            .artifact
            .artifact()
            .semantics
            .source_goal)
    }

    pub fn commonjs_require_bindings(
        &self,
        source_id: &SourceId,
    ) -> Result<Vec<(String, SourceId)>, GraphError> {
        let record = self.record(source_id)?;
        let mut bindings = Vec::new();
        for edge in &record.artifact.artifact().semantics.static_edges {
            if let StaticEdgeV1::CommonJsRequire { specifier } = edge {
                if self.defers_commonjs_require_edges(source_id) {
                    continue;
                }
                if self.is_bootstrap_internal_commonjs_require(source_id, specifier.as_str()) {
                    continue;
                }
                bindings.push((
                    specifier.as_str().to_owned(),
                    self.edge_target(record, specifier.as_str(), ResolutionKind::CommonJsRequire)?
                        .clone(),
                ));
            }
        }
        Ok(bindings)
    }

    /// Authenticated dynamic-import targets. Literal sites contribute their
    /// exact spelling; computed sites may contribute only the resolver's
    /// finite candidate map and never acquire a guessed target at call time.
    pub fn dynamic_import_bindings(
        &self,
        source_id: &SourceId,
    ) -> Result<Vec<DynamicImportBindingPlan>, GraphError> {
        let record = self.record(source_id)?;
        let mut declared = BTreeMap::new();
        for edge in &record.artifact.artifact().semantics.dynamic_edges {
            match edge {
                super::artifact::DynamicEdgeV1::Literal {
                    specifier,
                    attributes,
                } => match declared.insert(specifier.as_str().to_owned(), attributes.clone()) {
                    Some(previous) if previous != *attributes => {
                        return Err(GraphError::link(format!(
                            "literal dynamic-import spelling {:?} carries conflicting attributes",
                            specifier.as_str()
                        )));
                    }
                    _ => {}
                },
                super::artifact::DynamicEdgeV1::Computed { .. } => {}
            }
        }
        let mut bindings = Vec::new();
        for (specifier, attributes) in declared {
            bindings.push(DynamicImportBindingPlan {
                site: None,
                target: self
                    .edge_target(record, &specifier, ResolutionKind::DynamicImport)?
                    .clone(),
                specifier,
                attributes,
            });
        }
        if let Some(rows) = self.computed_candidate_sites.get(source_id) {
            for ((site, specifier), candidate) in rows {
                bindings.push(DynamicImportBindingPlan {
                    site: Some(*site),
                    specifier: specifier.clone(),
                    target: candidate.target.clone(),
                    attributes: candidate.attributes.clone(),
                });
            }
        }
        bindings.sort_by_key(DynamicImportBindingPlan::key);
        Ok(bindings)
    }

    pub fn dynamic_import_targets(
        &self,
        source_id: &SourceId,
    ) -> Result<Vec<(String, SourceId)>, GraphError> {
        self.dynamic_import_bindings(source_id).map(|bindings| {
            bindings
                .into_iter()
                .map(|binding| (binding.specifier, binding.target))
                .collect()
        })
    }

    /// Complete statically materialized closure. Unlike `evaluation_order`,
    /// this includes literal CommonJS require targets so their records and
    /// authority receipts exist before a reached `require()` evaluates them.
    fn static_linkage_order(&self, entry: &SourceId) -> Result<Vec<SourceId>, GraphError> {
        self.linkage_order_for_authorized(entry, &BTreeMap::new())
    }

    pub fn literal_static_target(
        &self,
        source_id: &SourceId,
        specifier: &str,
    ) -> Result<&SourceId, GraphError> {
        self.edge_target(
            self.record(source_id)?,
            specifier,
            ResolutionKind::EsmStatic,
        )
    }

    pub fn commonjs_require_target(
        &self,
        source_id: &SourceId,
        specifier: &str,
    ) -> Result<&SourceId, GraphError> {
        self.edge_target(
            self.record(source_id)?,
            specifier,
            ResolutionKind::CommonJsRequire,
        )
    }

    /// Collapse the entry closure into dependency-first SCCs and propagate
    /// async taint from every TLA component to its importers. This plan is
    /// pure and generation-independent; the native graph uses it to choose
    /// which record promise must settle before a parent may start.
    // @ref LLP 0026#6-top-level-await-and-dynamic-import
    pub fn asynchronous_evaluation_plan(
        &self,
        entry: &SourceId,
    ) -> Result<AsyncEvaluationPlan, GraphError> {
        let evaluation_order = self.evaluation_order(entry)?;
        struct Tarjan<'plan, 'artifact> {
            plan: &'plan SynchronousGraphPlan<'artifact>,
            next_index: usize,
            indices: BTreeMap<SourceId, usize>,
            lowlinks: BTreeMap<SourceId, usize>,
            stack: Vec<SourceId>,
            on_stack: BTreeSet<SourceId>,
            components: Vec<Vec<SourceId>>,
        }

        impl<'plan, 'artifact> Tarjan<'plan, 'artifact> {
            fn visit(&mut self, source_id: &SourceId) -> Result<(), GraphError> {
                let index = self.next_index;
                self.next_index += 1;
                self.indices.insert(source_id.clone(), index);
                self.lowlinks.insert(source_id.clone(), index);
                self.stack.push(source_id.clone());
                self.on_stack.insert(source_id.clone());

                let record = self.plan.record(source_id)?;
                let mut dependencies = BTreeSet::new();
                for edge in &record.artifact.artifact().semantics.static_edges {
                    if matches!(edge, StaticEdgeV1::CommonJsRequire { .. }) {
                        continue;
                    }
                    let target = self.plan.static_edge_target(record, edge)?;
                    dependencies.insert(target.clone());
                }
                for dependency in dependencies {
                    if !self.indices.contains_key(&dependency) {
                        self.visit(&dependency)?;
                        let child_low = self.lowlinks[&dependency];
                        let own_low = self.lowlinks[source_id];
                        self.lowlinks
                            .insert(source_id.clone(), own_low.min(child_low));
                    } else if self.on_stack.contains(&dependency) {
                        let dependency_index = self.indices[&dependency];
                        let own_low = self.lowlinks[source_id];
                        self.lowlinks
                            .insert(source_id.clone(), own_low.min(dependency_index));
                    }
                }

                if self.lowlinks[source_id] == self.indices[source_id] {
                    let mut component = Vec::new();
                    loop {
                        let member = self
                            .stack
                            .pop()
                            .expect("Tarjan root retains its stack member");
                        self.on_stack.remove(&member);
                        let complete = member == *source_id;
                        component.push(member);
                        if complete {
                            break;
                        }
                    }
                    self.components.push(component);
                }
                Ok(())
            }
        }

        let mut tarjan = Tarjan {
            plan: self,
            next_index: 0,
            indices: BTreeMap::new(),
            lowlinks: BTreeMap::new(),
            stack: Vec::new(),
            on_stack: BTreeSet::new(),
            components: Vec::new(),
        };
        tarjan.visit(entry)?;

        let rank: BTreeMap<_, _> = evaluation_order
            .iter()
            .enumerate()
            .map(|(index, source_id)| (source_id.clone(), index))
            .collect();
        for component in &mut tarjan.components {
            component.sort_by_key(|source_id| rank[source_id]);
        }

        // Tarjan emits components dependency-first for this record -> import
        // edge direction. Retain that order and calculate taint in one pass.
        let mut record_scc = BTreeMap::new();
        for (index, component) in tarjan.components.iter().enumerate() {
            for source_id in component {
                record_scc.insert(source_id.clone(), index);
            }
        }
        let mut sccs: Vec<AsyncEvaluationScc> = Vec::new();
        for (index, component) in tarjan.components.into_iter().enumerate() {
            let mut dependencies = BTreeSet::new();
            let mut contains_top_level_await = false;
            for source_id in &component {
                let record = self.record(source_id)?;
                contains_top_level_await |=
                    record.artifact.artifact().semantics.has_top_level_await;
                for edge in &record.artifact.artifact().semantics.static_edges {
                    if matches!(edge, StaticEdgeV1::CommonJsRequire { .. }) {
                        continue;
                    }
                    let target = self.static_edge_target(record, edge)?;
                    let dependency = record_scc[target];
                    if dependency != index {
                        dependencies.insert(dependency);
                    }
                }
            }
            let dependencies: Vec<_> = dependencies.into_iter().collect();
            if dependencies.iter().any(|dependency| *dependency >= index) {
                return Err(GraphError::link(
                    "internal SCC schedule is not dependency-first",
                ));
            }
            let async_tainted = contains_top_level_await
                || dependencies
                    .iter()
                    .any(|dependency| sccs[*dependency].async_tainted);
            sccs.push(AsyncEvaluationScc {
                records: component,
                dependencies,
                contains_top_level_await,
                async_tainted,
            });
        }

        Ok(AsyncEvaluationPlan {
            evaluation_order,
            sccs,
            record_scc,
        })
    }

    /// Authorize every reachable static edge before the native runtime may
    /// compile or instantiate any factory. The returned receipts are retained
    /// by the graph and remain bound to this snapshot and graph generation.
    // @ref LLP 0021#module-initialization-and-trusted-source-acquisition
    pub fn authorize_reachable_operations<P: GraphImportPolicy>(
        &self,
        entry: &SourceId,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
    ) -> anyhow::Result<Vec<AuthorizedGraphOperation>> {
        let mut receipts = Vec::new();
        for source_id in self.static_linkage_order(entry)? {
            let context = contexts.get(&source_id).ok_or_else(|| {
                anyhow::anyhow!("reachable ModuleRecord {source_id:?} has no CapSec context")
            })?;
            if context.requesting_record != source_id {
                anyhow::bail!("CapSec context requester disagrees with {source_id:?}");
            }
            let record = self.record(&source_id)?;
            let artifact = record.artifact.artifact();
            for edge in &artifact.semantics.static_edges {
                // Generated builtin fan-out is closed runtime-manifest linkage,
                // not a package-authored import edge. Its exact spelling and
                // builtin target are validated at this authenticated graph
                // boundary, while the target record's own compile/instantiate/
                // execute decisions and terminal effects remain fully gated.
                // @ref LLP 0021#module-initialization-and-trusted-source-acquisition
                if artifact.semantics.source_goal == SourceGoalV1::Builtin {
                    if let StaticEdgeV1::CommonJsRequire { specifier } = edge {
                        // Bootstrap-internal specifiers are served by the shared
                        // runtime's bootstrap module cache, never by a graph
                        // record, so activation deliberately creates no binding
                        // for them. There is no acquisition to authorize here;
                        // demanding a target would fail linkage for every
                        // builtin closure that reaches `fs` (i.e. almost all of
                        // them). The sibling validators at
                        // `validate_call_time_activation_support` and
                        // `commonjs_require_bindings` already skip the same set.
                        if self
                            .is_bootstrap_internal_commonjs_require(&source_id, specifier.as_str())
                        {
                            continue;
                        }
                        let target = self.edge_target(
                            record,
                            specifier.as_str(),
                            ResolutionKind::CommonJsRequire,
                        )?;
                        if self.artifact(target)?.artifact().semantics.source_goal
                            != SourceGoalV1::Builtin
                        {
                            anyhow::bail!(
                                "manifest builtin private dependency {specifier:?} from {source_id:?} is not a builtin record"
                            );
                        }
                        continue;
                    }
                }
                if self.defers_commonjs_require_edges(&source_id)
                    && matches!(edge, StaticEdgeV1::CommonJsRequire { .. })
                {
                    continue;
                }
                let (specifier, attributes, kind, resolution_kind) = match edge {
                    StaticEdgeV1::CommonJsRequire { specifier } => (
                        specifier,
                        super::identity::ImportAttributes::default(),
                        GraphOperationKind::LiteralRequire,
                        ResolutionKind::CommonJsRequire,
                    ),
                    StaticEdgeV1::SideEffect {
                        specifier,
                        attributes,
                    }
                    | StaticEdgeV1::Default {
                        specifier,
                        attributes,
                        ..
                    }
                    | StaticEdgeV1::Namespace {
                        specifier,
                        attributes,
                        ..
                    }
                    | StaticEdgeV1::Named {
                        specifier,
                        attributes,
                        ..
                    } => (
                        specifier,
                        attributes.clone(),
                        if attributes.asserts_json() {
                            GraphOperationKind::JsonLoad
                        } else {
                            GraphOperationKind::StaticImport
                        },
                        ResolutionKind::EsmStatic,
                    ),
                    StaticEdgeV1::ReExportNamed {
                        specifier,
                        attributes,
                        ..
                    }
                    | StaticEdgeV1::ReExportStar {
                        specifier,
                        attributes,
                    }
                    | StaticEdgeV1::ReExportNamespace {
                        specifier,
                        attributes,
                        ..
                    } => (
                        specifier,
                        attributes.clone(),
                        GraphOperationKind::ReExport,
                        ResolutionKind::EsmStatic,
                    ),
                };
                let target = self
                    .edge_target(record, specifier.as_str(), resolution_kind)?
                    .clone();
                let decision = GraphDecisionSet::new(
                    kind,
                    context.clone(),
                    target,
                    specifier.as_str(),
                    resolution_kind,
                    super::identity::ConditionSet::for_kind(resolution_kind),
                    attributes,
                    None,
                    None,
                )?;
                receipts.push(authorizer.authorize(decision)?);
            }
            // Factory compilation, instantiation, and execution are separate
            // record-owned decisions. They use the initialization task
            // boundary rather than inheriting an importer context.
            let initialization = GraphAuthorityContext::initialization_as(
                source_id.clone(),
                context.effect_owner.clone(),
                context.graph_generation,
            )?;
            let carrier_digest = match &artifact.payload {
                ModulePayloadV1::Inline { .. } => None,
                ModulePayloadV1::Carrier { carrier_digest, .. } => Some(carrier_digest.clone()),
            };
            for kind in [
                GraphOperationKind::CompileFactory,
                GraphOperationKind::InstantiateFactory,
                GraphOperationKind::ExecuteFactory,
            ] {
                let decision = GraphDecisionSet::new(
                    kind,
                    initialization.clone(),
                    source_id.clone(),
                    source_id.encode()?,
                    super::identity::ResolutionKind::Entry,
                    super::identity::ConditionSet::for_kind(super::identity::ResolutionKind::Entry),
                    super::identity::ImportAttributes::default(),
                    Some(artifact.semantics.source_integrity.clone()),
                    carrier_digest.clone(),
                )?;
                receipts.push(authorizer.authorize(decision)?);
            }
        }
        Ok(receipts)
    }

    /// Decide every finite dynamic-import candidate without failing entry
    /// linking merely because a dead branch would be denied. Only candidates
    /// carrying receipts enter the native exact-spelling table.
    pub fn authorize_dynamic_candidates<P: GraphImportPolicy>(
        &self,
        entry: &SourceId,
        authorizer: &ModuleGraphAuthorizer<'_, P>,
        contexts: &BTreeMap<SourceId, GraphAuthorityContext>,
    ) -> anyhow::Result<DynamicAuthorizationPlan> {
        let mut receipts = Vec::new();
        let mut allowed_bindings: BTreeMap<SourceId, BTreeSet<DynamicImportBindingKey>> =
            BTreeMap::new();
        let mut allowed_targets = BTreeSet::new();
        let mut owners = self.static_linkage_order(entry)?;
        let mut seen_owners: BTreeSet<_> = owners.iter().cloned().collect();
        let mut owner_index = 0;
        while owner_index < owners.len() {
            let source_id = owners[owner_index].clone();
            owner_index += 1;
            let bindings = self.dynamic_import_bindings(&source_id)?;
            if bindings.is_empty() {
                continue;
            }
            let context = contexts.get(&source_id).ok_or_else(|| {
                anyhow::anyhow!("dynamic candidate owner {source_id:?} has no CapSec context")
            })?;
            for binding in bindings {
                let binding_key = binding.key();
                let kind = if binding.attributes.asserts_json() {
                    GraphOperationKind::JsonLoad
                } else {
                    GraphOperationKind::DynamicImport
                };
                let decision = GraphDecisionSet::new(
                    kind,
                    context.clone(),
                    binding.target,
                    &binding.specifier,
                    super::identity::ResolutionKind::DynamicImport,
                    super::identity::ConditionSet::for_kind(
                        super::identity::ResolutionKind::DynamicImport,
                    ),
                    binding.attributes,
                    None,
                    None,
                )?;
                if let Some(receipt) = authorizer.authorize_if_allowed(decision)? {
                    allowed_targets.insert(receipt.decision().resource.target.clone());
                    allowed_bindings
                        .entry(source_id.clone())
                        .or_default()
                        .insert(binding_key);
                    for member in self.static_linkage_order(&receipt.decision().resource.target)? {
                        if seen_owners.insert(member.clone()) {
                            owners.push(member);
                        }
                    }
                    receipts.push(receipt);
                }
            }
        }
        for target in allowed_targets {
            receipts.extend(self.authorize_reachable_operations(&target, authorizer, contexts)?);
        }
        Ok(DynamicAuthorizationPlan {
            receipts,
            allowed_bindings,
        })
    }

    /// Resolve every factory import read to an authenticated ultimate cell or
    /// namespace. Re-export-only and side-effect edges do not create reads.
    pub fn import_bindings(
        &self,
        source_id: &SourceId,
    ) -> Result<Vec<ImportBindingPlan>, GraphError> {
        let record = self.record(source_id)?;
        let mut bindings = BTreeMap::new();
        for edge in &record.artifact.artifact().semantics.static_edges {
            let (specifier, imported) = match edge {
                StaticEdgeV1::Default { specifier, .. } => (specifier.as_str(), "default"),
                StaticEdgeV1::Namespace { specifier, .. } => (specifier.as_str(), "*"),
                StaticEdgeV1::Named {
                    specifier,
                    imported,
                    ..
                } => (specifier.as_str(), imported.as_str()),
                StaticEdgeV1::SideEffect { .. }
                | StaticEdgeV1::CommonJsRequire { .. }
                | StaticEdgeV1::ReExportNamed { .. }
                | StaticEdgeV1::ReExportStar { .. }
                | StaticEdgeV1::ReExportNamespace { .. } => continue,
            };
            let target_record = self.edge_target(record, specifier, ResolutionKind::EsmStatic)?;
            let target = if imported == "*" {
                ExportTarget {
                    record: target_record.clone(),
                    binding: "*".into(),
                }
            } else {
                match self.resolve_export(target_record, imported, &mut BTreeSet::new())? {
                    Resolution::Found(target) => target,
                    Resolution::Missing | Resolution::Ambiguous => {
                        return Err(GraphError::link(format!(
                            "import {imported:?} from {specifier:?} of {source_id:?} does not resolve uniquely"
                        )));
                    }
                }
            };
            let key = (specifier.to_owned(), imported.to_owned());
            match bindings.get(&key) {
                Some(existing) if existing != &target => {
                    return Err(GraphError::link(format!(
                        "duplicate import binding {key:?} of {source_id:?} disagrees"
                    )));
                }
                Some(_) => {}
                None => {
                    bindings.insert(key, target);
                }
            }
        }
        Ok(bindings
            .into_iter()
            .map(|((specifier, imported), target)| ImportBindingPlan {
                specifier,
                imported,
                target,
            })
            .collect())
    }

    pub fn namespace(
        &self,
        source_id: &SourceId,
    ) -> Result<BTreeMap<String, ExportTarget>, GraphError> {
        if !self.records.contains_key(source_id) {
            return Err(GraphError::link(format!(
                "namespace requested for absent record {source_id:?}"
            )));
        }
        let mut names = BTreeSet::new();
        self.collect_export_names(source_id, &mut BTreeSet::new(), &mut names)?;
        let mut namespace = BTreeMap::new();
        for name in names {
            let resolution = self.resolve_export(source_id, &name, &mut BTreeSet::new())?;
            match resolution {
                Resolution::Found(target) => {
                    namespace.insert(name, target);
                }
                Resolution::Missing | Resolution::Ambiguous
                    if self.has_explicit_export(source_id, &name)? =>
                {
                    return Err(GraphError::link(format!(
                        "explicit export {name:?} of {source_id:?} does not resolve uniquely"
                    )));
                }
                Resolution::Missing | Resolution::Ambiguous => {}
            }
        }
        Ok(namespace)
    }

    fn commonjs_export_names(
        &self,
        source_id: &SourceId,
        visiting: &mut BTreeSet<SourceId>,
    ) -> Result<BTreeSet<String>, GraphError> {
        if !visiting.insert(source_id.clone()) {
            return Ok(BTreeSet::new());
        }
        let record = self.record(source_id)?;
        let semantics = &record.artifact.artifact().semantics;
        let Some(commonjs) = &semantics.commonjs_exports else {
            visiting.remove(source_id);
            return Ok(BTreeSet::new());
        };
        let mut names = commonjs
            .names
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        for specifier in &commonjs.reexports {
            let target =
                self.edge_target(record, specifier.as_str(), ResolutionKind::CommonJsRequire)?;
            names.extend(self.commonjs_export_names(target, visiting)?);
        }
        visiting.remove(source_id);
        Ok(names)
    }

    fn has_explicit_export(&self, source_id: &SourceId, name: &str) -> Result<bool, GraphError> {
        Ok(self
            .record(source_id)?
            .artifact
            .artifact()
            .semantics
            .export_descriptors
            .iter()
            .any(|descriptor| match descriptor {
                ExportDescriptorV1::Local { exported, .. }
                | ExportDescriptorV1::Indirect { exported, .. }
                | ExportDescriptorV1::Namespace { exported, .. } => exported.as_str() == name,
                ExportDescriptorV1::Star { .. } => false,
            }))
    }

    fn collect_export_names(
        &self,
        source_id: &SourceId,
        visiting: &mut BTreeSet<SourceId>,
        names: &mut BTreeSet<String>,
    ) -> Result<(), GraphError> {
        if !visiting.insert(source_id.clone()) {
            return Ok(());
        }
        let record = self.record(source_id)?;
        if record.artifact.artifact().semantics.source_goal == SourceGoalV1::Json {
            names.insert("default".to_owned());
            visiting.remove(source_id);
            return Ok(());
        }
        if matches!(
            record.artifact.artifact().semantics.source_goal,
            SourceGoalV1::CommonJs | SourceGoalV1::Builtin
        ) {
            names.insert("default".to_owned());
            names.insert("module.exports".to_owned());
            names.extend(self.commonjs_export_names(source_id, &mut BTreeSet::new())?);
            visiting.remove(source_id);
            return Ok(());
        }
        for descriptor in &record.artifact.artifact().semantics.export_descriptors {
            match descriptor {
                ExportDescriptorV1::Local { exported, .. }
                | ExportDescriptorV1::Indirect { exported, .. }
                | ExportDescriptorV1::Namespace { exported, .. } => {
                    names.insert(exported.as_str().to_owned());
                }
                ExportDescriptorV1::Star { specifier } => {
                    let target =
                        self.edge_target(record, specifier.as_str(), ResolutionKind::EsmStatic)?;
                    let mut inherited = BTreeSet::new();
                    self.collect_export_names(target, visiting, &mut inherited)?;
                    inherited.remove("default");
                    names.extend(inherited);
                }
            }
        }
        visiting.remove(source_id);
        Ok(())
    }

    fn resolve_export(
        &self,
        source_id: &SourceId,
        name: &str,
        visiting: &mut BTreeSet<(SourceId, String)>,
    ) -> Result<Resolution, GraphError> {
        let key = (source_id.clone(), name.to_owned());
        if !visiting.insert(key.clone()) {
            return Ok(Resolution::Missing);
        }
        let record = self.record(source_id)?;
        if record.artifact.artifact().semantics.source_goal == SourceGoalV1::Json {
            visiting.remove(&key);
            return Ok(if name == "default" {
                Resolution::Found(ExportTarget {
                    record: source_id.clone(),
                    binding: name.to_owned(),
                })
            } else {
                Resolution::Missing
            });
        }
        if matches!(
            record.artifact.artifact().semantics.source_goal,
            SourceGoalV1::CommonJs | SourceGoalV1::Builtin
        ) {
            let is_export = name == "default"
                || name == "module.exports"
                || self
                    .commonjs_export_names(source_id, &mut BTreeSet::new())?
                    .contains(name);
            visiting.remove(&key);
            return Ok(if is_export {
                Resolution::Found(ExportTarget {
                    record: source_id.clone(),
                    binding: name.to_owned(),
                })
            } else {
                Resolution::Missing
            });
        }

        for descriptor in &record.artifact.artifact().semantics.export_descriptors {
            match descriptor {
                ExportDescriptorV1::Local { exported, .. } if exported.as_str() == name => {
                    visiting.remove(&key);
                    return Ok(Resolution::Found(ExportTarget {
                        record: source_id.clone(),
                        binding: name.to_owned(),
                    }));
                }
                ExportDescriptorV1::Indirect {
                    exported,
                    specifier,
                    imported,
                } if exported.as_str() == name => {
                    let target =
                        self.edge_target(record, specifier.as_str(), ResolutionKind::EsmStatic)?;
                    let result = self.resolve_export(target, imported.as_str(), visiting)?;
                    visiting.remove(&key);
                    return Ok(result);
                }
                ExportDescriptorV1::Namespace {
                    exported,
                    specifier,
                } if exported.as_str() == name => {
                    let target =
                        self.edge_target(record, specifier.as_str(), ResolutionKind::EsmStatic)?;
                    visiting.remove(&key);
                    return Ok(Resolution::Found(ExportTarget {
                        record: target.clone(),
                        binding: "*".into(),
                    }));
                }
                _ => {}
            }
        }

        if name == "default" {
            visiting.remove(&key);
            return Ok(Resolution::Missing);
        }
        let mut found: Option<ExportTarget> = None;
        for descriptor in &record.artifact.artifact().semantics.export_descriptors {
            let ExportDescriptorV1::Star { specifier } = descriptor else {
                continue;
            };
            let target = self.edge_target(record, specifier.as_str(), ResolutionKind::EsmStatic)?;
            match self.resolve_export(target, name, visiting)? {
                Resolution::Found(candidate) => match &found {
                    None => found = Some(candidate),
                    Some(existing) if existing == &candidate => {}
                    Some(_) => {
                        visiting.remove(&key);
                        return Ok(Resolution::Ambiguous);
                    }
                },
                Resolution::Ambiguous => {
                    visiting.remove(&key);
                    return Ok(Resolution::Ambiguous);
                }
                Resolution::Missing => {}
            }
        }
        visiting.remove(&key);
        Ok(found.map_or(Resolution::Missing, Resolution::Found))
    }

    fn record(&self, source_id: &SourceId) -> Result<&PlannedRecord<'artifact>, GraphError> {
        self.records.get(source_id).ok_or_else(|| {
            GraphError::link(format!("graph references absent record {source_id:?}"))
        })
    }

    fn visit_for_evaluation(
        &self,
        source_id: &SourceId,
        visiting: &mut BTreeSet<SourceId>,
        visited: &mut BTreeSet<SourceId>,
        order: &mut Vec<SourceId>,
    ) -> Result<(), GraphError> {
        if visited.contains(source_id) || !visiting.insert(source_id.clone()) {
            return Ok(());
        }
        let record = self.record(source_id)?;
        let mut seen_targets = BTreeSet::new();
        for edge in &record.artifact.artifact().semantics.static_edges {
            if matches!(edge, StaticEdgeV1::CommonJsRequire { .. }) {
                continue;
            }
            let target = self.static_edge_target(record, edge)?;
            if seen_targets.insert(target.clone()) {
                self.visit_for_evaluation(target, visiting, visited, order)?;
            }
        }
        visiting.remove(source_id);
        if visited.insert(source_id.clone()) {
            order.push(source_id.clone());
        }
        Ok(())
    }

    fn visit_for_linkage(
        &self,
        source_id: &SourceId,
        allowed_dynamic_bindings: &BTreeMap<SourceId, BTreeSet<DynamicImportBindingKey>>,
        visiting: &mut BTreeSet<SourceId>,
        visited: &mut BTreeSet<SourceId>,
        order: &mut Vec<SourceId>,
    ) -> Result<(), GraphError> {
        if visited.contains(source_id) || !visiting.insert(source_id.clone()) {
            return Ok(());
        }
        let record = self.record(source_id)?;
        let mut targets = BTreeSet::new();
        for edge in &record.artifact.artifact().semantics.static_edges {
            if matches!(
                edge,
                StaticEdgeV1::CommonJsRequire { specifier }
                    if self.is_bootstrap_internal_commonjs_require(
                        source_id,
                        specifier.as_str()
                    )
            ) {
                continue;
            }
            if self.defers_commonjs_require_edges(source_id)
                && matches!(edge, StaticEdgeV1::CommonJsRequire { .. })
            {
                continue;
            }
            targets.insert(
                self.static_edge_target(record, edge)
                    .map_err(|error| {
                        GraphError::link(format!("{error} (requested by {source_id:?})"))
                    })?
                    .clone(),
            );
        }
        // A deferred source intentionally has no authenticated dynamic target
        // until its exact site is reached. Enumerating its artifact edges here
        // would turn static linkage back into eager discovery and fail merely
        // because the target binding is absent. Invocation-time activation
        // publishes that target closure through its separate request path.
        // @ref LLP 0026#6-top-level-await-and-dynamic-import
        if !self.defers_dynamic_edges(source_id) {
            let allowed = allowed_dynamic_bindings.get(source_id);
            for binding in self.dynamic_import_bindings(source_id)? {
                if allowed.is_some_and(|bindings| bindings.contains(&binding.key())) {
                    targets.insert(binding.target);
                }
            }
        }
        for target in targets {
            self.visit_for_linkage(&target, allowed_dynamic_bindings, visiting, visited, order)?;
        }
        visiting.remove(source_id);
        if visited.insert(source_id.clone()) {
            order.push(source_id.clone());
        }
        Ok(())
    }

    fn edge_target<'a>(
        &self,
        record: &'a PlannedRecord<'artifact>,
        specifier: &str,
        resolution_kind: ResolutionKind,
    ) -> Result<&'a SourceId, GraphError> {
        record
            .edges
            .get(&GraphEdgeKey::new(specifier, resolution_kind))
            .ok_or_else(|| {
                GraphError::link(format!(
                    "{resolution_kind:?} edge {specifier:?} has no authenticated target"
                ))
            })
    }

    fn static_edge_target<'a>(
        &self,
        record: &'a PlannedRecord<'artifact>,
        edge: &StaticEdgeV1,
    ) -> Result<&'a SourceId, GraphError> {
        let key = static_edge_key(edge);
        self.edge_target(record, &key.specifier, key.resolution_kind)
    }
}

enum Resolution {
    Missing,
    Found(ExportTarget),
    Ambiguous,
}

fn edge_specifier(edge: &StaticEdgeV1) -> String {
    match edge {
        StaticEdgeV1::CommonJsRequire { specifier }
        | StaticEdgeV1::SideEffect { specifier, .. }
        | StaticEdgeV1::Default { specifier, .. }
        | StaticEdgeV1::Namespace { specifier, .. }
        | StaticEdgeV1::Named { specifier, .. }
        | StaticEdgeV1::ReExportNamed { specifier, .. }
        | StaticEdgeV1::ReExportStar { specifier, .. }
        | StaticEdgeV1::ReExportNamespace { specifier, .. } => specifier.as_str().to_owned(),
    }
}

fn static_edge_key(edge: &StaticEdgeV1) -> GraphEdgeKey {
    GraphEdgeKey::new(
        edge_specifier(edge),
        if matches!(edge, StaticEdgeV1::CommonJsRequire { .. }) {
            ResolutionKind::CommonJsRequire
        } else {
            ResolutionKind::EsmStatic
        },
    )
}

fn artifact_edge_keys(
    artifact: VerifiedModuleArtifactV1<'_>,
) -> impl Iterator<Item = GraphEdgeKey> + '_ {
    artifact
        .artifact()
        .semantics
        .static_edges
        .iter()
        .map(static_edge_key)
        .chain(
            artifact
                .artifact()
                .semantics
                .dynamic_edges
                .iter()
                .filter_map(|edge| {
                    edge.literal_specifier().map(|specifier| {
                        GraphEdgeKey::new(specifier, ResolutionKind::DynamicImport)
                    })
                }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_loader::artifact::{
        digest_bytes, ArtifactAdmissionV1, CanonicalSourceId, CommonJsExportsV1, DynamicEdgeV1,
        ModuleArtifactV1, ModulePayloadV1, ModuleSemanticsV1, ProducerIdentityV1, SourceDialectV1,
        SourceGoalV1, SourceMapV1, TransformFingerprintV1, MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
    };
    use crate::module_loader::identity::ImportAttributes;
    use capsec_semantics::model::{Digest, NonEmptyString, PathComponent, Principal};

    fn digest(label: &str) -> Digest {
        digest_bytes("module-graph-test", label.as_bytes()).unwrap()
    }

    fn name(value: &str) -> NonEmptyString {
        NonEmptyString::new(value).unwrap()
    }

    fn source(value: &str) -> SourceId {
        SourceId::synthetic("module-graph-test", value).unwrap()
    }

    #[test]
    fn composition_root_plan_validates_roots_and_names_main() {
        let app = source("composition-app");
        let agent = source("composition-agent");
        let absent = source("composition-absent");

        assert!(CompositionRootPlan::new(Vec::new(), &app).is_err());
        assert!(CompositionRootPlan::new(vec![app.clone(), app.clone()], &app).is_err());
        assert!(CompositionRootPlan::new(vec![app.clone(), agent.clone()], &absent).is_err());

        let plan = CompositionRootPlan::new(vec![agent.clone(), app.clone()], &app).unwrap();
        assert_eq!(plan.roots(), &[agent, app.clone()]);
        assert_eq!(plan.main_root(), &app);
    }

    #[test]
    fn composition_orders_assign_shared_records_to_first_root_segment() {
        let shared_id = source("composition-shared");
        let agent_id = source("composition-agent-entry");
        let app_id = source("composition-app-entry");
        let shared = artifact(shared_id.clone(), vec![], vec![], false);
        let agent = artifact(agent_id.clone(), vec![], vec![edge("./shared")], false);
        let app = artifact(app_id.clone(), vec![], vec![edge("./shared")], false);
        let plan = SynchronousGraphPlan::new([
            (verify(&shared), BTreeMap::new()),
            (
                verify(&agent),
                BTreeMap::from([("./shared".into(), shared_id.clone())]),
            ),
            (
                verify(&app),
                BTreeMap::from([("./shared".into(), shared_id.clone())]),
            ),
        ])
        .unwrap();
        let roots = [agent_id.clone(), app_id.clone()];

        assert_eq!(
            plan.linkage_order_for_roots(&roots).unwrap(),
            [shared_id.clone(), agent_id.clone(), app_id.clone()]
        );
        assert_eq!(
            plan.synchronous_evaluation_order_for_roots(&roots).unwrap(),
            [vec![shared_id, agent_id], vec![app_id]]
        );
    }

    #[test]
    fn composition_synchronous_segments_retain_tla_refusal() {
        let async_id = source("composition-async-dependency");
        let agent_id = source("composition-agent-with-async");
        let async_record = artifact(async_id.clone(), vec![], vec![], true);
        let agent = artifact(agent_id.clone(), vec![], vec![edge("./async")], false);
        let plan = SynchronousGraphPlan::new([
            (verify(&async_record), BTreeMap::new()),
            (
                verify(&agent),
                BTreeMap::from([("./async".into(), async_id.clone())]),
            ),
        ])
        .unwrap();

        let error = plan
            .synchronous_evaluation_order_for_roots(&[agent_id])
            .unwrap_err();
        assert_eq!(error.code, GraphErrorCode::RequireAsyncModule);
        assert!(error.detail.contains(&format!("{async_id:?}")));
    }

    fn edge(specifier: &str) -> StaticEdgeV1 {
        StaticEdgeV1::ReExportStar {
            specifier: name(specifier),
            attributes: ImportAttributes::default(),
        }
    }

    fn named_edge(specifier: &str, imported: &str, local: &str) -> StaticEdgeV1 {
        StaticEdgeV1::Named {
            specifier: name(specifier),
            imported: name(imported),
            local: name(local),
            attributes: ImportAttributes::default(),
        }
    }

    fn namespace_edge(specifier: &str, local: &str) -> StaticEdgeV1 {
        StaticEdgeV1::Namespace {
            specifier: name(specifier),
            local: name(local),
            attributes: ImportAttributes::default(),
        }
    }

    fn local(exported: &str) -> ExportDescriptorV1 {
        ExportDescriptorV1::Local {
            exported: name(exported),
            local: name(exported),
        }
    }

    fn star(specifier: &str) -> ExportDescriptorV1 {
        ExportDescriptorV1::Star {
            specifier: name(specifier),
        }
    }

    fn artifact(
        source_id: SourceId,
        export_descriptors: Vec<ExportDescriptorV1>,
        static_edges: Vec<StaticEdgeV1>,
        has_top_level_await: bool,
    ) -> ModuleArtifactV1 {
        let factory =
            "function () { return { declare: function () {}, execute: function () {} }; }";
        let fingerprint = TransformFingerprintV1 {
            producer: name("graph-test"),
            parser_version: name("parser-test"),
            transform_version: name("transform-test"),
            hermes_target: name("hermes-test"),
            typescript_jsx_options_digest: digest("ts-jsx"),
            module_runner_abi: name("ibex-module-runner-1"),
            hermes_compat_version: name("compat-test"),
            commonjs_detector: name("cjs-module-lexer"),
            commonjs_detector_version: name("2.1.0"),
            output_options_digest: digest("output"),
        };
        ModuleArtifactV1::new_inline(
            ModuleSemanticsV1 {
                source_id: CanonicalSourceId(source_id.clone()),
                source_goal: SourceGoalV1::Module,
                dialect: Some(SourceDialectV1::Js),
                source_integrity: digest("source"),
                transform_fingerprint: fingerprint,
                static_edges,
                dynamic_edges: Vec::new(),
                export_descriptors,
                commonjs_exports: None,
                has_top_level_await,
                factory_digest: digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory.as_bytes())
                    .unwrap(),
                source_map: SourceMapV1 {
                    version: 3,
                    source_ids: vec![CanonicalSourceId(source_id)],
                    names: Vec::new(),
                    mappings: String::new(),
                },
            },
            factory.into(),
            ProducerIdentityV1::InProcess {
                producer_id: name("graph-test"),
                producer_binary_digest: digest("producer"),
            },
        )
        .unwrap()
    }

    fn verify(artifact: &ModuleArtifactV1) -> VerifiedModuleArtifactV1<'_> {
        artifact
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: artifact.semantics.source_id.0.clone(),
                expected_source_integrity: digest("source"),
                expected_producer_id: name("graph-test"),
                producer_binary_digest: digest("producer"),
                transform_fingerprint_digest: artifact
                    .semantics
                    .transform_fingerprint
                    .digest()
                    .unwrap(),
            })
            .unwrap()
    }

    fn with_dynamic_edges(
        artifact: ModuleArtifactV1,
        dynamic_edges: Vec<DynamicEdgeV1>,
    ) -> ModuleArtifactV1 {
        let factory_source = match artifact.payload {
            ModulePayloadV1::Inline { factory_source, .. } => factory_source,
            ModulePayloadV1::Carrier { .. } => panic!("graph fixtures are inline"),
        };
        let mut semantics = artifact.semantics;
        semantics.dynamic_edges = dynamic_edges;
        ModuleArtifactV1::new_inline(semantics, factory_source, artifact.producer).unwrap()
    }

    fn commonjs_artifact(
        source_id: SourceId,
        static_edges: Vec<StaticEdgeV1>,
        dynamic_edges: Vec<DynamicEdgeV1>,
    ) -> ModuleArtifactV1 {
        let base = artifact(source_id, vec![], vec![], false);
        let factory_source = match base.payload {
            ModulePayloadV1::Inline { factory_source, .. } => factory_source,
            ModulePayloadV1::Carrier { .. } => unreachable!(),
        };
        let mut semantics = base.semantics;
        semantics.source_goal = SourceGoalV1::CommonJs;
        semantics.static_edges = static_edges;
        semantics.dynamic_edges = dynamic_edges;
        semantics.commonjs_exports = Some(CommonJsExportsV1 {
            detector: semantics.transform_fingerprint.commonjs_detector.clone(),
            detector_version: semantics
                .transform_fingerprint
                .commonjs_detector_version
                .clone(),
            names: Vec::new(),
            reexports: Vec::new(),
        });
        ModuleArtifactV1::new_inline(semantics, factory_source, base.producer).unwrap()
    }

    fn builtin_artifact(source_id: SourceId, static_edges: Vec<StaticEdgeV1>) -> ModuleArtifactV1 {
        let base = commonjs_artifact(source("builtin-template"), static_edges, Vec::new());
        let factory_source = match base.payload {
            ModulePayloadV1::Inline { factory_source, .. } => factory_source,
            ModulePayloadV1::Carrier { .. } => unreachable!(),
        };
        let mut semantics = base.semantics;
        semantics.source_id = CanonicalSourceId(source_id.clone());
        semantics.source_goal = SourceGoalV1::Builtin;
        semantics.source_map.source_ids = vec![CanonicalSourceId(source_id)];
        ModuleArtifactV1::new_inline(semantics, factory_source, base.producer).unwrap()
    }

    fn with_commonjs_exports(
        artifact: ModuleArtifactV1,
        names: &[&str],
        reexports: &[&str],
    ) -> ModuleArtifactV1 {
        let factory_source = match artifact.payload {
            ModulePayloadV1::Inline { factory_source, .. } => factory_source,
            ModulePayloadV1::Carrier { .. } => unreachable!(),
        };
        let mut semantics = artifact.semantics;
        let exports = semantics.commonjs_exports.as_mut().unwrap();
        exports.names = names.iter().map(|value| name(value)).collect();
        exports.reexports = reexports.iter().map(|value| name(value)).collect();
        ModuleArtifactV1::new_inline(semantics, factory_source, artifact.producer).unwrap()
    }

    #[test]
    fn authenticated_call_time_edges_traverse_and_builtin_fanout_stays_private() {
        let dynamic_entry_id = source("dynamic-entry");
        let dynamic_target_id = source("dynamic-target");
        let dynamic_entry = with_dynamic_edges(
            artifact(dynamic_entry_id.clone(), Vec::new(), Vec::new(), false),
            vec![DynamicEdgeV1::Literal {
                specifier: name("./dynamic-target.mjs"),
                attributes: ImportAttributes::default(),
            }],
        );
        let dynamic_target = artifact(dynamic_target_id.clone(), Vec::new(), Vec::new(), false);
        let dynamic_plan = SynchronousGraphPlan::new_typed([
            (
                verify(&dynamic_entry),
                BTreeMap::from([(
                    GraphEdgeKey::new("./dynamic-target.mjs", ResolutionKind::DynamicImport),
                    dynamic_target_id.clone(),
                )]),
            ),
            (verify(&dynamic_target), BTreeMap::new()),
        ])
        .unwrap();
        assert_eq!(
            dynamic_plan.evaluation_order(&dynamic_entry_id).unwrap(),
            [dynamic_entry_id.clone()]
        );
        assert_eq!(
            dynamic_plan.linkage_order(&dynamic_entry_id).unwrap(),
            [dynamic_target_id, dynamic_entry_id.clone()]
        );
        let deferred_dynamic_plan = SynchronousGraphPlan::new_typed_with_call_time_deferred(
            [(verify(&dynamic_entry), BTreeMap::new())],
            BTreeMap::new(),
            BTreeSet::from([dynamic_entry_id.clone()]),
        )
        .unwrap();
        assert_eq!(
            deferred_dynamic_plan
                .linkage_order_for_authorized(&dynamic_entry_id, &BTreeMap::new())
                .unwrap(),
            [dynamic_entry_id.clone()]
        );

        let commonjs_entry_id = source("commonjs-entry");
        let commonjs_target_id = source("commonjs-target");
        let commonjs_entry = commonjs_artifact(
            commonjs_entry_id.clone(),
            vec![StaticEdgeV1::CommonJsRequire {
                specifier: name("./commonjs-target.cjs"),
            }],
            Vec::new(),
        );
        let commonjs_target = commonjs_artifact(commonjs_target_id.clone(), Vec::new(), Vec::new());
        let commonjs_plan = SynchronousGraphPlan::new_typed([
            (
                verify(&commonjs_entry),
                BTreeMap::from([(
                    GraphEdgeKey::new("./commonjs-target.cjs", ResolutionKind::CommonJsRequire),
                    commonjs_target_id.clone(),
                )]),
            ),
            (verify(&commonjs_target), BTreeMap::new()),
        ])
        .unwrap();
        assert_eq!(
            commonjs_plan.evaluation_order(&commonjs_entry_id).unwrap(),
            [commonjs_entry_id.clone()]
        );
        assert_eq!(
            commonjs_plan.linkage_order(&commonjs_entry_id).unwrap(),
            [commonjs_target_id, commonjs_entry_id.clone()]
        );
        assert!(commonjs_plan
            .ensure_native_call_time_edges_supported()
            .unwrap_err()
            .to_string()
            .contains("CommonJS require activation"));
        let deferred_commonjs_plan = SynchronousGraphPlan::new_typed_with_call_time_deferred_edges(
            [(verify(&commonjs_entry), BTreeMap::new())],
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::from([commonjs_entry_id.clone()]),
        )
        .unwrap();
        deferred_commonjs_plan
            .ensure_native_call_time_edges_supported()
            .unwrap();
        assert!(deferred_commonjs_plan
            .commonjs_require_bindings(&commonjs_entry_id)
            .unwrap()
            .is_empty());
        assert_eq!(
            deferred_commonjs_plan
                .linkage_order_for_authorized(&commonjs_entry_id, &BTreeMap::new())
                .unwrap(),
            [commonjs_entry_id.clone()]
        );

        let builtin_owner_id = SourceId::builtin("ibex-runtime", "builtin-owner").unwrap();
        let builtin_target_id = SourceId::builtin("ibex-runtime", "builtin-target").unwrap();
        let builtin_owner = builtin_artifact(
            builtin_owner_id.clone(),
            vec![StaticEdgeV1::CommonJsRequire {
                specifier: name("./private-target"),
            }],
        );
        let builtin_target = builtin_artifact(builtin_target_id.clone(), Vec::new());
        let builtin_edges = BTreeMap::from([(
            GraphEdgeKey::new("./private-target", ResolutionKind::CommonJsRequire),
            builtin_target_id.clone(),
        )]);
        let builtin_plan = SynchronousGraphPlan::new_typed([
            (verify(&builtin_owner), builtin_edges.clone()),
            (verify(&builtin_target), BTreeMap::new()),
        ])
        .unwrap();
        builtin_plan
            .ensure_native_call_time_edges_supported()
            .unwrap();
        assert!(
            SynchronousGraphPlan::new_typed_with_call_time_deferred_edges(
                [(verify(&builtin_owner), BTreeMap::new())],
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::from([builtin_owner_id.clone()]),
            )
            .err()
            .expect("generated builtin call-time deferral was accepted")
            .to_string()
            .contains("generated builtin require edges cannot be deferred")
        );

        struct AllowAllPolicy {
            digest: Digest,
            generations: capsec_semantics::arming::SnapshotGenerations,
        }

        impl GraphImportPolicy for AllowAllPolicy {
            fn snapshot_digest(&self) -> &Digest {
                &self.digest
            }

            fn snapshot_generations(&self) -> capsec_semantics::arming::SnapshotGenerations {
                self.generations
            }

            fn authenticates_module_edge(
                &self,
                _importer: &capsec_semantics::model::Principal,
                _request_specifier: &str,
                _imported: &capsec_semantics::model::Principal,
                _resolution_kind: &str,
                _conditions: &[String],
                _attributes: &BTreeMap<String, String>,
            ) -> bool {
                true
            }
        }

        let generation = capsec_semantics::model::Generation::new(1).unwrap();
        let policy = AllowAllPolicy {
            digest: digest("builtin-policy"),
            generations: capsec_semantics::arming::SnapshotGenerations {
                policy: generation,
                negative: generation,
                dynamic: generation,
                handle: generation,
            },
        };
        let root = capsec_semantics::model::Principal::Root {
            identity: name("module-graph-root"),
        };
        let context = |requester: SourceId| {
            GraphAuthorityContext::new(
                requester,
                root.clone(),
                root.clone(),
                root.clone(),
                vec![root.clone()],
                capsec_semantics::model::Stage::Requested,
                1,
            )
            .unwrap()
        };
        let contexts = BTreeMap::from([
            (builtin_owner_id.clone(), context(builtin_owner_id.clone())),
            (
                builtin_target_id.clone(),
                context(builtin_target_id.clone()),
            ),
        ]);
        let receipts = builtin_plan
            .authorize_reachable_operations(
                &builtin_owner_id,
                &ModuleGraphAuthorizer::new(&policy),
                &contexts,
            )
            .unwrap();
        assert_eq!(receipts.len(), 6);
        assert!(!receipts
            .iter()
            .any(|receipt| receipt.decision().kind == GraphOperationKind::LiteralRequire));
        assert_eq!(
            builtin_plan.evaluation_order(&builtin_owner_id).unwrap(),
            [builtin_owner_id.clone()]
        );

        let bootstrap_owner_id =
            SourceId::builtin("ibex-runtime", "bootstrap-internal-owner").unwrap();
        let bootstrap_owner = builtin_artifact(
            bootstrap_owner_id.clone(),
            vec![StaticEdgeV1::CommonJsRequire {
                specifier: name("internal/test/binding"),
            }],
        );
        let derived_bootstrap_plan =
            SynchronousGraphPlan::new_typed([(verify(&bootstrap_owner), BTreeMap::new())]).unwrap();
        assert_eq!(
            derived_bootstrap_plan.bootstrap_internal_commonjs_requires(&bootstrap_owner_id),
            BTreeSet::from(["internal/test/binding".to_owned()])
        );
        let bootstrap_plan = SynchronousGraphPlan::new_typed_with_private_commonjs_edges(
            [(verify(&bootstrap_owner), BTreeMap::new())],
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeMap::from([(
                bootstrap_owner_id.clone(),
                BTreeSet::from(["internal/test/binding".to_owned()]),
            )]),
        )
        .unwrap();
        bootstrap_plan
            .ensure_native_call_time_edges_supported()
            .unwrap();
        assert!(bootstrap_plan
            .commonjs_require_bindings(&bootstrap_owner_id)
            .unwrap()
            .is_empty());
        assert_eq!(
            bootstrap_plan
                .linkage_order_for_authorized(&bootstrap_owner_id, &BTreeMap::new())
                .unwrap(),
            [bootstrap_owner_id.clone()]
        );
        assert!(SynchronousGraphPlan::new_typed_with_private_commonjs_edges(
            [(verify(&commonjs_entry), BTreeMap::new())],
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeMap::from([(
                commonjs_entry_id.clone(),
                BTreeSet::from(["./commonjs-target.cjs".to_owned()]),
            )]),
        )
        .err()
        .expect("non-builtin bootstrap-internal edge was accepted")
        .to_string()
        .contains("non-builtin"));

        let non_builtin_target_id = SourceId::file(
            root.clone(),
            vec![capsec_semantics::model::PathComponent::utf8("non-builtin-target.cjs").unwrap()],
        )
        .unwrap();
        let non_builtin_target =
            commonjs_artifact(non_builtin_target_id.clone(), Vec::new(), Vec::new());
        let escaped_plan = SynchronousGraphPlan::new_typed([
            (
                verify(&builtin_owner),
                BTreeMap::from([(
                    GraphEdgeKey::new("./private-target", ResolutionKind::CommonJsRequire),
                    non_builtin_target_id.clone(),
                )]),
            ),
            (verify(&non_builtin_target), BTreeMap::new()),
        ])
        .unwrap();
        let escaped_contexts = BTreeMap::from([
            (builtin_owner_id.clone(), context(builtin_owner_id.clone())),
            (
                non_builtin_target_id.clone(),
                context(non_builtin_target_id),
            ),
        ]);
        assert!(escaped_plan
            .authorize_reachable_operations(
                &builtin_owner_id,
                &ModuleGraphAuthorizer::new(&policy),
                &escaped_contexts,
            )
            .unwrap_err()
            .to_string()
            .contains("is not a builtin record"));
    }

    #[test]
    fn star_ambiguity_is_excluded_and_local_exports_win() {
        let left_id = source("left");
        let right_id = source("right");
        let hub_id = source("hub");
        let left = artifact(
            left_id.clone(),
            vec![local("left"), local("shared")],
            vec![],
            false,
        );
        let right = artifact(
            right_id.clone(),
            vec![local("right"), local("shared")],
            vec![],
            false,
        );
        let hub = artifact(
            hub_id.clone(),
            vec![star("./left"), star("./right"), local("shared")],
            vec![edge("./left"), edge("./right")],
            false,
        );
        let plan = SynchronousGraphPlan::new([
            (verify(&left), BTreeMap::new()),
            (verify(&right), BTreeMap::new()),
            (
                verify(&hub),
                BTreeMap::from([
                    ("./left".into(), left_id.clone()),
                    ("./right".into(), right_id.clone()),
                ]),
            ),
        ])
        .unwrap();
        let namespace = plan.namespace(&hub_id).unwrap();
        assert_eq!(
            namespace.keys().cloned().collect::<Vec<_>>(),
            ["left", "right", "shared"]
        );
        assert_eq!(namespace["shared"].record, hub_id);
    }

    #[test]
    fn cyclic_star_resolution_reuses_records_without_recursing_forever() {
        let a_id = source("a");
        let b_id = source("b");
        let a = artifact(
            a_id.clone(),
            vec![local("a"), star("./b")],
            vec![edge("./b")],
            false,
        );
        let b = artifact(
            b_id.clone(),
            vec![local("b"), star("./a")],
            vec![edge("./a")],
            false,
        );
        let plan = SynchronousGraphPlan::new([
            (verify(&a), BTreeMap::from([("./b".into(), b_id.clone())])),
            (verify(&b), BTreeMap::from([("./a".into(), a_id.clone())])),
        ])
        .unwrap();
        assert_eq!(
            plan.namespace(&a_id)
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(plan.evaluation_order(&a_id).unwrap(), [b_id, a_id]);
    }

    #[test]
    fn import_reads_resolve_to_ultimate_cells_and_stable_namespaces() {
        let leaf_id = source("leaf");
        let hub_id = source("hub");
        let entry_id = source("entry");
        let leaf = artifact(leaf_id.clone(), vec![local("value")], vec![], false);
        let hub = artifact(
            hub_id.clone(),
            vec![star("./leaf")],
            vec![edge("./leaf")],
            false,
        );
        let entry = artifact(
            entry_id.clone(),
            vec![],
            vec![
                named_edge("./hub", "value", "first"),
                named_edge("./hub", "value", "second"),
                namespace_edge("./hub", "hub"),
            ],
            false,
        );
        let plan = SynchronousGraphPlan::new([
            (verify(&leaf), BTreeMap::new()),
            (
                verify(&hub),
                BTreeMap::from([("./leaf".into(), leaf_id.clone())]),
            ),
            (
                verify(&entry),
                BTreeMap::from([("./hub".into(), hub_id.clone())]),
            ),
        ])
        .unwrap();

        assert_eq!(
            plan.import_bindings(&entry_id).unwrap(),
            [
                ImportBindingPlan {
                    specifier: "./hub".into(),
                    imported: "*".into(),
                    target: ExportTarget {
                        record: hub_id.clone(),
                        binding: "*".into(),
                    },
                },
                ImportBindingPlan {
                    specifier: "./hub".into(),
                    imported: "value".into(),
                    target: ExportTarget {
                        record: leaf_id.clone(),
                        binding: "value".into(),
                    },
                },
            ]
        );
        assert_eq!(
            plan.evaluation_order(&entry_id).unwrap(),
            [leaf_id, hub_id, entry_id]
        );
    }

    #[test]
    fn graph_disagreement_and_async_require_fail_before_execution() {
        let entry_id = source("entry");
        let mismatch = artifact(entry_id.clone(), vec![], vec![edge("./missing")], false);
        let error = SynchronousGraphPlan::new([(verify(&mismatch), BTreeMap::new())])
            .err()
            .unwrap();
        assert_eq!(error.code, GraphErrorCode::ModuleLink);
        assert!(error.to_string().starts_with("ERR_MODULE_LINK:"));

        let asynchronous = artifact(entry_id.clone(), vec![], vec![], true);
        let plan = SynchronousGraphPlan::new([(verify(&asynchronous), BTreeMap::new())]).unwrap();
        let error = plan.synchronous_evaluation_order(&entry_id).err().unwrap();
        assert_eq!(error.code, GraphErrorCode::RequireAsyncModule);
        assert!(error.to_string().starts_with("ERR_REQUIRE_ASYNC_MODULE:"));

        let requiring_id = source("lazy-requiring-entry");
        let lazy_async_id = source("lazy-async-target");
        let requiring = commonjs_artifact(
            requiring_id.clone(),
            vec![StaticEdgeV1::CommonJsRequire {
                specifier: name("./lazy-async.mjs"),
            }],
            Vec::new(),
        );
        let lazy_async = artifact(lazy_async_id.clone(), Vec::new(), Vec::new(), true);
        let lazy_plan = SynchronousGraphPlan::new_typed([
            (
                verify(&requiring),
                BTreeMap::from([(
                    GraphEdgeKey::new("./lazy-async.mjs", ResolutionKind::CommonJsRequire),
                    lazy_async_id.clone(),
                )]),
            ),
            (verify(&lazy_async), BTreeMap::new()),
        ])
        .unwrap();
        assert_eq!(
            lazy_plan
                .synchronous_evaluation_order(&requiring_id)
                .unwrap(),
            [requiring_id.clone()]
        );
        assert_eq!(
            lazy_plan.linkage_order(&requiring_id).unwrap(),
            [lazy_async_id, requiring_id]
        );
    }

    #[test]
    fn one_specifier_keeps_require_and_dynamic_targets_distinct() {
        let entry_id = source("commonjs-entry");
        let require_id = source("require-target");
        let dynamic_id = source("dynamic-target");
        let entry = commonjs_artifact(
            entry_id.clone(),
            vec![StaticEdgeV1::CommonJsRequire {
                specifier: name("conditional-package"),
            }],
            vec![DynamicEdgeV1::Literal {
                specifier: name("conditional-package"),
                attributes: ImportAttributes::default(),
            }],
        );
        let require_target = commonjs_artifact(require_id.clone(), vec![], vec![]);
        let dynamic_target = artifact(dynamic_id.clone(), vec![], vec![], false);
        let plan = SynchronousGraphPlan::new_typed([
            (
                verify(&entry),
                BTreeMap::from([
                    (
                        GraphEdgeKey::new("conditional-package", ResolutionKind::CommonJsRequire),
                        require_id.clone(),
                    ),
                    (
                        GraphEdgeKey::new("conditional-package", ResolutionKind::DynamicImport),
                        dynamic_id.clone(),
                    ),
                ]),
            ),
            (verify(&require_target), BTreeMap::new()),
            (verify(&dynamic_target), BTreeMap::new()),
        ])
        .unwrap();

        assert_eq!(
            plan.commonjs_require_target(&entry_id, "conditional-package")
                .unwrap(),
            &require_id
        );
        assert_eq!(
            plan.dynamic_import_targets(&entry_id).unwrap(),
            [("conditional-package".to_owned(), dynamic_id.clone())]
        );
        assert_eq!(
            plan.evaluation_order(&entry_id).unwrap(),
            [entry_id.clone()]
        );
        assert_eq!(
            plan.linkage_order(&entry_id).unwrap(),
            [dynamic_id, require_id, entry_id]
        );
    }

    #[test]
    fn esm_imports_resolve_against_commonjs_reexport_names() {
        let entry_id = source("esm-entry");
        let bridge_id = source("commonjs-bridge");
        let leaf_id = source("commonjs-leaf");
        let entry = artifact(
            entry_id.clone(),
            vec![],
            vec![named_edge("./bridge", "answer", "answer")],
            false,
        );
        let bridge = with_commonjs_exports(
            commonjs_artifact(
                bridge_id.clone(),
                vec![StaticEdgeV1::CommonJsRequire {
                    specifier: name("./leaf"),
                }],
                vec![],
            ),
            &[],
            &["./leaf"],
        );
        let leaf = with_commonjs_exports(
            commonjs_artifact(leaf_id.clone(), vec![], vec![]),
            &["answer"],
            &[],
        );
        let plan = SynchronousGraphPlan::new_typed([
            (
                verify(&entry),
                BTreeMap::from([(
                    GraphEdgeKey::new("./bridge", ResolutionKind::EsmStatic),
                    bridge_id.clone(),
                )]),
            ),
            (
                verify(&bridge),
                BTreeMap::from([(
                    GraphEdgeKey::new("./leaf", ResolutionKind::CommonJsRequire),
                    leaf_id.clone(),
                )]),
            ),
            (verify(&leaf), BTreeMap::new()),
        ])
        .unwrap();

        assert_eq!(
            plan.namespace(&bridge_id)
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["answer", "default", "module.exports"]
        );
        assert_eq!(
            plan.import_bindings(&entry_id).unwrap()[0].target,
            ExportTarget {
                record: bridge_id,
                binding: "answer".into(),
            }
        );
    }

    #[test]
    fn synchronous_refusal_is_reachable_closure_scoped() {
        let sync_id = source("sync");
        let async_id = source("async");
        let sync = artifact(sync_id.clone(), vec![], vec![], false);
        let asynchronous = artifact(async_id.clone(), vec![], vec![], true);
        let plan = SynchronousGraphPlan::new([
            (verify(&sync), BTreeMap::new()),
            (verify(&asynchronous), BTreeMap::new()),
        ])
        .unwrap();

        assert_eq!(
            plan.synchronous_evaluation_order(&sync_id).unwrap(),
            [sync_id]
        );
        assert_eq!(
            plan.synchronous_evaluation_order(&async_id)
                .unwrap_err()
                .code,
            GraphErrorCode::RequireAsyncModule
        );
    }

    #[test]
    fn async_plan_collapses_cycles_and_propagates_tla_taint() {
        let leaf_id = source("leaf");
        let cycle_a_id = source("cycle-a");
        let cycle_b_id = source("cycle-b");
        let entry_id = source("entry");
        let leaf = artifact(leaf_id.clone(), vec![], vec![], true);
        let cycle_a = artifact(
            cycle_a_id.clone(),
            vec![star("./b"), star("./leaf")],
            vec![edge("./b"), edge("./leaf")],
            false,
        );
        let cycle_b = artifact(
            cycle_b_id.clone(),
            vec![star("./a")],
            vec![edge("./a")],
            false,
        );
        let entry = artifact(
            entry_id.clone(),
            vec![star("./a")],
            vec![edge("./a")],
            false,
        );
        let plan = SynchronousGraphPlan::new([
            (verify(&leaf), BTreeMap::new()),
            (
                verify(&cycle_a),
                BTreeMap::from([
                    ("./b".into(), cycle_b_id.clone()),
                    ("./leaf".into(), leaf_id.clone()),
                ]),
            ),
            (
                verify(&cycle_b),
                BTreeMap::from([("./a".into(), cycle_a_id.clone())]),
            ),
            (
                verify(&entry),
                BTreeMap::from([("./a".into(), cycle_a_id.clone())]),
            ),
        ])
        .unwrap();

        let asynchronous = plan.asynchronous_evaluation_plan(&entry_id).unwrap();
        assert_eq!(asynchronous.sccs.len(), 3);
        assert_eq!(asynchronous.sccs[0].records, [leaf_id.clone()]);
        assert!(asynchronous.sccs[0].contains_top_level_await);
        assert_eq!(
            asynchronous.sccs[1]
                .records
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([cycle_a_id.clone(), cycle_b_id.clone()])
        );
        assert_eq!(asynchronous.sccs[1].dependencies, [0]);
        assert!(asynchronous.sccs[1].async_tainted);
        assert_eq!(asynchronous.sccs[2].records, [entry_id.clone()]);
        assert_eq!(asynchronous.sccs[2].dependencies, [1]);
        assert!(asynchronous.is_async_tainted(&entry_id).unwrap());
    }

    #[test]
    fn computed_dynamic_import_uses_only_the_authenticated_candidate_set() {
        let entry_id = source("computed-entry");
        let left_id = source("computed-left");
        let right_id = source("computed-right");
        let entry = with_dynamic_edges(
            artifact(entry_id.clone(), vec![], vec![], false),
            vec![DynamicEdgeV1::Computed { site: 0 }],
        );
        let left = artifact(left_id.clone(), vec![], vec![], false);
        let right = artifact(right_id.clone(), vec![], vec![], false);
        let plan = SynchronousGraphPlan::new_typed_with_computed_candidates(
            [
                (verify(&entry), BTreeMap::new()),
                (verify(&left), BTreeMap::new()),
                (verify(&right), BTreeMap::new()),
            ],
            BTreeMap::from([(
                entry_id.clone(),
                BTreeMap::from([
                    (
                        (0, "./left".into()),
                        ComputedCandidateBinding {
                            target: left_id.clone(),
                            attributes: ImportAttributes::default(),
                        },
                    ),
                    (
                        (0, "./right".into()),
                        ComputedCandidateBinding {
                            target: right_id.clone(),
                            attributes: ImportAttributes::default(),
                        },
                    ),
                ]),
            )]),
        )
        .unwrap();
        assert_eq!(
            plan.dynamic_import_bindings(&entry_id)
                .unwrap()
                .into_iter()
                .map(|binding| (
                    binding.site,
                    binding.specifier,
                    binding.target,
                    binding.attributes,
                ))
                .collect::<Vec<_>>(),
            [
                (
                    Some(0),
                    "./left".into(),
                    left_id.clone(),
                    ImportAttributes::default()
                ),
                (
                    Some(0),
                    "./right".into(),
                    right_id.clone(),
                    ImportAttributes::default()
                ),
            ]
        );
        assert_eq!(
            plan.linkage_order(&entry_id).unwrap(),
            [left_id, right_id, entry_id]
        );

        let closed_id = source("closed-entry");
        let closed = artifact(closed_id, vec![], vec![], false);
        assert!(SynchronousGraphPlan::new([(
            verify(&closed),
            BTreeMap::from([("./unadvertised".into(), source("unadvertised"))]),
        )])
        .is_err());
    }

    #[test]
    fn computed_candidates_keep_site_specific_attributes_through_authorization() {
        struct AllowAllPolicy {
            digest: Digest,
            generations: capsec_semantics::arming::SnapshotGenerations,
        }

        impl GraphImportPolicy for AllowAllPolicy {
            fn snapshot_digest(&self) -> &Digest {
                &self.digest
            }

            fn snapshot_generations(&self) -> capsec_semantics::arming::SnapshotGenerations {
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

        let root = Principal::Root {
            identity: name("candidate-root"),
        };
        let file = |name: &str| {
            SourceId::file(root.clone(), vec![PathComponent::utf8(name).unwrap()]).unwrap()
        };
        let entry_id = file("entry.mjs");
        let plain_id = file("plain.mjs");
        let json_id = file("data.json");
        let entry = with_dynamic_edges(
            artifact(entry_id.clone(), Vec::new(), Vec::new(), false),
            vec![
                DynamicEdgeV1::Computed { site: 0 },
                DynamicEdgeV1::Computed { site: 1 },
            ],
        );
        let plain = artifact(plain_id.clone(), Vec::new(), Vec::new(), false);
        let json = artifact(json_id.clone(), Vec::new(), Vec::new(), false);
        let json_attributes =
            ImportAttributes::new([("type".to_owned(), "json".to_owned())]).unwrap();
        let plan = SynchronousGraphPlan::new_typed_with_computed_candidates(
            [
                (verify(&entry), BTreeMap::new()),
                (verify(&plain), BTreeMap::new()),
                (verify(&json), BTreeMap::new()),
            ],
            BTreeMap::from([(
                entry_id.clone(),
                BTreeMap::from([
                    (
                        (0, "./same".to_owned()),
                        ComputedCandidateBinding {
                            target: plain_id.clone(),
                            attributes: ImportAttributes::default(),
                        },
                    ),
                    (
                        (1, "./same".to_owned()),
                        ComputedCandidateBinding {
                            target: json_id.clone(),
                            attributes: json_attributes.clone(),
                        },
                    ),
                ]),
            )]),
        )
        .unwrap();

        let bindings = plan.dynamic_import_bindings(&entry_id).unwrap();
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].site, Some(0));
        assert!(bindings[0].attributes.is_empty());
        assert_eq!(bindings[1].site, Some(1));
        assert_eq!(bindings[1].attributes, json_attributes);

        let generation = capsec_semantics::model::Generation::new(1).unwrap();
        let policy = AllowAllPolicy {
            digest: digest("candidate-policy"),
            generations: capsec_semantics::arming::SnapshotGenerations {
                policy: generation,
                negative: generation,
                dynamic: generation,
                handle: generation,
            },
        };
        let context = |source_id: SourceId| {
            GraphAuthorityContext::new(
                source_id,
                root.clone(),
                root.clone(),
                root.clone(),
                vec![root.clone()],
                capsec_semantics::model::Stage::Requested,
                1,
            )
            .unwrap()
        };
        let contexts = BTreeMap::from([
            (entry_id.clone(), context(entry_id.clone())),
            (plain_id.clone(), context(plain_id.clone())),
            (json_id.clone(), context(json_id.clone())),
        ]);
        let authorization = plan
            .authorize_dynamic_candidates(
                &entry_id,
                &ModuleGraphAuthorizer::new(&policy),
                &contexts,
            )
            .unwrap();
        assert!(
            authorization.allowed_bindings[&entry_id].contains(&DynamicImportBindingKey {
                site: Some(0),
                specifier: "./same".to_owned(),
            })
        );
        assert!(
            authorization.allowed_bindings[&entry_id].contains(&DynamicImportBindingKey {
                site: Some(1),
                specifier: "./same".to_owned(),
            })
        );
        let dynamic_attributes = authorization
            .receipts
            .iter()
            .filter(|receipt| {
                receipt.decision().resource.resolution_kind == ResolutionKind::DynamicImport
            })
            .map(|receipt| {
                (
                    receipt.decision().resource.target.clone(),
                    receipt.decision().resource.attributes.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert!(dynamic_attributes[&plain_id].is_empty());
        assert_eq!(dynamic_attributes[&json_id], json_attributes);
    }
}
