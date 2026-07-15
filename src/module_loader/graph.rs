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
    ExportDescriptorV1, ModulePayloadV1, StaticEdgeV1, VerifiedModuleArtifactV1,
};
use super::identity::SourceId;
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
    edges: BTreeMap<String, SourceId>,
}

/// Immutable link plan for one synchronous graph generation.
pub struct SynchronousGraphPlan<'artifact> {
    records: BTreeMap<SourceId, PlannedRecord<'artifact>>,
}

impl<'artifact> SynchronousGraphPlan<'artifact> {
    /// Build a plan from admitted artifacts and authenticated resolution edges.
    /// The edge map must exactly match the artifact's static specifier set;
    /// disagreement fails before any factory compilation or evaluation.
    pub fn new(
        records: impl IntoIterator<
            Item = (
                VerifiedModuleArtifactV1<'artifact>,
                BTreeMap<String, SourceId>,
            ),
        >,
    ) -> Result<Self, GraphError> {
        let mut planned = BTreeMap::new();
        for (artifact, edges) in records {
            let semantics = &artifact.artifact().semantics;
            let source_id = semantics.source_id.0.clone();
            if semantics.has_top_level_await {
                return Err(GraphError::asynchronous(&source_id));
            }
            let expected: BTreeSet<_> = semantics.static_edges.iter().map(edge_specifier).collect();
            let observed: BTreeSet<_> = edges.keys().cloned().collect();
            if expected != observed {
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
        Ok(Self { records: planned })
    }

    pub fn artifact(
        &self,
        source_id: &SourceId,
    ) -> Result<VerifiedModuleArtifactV1<'artifact>, GraphError> {
        Ok(self.record(source_id)?.artifact)
    }

    /// Dependency-first execution order for the entry's reachable closure.
    /// A visiting record is reused, so cycles append each record exactly once.
    pub fn evaluation_order(&self, entry: &SourceId) -> Result<Vec<SourceId>, GraphError> {
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut order = Vec::new();
        self.visit_for_evaluation(entry, &mut visiting, &mut visited, &mut order)?;
        Ok(order)
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
        for source_id in self.evaluation_order(entry)? {
            let context = contexts.get(&source_id).ok_or_else(|| {
                anyhow::anyhow!("reachable ModuleRecord {source_id:?} has no CapSec context")
            })?;
            if context.requesting_record != source_id {
                anyhow::bail!("CapSec context requester disagrees with {source_id:?}");
            }
            let record = self.record(&source_id)?;
            for edge in &record.artifact.artifact().semantics.static_edges {
                let (specifier, attributes, kind) = match edge {
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
                        attributes,
                        if attributes.asserts_json() {
                            GraphOperationKind::JsonLoad
                        } else {
                            GraphOperationKind::StaticImport
                        },
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
                    } => (specifier, attributes, GraphOperationKind::ReExport),
                };
                let target = self.edge_target(record, specifier.as_str())?.clone();
                let decision = GraphDecisionSet::new(
                    kind,
                    context.clone(),
                    target,
                    specifier.as_str(),
                    super::identity::ResolutionKind::EsmStatic,
                    super::identity::ConditionSet::for_kind(
                        super::identity::ResolutionKind::EsmStatic,
                    ),
                    attributes.clone(),
                    None,
                    None,
                )?;
                receipts.push(authorizer.authorize(decision)?);
            }

            // Factory compilation, instantiation, and execution are separate
            // record-owned decisions. They use the initialization task
            // boundary rather than inheriting an importer context.
            let artifact = record.artifact.artifact();
            let initialization =
                GraphAuthorityContext::initialization(source_id.clone(), context.graph_generation)?;
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
                | StaticEdgeV1::ReExportNamed { .. }
                | StaticEdgeV1::ReExportStar { .. }
                | StaticEdgeV1::ReExportNamespace { .. } => continue,
            };
            let target_record = self.edge_target(record, specifier)?;
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
        for descriptor in &record.artifact.artifact().semantics.export_descriptors {
            match descriptor {
                ExportDescriptorV1::Local { exported, .. }
                | ExportDescriptorV1::Indirect { exported, .. }
                | ExportDescriptorV1::Namespace { exported, .. } => {
                    names.insert(exported.as_str().to_owned());
                }
                ExportDescriptorV1::Star { specifier } => {
                    let target = self.edge_target(record, specifier.as_str())?;
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
                    let target = self.edge_target(record, specifier.as_str())?;
                    let result = self.resolve_export(target, imported.as_str(), visiting)?;
                    visiting.remove(&key);
                    return Ok(result);
                }
                ExportDescriptorV1::Namespace {
                    exported,
                    specifier,
                } if exported.as_str() == name => {
                    let target = self.edge_target(record, specifier.as_str())?;
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
            let target = self.edge_target(record, specifier.as_str())?;
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
            let target = self.edge_target(record, &edge_specifier(edge))?;
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

    fn edge_target<'a>(
        &self,
        record: &'a PlannedRecord<'artifact>,
        specifier: &str,
    ) -> Result<&'a SourceId, GraphError> {
        record.edges.get(specifier).ok_or_else(|| {
            GraphError::link(format!(
                "static edge {specifier:?} has no authenticated target"
            ))
        })
    }
}

enum Resolution {
    Missing,
    Found(ExportTarget),
    Ambiguous,
}

fn edge_specifier(edge: &StaticEdgeV1) -> String {
    match edge {
        StaticEdgeV1::SideEffect { specifier, .. }
        | StaticEdgeV1::Default { specifier, .. }
        | StaticEdgeV1::Namespace { specifier, .. }
        | StaticEdgeV1::Named { specifier, .. }
        | StaticEdgeV1::ReExportNamed { specifier, .. }
        | StaticEdgeV1::ReExportStar { specifier, .. }
        | StaticEdgeV1::ReExportNamespace { specifier, .. } => specifier.as_str().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_loader::artifact::{
        digest_bytes, ArtifactAdmissionV1, CanonicalSourceId, ModuleArtifactV1, ModuleSemanticsV1,
        ProducerIdentityV1, SourceDialectV1, SourceGoalV1, SourceMapV1, TransformFingerprintV1,
        MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
    };
    use crate::module_loader::identity::ImportAttributes;
    use capsec_semantics::model::{Digest, NonEmptyString};

    fn digest(label: &str) -> Digest {
        digest_bytes("module-graph-test", label.as_bytes()).unwrap()
    }

    fn name(value: &str) -> NonEmptyString {
        NonEmptyString::new(value).unwrap()
    }

    fn source(value: &str) -> SourceId {
        SourceId::synthetic("module-graph-test", value).unwrap()
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

        let asynchronous = artifact(entry_id, vec![], vec![], true);
        let error = SynchronousGraphPlan::new([(verify(&asynchronous), BTreeMap::new())])
            .err()
            .unwrap();
        assert_eq!(error.code, GraphErrorCode::RequireAsyncModule);
        assert!(error.to_string().starts_with("ERR_REQUIRE_ASYNC_MODULE:"));
    }
}
