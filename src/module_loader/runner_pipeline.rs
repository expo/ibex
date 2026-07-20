//! Authenticated source graph construction for the native module runner.
//!
//! Resolution and source acquisition always go through the installed Host.
//! The pipeline never falls back after an authorization, parse, link, or
//! execution failure; it reports only explicitly unsupported interop shapes as
//! candidates for the bounded legacy window.
//! @ref LLP 0026#1-source-admission-and-resolution

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use capsec_semantics::arming::ArmedSnapshot;
use capsec_semantics::model::{Digest, NonEmptyString, Principal, Stage};
use serde::{Deserialize, Serialize};

use crate::engine::module_runner::{GraphEvaluationContext, NativeModuleRecordConfig};

use super::artifact::{
    ArtifactAdmissionV1, DynamicEdgeV1, ModuleArtifactV1, StaticEdgeV1, VerifiedModuleArtifactV1,
};
use super::carrier::{
    AdmittedPreparedCarrierV1, PreparedCarrierAdmissionV1, PreparedModuleCarrierV1,
    VerifiedPreparedCarrierEntryV1,
};
use super::graph::{GraphEdgeKey, SynchronousGraphPlan};
use super::identity::{ImportAttributes, ResolutionKind, SourceId};
use super::producer_spike::{
    produce_builtin_artifact_v1, produce_commonjs_artifact_v1, produce_json_artifact_v1,
    produce_module_artifact_v1, unsupported_module_runner_reason,
};
use super::ModuleKind;

#[derive(Debug, Clone)]
pub struct LegacyModuleRunnerRequirement {
    pub reason: String,
}

pub enum SourceModuleGraphBuildV1 {
    Native(SourceModuleGraphV1),
    LegacyRequired(LegacyModuleRunnerRequirement),
}

trait SourceGraphHost {
    fn snapshot(&self) -> Result<Arc<ArmedSnapshot>>;

    fn resolve(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        kind: ResolutionKind,
        attributes: &ImportAttributes,
    ) -> Result<super::ResolvedModule>;

    fn resolve_manifest_builtin_internal(&self, specifier: &str) -> Result<super::ResolvedModule>;

    fn principal_id(&self, principal: &Principal) -> Result<u32>;
}

struct InstalledSourceGraphHost;

impl SourceGraphHost for InstalledSourceGraphHost {
    fn snapshot(&self) -> Result<Arc<ArmedSnapshot>> {
        crate::host::abi::current_module_runner_snapshot()
    }

    fn resolve(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        kind: ResolutionKind,
        attributes: &ImportAttributes,
    ) -> Result<super::ResolvedModule> {
        crate::host::abi::resolve_module_for_runner(
            specifier,
            specifier_referrer(referrer),
            None,
            kind,
            attributes,
        )
    }

    fn resolve_manifest_builtin_internal(&self, specifier: &str) -> Result<super::ResolvedModule> {
        crate::host::abi::resolve_manifest_builtin_internal_for_runner(specifier)
    }

    fn principal_id(&self, principal: &Principal) -> Result<u32> {
        crate::host::abi::module_runner_principal_id(principal)
    }
}

impl SourceGraphHost for crate::host::Host {
    fn snapshot(&self) -> Result<Arc<ArmedSnapshot>> {
        self.armed_snapshot()
            .cloned()
            .ok_or_else(|| anyhow!("module runner requires an armed snapshot"))
    }

    fn resolve(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        kind: ResolutionKind,
        attributes: &ImportAttributes,
    ) -> Result<super::ResolvedModule> {
        let mut resolved = self.resolve_module_meta_for_principal_typed_with_attributes(
            specifier, referrer, None, kind, attributes,
        )?;
        if resolved
            .path
            .as_deref()
            .and_then(Path::extension)
            .and_then(|value| value.to_str())
            .is_some_and(|extension| {
                matches!(
                    extension.to_ascii_lowercase().as_str(),
                    "mjs" | "mts" | "ts" | "tsx" | "jsx"
                )
            })
        {
            resolved.kind = ModuleKind::Esm;
        }
        self.load_authenticated_module_source_for_runner(resolved)
    }

    fn resolve_manifest_builtin_internal(&self, specifier: &str) -> Result<super::ResolvedModule> {
        crate::host::Host::resolve_manifest_builtin_internal(self, specifier)
    }

    fn principal_id(&self, principal: &Principal) -> Result<u32> {
        self.module_runner_principal_id(principal)
    }
}

fn specifier_referrer(referrer: Option<&Path>) -> Option<&Path> {
    referrer
}

const PREPARED_GRAPH_INDEX_SCHEMA_V1: &str = "ibex/prepared-module-graph/1";
const PREPARED_GRAPH_PRODUCER_ID: &str = "ibex-rolldown-module-preparer";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedGraphIndexV1 {
    schema: String,
    entry: SourceId,
    producer_binary_digest: Digest,
    deployment_graph_digest: Digest,
    records: Vec<PreparedGraphRecordIndexV1>,
    carriers: Vec<PreparedGraphCarrierIndexV1>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedGraphRecordIndexV1 {
    source_id: SourceId,
    bindings: Vec<PreparedGraphBindingV1>,
    artifact: ModuleArtifactV1,
    carrier_index: usize,
    entry_id: NonEmptyString,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedGraphBindingV1 {
    specifier: String,
    resolution_kind: ResolutionKind,
    target: SourceId,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedGraphCarrierIndexV1 {
    manifest_file: String,
    bytes_file: String,
}

struct SourceGraphRecordV1 {
    /// Native-only resolver path. This is never serialized into a prepared
    /// artifact or crossed into JavaScript.
    path: PathBuf,
    /// Authenticated VFS display identity. It is diagnostic metadata, never a
    /// cache key or a substitute for `SourceId`.
    source_label: String,
    /// Authenticated virtual filename used by CommonJS and `import.meta` path
    /// observables. Builtins have no file-backed virtual path.
    virtual_path: Option<String>,
    artifact: ModuleArtifactV1,
    bindings: BTreeMap<GraphEdgeKey, SourceId>,
    prepared: Option<PreparedRecordV1>,
}

struct PreparedRecordV1 {
    carrier: Arc<AdmittedPreparedCarrierV1>,
    entry_id: NonEmptyString,
    admission: ArtifactAdmissionV1,
}

pub struct SourceModuleGraphV1 {
    entry: SourceId,
    entry_vfs_source_id: crate::vfs::SourceId,
    snapshot: Arc<ArmedSnapshot>,
    principal_ids: BTreeMap<Principal, u32>,
    producer_binary_digest: Digest,
    records: BTreeMap<SourceId, SourceGraphRecordV1>,
}

impl SourceModuleGraphV1 {
    pub fn entry(&self) -> &SourceId {
        &self.entry
    }

    /// Exact typed VFS identity authenticated by the Host for the entry read.
    /// The graph's portable artifact identity is deliberately separate.
    pub fn entry_vfs_source_id(&self) -> &crate::vfs::SourceId {
        &self.entry_vfs_source_id
    }

    pub fn snapshot(&self) -> &ArmedSnapshot {
        &self.snapshot
    }

    /// Join a post-admission graph back to the exact structured file request
    /// that authorized its discovery. Entry bytes and grammar are checked here
    /// so every engine/preparer pairing shares one fail-closed boundary.
    /// @ref LLP 0026#authenticate-before-discovery-and-execute-under-derived-identity
    /// @ref LLP 0027#canonical-encoding-and-validation
    pub fn validate_authenticated_entry_request(
        &self,
        request: &crate::engine::evaluation::SourceRequest,
    ) -> Result<()> {
        use crate::engine::evaluation::{
            EntryKind, ModuleKind as RequestModuleKind, ParserDialect, SourceGoal, SourceRequest,
            SourceRole,
        };
        use crate::module_loader::artifact::{SourceDialectV1, SourceGoalV1};

        let record = self
            .records
            .get(&self.entry)
            .ok_or_else(|| anyhow!("authenticated native source graph omitted its entry record"))?;
        let entry_artifact = verify_record(record, &self.producer_binary_digest)?.artifact();
        if request.entry_kind() != EntryKind::File {
            bail!("authenticated native source graph requires a file request");
        }
        let SourceRequest::Program(program) = request else {
            bail!("authenticated native source graph requires a program request")
        };
        let expected_goal = match program.module_kind() {
            Some(RequestModuleKind::Esm) if program.goal() == SourceGoal::Module => {
                SourceGoalV1::Module
            }
            Some(RequestModuleKind::CommonJs)
                if program.goal() == SourceGoal::ScriptWithExtensions =>
            {
                SourceGoalV1::CommonJs
            }
            _ => bail!("authenticated file request has no native module grammar"),
        };
        let expected_dialect = match program.dialect() {
            ParserDialect::JavaScript => SourceDialectV1::Js,
            ParserDialect::JavaScriptJsx => SourceDialectV1::Jsx,
            ParserDialect::TypeScript => SourceDialectV1::Ts,
            ParserDialect::TypeScriptJsx => SourceDialectV1::Tsx,
        };

        if entry_artifact.semantics.source_id.0 != self.entry
            || request.source_id() != Some(&self.entry_vfs_source_id)
            || self.snapshot.digest() != request.authenticated_snapshot_digest()
            || self.entry.defining_principal() != Some(request.authenticated_principal())
            || entry_artifact.semantics.source_integrity != *request.source_digest()
        {
            bail!(
                "authenticated native source graph identity changed after the structured request was admitted"
            );
        }
        if !program.is_main()
            || program.role() != SourceRole::Entry
            || entry_artifact.semantics.source_goal != expected_goal
            || entry_artifact.semantics.dialect != Some(expected_dialect)
        {
            bail!("authenticated native source graph grammar differs from the structured request");
        }
        Ok(())
    }

    pub fn plan(&self) -> Result<SynchronousGraphPlan<'_>> {
        SynchronousGraphPlan::new_typed(
            self.records
                .iter()
                .map(|(_, record)| {
                    Ok((
                        verify_record(record, &self.producer_binary_digest)?,
                        record.bindings.clone(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
        )
        .map_err(anyhow::Error::from)
    }

    pub fn records(
        &self,
    ) -> impl Iterator<Item = (&SourceId, &Path, VerifiedModuleArtifactV1<'_>)> {
        self.records.iter().map(|(source_id, record)| {
            (
                source_id,
                record.path.as_path(),
                verify_record(record, &self.producer_binary_digest)
                    .expect("source graph records remain admitted"),
            )
        })
    }

    pub fn prepared_entries(
        &self,
    ) -> Result<Option<BTreeMap<SourceId, VerifiedPreparedCarrierEntryV1<'_>>>> {
        if self
            .records
            .values()
            .all(|record| record.prepared.is_none())
        {
            return Ok(None);
        }
        if self
            .records
            .values()
            .any(|record| record.prepared.is_none())
        {
            bail!("module graph cannot mix inline and prepared factories");
        }
        self.records
            .iter()
            .map(|(source_id, record)| {
                let prepared = record.prepared.as_ref().expect("checked above");
                Ok((
                    source_id.clone(),
                    prepared.carrier.entry(prepared.entry_id.as_str())?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()
            .map(Some)
    }

    pub fn native_execution_inputs(
        &self,
        graph_generation: u64,
    ) -> Result<(
        BTreeMap<SourceId, NativeModuleRecordConfig>,
        BTreeMap<SourceId, super::security::GraphAuthorityContext>,
    )> {
        let principals = self
            .records
            .keys()
            .filter_map(SourceId::defining_principal)
            .cloned()
            .collect::<BTreeSet<_>>();
        if principals != self.principal_ids.keys().cloned().collect() {
            bail!("native source graph principal projection differs from its closed record set");
        }

        let mut configs = BTreeMap::new();
        let mut authority_contexts = BTreeMap::new();
        for (source_id, record) in &self.records {
            let principal = match source_id.defining_principal().cloned() {
                Some(principal) => principal,
                None if matches!(source_id, SourceId::Builtin { .. }) => self
                    .principal_ids
                    .keys()
                    .find(|principal| principal.is_root())
                    .cloned()
                    .ok_or_else(|| anyhow!("builtin graph record has no root runtime owner"))?,
                None => bail!("source graph record has no defining principal"),
            };
            let principal_id = *self
                .principal_ids
                .get(&principal)
                .ok_or_else(|| anyhow!("source graph principal has no runtime projection"))?;
            let compartment_identity = module_runner_compartment_identity(&principal)?;
            let mut config = NativeModuleRecordConfig::new(
                principal_id,
                compartment_identity,
                GraphEvaluationContext::new(
                    source_id.clone(),
                    principal_id,
                    principal_id,
                    [principal_id],
                    graph_generation,
                )?,
                record.source_label.clone(),
                record.source_label.clone(),
            )?;
            if let Some(virtual_path) = record.virtual_path.as_ref() {
                config = config.with_authenticated_virtual_path(virtual_path.clone())?;
            }
            configs.insert(source_id.clone(), config);
            authority_contexts.insert(
                source_id.clone(),
                super::security::GraphAuthorityContext::new(
                    source_id.clone(),
                    principal.clone(),
                    principal.clone(),
                    principal.clone(),
                    vec![principal],
                    Stage::Requested,
                    graph_generation,
                )?,
            );
        }
        Ok((configs, authority_contexts))
    }
}

fn module_runner_compartment_identity(principal: &Principal) -> Result<Option<String>> {
    match principal {
        Principal::Root { .. } => Ok(None),
        Principal::Package { locator, .. } => Ok(Some(locator.as_str().to_owned())),
        _ => bail!("native source graph has a non-module defining principal"),
    }
}

fn verify_record<'a>(
    record: &'a SourceGraphRecordV1,
    producer_binary_digest: &Digest,
) -> Result<VerifiedModuleArtifactV1<'a>> {
    match record.prepared.as_ref() {
        Some(prepared) => record.artifact.verify_for_admission(&prepared.admission),
        None => record
            .artifact
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: record.artifact.semantics.source_id.0.clone(),
                expected_source_integrity: record.artifact.semantics.source_integrity.clone(),
                expected_producer_id: NonEmptyString::new("ibex-runtime-oxc")
                    .map_err(anyhow::Error::msg)?,
                producer_binary_digest: producer_binary_digest.clone(),
                transform_fingerprint_digest: record
                    .artifact
                    .semantics
                    .transform_fingerprint
                    .digest()?,
            }),
    }
}

pub fn build_authenticated_source_graph_v1(
    entry: &Path,
    producer_binary_digest: Digest,
    hermes_target: &str,
) -> Result<SourceModuleGraphBuildV1> {
    build_authenticated_source_graph_v1_with_host(
        &InstalledSourceGraphHost,
        entry,
        producer_binary_digest,
        hermes_target,
    )
}

/// Build through the exact Host retained by an authenticated ingress. Neither
/// graph construction nor later principal projection consults the ambient Host
/// slot, so replacing that slot cannot splice another snapshot into a request.
/// @ref LLP 0026#authenticate-before-discovery-and-execute-under-derived-identity
pub fn build_authenticated_source_graph_v1_for_host(
    host: &crate::host::Host,
    entry: &Path,
    producer_binary_digest: Digest,
    hermes_target: &str,
) -> Result<SourceModuleGraphBuildV1> {
    build_authenticated_source_graph_v1_with_host(
        host,
        entry,
        producer_binary_digest,
        hermes_target,
    )
}

fn build_authenticated_source_graph_v1_with_host(
    host: &impl SourceGraphHost,
    entry: &Path,
    producer_binary_digest: Digest,
    hermes_target: &str,
) -> Result<SourceModuleGraphBuildV1> {
    let snapshot = host.snapshot()?;
    let entry_specifier = entry
        .to_str()
        .ok_or_else(|| anyhow!("module-runner entry path is not UTF-8"))?;
    let entry_module = host.resolve(
        entry_specifier,
        None,
        ResolutionKind::Entry,
        &ImportAttributes::default(),
    )?;
    let entry_vfs_source_id = entry_module
        .source_id
        .clone()
        .ok_or_else(|| anyhow!("authenticated entry resolution produced no VFS SourceId"))?;
    let entry_id = entry_module
        .artifact_source_id
        .clone()
        .ok_or_else(|| anyhow!("authenticated entry resolution produced no SourceId"))?;
    if !entry_id
        .defining_principal()
        .is_some_and(Principal::is_root)
    {
        bail!("authenticated entry is not owned by the project root");
    }
    let mut queue = VecDeque::from([entry_module]);
    let mut records = BTreeMap::new();
    while let Some(module) = queue.pop_front() {
        let source_id = module
            .artifact_source_id
            .clone()
            .ok_or_else(|| anyhow!("authenticated module resolution produced no SourceId"))?;
        if records.contains_key(&source_id) {
            continue;
        }
        let path = match module.path.clone() {
            Some(path) => path,
            None if module.kind == ModuleKind::Builtin => match &source_id {
                SourceId::Builtin { source_key, .. } => {
                    PathBuf::from(format!("builtin:{}.js", source_key.as_str()))
                }
                _ => bail!("builtin module has a non-builtin SourceId"),
            },
            None => bail!("source module has no authenticated path"),
        };
        let (source_label, virtual_path) = if module.kind == ModuleKind::Builtin {
            let SourceId::Builtin { domain, source_key } = &source_id else {
                bail!("builtin module has a non-builtin SourceId");
            };
            (
                format!("builtin:{}:{}", domain.as_str(), source_key.as_str()),
                None,
            )
        } else {
            let source_label = module
                .source_label
                .as_ref()
                .ok_or_else(|| anyhow!("authenticated module has no VFS source label"))?
                .as_str()
                .to_owned();
            let virtual_path = module
                .virtual_path
                .clone()
                .ok_or_else(|| anyhow!("authenticated module has no virtual path"))?;
            let resolver_path = module
                .resolver_path
                .as_ref()
                .ok_or_else(|| anyhow!("authenticated module has no logical resolver path"))?;
            resolver_path
                .validate()
                .map_err(|error| anyhow!("authenticated resolver path is invalid: {error}"))?;
            if resolver_path.virtual_path() != virtual_path
                || !virtual_path.starts_with("/project/")
                || !source_label.starts_with("file:///project/")
            {
                bail!("authenticated module display envelope is inconsistent");
            }
            (source_label, Some(virtual_path))
        };
        let source = module
            .source
            .as_deref()
            .ok_or_else(|| anyhow!("source module has no authenticated bytes"))?;
        let source_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("module");
        let produced = match module.kind {
            ModuleKind::Esm => produce_module_artifact_v1(
                source_id.clone(),
                source_name,
                &path,
                source,
                producer_binary_digest.clone(),
                hermes_target,
            ),
            ModuleKind::CommonJs => produce_commonjs_artifact_v1(
                source_id.clone(),
                source_name,
                &path,
                source,
                producer_binary_digest.clone(),
                hermes_target,
            ),
            ModuleKind::Json => produce_json_artifact_v1(
                source_id.clone(),
                source,
                producer_binary_digest.clone(),
                hermes_target,
            ),
            ModuleKind::Builtin => produce_builtin_artifact_v1(
                source_id.clone(),
                source_name,
                source,
                producer_binary_digest.clone(),
                hermes_target,
            ),
        };
        let artifact = match produced {
            Ok(artifact) => artifact,
            Err(error) => {
                if let Some(reason) = unsupported_module_runner_reason(&error) {
                    return Ok(legacy(reason));
                }
                return Err(error);
            }
        };
        // The native runner currently has only prelinked lookup tables for
        // `require()` and `import()`. Letting either authored edge enter those
        // tables would resolve/read a dead branch and would authorize it before
        // the live caller/scheduler constraint set exists. Keep those shapes on
        // the bounded compatibility loader, whose edge gate runs at the call
        // site, until the native runner owns an in-drive call-time activation
        // capability. This check is deliberately before `artifact_edge_requests`:
        // the deferred target must not be resolved, probed, or read here.
        //
        // Generated builtin fan-out is the one closed exception. It is an exact
        // manifest-owned private implementation dependency, not an authored
        // package edge, and the native callback independently refuses to let
        // that synchronous-initialization exemption escape through a retained
        // `require` closure.
        // @ref LLP 0024#3-source-goal
        // @ref LLP 0026#1-source-admission-and-resolution
        // @ref LLP 0021#module-initialization-and-trusted-source-acquisition
        if !artifact.semantics.dynamic_edges.is_empty() {
            return Ok(legacy(
                "native call-time dynamic-import activation is not yet available",
            ));
        }
        if module.kind != ModuleKind::Builtin
            && artifact
                .semantics
                .static_edges
                .iter()
                .any(|edge| matches!(edge, StaticEdgeV1::CommonJsRequire { .. }))
        {
            return Ok(legacy(
                "native call-time CommonJS require activation is not yet available",
            ));
        }
        let mut bindings = BTreeMap::new();
        for key in artifact_edge_requests(&artifact) {
            let attributes = artifact_edge_attributes(&artifact, &key)?;
            let target = if module.kind == ModuleKind::Builtin {
                if key.resolution_kind != ResolutionKind::CommonJsRequire || !attributes.is_empty()
                {
                    bail!("generated builtin has a non-CommonJS or attributed private edge");
                }
                // Builtin implementation fan-out is not an authored package
                // edge and has no host filesystem referrer. Resolve only the
                // exact generated-manifest spelling; the public edge that
                // admitted this builtin was already policy-gated above.
                // @ref LLP 0026#1-source-admission-and-resolution
                host.resolve_manifest_builtin_internal(&key.specifier)?
            } else {
                host.resolve(
                    &key.specifier,
                    Some(&path),
                    key.resolution_kind,
                    &attributes,
                )?
            };
            let target_id = target
                .artifact_source_id
                .clone()
                .ok_or_else(|| anyhow!("authenticated dependency produced no SourceId"))?;
            if let Some(previous) = bindings.insert(key.clone(), target_id.clone()) {
                if previous != target_id {
                    bail!("one typed authored edge resolved to two SourceIds");
                }
            }
            queue.push_back(target);
        }
        records.insert(
            source_id,
            SourceGraphRecordV1 {
                path,
                source_label,
                virtual_path,
                artifact,
                bindings,
                prepared: None,
            },
        );
    }

    let principals = records
        .keys()
        .filter_map(SourceId::defining_principal)
        .cloned()
        .collect::<BTreeSet<_>>();
    let principal_ids = principals
        .into_iter()
        .map(|principal| {
            let principal_id = host.principal_id(&principal)?;
            Ok((principal, principal_id))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    // Validate the entire closure before the engine can compile one factory.
    let graph = SourceModuleGraphV1 {
        entry: entry_id,
        entry_vfs_source_id,
        snapshot,
        principal_ids,
        producer_binary_digest,
        records,
    };
    graph.plan()?;
    Ok(SourceModuleGraphBuildV1::Native(graph))
}

pub fn prepared_graph_cache_dir(artifact_dir: &Path, deployment_graph_digest: &Digest) -> PathBuf {
    let key = deployment_graph_digest
        .as_str()
        .strip_prefix("sha256-")
        .unwrap_or_else(|| deployment_graph_digest.as_str());
    artifact_dir.join(".module-runner").join(key)
}

struct RenderedPreparedCarrierV1 {
    defining_principal: Principal,
    manifest_file: String,
    manifest_bytes: Vec<u8>,
    bytes_file: String,
    bytes: Vec<u8>,
}

struct RenderedPreparedPublicationV1 {
    index_bytes: Vec<u8>,
    carriers: Vec<RenderedPreparedCarrierV1>,
}

/// Deterministically render the complete prepared publication from an already
/// authenticated inline graph. Reload uses this in-memory rendering as its
/// trust root: no digest or principal asserted by the writable cache is ever
/// allowed to authorize that same cache.
/// @ref LLP 0027#digest-domains — physical carrier bytes remain separately
/// authenticated, while admission is bound to the authenticated source graph.
fn render_prepared_source_graph_v1(
    graph: &SourceModuleGraphV1,
    deployment_graph_digest: &Digest,
) -> Result<RenderedPreparedPublicationV1> {
    if graph
        .records
        .values()
        .any(|record| record.prepared.is_some())
    {
        bail!("only an admitted inline graph can be published as a prepared graph");
    }
    let producer_id =
        NonEmptyString::new(PREPARED_GRAPH_PRODUCER_ID).map_err(anyhow::Error::msg)?;
    let root_principal = graph
        .records
        .keys()
        .filter_map(SourceId::defining_principal)
        .find(|principal| principal.is_root())
        .cloned()
        .ok_or_else(|| anyhow!("prepared graph has no root principal"))?;
    let mut carrier_indexes = BTreeMap::new();
    let mut carrier_index_records = Vec::new();
    let mut rendered_carriers = Vec::new();
    let mut prepared_artifacts = BTreeMap::new();
    for (carrier_index, (source_id, record)) in graph.records.iter().enumerate() {
        let principal = source_id
            .defining_principal()
            .cloned()
            .or_else(|| {
                matches!(source_id, SourceId::Builtin { .. }).then(|| root_principal.clone())
            })
            .ok_or_else(|| anyhow!("prepared carrier record has no defining principal"))?;
        let entry_id = NonEmptyString::new(record.artifact.semantic_digest.as_str())
            .map_err(anyhow::Error::msg)?;
        let (manifest, bytes) = PreparedModuleCarrierV1::from_inline_artifacts(
            principal.clone(),
            producer_id.clone(),
            graph.producer_binary_digest.clone(),
            deployment_graph_digest.clone(),
            [(
                entry_id.clone(),
                verify_record(record, &graph.producer_binary_digest)?,
            )],
        )?;
        let manifest_file = format!("carrier-{carrier_index}.json");
        let bytes_file = format!("carrier-{carrier_index}.js");
        prepared_artifacts.insert(
            source_id.clone(),
            (manifest.prepared_artifact(entry_id.as_str())?, entry_id),
        );
        carrier_indexes.insert(source_id.clone(), carrier_index);
        carrier_index_records.push(PreparedGraphCarrierIndexV1 {
            manifest_file: manifest_file.clone(),
            bytes_file: bytes_file.clone(),
        });
        rendered_carriers.push(RenderedPreparedCarrierV1 {
            defining_principal: principal,
            manifest_file,
            manifest_bytes: manifest.encode_canonical()?,
            bytes_file,
            bytes,
        });
    }

    let records = graph
        .records
        .iter()
        .map(|(source_id, record)| {
            let carrier_index = *carrier_indexes
                .get(source_id)
                .ok_or_else(|| anyhow!("prepared record has no carrier"))?;
            let (artifact, entry_id) = prepared_artifacts
                .remove(source_id)
                .ok_or_else(|| anyhow!("prepared artifact was not produced"))?;
            Ok(PreparedGraphRecordIndexV1 {
                source_id: source_id.clone(),
                bindings: record
                    .bindings
                    .iter()
                    .map(|(key, target)| PreparedGraphBindingV1 {
                        specifier: key.specifier.clone(),
                        resolution_kind: key.resolution_kind,
                        target: target.clone(),
                    })
                    .collect(),
                artifact,
                carrier_index,
                entry_id,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let index = PreparedGraphIndexV1 {
        schema: PREPARED_GRAPH_INDEX_SCHEMA_V1.into(),
        entry: graph.entry.clone(),
        producer_binary_digest: graph.producer_binary_digest.clone(),
        deployment_graph_digest: deployment_graph_digest.clone(),
        records,
        carriers: carrier_index_records,
    };
    let index_bytes = capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(index)?)
        .map_err(|error| anyhow!("cannot canonicalize prepared graph index: {error}"))?;
    Ok(RenderedPreparedPublicationV1 {
        index_bytes,
        carriers: rendered_carriers,
    })
}

/// Publish one immutable, principal-bound JavaScript carrier per original
/// record beside the
/// existing Rolldown artifact. The hidden directory is excluded from the
/// legacy output inventory but remains under the same cache lease and graph
/// digest. Publication is directory-atomic.
pub fn publish_prepared_source_graph_v1(
    graph: &SourceModuleGraphV1,
    artifact_dir: &Path,
    deployment_graph_digest: Digest,
) -> Result<PathBuf> {
    let destination = prepared_graph_cache_dir(artifact_dir, &deployment_graph_digest);
    if destination.join("index.json").is_file() {
        return Ok(destination);
    }
    let publication = render_prepared_source_graph_v1(graph, &deployment_graph_digest)?;
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("prepared graph cache has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let staging = parent.join(format!(
        ".stage-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir(&staging)?;

    let result = (|| -> Result<()> {
        for carrier in &publication.carriers {
            std::fs::write(
                staging.join(&carrier.manifest_file),
                &carrier.manifest_bytes,
            )?;
            std::fs::write(staging.join(&carrier.bytes_file), &carrier.bytes)?;
        }
        std::fs::write(staging.join("index.json"), &publication.index_bytes)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error);
    }
    match std::fs::rename(&staging, &destination) {
        Ok(()) => Ok(destination),
        Err(error) if destination.join("index.json").is_file() => {
            let _ = std::fs::remove_dir_all(&staging);
            Ok(destination)
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(&staging);
            Err(error.into())
        }
    }
}

fn read_authenticated_prepared_file(path: &Path, expected: &[u8], role: &str) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // O_NONBLOCK prevents a hostile FIFO from hanging before metadata can
        // reject it; it does not change regular-file reads.
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let mut file = options
        .open(path)
        .map_err(|error| anyhow!("cannot open prepared {role} {}: {error}", path.display()))?;
    let before = file.metadata().map_err(|error| {
        anyhow!(
            "cannot inspect opened prepared {role} {}: {error}",
            path.display()
        )
    })?;
    let expected_len = u64::try_from(expected.len())
        .map_err(|_| anyhow!("authenticated prepared {role} length is unsupported"))?;
    if !before.is_file() || before.len() != expected_len {
        bail!(
            "prepared {role} is not an exact-size regular file: {}",
            path.display()
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if before.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("prepared {role} is a reparse point: {}", path.display());
        }
    }

    let mut bytes = vec![0; expected.len()];
    file.read_exact(&mut bytes).map_err(|error| {
        anyhow!(
            "cannot read exact authenticated prepared {role} {}: {error}",
            path.display()
        )
    })?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing).map_err(|error| {
        anyhow!(
            "cannot finish authenticated prepared {role} {}: {error}",
            path.display()
        )
    })? != 0
    {
        bail!("prepared {role} grew while it was read: {}", path.display());
    }
    let after = file.metadata().map_err(|error| {
        anyhow!(
            "cannot re-inspect opened prepared {role} {}: {error}",
            path.display()
        )
    })?;
    if !after.is_file() || after.len() != expected_len || bytes != expected {
        bail!(
            "prepared {role} does not match the authenticated source graph: {}",
            path.display()
        );
    }
    Ok(bytes)
}

pub fn load_prepared_source_graph_v1(
    cache_dir: &Path,
    authenticated_source_graph: &SourceModuleGraphV1,
    expected_deployment_graph_digest: &Digest,
) -> Result<SourceModuleGraphV1> {
    let expected = render_prepared_source_graph_v1(
        authenticated_source_graph,
        expected_deployment_graph_digest,
    )?;
    // The writable cache is acceleration only. Retain each expected file once
    // through a no-follow, regular-file, exact-size descriptor and use those
    // authenticated owned bytes for every later admission step.
    // @ref LLP 0027#canonical-encoding-and-validation
    let index_bytes = read_authenticated_prepared_file(
        &cache_dir.join("index.json"),
        &expected.index_bytes,
        "graph index",
    )?;
    let mut expected_files = BTreeSet::from(["index.json".to_owned()]);
    let mut retained_carrier_files = BTreeMap::new();
    for carrier in &expected.carriers {
        expected_files.insert(carrier.manifest_file.clone());
        expected_files.insert(carrier.bytes_file.clone());
        let manifest_bytes = read_authenticated_prepared_file(
            &cache_dir.join(&carrier.manifest_file),
            &carrier.manifest_bytes,
            "carrier manifest",
        )?;
        let carrier_bytes = read_authenticated_prepared_file(
            &cache_dir.join(&carrier.bytes_file),
            &carrier.bytes,
            "carrier bytes",
        )?;
        if retained_carrier_files
            .insert(carrier.manifest_file.clone(), manifest_bytes)
            .is_some()
            || retained_carrier_files
                .insert(carrier.bytes_file.clone(), carrier_bytes)
                .is_some()
        {
            bail!("prepared carrier publication repeats a filename");
        }
    }
    let actual_files = std::fs::read_dir(cache_dir)?
        .map(|entry| {
            let entry = entry?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("prepared cache contains a non-UTF-8 filename"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if actual_files != expected_files {
        bail!("prepared cache file inventory differs from its authenticated publication");
    }
    let text = std::str::from_utf8(&index_bytes)?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|error| anyhow!("prepared graph index is not strict JSON: {error}"))?;
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
        .map_err(|error| anyhow!("cannot canonicalize prepared graph index: {error}"))?;
    if canonical != index_bytes {
        bail!("prepared graph index is not canonical JCS");
    }
    let index: PreparedGraphIndexV1 = serde_json::from_value(value)?;
    if index.schema != PREPARED_GRAPH_INDEX_SCHEMA_V1
        || index.producer_binary_digest != authenticated_source_graph.producer_binary_digest
        || &index.deployment_graph_digest != expected_deployment_graph_digest
    {
        bail!("prepared graph index schema, producer, or deployment graph is stale");
    }
    if index.records.is_empty() || index.carriers.is_empty() {
        bail!("prepared graph index is empty");
    }
    let authorized_semantic_digests = authenticated_source_graph
        .records
        .values()
        .map(|record| record.artifact.semantic_digest.clone())
        .collect::<BTreeSet<_>>();
    let producer_id =
        NonEmptyString::new(PREPARED_GRAPH_PRODUCER_ID).map_err(anyhow::Error::msg)?;
    let mut carriers = Vec::with_capacity(index.carriers.len());
    for (carrier_index, carrier) in index.carriers.iter().enumerate() {
        if carrier.manifest_file.contains('/')
            || carrier.manifest_file.contains('\\')
            || carrier.bytes_file.contains('/')
            || carrier.bytes_file.contains('\\')
        {
            bail!("prepared carrier filename escapes its cache directory");
        }
        let manifest_bytes = retained_carrier_files
            .get(&carrier.manifest_file)
            .ok_or_else(|| anyhow!("prepared carrier manifest was not retained"))?;
        let carrier_bytes = retained_carrier_files
            .get(&carrier.bytes_file)
            .ok_or_else(|| anyhow!("prepared carrier bytes were not retained"))?;
        let expected_carrier = expected
            .carriers
            .get(carrier_index)
            .ok_or_else(|| anyhow!("prepared graph names an unexpected carrier"))?;
        let admission = PreparedCarrierAdmissionV1 {
            expected_principal: expected_carrier.defining_principal.clone(),
            expected_producer_id: producer_id.clone(),
            producer_binary_digest: authenticated_source_graph.producer_binary_digest.clone(),
            deployment_graph_digest: expected_deployment_graph_digest.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            expected_engine_binary_digest: None,
            expected_bytecode_version: None,
        };
        carriers.push(Arc::new(AdmittedPreparedCarrierV1::decode_and_admit(
            manifest_bytes,
            carrier_bytes,
            &admission,
        )?));
    }

    let mut records = BTreeMap::new();
    for indexed in index.records {
        if records.contains_key(&indexed.source_id) {
            bail!("prepared graph repeats a SourceId");
        }
        if indexed.artifact.semantics.source_id.0 != indexed.source_id {
            bail!("prepared graph record identity disagrees with its artifact");
        }
        let trusted_record = authenticated_source_graph
            .records
            .get(&indexed.source_id)
            .ok_or_else(|| anyhow!("prepared graph record is absent from authenticated source"))?;
        let carrier = carriers
            .get(indexed.carrier_index)
            .cloned()
            .ok_or_else(|| anyhow!("prepared graph record names an absent carrier"))?;
        let carrier_manifest = carrier.manifest();
        let admission = ArtifactAdmissionV1::DigestBoundPrepared {
            expected_source_id: indexed.source_id.clone(),
            expected_source_integrity: trusted_record.artifact.semantics.source_integrity.clone(),
            expected_producer_id: producer_id.clone(),
            producer_binary_digest: authenticated_source_graph.producer_binary_digest.clone(),
            deployment_graph_digest: expected_deployment_graph_digest.clone(),
            expected_carrier_digest: carrier_manifest.carrier_digest.clone(),
            expected_entry_id: indexed.entry_id.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            transform_fingerprint_digest: trusted_record
                .artifact
                .semantics
                .transform_fingerprint
                .digest()?,
        };
        indexed.artifact.verify_for_admission(&admission)?;
        carrier.entry(indexed.entry_id.as_str())?;
        records.insert(
            indexed.source_id,
            SourceGraphRecordV1 {
                path: trusted_record.path.clone(),
                source_label: trusted_record.source_label.clone(),
                virtual_path: trusted_record.virtual_path.clone(),
                artifact: indexed.artifact,
                bindings: trusted_record.bindings.clone(),
                prepared: Some(PreparedRecordV1 {
                    carrier,
                    entry_id: indexed.entry_id,
                    admission,
                }),
            },
        );
    }
    let graph = SourceModuleGraphV1 {
        entry: authenticated_source_graph.entry.clone(),
        entry_vfs_source_id: authenticated_source_graph.entry_vfs_source_id.clone(),
        snapshot: authenticated_source_graph.snapshot.clone(),
        principal_ids: authenticated_source_graph.principal_ids.clone(),
        producer_binary_digest: authenticated_source_graph.producer_binary_digest.clone(),
        records,
    };
    graph.plan()?;
    if !graph.records.contains_key(graph.entry()) {
        bail!("prepared graph entry is absent");
    }
    Ok(graph)
}

fn legacy(reason: impl Into<String>) -> SourceModuleGraphBuildV1 {
    SourceModuleGraphBuildV1::LegacyRequired(LegacyModuleRunnerRequirement {
        reason: reason.into(),
    })
}

fn artifact_edge_requests(artifact: &ModuleArtifactV1) -> Vec<GraphEdgeKey> {
    let mut requests = Vec::new();
    for edge in &artifact.semantics.static_edges {
        let specifier = match edge {
            StaticEdgeV1::CommonJsRequire { specifier }
            | StaticEdgeV1::SideEffect { specifier, .. }
            | StaticEdgeV1::Default { specifier, .. }
            | StaticEdgeV1::Namespace { specifier, .. }
            | StaticEdgeV1::Named { specifier, .. }
            | StaticEdgeV1::ReExportNamed { specifier, .. }
            | StaticEdgeV1::ReExportStar { specifier, .. }
            | StaticEdgeV1::ReExportNamespace { specifier, .. } => specifier,
        };
        requests.push(GraphEdgeKey::new(
            specifier.as_str().to_owned(),
            if matches!(edge, StaticEdgeV1::CommonJsRequire { .. }) {
                ResolutionKind::CommonJsRequire
            } else {
                ResolutionKind::EsmStatic
            },
        ));
    }
    for edge in &artifact.semantics.dynamic_edges {
        match edge {
            DynamicEdgeV1::Literal { specifier, .. } => requests.push(GraphEdgeKey::new(
                specifier.as_str(),
                ResolutionKind::DynamicImport,
            )),
            DynamicEdgeV1::Computed { .. } => {}
        }
    }
    requests
}

fn artifact_edge_attributes(
    artifact: &ModuleArtifactV1,
    key: &GraphEdgeKey,
) -> Result<super::identity::ImportAttributes> {
    let mut matches = Vec::new();
    for edge in &artifact.semantics.static_edges {
        let (specifier, resolution_kind, attributes) = match edge {
            StaticEdgeV1::CommonJsRequire { specifier } => (
                specifier.as_str(),
                ResolutionKind::CommonJsRequire,
                super::identity::ImportAttributes::default(),
            ),
            StaticEdgeV1::SideEffect { attributes, .. }
            | StaticEdgeV1::Default { attributes, .. }
            | StaticEdgeV1::Namespace { attributes, .. }
            | StaticEdgeV1::Named { attributes, .. }
            | StaticEdgeV1::ReExportNamed { attributes, .. }
            | StaticEdgeV1::ReExportStar { attributes, .. }
            | StaticEdgeV1::ReExportNamespace { attributes, .. } => (
                match edge {
                    StaticEdgeV1::SideEffect { specifier, .. }
                    | StaticEdgeV1::Default { specifier, .. }
                    | StaticEdgeV1::Namespace { specifier, .. }
                    | StaticEdgeV1::Named { specifier, .. }
                    | StaticEdgeV1::ReExportNamed { specifier, .. }
                    | StaticEdgeV1::ReExportStar { specifier, .. }
                    | StaticEdgeV1::ReExportNamespace { specifier, .. } => specifier.as_str(),
                    StaticEdgeV1::CommonJsRequire { .. } => unreachable!(),
                },
                ResolutionKind::EsmStatic,
                attributes.clone(),
            ),
        };
        if specifier == key.specifier && resolution_kind == key.resolution_kind {
            matches.push(attributes);
        }
    }
    for edge in &artifact.semantics.dynamic_edges {
        if let DynamicEdgeV1::Literal {
            specifier,
            attributes,
        } = edge
        {
            if specifier.as_str() == key.specifier
                && key.resolution_kind == ResolutionKind::DynamicImport
            {
                matches.push(attributes.clone());
            }
        }
    }
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [attributes] => Ok(attributes.clone()),
        [] => bail!("typed artifact edge has no import-attribute record"),
        _ => bail!("one typed artifact edge spelling has conflicting import attributes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn armed_file_host(project_root: &Path) -> crate::host::Host {
        use capsec_semantics::arming::{
            ArmedEntry, ArmedEntryKind, ArmedExecutionMode, ArmedRootBinding, ArmedSnapshot,
            ExpectedArmingIdentity, ExpectedProtectedArtifact, ProtectedArtifactRole,
        };
        use capsec_semantics::model::{Digest, LogicalPath, LogicalRoot, PathComponent};

        let absolute_path = |path: &Path| LogicalPath {
            root: LogicalRoot::Absolute,
            components: path
                .components()
                .filter_map(|component| match component {
                    std::path::Component::Normal(component) => Some(
                        PathComponent::utf8(component.to_str().expect("test path is UTF-8"))
                            .unwrap(),
                    ),
                    _ => None,
                })
                .collect(),
            host_bound: Some(true),
        };
        let project_root = std::fs::canonicalize(project_root).unwrap();
        let package_root = project_root.join("node_modules/image-lib");
        std::fs::create_dir_all(&package_root).unwrap();

        let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        value["workflow"] = serde_json::json!("production");
        value["effectiveMode"] = serde_json::json!("enforce");
        value["entry"] = serde_json::to_value(ArmedEntry {
            kind: ArmedEntryKind::File,
            identity: NonEmptyString::new("file:///project/entry.mjs").unwrap(),
            mode: ArmedExecutionMode::Program,
        })
        .unwrap();

        let project_path = serde_json::to_value(absolute_path(&project_root)).unwrap();
        let package_path = serde_json::to_value(absolute_path(&package_root)).unwrap();
        let project_object = crate::host::object_identity_for_host_path(&project_root).unwrap();
        let package_object = crate::host::object_identity_for_host_path(&package_root).unwrap();
        for binding in value["rootBindings"].as_array_mut().unwrap() {
            if binding["logicalRoot"] == "project" {
                binding["hostPath"] = project_path.clone();
                binding["object"] = serde_json::to_value(&project_object).unwrap();
            } else if binding["logicalRoot"] == "package" {
                binding["hostPath"] = package_path.clone();
                binding["object"] = serde_json::to_value(&package_object).unwrap();
            }
        }
        value["projectRootDiscovery"] = serde_json::json!({
            "origin": project_path,
            "selectedRoot": project_path,
            "markerKind": "explicit-project",
            "markerPath": project_path,
            "markerSetVersion": capsec_semantics::arming::PROJECT_ROOT_MARKER_SET_VERSION,
        });

        let root_bindings = value["rootBindings"].as_array().unwrap().clone();
        let project_components = root_bindings
            .iter()
            .find(|binding| binding["logicalRoot"] == "project")
            .unwrap()["hostPath"]["components"]
            .as_array()
            .unwrap()
            .clone();
        for node in value["packageGraph"]["nodes"].as_array_mut().unwrap() {
            let principal = node["principal"].clone();
            let binding = root_bindings
                .iter()
                .find(|binding| binding.get("owner") == Some(&principal))
                .unwrap();
            let package_components = binding["hostPath"]["components"].as_array().unwrap();
            let (logical_root, relative) = package_components
                .strip_prefix(project_components.as_slice())
                .map(|relative| ("project", relative.to_vec()))
                .unwrap_or_else(|| ("package", Vec::new()));
            node["resolvingSpecifier"] = principal["name"].clone();
            node["rootObject"] = binding["object"].clone();
            node["virtualAliases"] = serde_json::json!([{
                "root": logical_root,
                "components": relative,
            }]);
            node["platformDisposition"] = serde_json::json!("required");
        }
        let authored_edges = value["packageGraph"]["importEdges"]
            .as_array()
            .unwrap()
            .clone();
        let mut typed_edges = Vec::new();
        for edge in authored_edges {
            let request = edge["imported"]["name"].as_str().unwrap();
            for (kind, conditions) in [
                ("common-js-require", vec!["node", "require"]),
                ("dynamic-import", vec!["import", "node"]),
                ("esm-static", vec!["import", "node"]),
            ] {
                typed_edges.push(serde_json::json!({
                    "importer": edge["importer"],
                    "imported": edge["imported"],
                    "requestSpecifier": request,
                    "resolutionKind": kind,
                    "conditions": conditions,
                    "attributes": {},
                }));
            }
        }
        value["packageGraph"]["importEdges"] = serde_json::Value::Array(typed_edges);
        value["packageGraph"]["digest"] = serde_json::Value::String(
            capsec_semantics::digest::compute_domain_digest(
                "ibex:capsec:package-graph:1",
                &value["packageGraph"],
                &["digest".to_owned()],
            )
            .unwrap(),
        );
        let bindings: Vec<ArmedRootBinding> =
            serde_json::from_value(value["rootBindings"].clone()).unwrap();
        value["pathCanonicalizers"] = serde_json::to_value(
            capsec_semantics::path_alias::contract_fixture_canonicalizer_rows(
                bindings
                    .iter()
                    .map(|binding| (binding.object.platform, binding.object.volume.clone())),
            )
            .unwrap(),
        )
        .unwrap();
        value["armedSnapshotDigest"] = serde_json::Value::String(
            capsec_semantics::digest::compute_checked_contract_digest(
                capsec_semantics::digest::DigestKind::ArmedSnapshot,
                &value,
            )
            .unwrap(),
        );

        let digest_at = |path: &[&str]| {
            let field = path
                .iter()
                .fold(&value, |current, segment| &current[*segment]);
            Digest::new(field.as_str().unwrap()).unwrap()
        };
        let protected_artifacts = value["protectedObjects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let role: ProtectedArtifactRole =
                    serde_json::from_value(row["role"].clone()).unwrap();
                let content_digest = match role {
                    ProtectedArtifactRole::EngineBinary => digest_at(&["engine", "binaryDigest"]),
                    ProtectedArtifactRole::ExactOperationManifest => {
                        digest_at(&["exactEmbedder", "operationManifestDigest"])
                    }
                    ProtectedArtifactRole::ExactWebgpuProfile => {
                        digest_at(&["exactGpuProvider", "profileDigest"])
                    }
                    ProtectedArtifactRole::ArmedPolicy => digest_at(&["policyDigest"]),
                    ProtectedArtifactRole::PackageGraph => digest_at(&["packageGraph", "digest"]),
                    ProtectedArtifactRole::Registry => digest_at(&["registryDigest"]),
                };
                ExpectedProtectedArtifact {
                    role,
                    host_path: serde_json::from_value(serde_json::json!({
                        "root": "absolute",
                        "components": [
                            {"encoding": "utf8", "value": "fixture"},
                            {"encoding": "utf8", "value": row["role"].as_str().unwrap()},
                        ],
                        "hostBound": true,
                    }))
                    .unwrap(),
                    object: serde_json::from_value(row["object"].clone()).unwrap(),
                    content_digest,
                }
            })
            .collect();
        let expected = ExpectedArmingIdentity {
            profile: value["capsVocab"].as_str().unwrap().into(),
            semantic_core: value["semanticCore"].as_str().unwrap().into(),
            vocab_digest: digest_at(&["vocabDigest"]),
            registry_digest: digest_at(&["registryDigest"]),
            policy_digest: digest_at(&["policyDigest"]),
            armed_snapshot_digest: digest_at(&["armedSnapshotDigest"]),
            target: value["engine"]["target"].as_str().unwrap().into(),
            engine_binary_digest: digest_at(&["engine", "binaryDigest"]),
            features: value["engine"]["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            entry: serde_json::from_value(value["entry"].clone()).unwrap(),
            project_root_discovery: serde_json::from_value(value["projectRootDiscovery"].clone())
                .unwrap(),
            path_canonicalizers: serde_json::from_value(value["pathCanonicalizers"].clone())
                .unwrap(),
            protected_artifacts,
        };
        let snapshot =
            ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap();
        // SAFETY: the fixture authenticates its complete snapshot immediately
        // above and substitutes only the test target-cell advertisement.
        unsafe {
            crate::host::Host::new_armed_for_test(
                crate::host::HostConfig {
                    mode: crate::host::SecurityMode::Enforce,
                    ..Default::default()
                },
                Arc::new(snapshot),
            )
        }
        .unwrap()
    }

    #[cfg(unix)]
    fn authenticated_file_request(
        host: &crate::host::Host,
    ) -> crate::engine::evaluation::SourceRequest {
        let vfs = host.virtual_file_system().unwrap();
        let entry = vfs
            .resolve_root_file_url("file:///project/entry.mjs", None)
            .unwrap();
        let session = host.mint_armed_session_token().unwrap();
        let mut sequence = crate::engine::evaluation::SubmissionSequence::new(session).unwrap();
        let submission = sequence
            .mint_file(entry.logical_referrer().unwrap(), &[])
            .unwrap();
        let request = host
            .authenticated_vfs_file_read(&vfs, entry, submission)
            .unwrap()
            .into_capsule()
            .into_request()
            .unwrap();
        vfs.close();
        request
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_entry_request_validation_rejects_substituted_bytes() {
        let project = tempfile::tempdir().unwrap();
        let entry = project.path().join("entry.mjs");
        std::fs::write(&entry, "export const value = 1;\n").unwrap();
        let entry = std::fs::canonicalize(entry).unwrap();
        let host = armed_file_host(project.path());
        let request = authenticated_file_request(&host);
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let mut graph = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest.clone(),
            "hermes-test",
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "test graph unexpectedly required legacy: {}",
                    requirement.reason
                )
            }
        };
        graph
            .validate_authenticated_entry_request(&request)
            .unwrap();

        let entry_id = graph.entry.clone();
        let (source_label, source_path) = {
            let record = graph.records.get(&entry_id).unwrap();
            (record.source_label.clone(), record.path.clone())
        };
        graph.records.get_mut(&entry_id).unwrap().artifact = produce_module_artifact_v1(
            entry_id.clone(),
            &source_label,
            &source_path,
            "export const value = 2;\n",
            producer_digest,
            "hermes-test",
        )
        .unwrap();
        graph.plan().unwrap();
        let error = graph
            .validate_authenticated_entry_request(&request)
            .expect_err("an internally valid graph substituted different entry bytes");
        assert!(
            error
                .to_string()
                .contains("identity changed after the structured request"),
            "unexpected integrity-join refusal: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_entry_request_validation_rejects_substituted_grammar() {
        let project = tempfile::tempdir().unwrap();
        let entry = project.path().join("entry.mjs");
        let source = "process.exitCode = 0;\n";
        std::fs::write(&entry, source).unwrap();
        let entry = std::fs::canonicalize(entry).unwrap();
        let host = armed_file_host(project.path());
        let request = authenticated_file_request(&host);
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let mut graph = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest.clone(),
            "hermes-test",
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "test graph unexpectedly required legacy: {}",
                    requirement.reason
                )
            }
        };
        graph
            .validate_authenticated_entry_request(&request)
            .unwrap();

        let entry_id = graph.entry.clone();
        let (source_label, source_path) = {
            let record = graph.records.get(&entry_id).unwrap();
            (record.source_label.clone(), record.path.clone())
        };
        graph.records.get_mut(&entry_id).unwrap().artifact = produce_commonjs_artifact_v1(
            entry_id.clone(),
            &source_label,
            &source_path,
            source,
            producer_digest,
            "hermes-test",
        )
        .unwrap();
        let entry_artifact = graph
            .records()
            .find(|(source_id, _, _)| *source_id == graph.entry())
            .unwrap()
            .2;
        assert_eq!(
            entry_artifact.artifact().semantics.source_integrity,
            *request.source_digest()
        );
        assert_eq!(
            entry_artifact.artifact().semantics.source_goal,
            super::super::artifact::SourceGoalV1::CommonJs
        );
        graph.plan().unwrap();
        let error = graph
            .validate_authenticated_entry_request(&request)
            .expect_err("an internally valid graph substituted CommonJS entry grammar");
        assert!(
            error
                .to_string()
                .contains("grammar differs from the structured request"),
            "unexpected grammar-join refusal: {error:#}"
        );
    }

    #[test]
    fn checked_in_schema_names_the_prepared_graph_envelope() {
        let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../schemas/prepared-module-graph-v1.schema.json"
        ))
        .unwrap();
        assert_eq!(
            schema["properties"]["schema"]["const"],
            PREPARED_GRAPH_INDEX_SCHEMA_V1
        );
        assert_eq!(schema["additionalProperties"], false);
    }

    #[test]
    fn prepared_cache_reader_requires_exact_authenticated_regular_file_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("carrier.bin");
        std::fs::write(&path, b"authenticated-carrier").unwrap();
        assert_eq!(
            read_authenticated_prepared_file(&path, b"authenticated-carrier", "test carrier")
                .unwrap(),
            b"authenticated-carrier"
        );
        assert!(
            read_authenticated_prepared_file(&path, b"authenticated-carrieR", "test carrier")
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
        assert!(read_authenticated_prepared_file(
            &path,
            b"authenticated-carrier-too-long",
            "test carrier"
        )
        .unwrap_err()
        .to_string()
        .contains("exact-size regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_cache_reader_rejects_symlinks_and_fifos_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.bin");
        let link = directory.path().join("link.bin");
        std::fs::write(&target, b"same").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_authenticated_prepared_file(&link, b"same", "test symlink").is_err());

        let fifo = directory.path().join("carrier.fifo");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo_path` is a live NUL-terminated path and mode 0600 has
        // no platform-specific pointer or lifetime requirements.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        assert!(read_authenticated_prepared_file(&fifo, b"same", "test fifo").is_err());
    }

    #[test]
    fn import_attributes_are_recovered_for_typed_authenticated_resolution() {
        let artifact = produce_module_artifact_v1(
            SourceId::synthetic("runner-pipeline-test", "entry.mjs").unwrap(),
            "entry.mjs",
            Path::new("entry.mjs"),
            "import value from './value.json' with { type: 'json' }; export { value };",
            super::super::artifact::source_integrity(b"producer").unwrap(),
            "hermes-test",
        )
        .unwrap();
        let key = artifact_edge_requests(&artifact).remove(0);
        assert!(artifact_edge_attributes(&artifact, &key)
            .unwrap()
            .asserts_json());
    }

    #[test]
    fn package_compartment_identity_is_the_authenticated_locator() {
        let package = Principal::Package {
            name: NonEmptyString::new("image-lib").unwrap(),
            integrity: Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned())
                .unwrap(),
            locator: capsec_semantics::model::PackageLocator::new("image-lib@2.4.1").unwrap(),
        };
        assert_eq!(
            module_runner_compartment_identity(&package)
                .unwrap()
                .as_deref(),
            Some("image-lib@2.4.1")
        );
        let root = Principal::Root {
            identity: NonEmptyString::new("project-root").unwrap(),
        };
        assert_eq!(module_runner_compartment_identity(&root).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn source_graph_retains_build_host_across_ambient_host_swap() {
        struct ResetAmbientHost;
        impl Drop for ResetAmbientHost {
            fn drop(&mut self) {
                crate::host::abi::install_host(crate::host::Host::strict());
            }
        }

        let _host_lock = crate::host::abi::host_test_lock();
        let _reset = ResetAmbientHost;
        let project = tempfile::tempdir().unwrap();
        let entry = project.path().join("entry.mjs");
        std::fs::write(&entry, "export const host = 'a';\n").unwrap();
        let entry = std::fs::canonicalize(entry).unwrap();
        let host_a = armed_file_host(project.path());
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let graph = match build_authenticated_source_graph_v1_for_host(
            &host_a,
            &entry,
            producer_digest.clone(),
            "hermes-test",
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "test graph unexpectedly required legacy execution: {}",
                    requirement.reason
                )
            }
        };
        let host_a_snapshot_digest = graph.snapshot().digest().clone();
        let (before_swap, _) = graph.native_execution_inputs(7).unwrap();
        let before_swap = before_swap.get(graph.entry()).unwrap();
        assert_eq!(before_swap.principal_id, 0);
        assert_eq!(before_swap.evaluation_context.graph_generation, 7);

        crate::host::abi::install_host(crate::host::Host::strict());
        let ambient_error =
            match build_authenticated_source_graph_v1(&entry, producer_digest, "hermes-test") {
                Err(error) => error,
                Ok(_) => panic!("closed ambient Host B unexpectedly built a source graph"),
            };
        assert!(
            ambient_error
                .to_string()
                .contains("module runner requires an armed snapshot"),
            "unexpected ambient Host B error: {ambient_error:#}"
        );

        let (after_swap, _) = graph.native_execution_inputs(11).unwrap();
        let after_swap = after_swap.get(graph.entry()).unwrap();
        assert_eq!(graph.snapshot().digest(), &host_a_snapshot_digest);
        assert_eq!(after_swap.principal_id, before_swap.principal_id);
        assert_eq!(
            after_swap.evaluation_context.requesting_record,
            before_swap.evaluation_context.requesting_record
        );
        assert_eq!(after_swap.evaluation_context.graph_generation, 11);
    }

    #[cfg(unix)]
    #[test]
    fn authored_deferred_edges_select_legacy_before_a_dead_target_can_be_probed() {
        let project = tempfile::tempdir().unwrap();
        let module_entry = project.path().join("entry.mjs");
        let commonjs_entry = project.path().join("entry.cjs");
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"deferred-edge-test","private":true,"type":"module"}"#,
        )
        .unwrap();
        let host = armed_file_host(project.path());
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();

        let assert_legacy_without_target = |entry: &Path, source: &str, expected_reason: &str| {
            std::fs::write(&entry, source).unwrap();
            let entry = std::fs::canonicalize(&entry).unwrap();
            match build_authenticated_source_graph_v1_for_host(
                &host,
                &entry,
                producer_digest.clone(),
                "hermes-test",
            )
            .unwrap()
            {
                SourceModuleGraphBuildV1::LegacyRequired(requirement) => assert!(
                    requirement.reason.contains(expected_reason),
                    "unexpected fallback reason: {}",
                    requirement.reason
                ),
                SourceModuleGraphBuildV1::Native(_) => {
                    panic!("an authored deferred edge entered the eager native graph")
                }
            }
        };

        assert_legacy_without_target(
            &module_entry,
            "if (false) import('./missing-dynamic.mjs');\nexport const reached = true;\n",
            "dynamic-import activation",
        );
        assert_legacy_without_target(
            &commonjs_entry,
            "if (false) require('./missing-require.cjs');\nmodule.exports = true;\n",
            "CommonJS require activation",
        );
        assert_legacy_without_target(
            &commonjs_entry,
            "const path = require('node:path');\nmodule.exports = path.sep;\n",
            "CommonJS require activation",
        );

        std::fs::write(
            project.path().join("dep.cjs"),
            "if (false) require('./missing-from-dependency.cjs');\nmodule.exports = 1;\n",
        )
        .unwrap();
        assert_legacy_without_target(
            &module_entry,
            "import value from './dep.cjs';\nexport { value };\n",
            "CommonJS require activation",
        );

        std::fs::write(
            project.path().join("dep-dynamic.mjs"),
            "if (false) import('./missing-from-dependency.mjs');\nexport const value = 2;\n",
        )
        .unwrap();
        assert_legacy_without_target(
            &module_entry,
            "import { value } from './dep-dynamic.mjs';\nexport { value };\n",
            "dynamic-import activation",
        );

        // Static declarations remain the preflight boundary. A missing static
        // target must still be resolved and refused instead of being hidden by
        // the deferred-edge compatibility guard.
        std::fs::write(&module_entry, "import './missing-static.mjs';\n").unwrap();
        let entry = std::fs::canonicalize(&module_entry).unwrap();
        let error = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest,
            "hermes-test",
        ) {
            Err(error) => error,
            Ok(_) => panic!("a missing static declaration did not fail graph preflight"),
        };
        assert!(
            error.to_string().contains("missing-static")
                || error.to_string().contains("Cannot find module")
                || error.to_string().contains("cannot resolve"),
            "unexpected static-edge error: {error:#}"
        );
    }
}
