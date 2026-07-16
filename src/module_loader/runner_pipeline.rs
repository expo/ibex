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
use super::identity::{ResolutionKind, SourceId};
use super::producer_spike::{
    produce_builtin_artifact_v1, produce_commonjs_artifact_v1, produce_json_artifact_v1,
    produce_module_artifact_v1,
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
    path: String,
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
    path: PathBuf,
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
    snapshot: Arc<ArmedSnapshot>,
    producer_binary_digest: Digest,
    records: BTreeMap<SourceId, SourceGraphRecordV1>,
}

impl SourceModuleGraphV1 {
    pub fn entry(&self) -> &SourceId {
        &self.entry
    }

    pub fn snapshot(&self) -> &ArmedSnapshot {
        &self.snapshot
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
        let mut principal_ids = BTreeMap::new();
        for principal in principals {
            let principal_id = crate::host::abi::module_runner_principal_id(&principal)?;
            principal_ids.insert(principal, principal_id);
        }

        let mut configs = BTreeMap::new();
        let mut authority_contexts = BTreeMap::new();
        for (source_id, record) in &self.records {
            let principal = match source_id.defining_principal().cloned() {
                Some(principal) => principal,
                None if matches!(source_id, SourceId::Builtin { .. }) => principal_ids
                    .keys()
                    .find(|principal| principal.is_root())
                    .cloned()
                    .ok_or_else(|| anyhow!("builtin graph record has no root runtime owner"))?,
                None => bail!("source graph record has no defining principal"),
            };
            let principal_id = *principal_ids
                .get(&principal)
                .ok_or_else(|| anyhow!("source graph principal has no runtime projection"))?;
            let source_label = record.path.to_string_lossy().into_owned();
            let meta_url = format!("file://{}", source_label.replace('\\', "/"));
            configs.insert(
                source_id.clone(),
                NativeModuleRecordConfig::new(
                    principal_id,
                    None,
                    GraphEvaluationContext::new(
                        source_id.clone(),
                        principal_id,
                        principal_id,
                        [principal_id],
                        graph_generation,
                    )?,
                    source_label,
                    meta_url,
                )?,
            );
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
    let snapshot = crate::host::abi::current_module_runner_snapshot()?;
    let entry_specifier = entry
        .to_str()
        .ok_or_else(|| anyhow!("module-runner entry path is not UTF-8"))?;
    let entry_module = crate::host::abi::resolve_module_for_runner(
        entry_specifier,
        None,
        None,
        ResolutionKind::Entry,
        &super::identity::ImportAttributes::default(),
    )?;
    let entry_id = entry_module
        .source_id
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
            .source_id
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
        let source = module
            .source
            .as_deref()
            .ok_or_else(|| anyhow!("source module has no authenticated bytes"))?;
        let source_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("module");
        let artifact = match module.kind {
            ModuleKind::Esm => produce_module_artifact_v1(
                source_id.clone(),
                source_name,
                &path,
                source,
                producer_binary_digest.clone(),
                hermes_target,
            )?,
            ModuleKind::CommonJs => produce_commonjs_artifact_v1(
                source_id.clone(),
                source_name,
                &path,
                source,
                producer_binary_digest.clone(),
                hermes_target,
            )?,
            ModuleKind::Json => produce_json_artifact_v1(
                source_id.clone(),
                source,
                producer_binary_digest.clone(),
                hermes_target,
            )?,
            ModuleKind::Builtin => produce_builtin_artifact_v1(
                source_id.clone(),
                source_name,
                source,
                producer_binary_digest.clone(),
                hermes_target,
            )?,
        };
        if artifact
            .semantics
            .dynamic_edges
            .iter()
            .any(|edge| matches!(edge, DynamicEdgeV1::Computed { .. }))
        {
            return Ok(legacy(
                "computed dynamic import has no authenticated finite candidate table",
            ));
        }
        let mut bindings = BTreeMap::new();
        for key in artifact_edge_requests(&artifact) {
            let attributes = artifact_edge_attributes(&artifact, &key)?;
            let target = crate::host::abi::resolve_module_for_runner(
                &key.specifier,
                Some(&path),
                None,
                key.resolution_kind,
                &attributes,
            )?;
            let target_id = target
                .source_id
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
                artifact,
                bindings,
                prepared: None,
            },
        );
    }

    // Validate the entire closure before the engine can compile one factory.
    let graph = SourceModuleGraphV1 {
        entry: entry_id,
        snapshot,
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

/// Publish one immutable, per-principal JavaScript carrier set beside the
/// existing Rolldown artifact. The hidden directory is excluded from the
/// legacy output inventory but remains under the same cache lease and graph
/// digest. Publication is directory-atomic.
pub fn publish_prepared_source_graph_v1(
    graph: &SourceModuleGraphV1,
    artifact_dir: &Path,
    deployment_graph_digest: Digest,
) -> Result<PathBuf> {
    if graph
        .records
        .values()
        .any(|record| record.prepared.is_some())
    {
        bail!("only an admitted inline graph can be published as a prepared graph");
    }
    let destination = prepared_graph_cache_dir(artifact_dir, &deployment_graph_digest);
    if destination.join("index.json").is_file() {
        return Ok(destination);
    }
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
        let producer_id =
            NonEmptyString::new(PREPARED_GRAPH_PRODUCER_ID).map_err(anyhow::Error::msg)?;
        let root_principal = graph
            .records
            .keys()
            .filter_map(SourceId::defining_principal)
            .find(|principal| principal.is_root())
            .cloned()
            .ok_or_else(|| anyhow!("prepared graph has no root principal"))?;
        let mut grouped: BTreeMap<Principal, Vec<(SourceId, NonEmptyString)>> = BTreeMap::new();
        for (source_id, record) in &graph.records {
            let principal = source_id
                .defining_principal()
                .cloned()
                .or_else(|| {
                    matches!(source_id, SourceId::Builtin { .. }).then(|| root_principal.clone())
                })
                .ok_or_else(|| anyhow!("prepared carrier record has no defining principal"))?;
            let entry_id = NonEmptyString::new(record.artifact.semantic_digest.as_str())
                .map_err(anyhow::Error::msg)?;
            grouped
                .entry(principal)
                .or_default()
                .push((source_id.clone(), entry_id));
        }

        let mut carrier_indexes = BTreeMap::new();
        let mut carriers = Vec::new();
        let mut prepared_artifacts = BTreeMap::new();
        for (carrier_index, (principal, entries)) in grouped.into_iter().enumerate() {
            let verified_entries = entries
                .iter()
                .map(|(source_id, entry_id)| {
                    let record = graph
                        .records
                        .get(source_id)
                        .ok_or_else(|| anyhow!("prepared record disappeared"))?;
                    Ok((
                        entry_id.clone(),
                        verify_record(record, &graph.producer_binary_digest)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let (manifest, bytes) = PreparedModuleCarrierV1::from_inline_artifacts(
                principal.clone(),
                producer_id.clone(),
                graph.producer_binary_digest.clone(),
                deployment_graph_digest.clone(),
                verified_entries,
            )?;
            let manifest_file = format!("carrier-{carrier_index}.json");
            let bytes_file = format!("carrier-{carrier_index}.js");
            std::fs::write(staging.join(&manifest_file), manifest.encode_canonical()?)?;
            std::fs::write(staging.join(&bytes_file), &bytes)?;
            for (source_id, entry_id) in entries {
                prepared_artifacts.insert(
                    source_id.clone(),
                    (manifest.prepared_artifact(entry_id.as_str())?, entry_id),
                );
            }
            carrier_indexes.insert(principal, carrier_index);
            carriers.push(PreparedGraphCarrierIndexV1 {
                manifest_file,
                bytes_file,
            });
        }

        let records = graph
            .records
            .iter()
            .map(|(source_id, record)| {
                let principal = match source_id.defining_principal() {
                    Some(principal) => principal,
                    None if matches!(source_id, SourceId::Builtin { .. }) => &root_principal,
                    None => bail!("prepared record has no principal"),
                };
                let carrier_index = *carrier_indexes
                    .get(principal)
                    .ok_or_else(|| anyhow!("prepared record has no carrier"))?;
                let (artifact, entry_id) = prepared_artifacts
                    .remove(source_id)
                    .ok_or_else(|| anyhow!("prepared artifact was not produced"))?;
                Ok(PreparedGraphRecordIndexV1 {
                    source_id: source_id.clone(),
                    path: record.path.to_string_lossy().into_owned(),
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
            deployment_graph_digest,
            records,
            carriers,
        };
        let bytes = capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(index)?)
            .map_err(|error| anyhow!("cannot canonicalize prepared graph index: {error}"))?;
        std::fs::write(staging.join("index.json"), bytes)?;
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

pub fn load_prepared_source_graph_v1(
    cache_dir: &Path,
    expected_producer_binary_digest: &Digest,
    expected_deployment_graph_digest: &Digest,
) -> Result<SourceModuleGraphV1> {
    let index_bytes = std::fs::read(cache_dir.join("index.json"))?;
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
        || &index.producer_binary_digest != expected_producer_binary_digest
        || &index.deployment_graph_digest != expected_deployment_graph_digest
    {
        bail!("prepared graph index schema, producer, or deployment graph is stale");
    }
    if index.records.is_empty() || index.carriers.is_empty() {
        bail!("prepared graph index is empty");
    }
    let authorized_semantic_digests = index
        .records
        .iter()
        .map(|record| record.artifact.semantic_digest.clone())
        .collect::<BTreeSet<_>>();
    let producer_id =
        NonEmptyString::new(PREPARED_GRAPH_PRODUCER_ID).map_err(anyhow::Error::msg)?;
    let mut carriers = Vec::with_capacity(index.carriers.len());
    for carrier in &index.carriers {
        if carrier.manifest_file.contains('/')
            || carrier.manifest_file.contains('\\')
            || carrier.bytes_file.contains('/')
            || carrier.bytes_file.contains('\\')
        {
            bail!("prepared carrier filename escapes its cache directory");
        }
        let manifest_bytes = std::fs::read(cache_dir.join(&carrier.manifest_file))?;
        let carrier_bytes = std::fs::read(cache_dir.join(&carrier.bytes_file))?;
        let manifest_value =
            capsec_semantics::strict_json::parse_strict(std::str::from_utf8(&manifest_bytes)?)
                .map_err(|error| {
                    anyhow!("prepared carrier manifest is not strict JSON: {error}")
                })?;
        let manifest: PreparedModuleCarrierV1 = serde_json::from_value(manifest_value)?;
        let admission = PreparedCarrierAdmissionV1 {
            expected_principal: manifest.defining_principal.clone(),
            expected_producer_id: producer_id.clone(),
            producer_binary_digest: expected_producer_binary_digest.clone(),
            deployment_graph_digest: expected_deployment_graph_digest.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            expected_engine_binary_digest: None,
            expected_bytecode_version: None,
        };
        carriers.push(Arc::new(AdmittedPreparedCarrierV1::decode_and_admit(
            &manifest_bytes,
            &carrier_bytes,
            &admission,
        )?));
    }

    let snapshot = crate::host::abi::current_module_runner_snapshot()?;
    let mut records = BTreeMap::new();
    for indexed in index.records {
        if records.contains_key(&indexed.source_id) {
            bail!("prepared graph repeats a SourceId");
        }
        if indexed.artifact.semantics.source_id.0 != indexed.source_id {
            bail!("prepared graph record identity disagrees with its artifact");
        }
        let path = PathBuf::from(&indexed.path);
        if !path.is_absolute() && !matches!(indexed.source_id, SourceId::Builtin { .. }) {
            bail!("prepared graph source label is not absolute");
        }
        if !matches!(indexed.source_id, SourceId::Builtin { .. }) {
            crate::host::abi::authenticate_prepared_module_record(
                &path,
                &indexed.source_id,
                &indexed.artifact.semantics.source_integrity,
            )?;
        }
        let mut bindings = BTreeMap::new();
        for binding in indexed.bindings {
            let key = GraphEdgeKey::new(binding.specifier, binding.resolution_kind);
            if bindings.insert(key, binding.target).is_some() {
                bail!("prepared graph repeats a typed binding");
            }
        }
        for key in artifact_edge_requests(&indexed.artifact) {
            let attributes = artifact_edge_attributes(&indexed.artifact, &key)?;
            let resolved = crate::host::abi::resolve_module_for_runner(
                &key.specifier,
                Some(&path),
                None,
                key.resolution_kind,
                &attributes,
            )?;
            let observed = resolved
                .source_id
                .ok_or_else(|| anyhow!("prepared dependency resolution produced no SourceId"))?;
            if bindings.get(&key) != Some(&observed) {
                bail!("prepared graph binding disagrees with authenticated resolution");
            }
        }
        let carrier = carriers
            .get(indexed.carrier_index)
            .cloned()
            .ok_or_else(|| anyhow!("prepared graph record names an absent carrier"))?;
        let carrier_manifest = carrier.manifest();
        let admission = ArtifactAdmissionV1::DigestBoundPrepared {
            expected_source_id: indexed.source_id.clone(),
            expected_source_integrity: indexed.artifact.semantics.source_integrity.clone(),
            expected_producer_id: producer_id.clone(),
            producer_binary_digest: expected_producer_binary_digest.clone(),
            deployment_graph_digest: expected_deployment_graph_digest.clone(),
            expected_carrier_digest: carrier_manifest.carrier_digest.clone(),
            expected_entry_id: indexed.entry_id.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            transform_fingerprint_digest: indexed
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
                path,
                artifact: indexed.artifact,
                bindings,
                prepared: Some(PreparedRecordV1 {
                    carrier,
                    entry_id: indexed.entry_id,
                    admission,
                }),
            },
        );
    }
    let graph = SourceModuleGraphV1 {
        entry: index.entry,
        snapshot,
        producer_binary_digest: expected_producer_binary_digest.clone(),
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
}
