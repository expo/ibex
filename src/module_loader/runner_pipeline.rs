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

use anyhow::{anyhow, bail, Context, Result};
use capsec_semantics::arming::ArmedSnapshot;
use capsec_semantics::model::{
    Digest, NonEmptyString, PackageLocator, PathComponent, Principal, StableId, Stage,
};
use serde::{Deserialize, Serialize};

use crate::engine::module_runner::{GraphEvaluationContext, NativeModuleRecordConfig};

use super::artifact::{
    source_integrity, ArtifactAdmissionV1, DynamicEdgeV1, ModuleArtifactV1, StaticEdgeV1,
    VerifiedModuleArtifactV1,
};
use super::carrier::{
    AdmittedPreparedCarrierV2, PreparedCarrierAdmissionV2, PreparedModuleCarrierV2,
    VerifiedPreparedCarrierEntryV2,
};
use super::compatibility::LegacyModuleRunnerRequirement;
use super::computed_candidates::{
    ComputedCandidateTableV1, ComputedCandidateTargetV1, COMPUTED_CANDIDATES_SCHEMA_V1,
};
use super::embedded_graph::{
    EmbeddedCarrierBindingV1, EmbeddedCarrierFactV1, EmbeddedModuleEdgeV1, EmbeddedModuleGraphV1,
    EmbeddedModuleRecordV1, VirtualSourceLabelV1, EMBEDDED_MODULE_GRAPH_SCHEMA_V1,
};
use super::graph::{ComputedCandidateSiteMap, GraphEdgeKey, SynchronousGraphPlan};
use super::identity::{ResolutionKind, SourceId};
#[cfg(test)]
use super::producer_spike::produce_module_artifact_v1;
use super::producer_spike::{
    produce_builtin_artifact_v1, produce_commonjs_artifact_with_sites_v1, produce_json_artifact_v1,
    produce_module_artifact_with_sites_v1, unsupported_module_runner_reason,
    verify_current_transform_fingerprint_v1,
};
use super::{package_tree_integrity, ModuleKind, ModuleLoader, ResolvedModule};

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
        attributes: &super::identity::ImportAttributes,
    ) -> Result<ResolvedModule>;

    fn resolve_manifest_builtin_internal(&self, specifier: &str) -> Result<ResolvedModule>;

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
        attributes: &super::identity::ImportAttributes,
    ) -> Result<ResolvedModule> {
        crate::host::abi::resolve_module_for_runner(specifier, referrer, None, kind, attributes)
    }

    fn resolve_manifest_builtin_internal(&self, specifier: &str) -> Result<ResolvedModule> {
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
        attributes: &super::identity::ImportAttributes,
    ) -> Result<ResolvedModule> {
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

    fn resolve_manifest_builtin_internal(&self, specifier: &str) -> Result<ResolvedModule> {
        crate::host::Host::resolve_manifest_builtin_internal(self, specifier)
    }

    fn principal_id(&self, principal: &Principal) -> Result<u32> {
        self.module_runner_principal_id(principal)
    }
}

const PREPARED_GRAPH_INDEX_SCHEMA_V2: &str = "ibex/prepared-module-graph/2";
const PREPARED_GRAPH_PRODUCER_ID: &str = "ibex-rolldown-module-preparer";
const EMBEDDED_GRAPH_PRODUCER_ID: &str = "ibex-sfe-graph-preparer";

/// One manifest/payload pair ready to become typed executable-envelope
/// sections. v1 deliberately keeps one original module per pair.
pub struct EmbeddedPreparedCarrierV1 {
    pub pair_id: String,
    pub manifest: PreparedModuleCarrierV2,
    pub payload: Vec<u8>,
}

/// Path-independent output of the authenticated source-graph publisher.
pub struct PreparedEmbeddedSourceGraphV1 {
    pub graph: EmbeddedModuleGraphV1,
    pub carriers: Vec<EmbeddedPreparedCarrierV1>,
    pub candidate_tables: Vec<ComputedCandidateTableV1>,
}

/// Complete path-independent publication result plus the entry facts needed
/// to bind a reviewed canonical policy. Source paths are used only while
/// capturing bytes and resolving literal edges; none cross this boundary.
pub struct CapturedEmbeddedSourceGraphV1 {
    pub prepared: PreparedEmbeddedSourceGraphV1,
    pub entry_components: Vec<PathComponent>,
    pub entry_source_integrity: Digest,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedGraphIndexV2 {
    schema: String,
    entry: SourceId,
    producer_binary_digest: Digest,
    deployment_graph_digest: Digest,
    records: Vec<PreparedGraphRecordIndexV1>,
    carriers: Vec<PreparedGraphCarrierIndexV1>,
    candidate_tables: Vec<PreparedGraphCandidateTableIndexV2>,
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedGraphCandidateTableIndexV2 {
    file: String,
    digest: Digest,
}

struct SourceGraphRecordV1 {
    path: PathBuf,
    artifact: ModuleArtifactV1,
    bindings: BTreeMap<GraphEdgeKey, SourceId>,
    binding_attributes: BTreeMap<GraphEdgeKey, super::identity::ImportAttributes>,
    candidate_tables: Vec<ComputedCandidateTableV1>,
    prepared: Option<PreparedRecordV1>,
}

#[derive(Debug, Default, Deserialize)]
struct CandidateRootManifestV1 {
    #[serde(default)]
    ibex: CandidateIbexManifestV1,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CandidateIbexManifestV1 {
    #[serde(default)]
    computed_candidates: CandidateDeclarationsV1,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateDeclarationsV1 {
    #[serde(default)]
    sites: Vec<CandidateDeclarationV1>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateDeclarationV1 {
    #[serde(default)]
    requester: Option<String>,
    label: StableId,
    #[serde(default)]
    specifiers: Vec<NonEmptyString>,
    #[serde(default)]
    package_closures: Vec<PackageLocator>,
}

struct PreparedRecordV1 {
    carrier: Arc<AdmittedPreparedCarrierV2>,
    entry_id: NonEmptyString,
    admission: ArtifactAdmissionV1,
}

pub struct SourceModuleGraphV1 {
    entry: SourceId,
    entry_vfs_source_id: Option<crate::vfs::SourceId>,
    snapshot: Arc<ArmedSnapshot>,
    principal_ids: BTreeMap<Principal, u32>,
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
            || self.entry_vfs_source_id.as_ref() != request.source_id()
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
        SynchronousGraphPlan::new_typed_with_computed_candidates(
            self.records
                .iter()
                .map(|(_, record)| {
                    Ok((
                        verify_record(record, &self.producer_binary_digest)?,
                        record.bindings.clone(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
            computed_candidate_site_map(&self.records),
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
    ) -> Result<Option<BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>>> {
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
        for table in self
            .records
            .values()
            .flat_map(|record| record.candidate_tables.iter())
        {
            if table.generation != graph_generation {
                bail!(
                    "computed-candidate table generation {} cannot link into execution generation {}",
                    table.generation,
                    graph_generation
                );
            }
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

fn computed_candidate_site_map(
    records: &BTreeMap<SourceId, SourceGraphRecordV1>,
) -> ComputedCandidateSiteMap {
    let mut rows = ComputedCandidateSiteMap::new();
    for record in records.values() {
        for table in &record.candidate_tables {
            for candidate in &table.candidates {
                rows.entry(table.requester.0.clone()).or_default().insert(
                    (table.site, candidate.specifier.as_str().to_owned()),
                    candidate.target.0.clone(),
                );
            }
        }
    }
    rows
}

/// Capture the closed source and computed-candidate closure used by
/// `ibex compile` without first
/// arming application authority. Every file receives a portable root/package
/// SourceId and exact content identity before the shared embedded publisher
/// derives the authenticated graph snapshot. The subsequently supplied policy
/// must bind this identity exactly; capture itself grants no authority.
///
/// Candidate declarations come only from the reviewed root manifest and join
/// the producer-owned site table by `(requester, label)`. Resolution happens
/// once here; invocation consumes only authenticated exact-spelling rows.
/// @ref LLP 0028#2-disposition-of-the-legacy-window-interop-shapes
/// @ref LLP 0029#1-command-surface-and-producer-pipeline
pub fn capture_embedded_source_graph_v1(
    entry: &Path,
    producer_binary_digest: Digest,
) -> Result<CapturedEmbeddedSourceGraphV1> {
    let entry = std::fs::canonicalize(entry)
        .map_err(|error| anyhow!("cannot canonicalize entry {}: {error}", entry.display()))?;
    let project_root = discover_compiled_project_root(&entry)?;
    let entry_relative = entry
        .strip_prefix(&project_root)
        .context("compiled entry escapes the discovered project root")?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let candidate_declarations = load_candidate_declarations_v1(&project_root, &entry_relative)?;
    let mut matched_candidate_declarations = BTreeSet::new();
    let root_owner = Principal::Root {
        identity: NonEmptyString::new("project-root").map_err(anyhow::Error::msg)?,
    };
    let loader = ModuleLoader::new();
    let entry_specifier = entry
        .to_str()
        .ok_or_else(|| anyhow!("compiled entry path is not UTF-8"))?;
    let entry_module = loader.resolve_meta_typed(
        entry_specifier,
        None,
        ResolutionKind::Entry,
        &super::identity::ConditionSet::for_kind(ResolutionKind::Entry),
        &super::identity::ImportAttributes::default(),
    )?;
    let mut package_integrities = BTreeMap::new();
    let entry_module = prepare_compiled_module(
        &loader,
        entry_module,
        &project_root,
        &root_owner,
        &mut package_integrities,
    )?;
    let entry_id = entry_module
        .artifact_source_id
        .clone()
        .ok_or_else(|| anyhow!("compiled entry resolution produced no SourceId"))?;
    let entry_components = match &entry_id {
        SourceId::File {
            principal: Principal::Root { .. },
            path,
        } => path.clone(),
        _ => bail!("compiled entry is not owned by the project root"),
    };

    let mut queue = VecDeque::from([entry_module]);
    let mut records = BTreeMap::new();
    while let Some(module) = queue.pop_front() {
        let source_id = module
            .artifact_source_id
            .clone()
            .ok_or_else(|| anyhow!("compiled module resolution produced no SourceId"))?;
        if records.contains_key(&source_id) {
            continue;
        }
        let source = module
            .source
            .as_deref()
            .ok_or_else(|| anyhow!("compiled module resolution produced no source bytes"))?;
        let portable_name = compiled_portable_source_name(&source_id)?;
        let portable_path = PathBuf::from(&portable_name);
        let produced = match module.kind {
            ModuleKind::Esm => produce_module_artifact_with_sites_v1(
                source_id.clone(),
                &portable_name,
                &portable_path,
                source,
                producer_binary_digest.clone(),
            ),
            ModuleKind::CommonJs => produce_commonjs_artifact_with_sites_v1(
                source_id.clone(),
                &portable_name,
                &portable_path,
                source,
                producer_binary_digest.clone(),
            ),
            ModuleKind::Json => {
                produce_json_artifact_v1(source_id.clone(), source, producer_binary_digest.clone())
                    .map(|artifact| super::producer_spike::ProducedModuleArtifactV1 {
                        artifact,
                        dynamic_import_sites: Vec::new(),
                    })
            }
            ModuleKind::Builtin => produce_builtin_artifact_v1(
                source_id.clone(),
                &portable_name,
                source,
                producer_binary_digest.clone(),
            )
            .map(|artifact| super::producer_spike::ProducedModuleArtifactV1 {
                artifact,
                dynamic_import_sites: Vec::new(),
            }),
        }
        .map_err(|error| anyhow!("cannot prepare compiled module {portable_name:?}: {error}"))?;
        let artifact = produced.artifact;

        let mut bindings = BTreeMap::new();
        let mut binding_attributes = BTreeMap::new();
        for key in artifact_edge_requests(&artifact) {
            let attributes = artifact_edge_attributes(&artifact, &key)?;
            let target = loader.resolve_meta_typed(
                &key.specifier,
                module.path.as_deref(),
                key.resolution_kind,
                &super::identity::ConditionSet::for_kind(key.resolution_kind),
                &attributes,
            )?;
            let target = prepare_compiled_module(
                &loader,
                target,
                &project_root,
                &root_owner,
                &mut package_integrities,
            )?;
            let target_id = target
                .artifact_source_id
                .clone()
                .ok_or_else(|| anyhow!("compiled dependency produced no SourceId"))?;
            if let Some(previous) = bindings.insert(key, target_id.clone()) {
                if previous != target_id {
                    bail!("one typed dependency request resolved to two SourceIds");
                }
            }
            queue.push_back(target);
        }
        let requester = root_requester_path(&source_id);
        let mut candidate_tables = Vec::new();
        if let Some(requester) = requester {
            for site in produced.dynamic_import_sites {
                if !site.runtime_options_supported {
                    continue;
                }
                let Some(label) = site.label else {
                    continue;
                };
                let declaration_key = (requester.clone(), label.as_str().to_owned());
                let Some(specifiers) = candidate_declarations.get(&declaration_key) else {
                    continue;
                };
                matched_candidate_declarations.insert(declaration_key);
                let mut candidates = Vec::new();
                for specifier in specifiers {
                    let key = GraphEdgeKey::new(specifier.as_str(), ResolutionKind::DynamicImport);
                    let target = loader.resolve_meta_typed(
                        specifier.as_str(),
                        module.path.as_deref(),
                        ResolutionKind::DynamicImport,
                        &super::identity::ConditionSet::for_kind(ResolutionKind::DynamicImport),
                        &site.attributes,
                    )?;
                    let target = prepare_compiled_module(
                        &loader,
                        target,
                        &project_root,
                        &root_owner,
                        &mut package_integrities,
                    )?;
                    let target_id = target
                        .artifact_source_id
                        .clone()
                        .ok_or_else(|| anyhow!("computed candidate produced no SourceId"))?;
                    let target_integrity = source_integrity(
                        target
                            .source
                            .as_deref()
                            .ok_or_else(|| anyhow!("computed candidate produced no source bytes"))?
                            .as_bytes(),
                    )?;
                    if let Some(previous) = bindings.insert(key.clone(), target_id.clone()) {
                        if previous != target_id {
                            bail!("one computed candidate spelling resolved to two SourceIds");
                        }
                    }
                    if let Some(previous) = binding_attributes.insert(key, site.attributes.clone())
                    {
                        if previous != site.attributes {
                            bail!("one computed candidate spelling carries two attribute bags");
                        }
                    }
                    candidates.push(ComputedCandidateTargetV1 {
                        specifier: specifier.clone(),
                        attributes: site.attributes.clone(),
                        target: super::artifact::CanonicalSourceId(target_id),
                        target_source_integrity: target_integrity,
                    });
                    queue.push_back(target);
                }
                candidates.sort_by_key(|candidate| {
                    capsec_semantics::canonical::to_jcs_bytes(
                        &serde_json::to_value(candidate).expect("candidate serializes"),
                    )
                    .expect("candidate canonicalizes")
                });
                let table = ComputedCandidateTableV1 {
                    schema: COMPUTED_CANDIDATES_SCHEMA_V1.into(),
                    requester: super::artifact::CanonicalSourceId(source_id.clone()),
                    requester_source_integrity: artifact.semantics.source_integrity.clone(),
                    transform_fingerprint_digest: artifact
                        .semantics
                        .transform_fingerprint
                        .digest()?,
                    site: site.site,
                    generation: 1,
                    label,
                    original_source_span: site.original_source_span,
                    candidates,
                };
                table.validate_requester(&artifact)?;
                candidate_tables.push(table);
            }
        }
        let record_path = module.path.unwrap_or(portable_path);
        records.insert(
            source_id,
            SourceGraphRecordV1 {
                path: record_path,
                artifact,
                bindings,
                binding_attributes,
                candidate_tables,
                prepared: None,
            },
        );
    }

    if matched_candidate_declarations.len() != candidate_declarations.len() {
        let missing = candidate_declarations
            .keys()
            .filter(|key| !matched_candidate_declarations.contains(*key))
            .map(|(requester, label)| format!("{requester}#{label}"))
            .collect::<Vec<_>>();
        bail!(
            "computed-candidate declarations do not match producer sites: {}",
            missing.join(", ")
        );
    }

    let entry_source_integrity = records
        .get(&entry_id)
        .ok_or_else(|| anyhow!("compiled graph lost its entry"))?
        .artifact
        .semantics
        .source_integrity
        .clone();
    let prepared = prepare_embedded_records_v1(&entry_id, &records, &producer_binary_digest)?;
    Ok(CapturedEmbeddedSourceGraphV1 {
        prepared,
        entry_components,
        entry_source_integrity,
    })
}

fn prepare_compiled_module(
    loader: &ModuleLoader,
    mut module: ResolvedModule,
    project_root: &Path,
    root_owner: &Principal,
    package_integrities: &mut BTreeMap<PathBuf, Digest>,
) -> Result<ResolvedModule> {
    if module.kind == ModuleKind::Builtin {
        if !matches!(module.artifact_source_id, Some(SourceId::Builtin { .. })) {
            bail!("builtin resolution produced no authenticated builtin SourceId");
        }
        return loader.load_runner_source(module);
    }
    let path = module
        .path
        .as_ref()
        .ok_or_else(|| anyhow!("file module resolution produced no path"))?;
    let path = std::fs::canonicalize(path)
        .map_err(|error| anyhow!("cannot canonicalize module {}: {error}", path.display()))?;
    module.path = Some(path.clone());
    let source_id = if let (Some(name), Some(package_root)) = (
        module.package_name.as_deref(),
        module.package_root.as_deref(),
    ) {
        let package_root = std::fs::canonicalize(package_root).map_err(|error| {
            anyhow!(
                "cannot canonicalize package root {}: {error}",
                package_root.display()
            )
        })?;
        let version = module
            .package_version
            .as_deref()
            .ok_or_else(|| anyhow!("package {name:?} has no version identity"))?;
        let integrity = match package_integrities.get(&package_root) {
            Some(integrity) => integrity.clone(),
            None => {
                let integrity = Digest::new(package_tree_integrity(&package_root)?)
                    .map_err(anyhow::Error::msg)?;
                package_integrities.insert(package_root.clone(), integrity.clone());
                integrity
            }
        };
        let relative = path.strip_prefix(&package_root).map_err(|_| {
            anyhow!(
                "resolved package module {} escapes {}",
                path.display(),
                package_root.display()
            )
        })?;
        SourceId::file(
            Principal::Package {
                name: NonEmptyString::new(name).map_err(anyhow::Error::msg)?,
                integrity,
                locator: PackageLocator::new(format!("{name}@{version}"))
                    .map_err(anyhow::Error::msg)?,
            },
            compiled_portable_components(relative)?,
        )?
    } else {
        let relative = path.strip_prefix(project_root).map_err(|_| {
            anyhow!(
                "first-party module {} escapes project root {}",
                path.display(),
                project_root.display()
            )
        })?;
        SourceId::file(root_owner.clone(), compiled_portable_components(relative)?)?
    };
    module.artifact_source_id = Some(source_id);
    loader.load_runner_source(module)
}

fn discover_compiled_project_root(entry: &Path) -> Result<PathBuf> {
    let entry_parent = entry
        .parent()
        .ok_or_else(|| anyhow!("compiled entry has no parent directory"))?;
    let mut cursor = entry_parent;
    loop {
        if cursor.join("package.json").is_file() {
            return Ok(cursor.to_path_buf());
        }
        let Some(parent) = cursor.parent() else {
            return Ok(entry_parent.to_path_buf());
        };
        cursor = parent;
    }
}

fn root_requester_path(source_id: &SourceId) -> Option<String> {
    let SourceId::File {
        principal: Principal::Root { .. },
        path,
    } = source_id
    else {
        return None;
    };
    path.iter()
        .map(|component| match component {
            PathComponent::Utf8(value) => Some(value.as_str()),
            PathComponent::Base64Url(_) => None,
        })
        .collect::<Option<Vec<_>>>()
        .map(|components| components.join("/"))
}

fn authenticated_root_requester_path(
    source_id: &SourceId,
    path: &Path,
    project_root: &Path,
) -> Option<String> {
    if !source_id
        .defining_principal()
        .is_some_and(Principal::is_root)
    {
        return None;
    }
    path.strip_prefix(project_root)
        .ok()?
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .filter(|components| !components.is_empty())
        .map(|components| components.join("/"))
}

fn load_candidate_declarations_v1(
    project_root: &Path,
    entry_relative: &str,
) -> Result<BTreeMap<(String, String), Vec<NonEmptyString>>> {
    let path = project_root.join("package.json");
    if !path.is_file() {
        return Ok(BTreeMap::new());
    }
    let bytes = std::fs::read(&path)
        .with_context(|| format!("cannot read candidate manifest {}", path.display()))?;
    let value = capsec_semantics::strict_json::parse_slice_strict(&bytes)
        .map_err(|error| anyhow!("candidate manifest is not strict JSON: {error}"))?;
    let manifest: CandidateRootManifestV1 = serde_json::from_value(value)
        .context("package.json computed-candidate declarations are malformed")?;
    let mut declarations = BTreeMap::new();
    for declaration in manifest.ibex.computed_candidates.sites {
        let requester = declaration
            .requester
            .unwrap_or_else(|| entry_relative.to_owned());
        if requester.is_empty()
            || Path::new(&requester).is_absolute()
            || requester
                .split('/')
                .any(|component| component == ".." || component.is_empty())
        {
            bail!("computed-candidate requester {requester:?} is not project-relative");
        }
        let mut specifiers = declaration.specifiers;
        for locator in declaration.package_closures {
            let spelling = locator
                .as_str()
                .rsplit_once('@')
                .map(|(name, _)| name)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    anyhow!(
                        "package-closure locator {:?} has no package spelling",
                        locator.as_str()
                    )
                })?;
            specifiers.push(NonEmptyString::new(spelling).map_err(anyhow::Error::msg)?);
        }
        specifiers.sort();
        specifiers.dedup();
        if specifiers.is_empty() {
            bail!(
                "computed-candidate declaration {}#{} has no candidates",
                requester,
                declaration.label.as_str()
            );
        }
        if declarations
            .insert(
                (requester, declaration.label.as_str().to_owned()),
                specifiers,
            )
            .is_some()
        {
            bail!("computed-candidate manifest repeats one requester label");
        }
    }
    Ok(declarations)
}

fn compiled_portable_components(path: &Path) -> Result<Vec<PathComponent>> {
    let components = path
        .components()
        .map(|component| {
            let value = component
                .as_os_str()
                .to_str()
                .ok_or_else(|| anyhow!("compiled source path is not UTF-8"))?;
            PathComponent::utf8(value).map_err(anyhow::Error::msg)
        })
        .collect::<Result<Vec<_>>>()?;
    if components.is_empty() {
        bail!("compiled source path has no portable components");
    }
    Ok(components)
}

fn compiled_portable_source_name(source_id: &SourceId) -> Result<String> {
    match source_id {
        SourceId::File { path, .. } => path
            .last()
            .and_then(|component| std::str::from_utf8(component.bytes()).ok())
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("compiled source filename is not portable UTF-8")),
        SourceId::Builtin { source_key, .. } => Ok(format!("{}.js", source_key.as_str())),
        SourceId::Synthetic { .. } => bail!("synthetic sources are not packable in v1"),
    }
}

pub fn build_authenticated_source_graph_v1(
    entry: &Path,
    producer_binary_digest: Digest,
) -> Result<SourceModuleGraphBuildV1> {
    build_authenticated_source_graph_v1_with_host(
        &InstalledSourceGraphHost,
        entry,
        producer_binary_digest,
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
    _hermes_target: &str,
) -> Result<SourceModuleGraphBuildV1> {
    build_authenticated_source_graph_v1_with_host(host, entry, producer_binary_digest)
}

fn build_authenticated_source_graph_v1_with_host(
    host: &impl SourceGraphHost,
    entry: &Path,
    producer_binary_digest: Digest,
) -> Result<SourceModuleGraphBuildV1> {
    let snapshot = host.snapshot()?;
    let canonical_entry = std::fs::canonicalize(entry)
        .with_context(|| format!("cannot canonicalize module entry {}", entry.display()))?;
    let project_root = discover_compiled_project_root(&canonical_entry)?;
    let entry_relative = canonical_entry
        .strip_prefix(&project_root)
        .context("module entry escapes its project root")?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let candidate_declarations = load_candidate_declarations_v1(&project_root, &entry_relative)?;
    let mut matched_candidate_declarations = BTreeSet::new();
    let entry_specifier = entry
        .to_str()
        .ok_or_else(|| anyhow!("module-runner entry path is not UTF-8"))?;
    let entry_module = host.resolve(
        entry_specifier,
        None,
        ResolutionKind::Entry,
        &super::identity::ImportAttributes::default(),
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
        let source = module
            .source
            .as_deref()
            .ok_or_else(|| anyhow!("source module has no authenticated bytes"))?;
        let source_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("module");
        let produced = match module.kind {
            ModuleKind::Esm => produce_module_artifact_with_sites_v1(
                source_id.clone(),
                source_name,
                &path,
                source,
                producer_binary_digest.clone(),
            ),
            ModuleKind::CommonJs => produce_commonjs_artifact_with_sites_v1(
                source_id.clone(),
                source_name,
                &path,
                source,
                producer_binary_digest.clone(),
            ),
            ModuleKind::Json => {
                produce_json_artifact_v1(source_id.clone(), source, producer_binary_digest.clone())
                    .map(|artifact| super::producer_spike::ProducedModuleArtifactV1 {
                        artifact,
                        dynamic_import_sites: Vec::new(),
                    })
            }
            ModuleKind::Builtin => produce_builtin_artifact_v1(
                source_id.clone(),
                source_name,
                source,
                producer_binary_digest.clone(),
            )
            .map(|artifact| super::producer_spike::ProducedModuleArtifactV1 {
                artifact,
                dynamic_import_sites: Vec::new(),
            }),
        };
        let produced = match produced {
            Ok(produced) => produced,
            Err(error) => {
                if let Some(requirement) = unsupported_module_runner_reason(&error) {
                    return Ok(legacy(
                        requirement
                            .clone()
                            .with_original_source(source_id.encode()?, source)?,
                    ));
                }
                return Err(error);
            }
        };
        let artifact = produced.artifact;
        let mut bindings = BTreeMap::new();
        let mut binding_attributes = BTreeMap::new();
        for key in artifact_edge_requests(&artifact) {
            let attributes = artifact_edge_attributes(&artifact, &key)?;
            let target = if module.kind == ModuleKind::Builtin {
                if key.resolution_kind != ResolutionKind::CommonJsRequire || !attributes.is_empty()
                {
                    bail!("generated builtin has a non-CommonJS or attributed private edge");
                }
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
        let mut candidate_tables = Vec::new();
        if let Some(requester) = authenticated_root_requester_path(&source_id, &path, &project_root)
        {
            for site in produced.dynamic_import_sites {
                if !site.runtime_options_supported {
                    continue;
                }
                let Some(label) = site.label else {
                    continue;
                };
                let declaration_key = (requester.clone(), label.as_str().to_owned());
                let Some(specifiers) = candidate_declarations.get(&declaration_key) else {
                    continue;
                };
                matched_candidate_declarations.insert(declaration_key);
                let mut candidates = Vec::new();
                for specifier in specifiers {
                    let key = GraphEdgeKey::new(specifier.as_str(), ResolutionKind::DynamicImport);
                    let target = host.resolve(
                        specifier.as_str(),
                        Some(&path),
                        ResolutionKind::DynamicImport,
                        &site.attributes,
                    )?;
                    let target_id = target
                        .artifact_source_id
                        .clone()
                        .ok_or_else(|| anyhow!("authenticated candidate produced no SourceId"))?;
                    let target_integrity = source_integrity(
                        target
                            .source
                            .as_deref()
                            .ok_or_else(|| {
                                anyhow!("authenticated candidate produced no source bytes")
                            })?
                            .as_bytes(),
                    )?;
                    if let Some(previous) = bindings.insert(key.clone(), target_id.clone()) {
                        if previous != target_id {
                            bail!("one authenticated candidate spelling resolved twice");
                        }
                    }
                    if let Some(previous) = binding_attributes.insert(key, site.attributes.clone())
                    {
                        if previous != site.attributes {
                            bail!(
                                "one authenticated candidate spelling carries two attribute bags"
                            );
                        }
                    }
                    candidates.push(ComputedCandidateTargetV1 {
                        specifier: specifier.clone(),
                        attributes: site.attributes.clone(),
                        target: super::artifact::CanonicalSourceId(target_id),
                        target_source_integrity: target_integrity,
                    });
                    queue.push_back(target);
                }
                candidates.sort_by_key(|candidate| {
                    capsec_semantics::canonical::to_jcs_bytes(
                        &serde_json::to_value(candidate).expect("candidate serializes"),
                    )
                    .expect("candidate canonicalizes")
                });
                candidate_tables.push(ComputedCandidateTableV1 {
                    schema: COMPUTED_CANDIDATES_SCHEMA_V1.into(),
                    requester: super::artifact::CanonicalSourceId(source_id.clone()),
                    requester_source_integrity: artifact.semantics.source_integrity.clone(),
                    transform_fingerprint_digest: artifact
                        .semantics
                        .transform_fingerprint
                        .digest()?,
                    site: site.site,
                    generation: snapshot.generations().dynamic.get().max(1),
                    label,
                    original_source_span: site.original_source_span,
                    candidates,
                });
            }
        }
        records.insert(
            source_id,
            SourceGraphRecordV1 {
                path,
                artifact,
                bindings,
                binding_attributes,
                candidate_tables,
                prepared: None,
            },
        );
    }

    if matched_candidate_declarations.len() != candidate_declarations.len() {
        bail!("computed-candidate declarations do not match authenticated producer sites");
    }

    let principal_ids = records
        .keys()
        .filter_map(SourceId::defining_principal)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|principal| {
            let principal_id = host.principal_id(&principal)?;
            Ok((principal, principal_id))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    // Validate the entire closure before the engine can compile one factory.
    let graph = SourceModuleGraphV1 {
        entry: entry_id,
        entry_vfs_source_id: Some(entry_vfs_source_id),
        snapshot,
        principal_ids,
        producer_binary_digest,
        records,
    };
    graph.plan()?;
    Ok(SourceModuleGraphBuildV1::Native(graph))
}

/// Publish an already authenticated source graph into the path-independent
/// inner executable contract. The authenticated snapshot identity is computed
/// before carrier construction, then rebound into every carrier manifest and
/// re-admitted as a complete graph/pair bijection before returning.
/// @ref LLP 0029#2-executable-layout-stub-envelope-footer
pub fn prepare_embedded_source_graph_v1(
    graph: &SourceModuleGraphV1,
) -> Result<PreparedEmbeddedSourceGraphV1> {
    graph.plan()?;
    prepare_embedded_records_v1(&graph.entry, &graph.records, &graph.producer_binary_digest)
}

fn prepare_embedded_records_v1(
    entry: &SourceId,
    records: &BTreeMap<SourceId, SourceGraphRecordV1>,
    producer_binary_digest: &Digest,
) -> Result<PreparedEmbeddedSourceGraphV1> {
    SynchronousGraphPlan::new_typed_with_computed_candidates(
        records
            .values()
            .map(|record| {
                Ok((
                    verify_record(record, producer_binary_digest)?,
                    record.bindings.clone(),
                ))
            })
            .collect::<Result<Vec<_>>>()?,
        computed_candidate_site_map(records),
    )?;
    if !records.contains_key(entry) {
        bail!("embedded source graph entry is absent");
    }
    let root_owner = records
        .keys()
        .filter_map(SourceId::defining_principal)
        .find(|principal| principal.is_root())
        .cloned()
        .ok_or_else(|| anyhow!("embedded source graph has no root principal"))?;
    let mut ordered = records
        .iter()
        .map(|(source_id, record)| Ok((source_id.encode()?, source_id, record)))
        .collect::<Result<Vec<_>>>()?;
    ordered.sort_by(|left, right| left.0.cmp(&right.0));

    let mut candidate_tables = records
        .values()
        .flat_map(|record| record.candidate_tables.iter().cloned())
        .collect::<Vec<_>>();
    candidate_tables.sort_by_key(|table| table.digest().expect("candidate table validates"));
    let mut candidate_sets = Vec::with_capacity(candidate_tables.len());
    for table in &candidate_tables {
        let requester = records
            .get(&table.requester.0)
            .ok_or_else(|| anyhow!("computed-candidate requester is absent from graph"))?;
        table.validate_requester(&requester.artifact)?;
        for candidate in &table.candidates {
            let target = records
                .get(&candidate.target.0)
                .ok_or_else(|| anyhow!("computed-candidate target is absent from graph"))?;
            if target.artifact.semantics.source_integrity != candidate.target_source_integrity {
                bail!("computed-candidate target integrity is stale");
            }
            let key =
                GraphEdgeKey::new(candidate.specifier.as_str(), ResolutionKind::DynamicImport);
            if requester.bindings.get(&key) != Some(&candidate.target.0)
                || requester.binding_attributes.get(&key) != Some(&candidate.attributes)
            {
                bail!("computed-candidate row disagrees with authenticated graph edge");
            }
        }
        candidate_sets.push(table.graph_projection()?);
    }
    candidate_sets.sort_by_key(|row| {
        capsec_semantics::canonical::to_jcs_bytes(
            &serde_json::to_value(row).expect("candidate projection serializes"),
        )
        .expect("candidate projection canonicalizes")
    });

    let mut embedded_records = ordered
        .iter()
        .enumerate()
        .map(|(index, (_, source_id, record))| {
            let edges = record
                .bindings
                .iter()
                .map(|(key, target)| {
                    Ok(EmbeddedModuleEdgeV1 {
                        specifier: NonEmptyString::new(key.specifier.clone())
                            .map_err(anyhow::Error::msg)?,
                        resolution_kind: key.resolution_kind,
                        conditions: super::identity::ConditionSet::for_kind(key.resolution_kind),
                        attributes: record
                            .binding_attributes
                            .get(key)
                            .cloned()
                            .map(Ok)
                            .unwrap_or_else(|| artifact_edge_attributes(&record.artifact, key))?,
                        target: super::artifact::CanonicalSourceId(target.clone()),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let mut keyed_edges = edges
                .into_iter()
                .map(|edge| {
                    let value = serde_json::to_value(&edge)?;
                    let key = capsec_semantics::canonical::to_jcs_bytes(&value)?;
                    Ok((key, edge))
                })
                .collect::<Result<Vec<_>>>()?;
            keyed_edges.sort_by(|left, right| left.0.cmp(&right.0));
            let edges = keyed_edges.into_iter().map(|(_, edge)| edge).collect();
            let encoded = source_id.encode()?;
            Ok(EmbeddedModuleRecordV1 {
                source_id: super::artifact::CanonicalSourceId((*source_id).clone()),
                source_integrity: record.artifact.semantics.source_integrity.clone(),
                semantic_digest: record.artifact.semantic_digest.clone(),
                carrier: EmbeddedCarrierBindingV1 {
                    pair_id: NonEmptyString::new(format!("module-{index:04}"))
                        .map_err(anyhow::Error::msg)?,
                    entry_id: NonEmptyString::new(record.artifact.semantic_digest.as_str())
                        .map_err(anyhow::Error::msg)?,
                },
                edges,
                virtual_source: VirtualSourceLabelV1::new(format!("/app/modules/{encoded}"))?,
                candidate_table_refs: candidate_tables
                    .iter()
                    .filter(|table| table.requester.0 == **source_id)
                    .map(|table| {
                        NonEmptyString::new(table.digest()?.as_str()).map_err(anyhow::Error::msg)
                    })
                    .collect::<Result<Vec<_>>>()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let placeholder = super::artifact::digest_bytes("ibex:sfe-graph-placeholder:1", &[])?;
    let mut embedded_graph = EmbeddedModuleGraphV1 {
        schema: EMBEDDED_MODULE_GRAPH_SCHEMA_V1.into(),
        graph_identity: placeholder,
        entry: super::artifact::CanonicalSourceId(entry.clone()),
        records: std::mem::take(&mut embedded_records),
    };
    embedded_graph.validate_contract()?;
    let graph_identity = embedded_graph
        .authenticated_snapshot(candidate_sets.clone())?
        .identity()?;
    embedded_graph.graph_identity = graph_identity.clone();

    let producer_id =
        NonEmptyString::new(EMBEDDED_GRAPH_PRODUCER_ID).map_err(anyhow::Error::msg)?;
    let mut carriers = Vec::with_capacity(ordered.len());
    let mut facts = BTreeMap::new();
    for ((_, source_id, record), embedded_record) in
        ordered.into_iter().zip(&embedded_graph.records)
    {
        let verified = verify_record(record, producer_binary_digest)?;
        let principal = source_id
            .defining_principal()
            .cloned()
            .unwrap_or_else(|| root_owner.clone());
        let (manifest, payload) = PreparedModuleCarrierV2::from_inline_artifacts(
            principal,
            producer_id.clone(),
            producer_binary_digest.clone(),
            graph_identity.clone(),
            [(embedded_record.carrier.entry_id.clone(), verified)],
        )?;
        let pair_id = embedded_record.carrier.pair_id.as_str().to_owned();
        facts.insert(
            pair_id.clone(),
            EmbeddedCarrierFactV1 {
                source_id: embedded_record.source_id.clone(),
                semantic_digest: embedded_record.semantic_digest.clone(),
                entry_id: embedded_record.carrier.entry_id.clone(),
            },
        );
        carriers.push(EmbeddedPreparedCarrierV1 {
            pair_id,
            manifest,
            payload,
        });
    }
    let bytes = embedded_graph.canonical_bytes()?;
    EmbeddedModuleGraphV1::decode_and_admit(&bytes, &facts, &candidate_sets)?;
    Ok(PreparedEmbeddedSourceGraphV1 {
        graph: embedded_graph,
        carriers,
        candidate_tables,
    })
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
            let (manifest, bytes) = PreparedModuleCarrierV2::from_inline_artifacts(
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
        let mut tables = graph
            .records
            .values()
            .flat_map(|record| record.candidate_tables.iter())
            .collect::<Vec<_>>();
        tables.sort_by_key(|table| table.digest().expect("candidate table validates"));
        let candidate_tables = tables
            .into_iter()
            .enumerate()
            .map(|(index, table)| {
                let file = format!("candidate-{index}.json");
                let digest = table.digest()?;
                std::fs::write(staging.join(&file), table.canonical_bytes()?)?;
                Ok(PreparedGraphCandidateTableIndexV2 { file, digest })
            })
            .collect::<Result<Vec<_>>>()?;
        let index = PreparedGraphIndexV2 {
            schema: PREPARED_GRAPH_INDEX_SCHEMA_V2.into(),
            entry: graph.entry.clone(),
            producer_binary_digest: graph.producer_binary_digest.clone(),
            deployment_graph_digest,
            records,
            carriers,
            candidate_tables,
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
        Err(_error) if destination.join("index.json").is_file() => {
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
    authenticated_source_graph: &SourceModuleGraphV1,
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
    let index: PreparedGraphIndexV2 = serde_json::from_value(value)?;
    if index.schema != PREPARED_GRAPH_INDEX_SCHEMA_V2
        || index.producer_binary_digest != authenticated_source_graph.producer_binary_digest
        || &index.deployment_graph_digest != expected_deployment_graph_digest
    {
        bail!("prepared graph index schema, producer, or deployment graph is stale");
    }
    if index.records.is_empty() || index.carriers.is_empty() {
        bail!("prepared graph index is empty");
    }
    let mut candidate_tables = Vec::with_capacity(index.candidate_tables.len());
    for candidate in &index.candidate_tables {
        if candidate.file.contains('/') || candidate.file.contains('\\') {
            bail!("prepared candidate-table filename escapes its cache directory");
        }
        let bytes = std::fs::read(cache_dir.join(&candidate.file))?;
        let table = ComputedCandidateTableV1::decode_canonical(&bytes)?;
        if table.digest()? != candidate.digest {
            bail!("prepared candidate-table digest is stale");
        }
        candidate_tables.push(table);
    }
    let expected_candidate_digests = authenticated_source_graph
        .records
        .values()
        .flat_map(|record| record.candidate_tables.iter())
        .map(ComputedCandidateTableV1::digest)
        .collect::<Result<BTreeSet<_>>>()?;
    let observed_candidate_digests = candidate_tables
        .iter()
        .map(ComputedCandidateTableV1::digest)
        .collect::<Result<BTreeSet<_>>>()?;
    if observed_candidate_digests != expected_candidate_digests {
        bail!("prepared candidate tables differ from the authenticated source graph");
    }
    let authorized_semantic_digests = authenticated_source_graph
        .records
        .values()
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
        let manifest: PreparedModuleCarrierV2 = serde_json::from_value(manifest_value)?;
        let admission = PreparedCarrierAdmissionV2 {
            expected_principal: manifest.defining_principal.clone(),
            expected_producer_id: producer_id.clone(),
            producer_binary_digest: authenticated_source_graph.producer_binary_digest.clone(),
            deployment_graph_digest: expected_deployment_graph_digest.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            expected_engine_binding: None,
            expected_bytecode_version: None,
        };
        carriers.push(Arc::new(AdmittedPreparedCarrierV2::decode_and_admit(
            &manifest_bytes,
            &carrier_bytes,
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
        // Source-transform configuration and evaluator/HBC identity are
        // independent. Revalidate the former here; carrier admission below
        // separately checks the latter for bytecode carriers.
        // @ref LLP 0028#1-toolchain-and-pin-rotation--atomic-with-identity-rotation
        verify_current_transform_fingerprint_v1(&indexed.artifact.semantics)?;
        let path = trusted_record.path.clone();
        if indexed.path != path.to_string_lossy() {
            bail!("prepared graph path differs from authenticated source");
        }
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
        if bindings != trusted_record.bindings {
            bail!("prepared graph bindings differ from authenticated source");
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
            producer_binary_digest: authenticated_source_graph.producer_binary_digest.clone(),
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
        let record_candidate_tables = candidate_tables
            .iter()
            .filter(|table| table.requester.0 == indexed.source_id)
            .cloned()
            .collect::<Vec<_>>();
        let binding_attributes = record_candidate_tables
            .iter()
            .flat_map(|table| {
                table.candidates.iter().map(|candidate| {
                    (
                        GraphEdgeKey::new(
                            candidate.specifier.as_str(),
                            ResolutionKind::DynamicImport,
                        ),
                        candidate.attributes.clone(),
                    )
                })
            })
            .collect();
        records.insert(
            indexed.source_id,
            SourceGraphRecordV1 {
                path,
                artifact: indexed.artifact,
                bindings,
                binding_attributes,
                candidate_tables: record_candidate_tables,
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

fn legacy(requirement: LegacyModuleRunnerRequirement) -> SourceModuleGraphBuildV1 {
    SourceModuleGraphBuildV1::LegacyRequired(requirement)
}

pub fn artifact_edge_requests(artifact: &ModuleArtifactV1) -> Vec<GraphEdgeKey> {
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

pub fn artifact_edge_attributes(
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
    use capsec_semantics::model::PathComponent;

    #[test]
    fn checked_in_schema_names_the_prepared_graph_envelope() {
        let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../schemas/prepared-module-graph-v2.schema.json"
        ))
        .unwrap();
        assert_eq!(
            schema["properties"]["schema"]["const"],
            PREPARED_GRAPH_INDEX_SCHEMA_V2
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
        )
        .unwrap();
        let key = artifact_edge_requests(&artifact).remove(0);
        assert!(artifact_edge_attributes(&artifact, &key)
            .unwrap()
            .asserts_json());
    }

    fn embedded_test_records(
        checkout: &str,
    ) -> (SourceId, Digest, BTreeMap<SourceId, SourceGraphRecordV1>) {
        let owner = Principal::Root {
            identity: NonEmptyString::new("portable-project").unwrap(),
        };
        let source_id = |name: &str| {
            SourceId::file(owner.clone(), vec![PathComponent::utf8(name).unwrap()]).unwrap()
        };
        let entry = source_id("entry.mjs");
        let value = source_id("value.mjs");
        let builtin = SourceId::builtin("ibex-runtime", "node_path").unwrap();
        let producer = super::super::artifact::source_integrity(b"embedded-producer").unwrap();
        let entry_artifact = produce_module_artifact_v1(
            entry.clone(),
            "entry.mjs",
            Path::new("entry.mjs"),
            "import path from 'node:path'; import { value } from './value.mjs'; export const answer = path.basename('/tmp/ibex') === 'ibex' ? value + 1 : 0;",
            producer.clone(),
        )
        .unwrap();
        let value_artifact = produce_module_artifact_v1(
            value.clone(),
            "value.mjs",
            Path::new("value.mjs"),
            "export const value = 41;",
            producer.clone(),
        )
        .unwrap();
        let builtin_artifact = produce_builtin_artifact_v1(
            builtin.clone(),
            "node_path",
            "module.exports = { basename: function (value) { return value.slice(value.lastIndexOf('/') + 1); } };",
            producer.clone(),
        )
        .unwrap();
        let mut entry_bindings = BTreeMap::new();
        entry_bindings.insert(
            GraphEdgeKey::new("./value.mjs", ResolutionKind::EsmStatic),
            value.clone(),
        );
        entry_bindings.insert(
            GraphEdgeKey::new("node:path", ResolutionKind::EsmStatic),
            builtin.clone(),
        );
        let record = |name: &str, artifact, bindings| SourceGraphRecordV1 {
            path: PathBuf::from(checkout).join(name),
            artifact,
            bindings,
            binding_attributes: BTreeMap::new(),
            candidate_tables: Vec::new(),
            prepared: None,
        };
        (
            entry.clone(),
            producer,
            BTreeMap::from([
                (entry, record("entry.mjs", entry_artifact, entry_bindings)),
                (value, record("value.mjs", value_artifact, BTreeMap::new())),
                (
                    builtin,
                    record("builtin:node_path.js", builtin_artifact, BTreeMap::new()),
                ),
            ]),
        )
    }

    #[test]
    fn authenticated_graph_publisher_is_path_independent_and_includes_builtins() {
        let (entry_a, producer_a, records_a) = embedded_test_records("/tmp/checkout-a/src");
        let (entry_b, producer_b, records_b) = embedded_test_records("/var/tmp/checkout-b/src");
        let first = prepare_embedded_records_v1(&entry_a, &records_a, &producer_a).unwrap();
        let second = prepare_embedded_records_v1(&entry_b, &records_b, &producer_b).unwrap();

        assert_eq!(first.graph, second.graph);
        assert_eq!(first.graph.records.len(), 3);
        assert!(first
            .graph
            .records
            .iter()
            .any(|record| matches!(record.source_id.0, SourceId::Builtin { .. })));
        assert_eq!(first.carriers.len(), 3);
        for (left, right) in first.carriers.iter().zip(&second.carriers) {
            assert_eq!(left.pair_id, right.pair_id);
            assert_eq!(left.manifest, right.manifest);
            assert_eq!(left.payload, right.payload);
        }
        let graph_bytes = first.graph.canonical_bytes().unwrap();
        assert!(!graph_bytes.windows(9).any(|bytes| bytes == b"checkout-"));
    }

    #[test]
    fn production_capture_is_path_independent_before_policy_admission() {
        let temporary = tempfile::tempdir().unwrap();
        let producer = super::super::artifact::source_integrity(b"capture-producer").unwrap();
        let mut captures = Vec::new();
        for checkout in ["checkout-a", "checkout-b"] {
            let root = temporary.path().join(checkout);
            std::fs::create_dir(&root).unwrap();
            std::fs::write(
                root.join("entry.mjs"),
                "import path from 'node:path'; import { value } from './value.mjs'; export const answer = path.basename('/tmp/ibex') === 'ibex' ? value + 1 : 0;",
            )
            .unwrap();
            std::fs::write(root.join("value.mjs"), "export const value = 41;").unwrap();
            captures.push(
                capture_embedded_source_graph_v1(&root.join("entry.mjs"), producer.clone())
                    .unwrap(),
            );
        }
        let [first, second] = captures.as_slice() else {
            unreachable!()
        };
        assert_eq!(first.entry_components, second.entry_components);
        assert_eq!(first.entry_source_integrity, second.entry_source_integrity);
        assert_eq!(first.prepared.graph, second.prepared.graph);
        assert_eq!(first.prepared.carriers.len(), 3);
        for (left, right) in first
            .prepared
            .carriers
            .iter()
            .zip(&second.prepared.carriers)
        {
            assert_eq!(left.pair_id, right.pair_id);
            assert_eq!(left.manifest, right.manifest);
            assert_eq!(left.payload, right.payload);
        }
    }

    #[test]
    fn production_capture_materializes_digest_bound_candidate_tables() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"ibex":{"computedCandidates":{"sites":[{"requester":"entry.mjs","label":"routes","specifiers":["./a.mjs","./b.mjs"]}]}}}"#,
        )
        .unwrap();
        std::fs::write(
            root.path().join("entry.mjs"),
            r#"const chosen = "./a.mjs"; export const loaded = import(chosen, { with: { "ibex:site": "routes" } });"#,
        )
        .unwrap();
        std::fs::write(root.path().join("a.mjs"), "export const value = 'a';").unwrap();
        std::fs::write(root.path().join("b.mjs"), "export const value = 'b';").unwrap();
        let producer = super::super::artifact::source_integrity(b"candidate-producer").unwrap();
        let captured =
            capture_embedded_source_graph_v1(&root.path().join("entry.mjs"), producer).unwrap();
        assert_eq!(captured.prepared.graph.records.len(), 3);
        assert_eq!(captured.prepared.candidate_tables.len(), 1);
        let table = &captured.prepared.candidate_tables[0];
        assert_eq!(table.label.as_str(), "routes");
        assert_eq!(
            table
                .candidates
                .iter()
                .map(|candidate| candidate.specifier.as_str())
                .collect::<Vec<_>>(),
            ["./a.mjs", "./b.mjs"]
        );
        let requester = captured
            .prepared
            .graph
            .records
            .iter()
            .find(|record| record.source_id == table.requester)
            .unwrap();
        assert_eq!(
            requester.candidate_table_refs[0].as_str(),
            table.digest().unwrap().as_str()
        );
    }

    #[test]
    fn embedded_publication_refuses_inter_step_artifact_and_edge_mutation() {
        let (entry, producer, mut artifact_mutation) = embedded_test_records("/tmp/checkout/src");
        artifact_mutation
            .get_mut(&entry)
            .unwrap()
            .artifact
            .semantics
            .source_integrity = super::super::artifact::source_integrity(b"changed").unwrap();
        assert!(prepare_embedded_records_v1(&entry, &artifact_mutation, &producer).is_err());

        let (entry, producer, mut edge_mutation) = embedded_test_records("/tmp/checkout/src");
        edge_mutation
            .get_mut(&entry)
            .unwrap()
            .bindings
            .remove(&GraphEdgeKey::new("./value.mjs", ResolutionKind::EsmStatic));
        let error = prepare_embedded_records_v1(&entry, &edge_mutation, &producer)
            .err()
            .expect("edge mutation must refuse");
        assert!(error
            .to_string()
            .contains("artifact/resolver graph disagreement"));
    }
}
