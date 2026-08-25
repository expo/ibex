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
use capsec_semantics::arming::{ArmedSnapshot, PreparedGraphCommitmentV1};
use capsec_semantics::model::{
    Digest, NonEmptyString, PackageLocator, PathComponent, Principal, StableId, Stage,
};
use serde::{Deserialize, Serialize};

use crate::engine::module_runner::{
    DeferredDynamicImportBindings, DeferredDynamicImportLinks, DynamicModuleActivationKind,
    DynamicModuleActivationRequest, GraphEvaluationContext, NativeModuleRecordConfig,
};

#[cfg(feature = "dev-committed-embedder")]
use super::artifact::MODULE_ARTIFACT_SCHEMA_V1;
use super::artifact::{
    digest_bytes, source_integrity, ArtifactAdmissionV1, DynamicEdgeV1, ModuleArtifactV1,
    ProducerIdentityV1, StaticEdgeV1, TransformFingerprintV1, VerifiedModuleArtifactV1,
};
use super::carrier::{
    AdmittedPreparedCarrierV2, PreparedCarrierAdmissionV2, PreparedCarrierEncodingV2,
    PreparedCarrierEngineBindingV2, PreparedModuleCarrierV2, VerifiedPreparedCarrierEntryV2,
};
#[cfg(feature = "dev-committed-embedder")]
use super::carrier::{
    AdmittedPreparedCarrierV3, PreparedCarrierAdmissionV3, PreparedModuleCarrierV3,
};
use super::compatibility::LegacyModuleRunnerRequirement;
#[cfg(feature = "dev-committed-embedder")]
use super::composition::{
    compute_package_graph_digest_v1, parse_composition_verifier_expectations_v1,
    parse_prepared_composition_commitment_v1, CompositionRefusalCode, CompositionRole,
    CompositionVerifierExpectationsV1, HostBridgedInventoryRowV1, PreparedCompositionCommitmentV1,
    PreparedPackageV1, MAX_PACKAGE_CANDIDATE_TABLE_BYTES_V1, MAX_PACKAGE_CARRIER_BYTES_V1,
    MAX_PACKAGE_INDEX_BYTES_V1, MAX_PACKAGE_MANIFEST_BYTES_V1, PREPARED_PACKAGE_ROOT_DOMAIN_V1,
    PREPARED_PACKAGE_SCHEMA_V1,
};
use super::computed_candidates::{
    ComputedCandidateTableV1, ComputedCandidateTargetV1, COMPUTED_CANDIDATES_SCHEMA_V1,
};
#[cfg(feature = "dev-committed-embedder")]
use super::computed_candidates::{ComputedCandidateTableV2, COMPUTED_CANDIDATES_SCHEMA_V2};
use super::embedded_graph::{
    EmbeddedCarrierBindingV1, EmbeddedCarrierFactV1, EmbeddedModuleEdgeV1, EmbeddedModuleGraphV1,
    EmbeddedModuleRecordV1, VirtualSourceLabelV1, EMBEDDED_MODULE_GRAPH_SCHEMA_V1,
};
use super::generation::{AuthenticatedGenerationGraphV2, CandidateSitePinV1, ExecutionGeneration};
use super::graph::{
    ComputedCandidateBinding, ComputedCandidateSiteMap, GraphEdgeKey, SynchronousGraphPlan,
};
use super::identity::{ResolutionKind, SourceId};
use super::producer_spike::{
    produce_builtin_artifact_v1, produce_commonjs_artifact_with_sites_v1, produce_json_artifact_v1,
    produce_module_artifact_with_sites_v1, unsupported_module_runner_reason,
    verify_current_transform_fingerprint_v1, GuardedUnsupportedShapeV1,
};
#[cfg(test)]
use super::producer_spike::{produce_commonjs_artifact_v1, produce_module_artifact_v1};
use super::security::{
    AuthorizedGraphOperation, GraphAuthorityContext, GraphDecisionSet, GraphOperationKind,
    ModuleGraphAuthorizer,
};
use super::{package_tree_integrity, ModuleKind, ModuleLoader, ResolvedModule};

pub enum SourceModuleGraphBuildV1 {
    Native(SourceModuleGraphV1),
    LegacyRequired(LegacyModuleRunnerRequirement),
}

trait SourceGraphHost {
    fn snapshot(&self) -> Result<Arc<ArmedSnapshot>>;

    fn resolve_meta(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        kind: ResolutionKind,
        attributes: &super::identity::ImportAttributes,
    ) -> Result<ResolvedModule>;

    fn load_source(&self, module: ResolvedModule) -> Result<ResolvedModule>;

    fn resolve(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        kind: ResolutionKind,
        attributes: &super::identity::ImportAttributes,
    ) -> Result<ResolvedModule> {
        let module = self.resolve_meta(specifier, referrer, kind, attributes)?;
        self.load_source(module)
    }

    fn resolve_manifest_builtin_internal(&self, specifier: &str) -> Result<ResolvedModule>;

    fn principal_id(&self, principal: &Principal) -> Result<u32>;
}

struct InstalledSourceGraphHost;

impl SourceGraphHost for InstalledSourceGraphHost {
    fn snapshot(&self) -> Result<Arc<ArmedSnapshot>> {
        crate::host::abi::current_module_runner_snapshot()
    }

    fn resolve_meta(
        &self,
        specifier: &str,
        referrer: Option<&Path>,
        kind: ResolutionKind,
        attributes: &super::identity::ImportAttributes,
    ) -> Result<ResolvedModule> {
        crate::host::abi::resolve_module_meta_for_runner(
            specifier, referrer, None, kind, attributes,
        )
    }

    fn load_source(&self, module: ResolvedModule) -> Result<ResolvedModule> {
        crate::host::abi::load_module_source_for_runner(module)
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

    fn resolve_meta(
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
        Ok(resolved)
    }

    fn load_source(&self, module: ResolvedModule) -> Result<ResolvedModule> {
        self.load_authenticated_module_source_for_runner(module)
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
const PREPARED_PUBLICATION_ROOT_DOMAIN_V1: &str = "ibex:prepared-publication-root:1";
const PREPARED_SEMANTIC_INVENTORY_DOMAIN_V1: &str = "ibex:prepared-semantic-inventory:1";
const PREPARED_PRINCIPAL_SET_DOMAIN_V1: &str = "ibex:prepared-principal-set:1";
const MAX_PREPARED_INDEX_BYTES_V1: u64 = 64 * 1024 * 1024;
const MAX_PREPARED_MANIFEST_BYTES_V1: u64 = 16 * 1024 * 1024;
const MAX_PREPARED_CARRIER_BYTES_V1: u64 = 512 * 1024 * 1024;
const MAX_PREPARED_CANDIDATE_BYTES_V1: u64 = 64 * 1024 * 1024;
const PREPARED_ACTIVATION_CACHE_KEY_DOMAIN_V1: &str =
    "ibex/prepared-activation-carrier-cache-key/1";
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
    pub guarded_unsupported_sites: Vec<CapturedGuardedUnsupportedSiteV1>,
}

/// A deterministic compile-time diagnostic row for a guard that remains in
/// the emitted factory. This is capture metadata, not part of graph identity:
/// the authenticated factory bytes carry the invocation-time behavior.
/// @ref LLP 0029#1-command-surface-and-producer-pipeline — default compilation
/// preserves invocation timing while `--deny-unsupported` audits this inventory
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CapturedGuardedUnsupportedSiteV1 {
    pub source_id: String,
    pub start: u32,
    pub end: u32,
    pub shape: GuardedUnsupportedShapeV1,
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

pub(crate) struct SourceGraphRecordV1 {
    /// Native-only resolver path. This is never serialized into a prepared
    /// artifact or crossed into JavaScript.
    // @ref LLP 0023#6-path-bearing-observables — private native paths cannot become realm-visible labels
    path: PathBuf,
    /// Authenticated VFS display identity. It is diagnostic metadata, never a
    /// cache key or a substitute for `SourceId`.
    // @ref LLP 0023#2-identity-versus-spelling — SourceLabel is display identity, not a cache or authorization key
    source_label: String,
    /// Authenticated virtual filename used by CommonJS and `import.meta` path
    /// observables. Builtins have no file-backed virtual path.
    virtual_path: Option<String>,
    artifact: ModuleArtifactV1,
    bindings: BTreeMap<GraphEdgeKey, SourceId>,
    candidate_tables: Vec<ComputedCandidateTableV1>,
    deferred_dynamic: DeferredSourceDynamicBindingsV1,
    deferred_commonjs_requires: BTreeSet<String>,
    bootstrap_internal_commonjs_requires: BTreeSet<String>,
    prepared: Option<PreparedRecordV1>,
}

#[derive(Clone, Debug, Default)]
struct DeferredSourceDynamicBindingsV1 {
    enabled: bool,
    literal_attributes: BTreeMap<String, super::identity::ImportAttributes>,
    computed_attributes: BTreeMap<(u32, String), super::identity::ImportAttributes>,
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

#[derive(Clone, Debug)]
pub struct PreparedActivationCacheCandidateV1 {
    pub cache_dir: PathBuf,
    pub deployment_graph_digest: Digest,
}

/// Opaque runtime-owned discovery capability for invocation-time prepared
/// carriers. The graph calls it only after an exact reached edge has been
/// authorized and its source closure has produced retained acquisition
/// receipts.
pub trait PreparedActivationCacheLocatorV1: Send + Sync {
    /// Optionally populate cache candidates for the exact records whose source
    /// acquisition was just authorized. Consumers still authenticate every
    /// returned byte against those records, so publication remains an
    /// acceleration rather than authority.
    fn publish_authenticated_records(
        &self,
        _graph: &SourceModuleGraphV1,
        _record_ids: &BTreeSet<SourceId>,
    ) -> Result<()> {
        Ok(())
    }

    fn locate(&self, target: &SourceId) -> Result<Vec<PreparedActivationCacheCandidateV1>>;
}

pub struct SourceModuleGraphV1 {
    entry: SourceId,
    entry_vfs_source_id: Option<crate::vfs::SourceId>,
    execution_generation: ExecutionGeneration,
    snapshot: Arc<ArmedSnapshot>,
    principal_ids: BTreeMap<Principal, u32>,
    producer_binary_digest: Digest,
    records: BTreeMap<SourceId, SourceGraphRecordV1>,
    activation_host: Option<crate::host::Host>,
    project_root: PathBuf,
    candidate_declarations: BTreeMap<(String, String), Vec<NonEmptyString>>,
    matched_candidate_declarations: BTreeSet<(String, String)>,
    prepared_activation_cache_locator: Option<Arc<dyn PreparedActivationCacheLocatorV1>>,
    _source_access_receipts: Vec<AuthorizedGraphOperation>,
    _prepared_access_receipts: Vec<AuthorizedGraphOperation>,
    _activation_receipts: Vec<AuthorizedGraphOperation>,
}

pub struct SourceGraphActivationCheckpoint {
    record_ids: BTreeSet<SourceId>,
    principal_ids: BTreeMap<Principal, u32>,
    matched_candidate_declarations: BTreeSet<(String, String)>,
    prepared_access_receipt_count: usize,
    activation_receipt_count: usize,
}

/// Opaque proof that one structured file request was joined to one exact
/// authenticated source graph before prepared-cache discovery. It is
/// process-local and deliberately has no public constructor or serialization.
#[derive(Clone, Debug)]
pub struct AuthenticatedEntryJoinV1 {
    entry: SourceId,
    entry_vfs_source_id: crate::vfs::SourceId,
    source_integrity: Digest,
    snapshot_digest: Digest,
    producer_binary_digest: Digest,
}

impl SourceModuleGraphV1 {
    pub fn activation_checkpoint(&self) -> SourceGraphActivationCheckpoint {
        SourceGraphActivationCheckpoint {
            record_ids: self.records.keys().cloned().collect(),
            principal_ids: self.principal_ids.clone(),
            matched_candidate_declarations: self.matched_candidate_declarations.clone(),
            prepared_access_receipt_count: self._prepared_access_receipts.len(),
            activation_receipt_count: self._activation_receipts.len(),
        }
    }

    pub fn rollback_activation(&mut self, checkpoint: SourceGraphActivationCheckpoint) {
        self.records
            .retain(|source_id, _| checkpoint.record_ids.contains(source_id));
        self.principal_ids = checkpoint.principal_ids;
        self.matched_candidate_declarations = checkpoint.matched_candidate_declarations;
        self._prepared_access_receipts
            .truncate(checkpoint.prepared_access_receipt_count);
        self._activation_receipts
            .truncate(checkpoint.activation_receipt_count);
    }

    pub fn set_prepared_activation_cache_locator(
        &mut self,
        locator: Arc<dyn PreparedActivationCacheLocatorV1>,
    ) {
        self.prepared_activation_cache_locator = Some(locator);
    }

    pub fn entry(&self) -> &SourceId {
        &self.entry
    }

    pub fn execution_generation(&self) -> ExecutionGeneration {
        self.execution_generation
    }

    pub fn snapshot(&self) -> &ArmedSnapshot {
        &self.snapshot
    }

    /// Build the authenticated hot-revision graph from the exact rows retained
    /// by the admitted source/link plan.
    /// @ref LLP 0055#4-the-typed-authenticated-graph-obligation-4 — the source
    /// graph is the sole production constructor for plan-derived V2 rows.
    pub fn generation_graph_v2(&self) -> Result<AuthenticatedGenerationGraphV2> {
        let rows = self
            .records
            .values()
            .map(|record| {
                let verified = verify_record(record, &self.producer_binary_digest)?;
                let bindings = record.bindings.clone();
                let mut candidate_sites = BTreeMap::new();
                for table in &record.candidate_tables {
                    let pin = CandidateSitePinV1 {
                        digest: table.digest()?,
                        attributes_digest: computed_candidate_attributes_digest(table)?,
                    };
                    if candidate_sites.insert(u64::from(table.site), pin).is_some() {
                        bail!("source graph repeats a computed-candidate site");
                    }
                }
                Ok((
                    verified,
                    bindings,
                    candidate_sites,
                    record
                        .deferred_dynamic
                        .literal_attributes
                        .keys()
                        .map(|specifier| {
                            GraphEdgeKey::new(specifier, ResolutionKind::DynamicImport)
                        })
                        .collect(),
                    record
                        .deferred_commonjs_requires
                        .iter()
                        .map(|specifier| {
                            GraphEdgeKey::new(specifier, ResolutionKind::CommonJsRequire)
                        })
                        .collect(),
                    record.bootstrap_internal_commonjs_requires.clone(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        AuthenticatedGenerationGraphV2::from_verified(rows)
    }

    #[cfg(test)]
    pub(crate) fn source_access_receipt_count(&self) -> usize {
        self._source_access_receipts.len()
    }

    #[cfg(test)]
    pub(crate) fn prepared_access_receipt_count(&self) -> usize {
        self._prepared_access_receipts.len()
    }

    #[cfg(test)]
    pub(crate) fn activation_receipt_count(&self) -> usize {
        self._activation_receipts.len()
    }

    /// Join a post-admission graph back to the exact structured file request
    /// that authorized its discovery. Entry bytes and grammar are checked here
    /// so every engine/preparer pairing shares one fail-closed boundary.
    /// @ref LLP 0026#authenticate-before-discovery-and-execute-under-derived-identity
    /// @ref LLP 0027#canonical-encoding-and-validation
    pub fn validate_authenticated_entry_request(
        &self,
        request: &crate::engine::evaluation::SourceRequest,
    ) -> Result<AuthenticatedEntryJoinV1> {
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
        Ok(AuthenticatedEntryJoinV1 {
            entry: self.entry.clone(),
            entry_vfs_source_id: self
                .entry_vfs_source_id
                .clone()
                .expect("validated entry request has a VFS SourceId"),
            source_integrity: entry_artifact.semantics.source_integrity.clone(),
            snapshot_digest: self.snapshot.digest().clone(),
            producer_binary_digest: self.producer_binary_digest.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn authenticated_entry_join_for_test(&self) -> Result<AuthenticatedEntryJoinV1> {
        let record = self
            .records
            .get(&self.entry)
            .ok_or_else(|| anyhow!("authenticated native source graph omitted its entry record"))?;
        let entry_artifact = verify_record(record, &self.producer_binary_digest)?.artifact();
        Ok(AuthenticatedEntryJoinV1 {
            entry: self.entry.clone(),
            entry_vfs_source_id: self
                .entry_vfs_source_id
                .clone()
                .ok_or_else(|| anyhow!("test source graph has no VFS entry identity"))?,
            source_integrity: entry_artifact.semantics.source_integrity.clone(),
            snapshot_digest: self.snapshot.digest().clone(),
            producer_binary_digest: self.producer_binary_digest.clone(),
        })
    }

    pub fn plan(&self) -> Result<SynchronousGraphPlan<'_>> {
        SynchronousGraphPlan::new_typed_with_private_commonjs_edges(
            self.records
                .iter()
                .map(|(_, record)| {
                    Ok((
                        verify_record(record, &self.producer_binary_digest)?,
                        record.bindings.clone(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
            computed_candidate_site_map(&self.records)?,
            self.records
                .iter()
                .filter(|(_, record)| record.deferred_dynamic.enabled)
                .map(|(source_id, _)| source_id.clone())
                .collect(),
            self.records
                .iter()
                .filter(|(_, record)| !record.deferred_commonjs_requires.is_empty())
                .map(|(source_id, _)| source_id.clone())
                .collect(),
            self.records
                .iter()
                .filter(|(_, record)| !record.bootstrap_internal_commonjs_requires.is_empty())
                .map(|(source_id, record)| {
                    (
                        source_id.clone(),
                        record.bootstrap_internal_commonjs_requires.clone(),
                    )
                })
                .collect(),
        )
        .map_err(anyhow::Error::from)
    }

    pub fn deferred_dynamic_links(&self) -> DeferredDynamicImportLinks {
        self.records
            .iter()
            .filter_map(|(source_id, record)| {
                if !record.deferred_dynamic.enabled
                    && record.deferred_commonjs_requires.is_empty()
                    && record.bootstrap_internal_commonjs_requires.is_empty()
                {
                    return None;
                }
                Some((
                    source_id.clone(),
                    DeferredDynamicImportBindings {
                        literal_specifiers: record
                            .deferred_dynamic
                            .literal_attributes
                            .keys()
                            .cloned()
                            .collect(),
                        computed_candidates: record
                            .deferred_dynamic
                            .computed_attributes
                            .keys()
                            .cloned()
                            .collect(),
                        commonjs_require_specifiers: record.deferred_commonjs_requires.clone(),
                        bootstrap_internal_commonjs_specifiers: record
                            .bootstrap_internal_commonjs_requires
                            .clone(),
                    },
                ))
            })
            .collect()
    }

    pub fn has_call_time_activation_links(&self) -> bool {
        self.records.values().any(|record| {
            record.deferred_dynamic.enabled || !record.deferred_commonjs_requires.is_empty()
        })
    }

    /// Resolve and acquire one reached deferred import through the exact Host
    /// retained by authenticated ingress, then atomically extend this source
    /// graph with only the target's static closure.
    // @ref LLP 0024#3-source-goal
    // @ref LLP 0026#6-top-level-await-and-dynamic-import
    pub fn activate_dynamic_target(
        &mut self,
        request: &DynamicModuleActivationRequest,
    ) -> Result<SourceId> {
        let requester = self
            .records
            .get(&request.requester)
            .ok_or_else(|| anyhow!("dynamic activation requester is absent from source graph"))?;
        let attributes = match &request.kind {
            DynamicModuleActivationKind::Literal => requester
                .deferred_dynamic
                .literal_attributes
                .get(&request.specifier),
            DynamicModuleActivationKind::Computed { site } => requester
                .deferred_dynamic
                .computed_attributes
                .get(&(*site, request.specifier.clone())),
        }
        .cloned()
        .ok_or_else(|| {
            anyhow!("dynamic activation site and spelling are not authenticated declarations")
        })?;
        self.activate_call_time_target(
            &request.requester,
            &request.specifier,
            ResolutionKind::DynamicImport,
            GraphOperationKind::DynamicImport,
            attributes,
            request.graph_generation(),
        )
    }

    /// Resolve and acquire one exactly reached authored CommonJS `require()`.
    /// Merely constructing the source graph retains the spelling but neither
    /// resolves nor reads the target.
    // @ref LLP 0024#3-source-goal
    // @ref LLP 0026#7-commonjs-interop
    pub fn activate_commonjs_require_target(
        &mut self,
        requester: &SourceId,
        specifier: &str,
        graph_generation: u64,
    ) -> Result<SourceId> {
        let record = self
            .records
            .get(requester)
            .ok_or_else(|| anyhow!("CommonJS activation requester is absent from source graph"))?;
        if !record.deferred_commonjs_requires.contains(specifier) {
            bail!("CommonJS require spelling is not an authenticated declaration");
        }
        self.activate_call_time_target(
            requester,
            specifier,
            ResolutionKind::CommonJsRequire,
            GraphOperationKind::LiteralRequire,
            super::identity::ImportAttributes::default(),
            graph_generation,
        )
    }

    fn activate_call_time_target(
        &mut self,
        requester_id: &SourceId,
        specifier: &str,
        resolution_kind: ResolutionKind,
        operation_kind: GraphOperationKind,
        attributes: super::identity::ImportAttributes,
        graph_generation: u64,
    ) -> Result<SourceId> {
        let host = self
            .activation_host
            .clone()
            .ok_or_else(|| anyhow!("source graph has no retained activation Host"))?;
        let requester = self
            .records
            .get(requester_id)
            .ok_or_else(|| anyhow!("call-time activation requester is absent from source graph"))?;
        let key = GraphEdgeKey::new(specifier, resolution_kind);
        let authorizer = ModuleGraphAuthorizer::new(self.snapshot.as_ref());
        let target_meta = host.resolve_meta(
            specifier,
            Some(&requester.path),
            resolution_kind,
            &attributes,
        )?;
        let target_id = target_meta
            .artifact_source_id
            .clone()
            .ok_or_else(|| anyhow!("call-time activation resolution produced no SourceId"))?;
        if self.records.contains_key(&target_id) {
            let decision = graph_edge_decision(
                requester_id,
                &key,
                operation_kind,
                &attributes,
                graph_generation,
                target_id.clone(),
            )?;
            self._activation_receipts
                .push(authorizer.authorize(decision)?);
            return Ok(target_id);
        }

        let (target, target_receipt) = authorize_source_acquisition(
            &host,
            &authorizer,
            requester_id,
            &key,
            operation_kind,
            &attributes,
            graph_generation,
            target_meta,
        )?;
        let mut pending_receipts = vec![target_receipt];
        let mut pending_records = BTreeMap::new();
        let mut pending_principal_ids = self.principal_ids.clone();
        let mut pending_matched = self.matched_candidate_declarations.clone();
        let mut queue = VecDeque::from([target]);

        while let Some(module) = queue.pop_front() {
            let source_id = module
                .artifact_source_id
                .clone()
                .ok_or_else(|| anyhow!("activated source produced no SourceId"))?;
            if self.records.contains_key(&source_id) || pending_records.contains_key(&source_id) {
                continue;
            }
            let path = match module.path.clone() {
                Some(path) => path,
                None if module.kind == ModuleKind::Builtin => match &source_id {
                    SourceId::Builtin { source_key, .. } => {
                        PathBuf::from(format!("builtin:{}.js", source_key.as_str()))
                    }
                    _ => bail!("activated builtin has a non-builtin SourceId"),
                },
                None => bail!("activated source has no authenticated path"),
            };
            let source_label = match module.source_label.as_ref() {
                Some(label) => label.as_str().to_owned(),
                None => match &source_id {
                    SourceId::Builtin { source_key, .. } => {
                        format!("builtin:{}", source_key.as_str())
                    }
                    _ => bail!("activated file source has no VFS source label"),
                },
            };
            let virtual_path = module.virtual_path.clone();
            if matches!(&source_id, SourceId::Builtin { .. }) {
                if virtual_path.is_some() {
                    bail!("activated builtin unexpectedly has a virtual path");
                }
            } else {
                let virtual_path = virtual_path
                    .as_deref()
                    .ok_or_else(|| anyhow!("activated file source has no virtual path"))?;
                if !virtual_path.starts_with("/project/")
                    || source_label != format!("file://{virtual_path}")
                {
                    bail!("activated file source has invalid authenticated metadata");
                }
            }
            let source = module
                .source
                .as_deref()
                .ok_or_else(|| anyhow!("activated source has no authenticated bytes"))?;
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
                    self.producer_binary_digest.clone(),
                ),
                ModuleKind::CommonJs => produce_commonjs_artifact_with_sites_v1(
                    source_id.clone(),
                    source_name,
                    &path,
                    source,
                    self.producer_binary_digest.clone(),
                ),
                ModuleKind::Json => produce_json_artifact_v1(
                    source_id.clone(),
                    source,
                    self.producer_binary_digest.clone(),
                )
                .map(|artifact| super::producer_spike::ProducedModuleArtifactV1 {
                    artifact,
                    dynamic_import_sites: Vec::new(),
                    guarded_unsupported_sites: Vec::new(),
                }),
                ModuleKind::Builtin => produce_builtin_artifact_v1(
                    source_id.clone(),
                    source_name,
                    source,
                    self.producer_binary_digest.clone(),
                )
                .map(|artifact| super::producer_spike::ProducedModuleArtifactV1 {
                    artifact,
                    dynamic_import_sites: Vec::new(),
                    guarded_unsupported_sites: Vec::new(),
                }),
            }
            .map_err(|error| anyhow!("cannot prepare activated module {source_name:?}: {error}"))?;
            let artifact = produced.artifact;
            ensure_source_graph_call_time_edges_supported(&artifact, true)?;
            let mut bindings = BTreeMap::new();
            let mut deferred_dynamic = DeferredSourceDynamicBindingsV1::default();
            let deferred_commonjs_requires = deferred_commonjs_require_specifiers(&artifact, true);
            let bootstrap_internal_commonjs_requires =
                bootstrap_internal_commonjs_require_specifiers(&artifact);
            deferred_dynamic.enabled = !artifact.semantics.dynamic_edges.is_empty();
            for edge in &artifact.semantics.dynamic_edges {
                if let DynamicEdgeV1::Literal {
                    specifier,
                    attributes,
                } = edge
                {
                    // @ref LLP 0027#artifact-envelope — authored sites remain distinct
                    // artifact edges, while identical spelling/attribute rows share one binding.
                    match deferred_dynamic
                        .literal_attributes
                        .insert(specifier.as_str().to_owned(), attributes.clone())
                    {
                        Some(previous) if previous != *attributes => {
                            bail!(
                                "activated artifact literal dynamic-import spelling {:?} carries conflicting attributes",
                                specifier.as_str()
                            );
                        }
                        _ => {}
                    }
                }
            }

            for dependency_key in artifact_edge_requests(&artifact)
                .into_iter()
                .filter(|edge| {
                    edge.resolution_kind != ResolutionKind::DynamicImport
                        && !(edge.resolution_kind == ResolutionKind::CommonJsRequire
                            && deferred_commonjs_requires.contains(&edge.specifier))
                        && !(edge.resolution_kind == ResolutionKind::CommonJsRequire
                            && bootstrap_internal_commonjs_requires.contains(&edge.specifier))
                })
            {
                let dependency_attributes = artifact_edge_attributes(&artifact, &dependency_key)?;
                let dependency_meta = if module.kind == ModuleKind::Builtin {
                    if dependency_key.resolution_kind != ResolutionKind::CommonJsRequire
                        || !dependency_attributes.is_empty()
                    {
                        bail!("activated builtin has an invalid private edge");
                    }
                    host.resolve_manifest_builtin_internal(&dependency_key.specifier)
                        .with_context(|| {
                            format!(
                                "activated builtin {source_id:?} requested non-manifest dependency {:?}",
                                dependency_key.specifier
                            )
                        })?
                } else {
                    host.resolve_meta(
                        &dependency_key.specifier,
                        Some(&path),
                        dependency_key.resolution_kind,
                        &dependency_attributes,
                    )?
                };
                let dependency_id = dependency_meta
                    .artifact_source_id
                    .clone()
                    .ok_or_else(|| anyhow!("activated dependency produced no SourceId"))?;
                if module.kind != ModuleKind::Builtin {
                    let operation_kind = artifact_edge_operation_kind(
                        &artifact,
                        &dependency_key,
                        &dependency_attributes,
                    )?;
                    if self.records.contains_key(&dependency_id)
                        || pending_records.contains_key(&dependency_id)
                    {
                        let decision = graph_edge_decision(
                            &source_id,
                            &dependency_key,
                            operation_kind,
                            &dependency_attributes,
                            graph_generation,
                            dependency_id.clone(),
                        )?;
                        pending_receipts.push(authorizer.authorize(decision)?);
                    } else {
                        let (loaded, receipt) = authorize_source_acquisition(
                            &host,
                            &authorizer,
                            &source_id,
                            &dependency_key,
                            operation_kind,
                            &dependency_attributes,
                            graph_generation,
                            dependency_meta,
                        )?;
                        pending_receipts.push(receipt);
                        queue.push_back(loaded);
                    }
                } else {
                    queue.push_back(dependency_meta);
                }
                if let Some(previous) =
                    bindings.insert(dependency_key.clone(), dependency_id.clone())
                {
                    if previous != dependency_id {
                        bail!("one activated dependency resolved to two SourceIds");
                    }
                }
            }

            if let Some(requester_path) =
                authenticated_root_requester_path(&source_id, &path, &self.project_root)
            {
                for site in produced.dynamic_import_sites {
                    if !site.runtime_options_supported {
                        continue;
                    }
                    let Some(label) = site.label else {
                        continue;
                    };
                    let declaration_key = (requester_path.clone(), label.as_str().to_owned());
                    let Some(specifiers) = self.candidate_declarations.get(&declaration_key) else {
                        continue;
                    };
                    pending_matched.insert(declaration_key);
                    for specifier in specifiers {
                        if let Some(previous) = deferred_dynamic.computed_attributes.insert(
                            (site.site, specifier.as_str().to_owned()),
                            site.attributes.clone(),
                        ) {
                            if previous != site.attributes {
                                bail!("activated computed candidate carries two attribute bags");
                            }
                        }
                    }
                }
            }
            if let Some(principal) = source_id.defining_principal().cloned() {
                if !pending_principal_ids.contains_key(&principal) {
                    pending_principal_ids.insert(principal.clone(), host.principal_id(&principal)?);
                }
            }
            pending_records.insert(
                source_id,
                SourceGraphRecordV1 {
                    path,
                    source_label,
                    virtual_path,
                    artifact,
                    bindings,
                    candidate_tables: Vec::new(),
                    deferred_dynamic,
                    deferred_commonjs_requires,
                    bootstrap_internal_commonjs_requires,
                    prepared: None,
                },
            );
        }

        let known_requesters = self
            .records
            .iter()
            .chain(pending_records.iter())
            .filter_map(|(source_id, record)| {
                authenticated_root_requester_path(source_id, &record.path, &self.project_root)
            })
            .collect::<BTreeSet<_>>();
        if self
            .candidate_declarations
            .keys()
            .any(|(requester, label)| {
                known_requesters.contains(requester)
                    && !pending_matched.contains(&(requester.clone(), label.clone()))
            })
        {
            bail!("activated computed-candidate declarations do not match producer sites");
        }
        let deferred_sources = self
            .records
            .iter()
            .chain(pending_records.iter())
            .filter(|(_, record)| record.deferred_dynamic.enabled)
            .map(|(source_id, _)| source_id.clone())
            .collect();
        let deferred_commonjs_sources = self
            .records
            .iter()
            .chain(pending_records.iter())
            .filter(|(_, record)| !record.deferred_commonjs_requires.is_empty())
            .map(|(source_id, _)| source_id.clone())
            .collect();
        SynchronousGraphPlan::new_typed_with_private_commonjs_edges(
            self.records
                .iter()
                .chain(pending_records.iter())
                .map(|(_, record)| {
                    Ok((
                        verify_record(record, &self.producer_binary_digest)?,
                        record.bindings.clone(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
            BTreeMap::new(),
            deferred_sources,
            deferred_commonjs_sources,
            self.records
                .iter()
                .chain(pending_records.iter())
                .filter(|(_, record)| !record.bootstrap_internal_commonjs_requires.is_empty())
                .map(|(source_id, record)| {
                    (
                        source_id.clone(),
                        record.bootstrap_internal_commonjs_requires.clone(),
                    )
                })
                .collect(),
        )?;

        let activated_record_ids = pending_records.keys().cloned().collect::<BTreeSet<_>>();
        self.records.append(&mut pending_records);
        self.principal_ids = pending_principal_ids;
        self.matched_candidate_declarations = pending_matched;
        self._activation_receipts.extend(pending_receipts);
        if let Some(locator) = self.prepared_activation_cache_locator.clone() {
            let _ = locator.publish_authenticated_records(self, &activated_record_ids);
            if let Ok(candidates) = locator.locate(&target_id) {
                for candidate in candidates {
                    if load_prepared_activation_records_v1(
                        self,
                        &activated_record_ids,
                        &candidate.cache_dir,
                        &candidate.deployment_graph_digest,
                    )
                    .is_ok()
                    {
                        break;
                    }
                }
            }
        }
        Ok(target_id)
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

    pub fn available_prepared_entries(
        &self,
    ) -> Result<BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'_>>> {
        self.records
            .iter()
            .filter_map(|(source_id, record)| {
                record.prepared.as_ref().map(|prepared| {
                    Ok((
                        source_id.clone(),
                        prepared.carrier.entry(prepared.entry_id.as_str())?,
                    ))
                })
            })
            .collect()
    }

    pub fn native_execution_inputs(
        &self,
        graph_generation: u64,
    ) -> Result<(
        BTreeMap<SourceId, NativeModuleRecordConfig>,
        BTreeMap<SourceId, super::security::GraphAuthorityContext>,
    )> {
        if graph_generation != self.execution_generation.get() {
            bail!(
                "native execution inputs generation {} does not match the graph's execution generation {}",
                graph_generation,
                self.execution_generation.get()
            );
        }
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
            let source_label = record.source_label.clone();
            let virtual_path = record.virtual_path.clone();
            if matches!(source_id, SourceId::Builtin { .. }) {
                if virtual_path.is_some() {
                    bail!("builtin record unexpectedly has a virtual filesystem path");
                }
            } else {
                let path = virtual_path
                    .as_deref()
                    .ok_or_else(|| anyhow!("file record has no authenticated virtual path"))?;
                if source_label != format!("file://{path}") {
                    bail!("file record source label disagrees with its virtual path");
                }
            }
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
                source_label.clone(),
                source_label,
            )?;
            if let Some(virtual_path) = virtual_path {
                config = config.with_authenticated_virtual_path(virtual_path)?;
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

fn computed_candidate_attributes_digest(table: &ComputedCandidateTableV1) -> Result<Digest> {
    let rows = table
        .candidates
        .iter()
        .map(|candidate| {
            serde_json::json!({
                "specifier": candidate.specifier.as_str(),
                "attributes": &candidate.attributes,
            })
        })
        .collect();
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&serde_json::Value::Array(rows))
        .map_err(|error| anyhow!("cannot canonicalize computed-candidate attributes: {error}"))?;
    source_integrity(&canonical)
}

fn computed_candidate_site_map(
    records: &BTreeMap<SourceId, SourceGraphRecordV1>,
) -> Result<ComputedCandidateSiteMap> {
    let mut rows = ComputedCandidateSiteMap::new();
    for record in records.values() {
        for table in &record.candidate_tables {
            for candidate in &table.candidates {
                let key = (table.site, candidate.specifier.as_str().to_owned());
                let binding = ComputedCandidateBinding {
                    target: candidate.target.0.clone(),
                    attributes: candidate.attributes.clone(),
                };
                if let Some(previous) = rows
                    .entry(table.requester.0.clone())
                    .or_default()
                    .insert(key, binding.clone())
                {
                    if previous != binding {
                        bail!("computed-candidate site and spelling disagree across sidecars");
                    }
                }
            }
        }
    }
    Ok(rows)
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
    let mut guarded_unsupported_sites = Vec::new();
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
        let (source_label, virtual_path) = portable_record_display(&source_id)?;
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
                        guarded_unsupported_sites: Vec::new(),
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
                guarded_unsupported_sites: Vec::new(),
            }),
        }
        .map_err(|error| anyhow!("cannot prepare compiled module {portable_name:?}: {error}"))?;
        let super::producer_spike::ProducedModuleArtifactV1 {
            artifact,
            dynamic_import_sites,
            guarded_unsupported_sites: module_guarded_sites,
        } = produced;
        let source_identity = source_id.encode()?;
        guarded_unsupported_sites.extend(module_guarded_sites.into_iter().map(|site| {
            CapturedGuardedUnsupportedSiteV1 {
                source_id: source_identity.clone(),
                start: site.original_source_span.start,
                end: site.original_source_span.end,
                shape: site.shape,
            }
        }));
        let bootstrap_internal_commonjs_requires =
            bootstrap_internal_commonjs_require_specifiers(&artifact);

        let mut bindings = BTreeMap::new();
        for key in artifact_edge_requests(&artifact) {
            // Builtins reach these sealed objects through the native bootstrap
            // resolver. They are deliberately not application graph records,
            // package resolutions, or independently supplied carrier bytes.
            // @ref LLP 0004#one-source-many-specifiers
            if key.resolution_kind == ResolutionKind::CommonJsRequire
                && bootstrap_internal_commonjs_requires.contains(&key.specifier)
            {
                continue;
            }
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
            for site in dynamic_import_sites {
                if !site.runtime_options_supported {
                    continue;
                }
                let Some(label) = site.label else {
                    guarded_unsupported_sites.push(CapturedGuardedUnsupportedSiteV1 {
                        source_id: source_identity.clone(),
                        start: site.original_source_span.start,
                        end: site.original_source_span.end,
                        shape:
                            GuardedUnsupportedShapeV1::ComputedDynamicImportWithoutCandidateTable,
                    });
                    continue;
                };
                let declaration_key = (requester.clone(), label.as_str().to_owned());
                let Some(specifiers) = candidate_declarations.get(&declaration_key) else {
                    guarded_unsupported_sites.push(CapturedGuardedUnsupportedSiteV1 {
                        source_id: source_identity.clone(),
                        start: site.original_source_span.start,
                        end: site.original_source_span.end,
                        shape:
                            GuardedUnsupportedShapeV1::ComputedDynamicImportWithoutCandidateTable,
                    });
                    continue;
                };
                matched_candidate_declarations.insert(declaration_key);
                let mut candidates = Vec::new();
                for specifier in specifiers {
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
        } else {
            for site in dynamic_import_sites {
                if site.runtime_options_supported {
                    guarded_unsupported_sites.push(CapturedGuardedUnsupportedSiteV1 {
                        source_id: source_identity.clone(),
                        start: site.original_source_span.start,
                        end: site.original_source_span.end,
                        shape:
                            GuardedUnsupportedShapeV1::ComputedDynamicImportWithoutCandidateTable,
                    });
                }
            }
        }
        let record_path = module.path.unwrap_or(portable_path);
        records.insert(
            source_id,
            SourceGraphRecordV1 {
                path: record_path,
                source_label,
                virtual_path,
                artifact,
                bindings,
                candidate_tables,
                deferred_dynamic: DeferredSourceDynamicBindingsV1::default(),
                deferred_commonjs_requires: BTreeSet::new(),
                bootstrap_internal_commonjs_requires,
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
    guarded_unsupported_sites.sort();
    let prepared = prepare_embedded_records_v1(&entry_id, &records, &producer_binary_digest)?;
    Ok(CapturedEmbeddedSourceGraphV1 {
        prepared,
        entry_components,
        entry_source_integrity,
        guarded_unsupported_sites,
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
    let mut nearest_package = None;
    let mut outermost_workspace = None;
    loop {
        let package_path = cursor.join("package.json");
        if package_path.is_file() {
            nearest_package.get_or_insert_with(|| cursor.to_path_buf());
            let package_bytes = std::fs::read(&package_path).with_context(|| {
                format!("cannot read project marker {}", package_path.display())
            })?;
            let package: serde_json::Value =
                serde_json::from_slice(&package_bytes).with_context(|| {
                    format!("project marker is not JSON: {}", package_path.display())
                })?;
            if package.get("workspaces").is_some() {
                outermost_workspace = Some(cursor.to_path_buf());
            }
        }
        let Some(parent) = cursor.parent() else {
            return Ok(outermost_workspace
                .or(nearest_package)
                .unwrap_or_else(|| entry_parent.to_path_buf()));
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

fn portable_record_display(source_id: &SourceId) -> Result<(String, Option<String>)> {
    match source_id {
        SourceId::Builtin { domain, source_key } => Ok((
            format!("builtin:{}:{}", domain.as_str(), source_key.as_str()),
            None,
        )),
        SourceId::File { .. } => {
            let encoded = source_id.encode()?;
            let display = VirtualSourceLabelV1::new(format!("/app/modules/{encoded}"))?;
            Ok((display.import_meta_url, Some(display.path)))
        }
        SourceId::Synthetic { .. } => bail!("synthetic sources are not packable in v1"),
    }
}

fn artifact_edge_operation_kind(
    artifact: &ModuleArtifactV1,
    key: &GraphEdgeKey,
    attributes: &super::identity::ImportAttributes,
) -> Result<GraphOperationKind> {
    let kind = match key.resolution_kind {
        ResolutionKind::CommonJsRequire => GraphOperationKind::LiteralRequire,
        ResolutionKind::DynamicImport => GraphOperationKind::DynamicImport,
        ResolutionKind::EsmStatic if attributes.asserts_json() => GraphOperationKind::JsonLoad,
        ResolutionKind::EsmStatic => {
            let is_reexport = artifact
                .semantics
                .static_edges
                .iter()
                .any(|edge| match edge {
                    StaticEdgeV1::ReExportNamed { specifier, .. }
                    | StaticEdgeV1::ReExportStar { specifier, .. }
                    | StaticEdgeV1::ReExportNamespace { specifier, .. } => {
                        specifier.as_str() == key.specifier
                    }
                    _ => false,
                });
            if is_reexport {
                GraphOperationKind::ReExport
            } else {
                GraphOperationKind::StaticImport
            }
        }
        ResolutionKind::Entry => bail!("an authored dependency edge cannot have entry resolution"),
    };
    Ok(kind)
}

/// Refuse an authored call-time edge before resolving or acquiring any of its
/// targets. The native linker repeats this check at its own trust boundary,
/// but graph construction is the first place a source artifact can cause
/// dependency discovery and therefore owns the no-probe ordering.
///
/// Manifest builtin `require()` fan-out is the sole exception: it is a
/// generated, exact builtin-to-builtin initialization closure rather than an
/// authored deferred edge, and the completed graph validates that distinction
/// again before native linking.
// @ref LLP 0024#3-source-goal
// @ref LLP 0026#6-top-level-await-and-dynamic-import
fn ensure_source_graph_call_time_edges_supported(
    artifact: &ModuleArtifactV1,
    call_time_activation_available: bool,
) -> Result<()> {
    let source_id = &artifact.semantics.source_id.0;
    if !artifact.semantics.dynamic_edges.is_empty() && !call_time_activation_available {
        bail!("native call-time dynamic-import activation is unavailable for {source_id:?}");
    }
    if artifact.semantics.source_goal != super::artifact::SourceGoalV1::Builtin
        && artifact
            .semantics
            .static_edges
            .iter()
            .any(|edge| matches!(edge, StaticEdgeV1::CommonJsRequire { .. }))
        && !call_time_activation_available
    {
        bail!("native call-time CommonJS require activation is unavailable for {source_id:?}");
    }
    Ok(())
}

fn deferred_commonjs_require_specifiers(
    artifact: &ModuleArtifactV1,
    call_time_activation_available: bool,
) -> BTreeSet<String> {
    if !call_time_activation_available
        || artifact.semantics.source_goal == super::artifact::SourceGoalV1::Builtin
    {
        return BTreeSet::new();
    }
    artifact
        .semantics
        .static_edges
        .iter()
        .filter_map(|edge| match edge {
            StaticEdgeV1::CommonJsRequire { specifier } => Some(specifier.as_str().to_owned()),
            _ => None,
        })
        .collect()
}

fn bootstrap_internal_commonjs_require_specifiers(artifact: &ModuleArtifactV1) -> BTreeSet<String> {
    if artifact.semantics.source_goal != super::artifact::SourceGoalV1::Builtin {
        return BTreeSet::new();
    }
    artifact
        .semantics
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
        .collect()
}

fn authorize_source_acquisition(
    host: &impl SourceGraphHost,
    authorizer: &ModuleGraphAuthorizer<'_, ArmedSnapshot>,
    requester: &SourceId,
    key: &GraphEdgeKey,
    operation_kind: GraphOperationKind,
    attributes: &super::identity::ImportAttributes,
    graph_generation: u64,
    meta: ResolvedModule,
) -> Result<(ResolvedModule, AuthorizedGraphOperation)> {
    let target = meta
        .artifact_source_id
        .clone()
        .ok_or_else(|| anyhow!("authenticated dependency metadata produced no SourceId"))?;
    let decision = graph_edge_decision(
        requester,
        key,
        operation_kind,
        attributes,
        graph_generation,
        target,
    )?;
    authorizer.authorize_then_acquire_source(
        decision,
        || host.load_source(meta),
        |loaded| {
            let source = loaded
                .source
                .as_deref()
                .ok_or_else(|| anyhow!("authenticated source acquisition returned no bytes"))?;
            source_integrity(source.as_bytes())
        },
    )
}

fn graph_edge_decision(
    requester: &SourceId,
    key: &GraphEdgeKey,
    operation_kind: GraphOperationKind,
    attributes: &super::identity::ImportAttributes,
    graph_generation: u64,
    target: SourceId,
) -> Result<GraphDecisionSet> {
    let owner = requester
        .defining_principal()
        .cloned()
        .ok_or_else(|| anyhow!("authored dependency requester has no defining principal"))?;
    let context = GraphAuthorityContext::new(
        requester.clone(),
        owner.clone(),
        owner.clone(),
        owner.clone(),
        vec![owner],
        Stage::Requested,
        graph_generation,
    )?;
    GraphDecisionSet::new(
        operation_kind,
        context,
        target,
        key.specifier.as_str(),
        key.resolution_kind,
        super::identity::ConditionSet::for_kind(key.resolution_kind),
        attributes.clone(),
        None,
        None,
    )
}

pub fn build_authenticated_source_graph_v1(
    entry: &Path,
    producer_binary_digest: Digest,
    execution_generation: ExecutionGeneration,
) -> Result<SourceModuleGraphBuildV1> {
    build_authenticated_source_graph_v1_with_host(
        &InstalledSourceGraphHost,
        None,
        entry,
        producer_binary_digest,
        execution_generation,
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
    execution_generation: ExecutionGeneration,
) -> Result<SourceModuleGraphBuildV1> {
    build_authenticated_source_graph_v1_with_host(
        host,
        Some(host.clone()),
        entry,
        producer_binary_digest,
        execution_generation,
    )
}

fn build_authenticated_source_graph_v1_with_host(
    host: &impl SourceGraphHost,
    activation_host: Option<crate::host::Host>,
    entry: &Path,
    producer_binary_digest: Digest,
    // @ref LLP 0055#1-the-hotrevision-counter-and-successor-law — execution coordinate is session-minted, never the authority counter.
    execution_generation: ExecutionGeneration,
) -> Result<SourceModuleGraphBuildV1> {
    let snapshot = host.snapshot()?;
    let authorizer = ModuleGraphAuthorizer::new(snapshot.as_ref());
    let graph_generation = execution_generation.get();
    let mut source_access_receipts = Vec::new();
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
                        guarded_unsupported_sites: Vec::new(),
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
                guarded_unsupported_sites: Vec::new(),
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
        ensure_source_graph_call_time_edges_supported(&artifact, activation_host.is_some())?;
        let mut bindings = BTreeMap::new();
        let mut deferred_dynamic = DeferredSourceDynamicBindingsV1::default();
        let deferred_commonjs_requires =
            deferred_commonjs_require_specifiers(&artifact, activation_host.is_some());
        let bootstrap_internal_commonjs_requires =
            bootstrap_internal_commonjs_require_specifiers(&artifact);
        deferred_dynamic.enabled = !artifact.semantics.dynamic_edges.is_empty();
        for edge in &artifact.semantics.dynamic_edges {
            if let DynamicEdgeV1::Literal {
                specifier,
                attributes,
            } = edge
            {
                // @ref LLP 0027#artifact-envelope — authored sites remain distinct
                // artifact edges, while identical spelling/attribute rows share one binding.
                match deferred_dynamic
                    .literal_attributes
                    .insert(specifier.as_str().to_owned(), attributes.clone())
                {
                    Some(previous) if previous != *attributes => {
                        bail!(
                            "authenticated artifact literal dynamic-import spelling {:?} carries conflicting attributes",
                            specifier.as_str()
                        );
                    }
                    _ => {}
                }
            }
        }
        for key in artifact_edge_requests(&artifact).into_iter().filter(|key| {
            key.resolution_kind != ResolutionKind::DynamicImport
                && !(key.resolution_kind == ResolutionKind::CommonJsRequire
                    && deferred_commonjs_requires.contains(&key.specifier))
                && !(key.resolution_kind == ResolutionKind::CommonJsRequire
                    && bootstrap_internal_commonjs_requires.contains(&key.specifier))
        }) {
            let attributes = artifact_edge_attributes(&artifact, &key)?;
            let target = if module.kind == ModuleKind::Builtin {
                if key.resolution_kind != ResolutionKind::CommonJsRequire || !attributes.is_empty()
                {
                    bail!("generated builtin has a non-CommonJS or attributed private edge");
                }
                match host.resolve_manifest_builtin_internal(&key.specifier) {
                    Ok(target) => target,
                    // Bootstrap-internal specifiers are served by the shared
                    // runtime's bootstrap module cache, or are intentionally
                    // absent and guarded at the require site (fs's optional
                    // `internal/test/binding`). The manifest resolver refuses
                    // them by design, so they are call-time edges, not eager
                    // host-resolvable materialization edges; leave them out of
                    // the binding table instead of failing the graph.
                    Err(_)
                        if crate::module_loader::is_bootstrap_internal_module_specifier(
                            &key.specifier,
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            } else {
                let meta = match host.resolve_meta(
                    &key.specifier,
                    Some(&path),
                    key.resolution_kind,
                    &attributes,
                ) {
                    Ok(meta) => meta,
                    // Call-time edges preserve Node error timing: a target
                    // that does not resolve is left unbound, and the engine
                    // rejects the import promise / throws a catchable require
                    // error if the site actually runs. Link-time (ESM static)
                    // resolution failures still fail the graph here.
                    Err(_)
                        if matches!(
                            key.resolution_kind,
                            ResolutionKind::CommonJsRequire | ResolutionKind::DynamicImport
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let operation_kind = artifact_edge_operation_kind(&artifact, &key, &attributes)?;
                let (target, receipt) = authorize_source_acquisition(
                    host,
                    &authorizer,
                    &source_id,
                    &key,
                    operation_kind,
                    &attributes,
                    graph_generation,
                    meta,
                )?;
                source_access_receipts.push(receipt);
                target
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
        let candidate_tables = Vec::new();
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
                for specifier in specifiers {
                    if let Some(previous) = deferred_dynamic.computed_attributes.insert(
                        (site.site, specifier.as_str().to_owned()),
                        site.attributes.clone(),
                    ) {
                        if previous != site.attributes {
                            bail!(
                                "one authenticated candidate spelling carries two attribute bags"
                            );
                        }
                    }
                }
            }
        }
        records.insert(
            source_id,
            SourceGraphRecordV1 {
                path,
                source_label,
                virtual_path,
                artifact,
                bindings,
                candidate_tables,
                deferred_dynamic,
                deferred_commonjs_requires,
                bootstrap_internal_commonjs_requires,
                prepared: None,
            },
        );
    }

    let known_requesters = records
        .iter()
        .filter_map(|(source_id, record)| {
            authenticated_root_requester_path(source_id, &record.path, &project_root)
        })
        .collect::<BTreeSet<_>>();
    if candidate_declarations.keys().any(|(requester, label)| {
        known_requesters.contains(requester)
            && !matched_candidate_declarations.contains(&(requester.clone(), label.clone()))
    }) {
        bail!("computed-candidate declarations for a linked requester do not match authenticated producer sites");
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
        execution_generation,
        snapshot,
        principal_ids,
        producer_binary_digest,
        records,
        activation_host,
        project_root,
        candidate_declarations,
        matched_candidate_declarations,
        prepared_activation_cache_locator: None,
        _source_access_receipts: source_access_receipts,
        _prepared_access_receipts: Vec::new(),
        _activation_receipts: Vec::new(),
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
    SynchronousGraphPlan::new_typed_with_private_commonjs_edges(
        records
            .values()
            .map(|record| {
                Ok((
                    verify_record(record, producer_binary_digest)?,
                    record.bindings.clone(),
                ))
            })
            .collect::<Result<Vec<_>>>()?,
        computed_candidate_site_map(records)?,
        records
            .iter()
            .filter(|(_, record)| record.deferred_dynamic.enabled)
            .map(|(source_id, _)| source_id.clone())
            .collect(),
        records
            .iter()
            .filter(|(_, record)| !record.deferred_commonjs_requires.is_empty())
            .map(|(source_id, _)| source_id.clone())
            .collect(),
        records
            .iter()
            .filter(|(_, record)| !record.bootstrap_internal_commonjs_requires.is_empty())
            .map(|(source_id, record)| {
                (
                    source_id.clone(),
                    record.bootstrap_internal_commonjs_requires.clone(),
                )
            })
            .collect(),
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
                        attributes: artifact_edge_attributes(&record.artifact, key)?,
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

struct RenderedPreparedCarrierV2 {
    defining_principal: Principal,
    member_source_ids: Vec<SourceId>,
    carrier_digest: Digest,
    manifest_file: String,
    manifest_bytes: Vec<u8>,
    bytes_file: String,
    bytes: Vec<u8>,
}

struct RenderedPreparedCandidateTableV2 {
    file: String,
    bytes: Vec<u8>,
}

struct RenderedPreparedPublicationV2 {
    index_bytes: Vec<u8>,
    carriers: Vec<RenderedPreparedCarrierV2>,
    candidate_tables: Vec<RenderedPreparedCandidateTableV2>,
}

/// Deterministically render the complete prepared publication from an already
/// authenticated inline graph. Reload uses this in-memory rendering as its
/// trust root: no digest or principal asserted by the writable cache is ever
/// allowed to authorize that same cache.
/// @ref LLP 0027#digest-domains — physical carrier bytes remain separately
/// authenticated, while admission is bound to the authenticated source graph.
fn render_prepared_source_graph_v2(
    graph: &SourceModuleGraphV1,
    deployment_graph_digest: &Digest,
) -> Result<RenderedPreparedPublicationV2> {
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
    let mut carrier_index_records = Vec::new();
    let mut rendered_carriers = Vec::new();
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
        let member_source_ids = entries
            .iter()
            .map(|(source_id, _)| source_id.clone())
            .collect();
        for (source_id, entry_id) in entries {
            prepared_artifacts.insert(
                source_id,
                (manifest.prepared_artifact(entry_id.as_str())?, entry_id),
            );
        }
        carrier_indexes.insert(principal.clone(), carrier_index);
        carrier_index_records.push(PreparedGraphCarrierIndexV1 {
            manifest_file: manifest_file.clone(),
            bytes_file: bytes_file.clone(),
        });
        rendered_carriers.push(RenderedPreparedCarrierV2 {
            defining_principal: principal,
            member_source_ids,
            carrier_digest: manifest.carrier_digest.clone(),
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
    let mut candidate_table_indexes = Vec::with_capacity(tables.len());
    let mut rendered_candidate_tables = Vec::with_capacity(tables.len());
    for (index, table) in tables.into_iter().enumerate() {
        let file = format!("candidate-{index}.json");
        candidate_table_indexes.push(PreparedGraphCandidateTableIndexV2 {
            file: file.clone(),
            digest: table.digest()?,
        });
        rendered_candidate_tables.push(RenderedPreparedCandidateTableV2 {
            file,
            bytes: table.canonical_bytes()?,
        });
    }

    let index = PreparedGraphIndexV2 {
        schema: PREPARED_GRAPH_INDEX_SCHEMA_V2.into(),
        entry: graph.entry.clone(),
        producer_binary_digest: graph.producer_binary_digest.clone(),
        deployment_graph_digest: deployment_graph_digest.clone(),
        records,
        carriers: carrier_index_records,
        candidate_tables: candidate_table_indexes,
    };
    let index_bytes = capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(index)?)
        .map_err(|error| anyhow!("cannot canonicalize prepared graph index: {error}"))?;
    Ok(RenderedPreparedPublicationV2 {
        index_bytes,
        carriers: rendered_carriers,
        candidate_tables: rendered_candidate_tables,
    })
}

fn prepared_activation_record_cache_dir(
    cache_dir: &Path,
    source_id: &SourceId,
    semantic_digest: &Digest,
) -> Result<PathBuf> {
    let identity = capsec_semantics::canonical::to_jcs_bytes(&serde_json::json!({
        "semanticDigest": semantic_digest,
        "sourceId": source_id,
    }))
    .map_err(|error| anyhow!("cannot canonicalize prepared activation identity: {error}"))?;
    let key = digest_bytes(PREPARED_ACTIVATION_CACHE_KEY_DOMAIN_V1, &identity)?;
    let key = key
        .as_str()
        .strip_prefix("sha256-")
        .unwrap_or_else(|| key.as_str());
    Ok(cache_dir.join("activation").join(key))
}

fn prepared_record_principal(
    graph: &SourceModuleGraphV1,
    source_id: &SourceId,
) -> Result<Principal> {
    source_id
        .defining_principal()
        .cloned()
        .or_else(|| {
            matches!(source_id, SourceId::Builtin { .. })
                .then(|| {
                    graph
                        .records
                        .keys()
                        .filter_map(SourceId::defining_principal)
                        .find(|principal| principal.is_root())
                        .cloned()
                })
                .flatten()
        })
        .ok_or_else(|| anyhow!("prepared activation record has no defining principal"))
}

/// Publish deterministic one-record carriers for an invocation-time activated
/// closure. There is deliberately no activation index: after source
/// acquisition the exact SourceId and semantic digest derive each immutable
/// path directly.
// @ref LLP 0026#authenticate-before-discovery-and-execute-under-derived-identity
pub fn publish_prepared_activation_records_v1(
    graph: &SourceModuleGraphV1,
    record_ids: &BTreeSet<SourceId>,
    artifact_dir: &Path,
    deployment_graph_digest: Digest,
) -> Result<PathBuf> {
    if record_ids.is_empty() {
        bail!("prepared activation publication requires at least one record");
    }
    let cache_dir = prepared_graph_cache_dir(artifact_dir, &deployment_graph_digest);
    let activation_root = cache_dir.join("activation");
    std::fs::create_dir_all(&activation_root)?;
    let producer_id =
        NonEmptyString::new(PREPARED_GRAPH_PRODUCER_ID).map_err(anyhow::Error::msg)?;

    for source_id in record_ids {
        let record = graph
            .records
            .get(source_id)
            .ok_or_else(|| anyhow!("prepared activation record is absent from source graph"))?;
        if record.prepared.is_some() {
            bail!("only an admitted inline record can be published for call-time activation");
        }
        let verified = verify_record(record, &graph.producer_binary_digest)?;
        let entry_id = NonEmptyString::new(record.artifact.semantic_digest.as_str())
            .map_err(anyhow::Error::msg)?;
        let principal = prepared_record_principal(graph, source_id)?;
        let (manifest, payload) = PreparedModuleCarrierV2::from_inline_artifacts(
            principal,
            producer_id.clone(),
            graph.producer_binary_digest.clone(),
            deployment_graph_digest.clone(),
            [(entry_id, verified)],
        )?;
        let destination = prepared_activation_record_cache_dir(
            &cache_dir,
            source_id,
            &record.artifact.semantic_digest,
        )?;
        if destination.join("manifest.json").is_file() && destination.join("payload.js").is_file() {
            continue;
        }
        let staging = activation_root.join(format!(
            ".stage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir(&staging)?;
        let result = (|| -> Result<()> {
            std::fs::write(staging.join("manifest.json"), manifest.encode_canonical()?)?;
            std::fs::write(staging.join("payload.js"), payload)?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error);
        }
        match std::fs::rename(&staging, &destination) {
            Ok(()) => {}
            Err(_)
                if destination.join("manifest.json").is_file()
                    && destination.join("payload.js").is_file() =>
            {
                let _ = std::fs::remove_dir_all(&staging);
            }
            Err(error) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(error.into());
            }
        }
    }
    Ok(cache_dir)
}

/// Atomically replace the selected inline records with already-published
/// invocation-time prepared carriers. Every carrier read derives from that
/// record's retained source-acquisition receipt; a miss or invalid member
/// leaves the graph entirely inline.
// @ref LLP 0021#module-initialization-and-trusted-source-acquisition
// @ref LLP 0026#authenticate-before-discovery-and-execute-under-derived-identity
pub fn load_prepared_activation_records_v1(
    graph: &mut SourceModuleGraphV1,
    record_ids: &BTreeSet<SourceId>,
    cache_dir: &Path,
    expected_deployment_graph_digest: &Digest,
) -> Result<()> {
    if record_ids.is_empty() {
        bail!("prepared activation load requires at least one record");
    }
    let producer_id =
        NonEmptyString::new(PREPARED_GRAPH_PRODUCER_ID).map_err(anyhow::Error::msg)?;
    let authorizer = ModuleGraphAuthorizer::new(graph.snapshot.as_ref());
    let mut pending = Vec::with_capacity(record_ids.len());
    let mut receipts = Vec::with_capacity(record_ids.len());

    for source_id in record_ids {
        let record = graph
            .records
            .get(source_id)
            .ok_or_else(|| anyhow!("prepared activation record is absent from source graph"))?;
        if record.prepared.is_some() {
            bail!("prepared activation record was already prepared");
        }
        let source_integrity = record.artifact.semantics.source_integrity.clone();
        let source_receipt = graph
            ._activation_receipts
            .iter()
            .find(|receipt| {
                receipt.decision().kind == GraphOperationKind::SourceAcquisition
                    && receipt.decision().resource.target == *source_id
                    && receipt.decision().resource.source_integrity.as_ref()
                        == Some(&source_integrity)
            })
            .ok_or_else(|| {
                anyhow!("prepared activation record has no retained source-access receipt")
            })?;
        let entry_id = NonEmptyString::new(record.artifact.semantic_digest.as_str())
            .map_err(anyhow::Error::msg)?;
        let principal = prepared_record_principal(graph, source_id)?;
        let verified = verify_record(record, &graph.producer_binary_digest)?;
        let (expected_manifest, expected_payload) = PreparedModuleCarrierV2::from_inline_artifacts(
            principal.clone(),
            producer_id.clone(),
            graph.producer_binary_digest.clone(),
            expected_deployment_graph_digest.clone(),
            [(entry_id.clone(), verified)],
        )?;
        let carrier_digest = expected_manifest.carrier_digest.clone();
        let record_dir = prepared_activation_record_cache_dir(
            cache_dir,
            source_id,
            &record.artifact.semantic_digest,
        )?;
        let expected_manifest_bytes = expected_manifest.encode_canonical()?;
        let ((manifest_bytes, payload), receipt) = authorizer
            .authorize_then_read_prepared_carrier(
                source_receipt,
                &source_integrity,
                carrier_digest.clone(),
                || {
                    Ok((
                        read_authenticated_prepared_file(
                            &record_dir.join("manifest.json"),
                            &expected_manifest_bytes,
                            "activation carrier manifest",
                        )?,
                        read_authenticated_prepared_file(
                            &record_dir.join("payload.js"),
                            &expected_payload,
                            "activation carrier payload",
                        )?,
                    ))
                },
            )?;
        if manifest_bytes != expected_manifest_bytes || payload != expected_payload {
            bail!("prepared activation carrier differs from authenticated source");
        }
        let authorized_semantic_digests =
            Arc::new(BTreeSet::from([record.artifact.semantic_digest.clone()]));
        let prepared_artifact = expected_manifest.prepared_artifact(entry_id.as_str())?;
        let admission = PreparedCarrierAdmissionV2 {
            expected_principal: principal,
            expected_producer_id: producer_id.clone(),
            producer_binary_digest: graph.producer_binary_digest.clone(),
            deployment_graph_digest: expected_deployment_graph_digest.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            expected_engine_binding: None,
            expected_bytecode_version: None,
        };
        let carrier = Arc::new(AdmittedPreparedCarrierV2::decode_and_admit(
            &manifest_bytes,
            &payload,
            &admission,
        )?);
        let artifact_admission = ArtifactAdmissionV1::DigestBoundPrepared {
            expected_source_id: source_id.clone(),
            expected_source_integrity: source_integrity,
            expected_producer_id: producer_id.clone(),
            producer_binary_digest: graph.producer_binary_digest.clone(),
            deployment_graph_digest: expected_deployment_graph_digest.clone(),
            expected_carrier_digest: carrier_digest,
            expected_entry_id: entry_id.clone(),
            authorized_semantic_digests,
            transform_fingerprint_digest: record
                .artifact
                .semantics
                .transform_fingerprint
                .digest()?,
        };
        prepared_artifact.verify_for_admission(&artifact_admission)?;
        carrier.entry(entry_id.as_str())?;
        pending.push((
            source_id.clone(),
            prepared_artifact,
            PreparedRecordV1 {
                carrier,
                entry_id,
                admission: artifact_admission,
            },
        ));
        receipts.push(receipt);
    }

    for (source_id, artifact, prepared) in pending {
        let record = graph
            .records
            .get_mut(&source_id)
            .expect("prepared activation record remained present");
        record.artifact = artifact;
        record.prepared = Some(prepared);
    }
    graph._prepared_access_receipts.extend(receipts);
    Ok(())
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
    let destination = prepared_graph_cache_dir(artifact_dir, &deployment_graph_digest);
    if destination.join("index.json").is_file() {
        return Ok(destination);
    }
    let publication = render_prepared_source_graph_v2(graph, &deployment_graph_digest)?;
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
        for candidate in &publication.candidate_tables {
            std::fs::write(staging.join(&candidate.file), &candidate.bytes)?;
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

/// Derive the production commitment facets from the exact deterministic
/// publication bytes. Deployment tooling carries the returned record into the
/// armed snapshot; it must never write it inside the writable cache.
/// @ref LLP 0042#binding-surface
pub fn prepared_graph_commitment_v1(
    graph: &SourceModuleGraphV1,
    deployment_graph_digest: Digest,
    target: String,
    policy_digest: Digest,
) -> Result<PreparedGraphCommitmentV1> {
    let publication = render_prepared_source_graph_v2(graph, &deployment_graph_digest)?;
    let value: serde_json::Value = serde_json::from_slice(&publication.index_bytes)?;
    let index: PreparedGraphIndexV2 = serde_json::from_value(value)?;
    let (semantic_inventory_digest, principal_set_digest, _, _) =
        prepared_commitment_facets(&index)?;
    Ok(PreparedGraphCommitmentV1 {
        schema: capsec_semantics::arming::PREPARED_GRAPH_COMMITMENT_SCHEMA_V1.into(),
        workflow: "production".into(),
        target,
        entry_source_id: NonEmptyString::new(index.entry.encode()?).map_err(anyhow::Error::msg)?,
        deployment_graph_digest,
        publication_root_digest: digest_bytes(
            PREPARED_PUBLICATION_ROOT_DOMAIN_V1,
            &publication.index_bytes,
        )?,
        producer: capsec_semantics::arming::PreparedGraphProducerV1 {
            id: NonEmptyString::new(PREPARED_GRAPH_PRODUCER_ID).map_err(anyhow::Error::msg)?,
            binary_digest: graph.producer_binary_digest.clone(),
        },
        semantic_inventory_digest,
        principal_set_digest,
        policy_digest,
    })
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

/// Retain one cache file without following links and without allocating from
/// an attacker-controlled length. Content authentication is performed by the
/// caller against the independently armed publication root.
pub(crate) fn read_bounded_prepared_file(
    path: &Path,
    maximum_len: u64,
    role: &str,
) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
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
    let before = file.metadata()?;
    if !before.is_file() || before.len() > maximum_len {
        bail!(
            "IBEX_PREPARED_COMMITMENT_CORRUPT prepared {role} is not a bounded regular file: {}",
            path.display()
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if before.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!(
                "IBEX_PREPARED_COMMITMENT_CORRUPT prepared {role} is a reparse point: {}",
                path.display()
            );
        }
    }
    let capacity = usize::try_from(before.len())
        .map_err(|_| anyhow!("prepared {role} length is unsupported"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(maximum_len + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_len {
        bail!("IBEX_PREPARED_COMMITMENT_CORRUPT prepared {role} exceeds its hard limit");
    }
    let after = file.metadata()?;
    if !after.is_file() || before.len() != after.len() || bytes.len() as u64 != after.len() {
        bail!(
            "IBEX_PREPARED_COMMITMENT_CORRUPT prepared {role} changed while retained: {}",
            path.display()
        );
    }
    Ok(bytes)
}

fn prepared_commitment_facets(
    index: &PreparedGraphIndexV2,
) -> Result<(Digest, Digest, BTreeSet<Digest>, Vec<Principal>)> {
    let semantic_digests = index
        .records
        .iter()
        .map(|record| record.artifact.semantic_digest.clone())
        .collect::<BTreeSet<_>>();
    let semantic_value = serde_json::Value::Array(
        semantic_digests
            .iter()
            .map(|digest| serde_json::Value::String(digest.as_str().to_owned()))
            .collect(),
    );
    let semantic_bytes = capsec_semantics::canonical::to_jcs_bytes(&semantic_value)?;
    let semantic_inventory = digest_bytes(PREPARED_SEMANTIC_INVENTORY_DOMAIN_V1, &semantic_bytes)?;

    let root_principal = index
        .records
        .iter()
        .filter_map(|record| record.source_id.defining_principal())
        .find(|principal| principal.is_root())
        .cloned()
        .ok_or_else(|| anyhow!("prepared publication has no root principal"))?;
    let mut principals_by_key = BTreeMap::new();
    for record in &index.records {
        let principal = record
            .source_id
            .defining_principal()
            .cloned()
            .unwrap_or_else(|| root_principal.clone());
        principals_by_key.insert(principal.canonical_order_key()?, principal);
    }
    let principals = principals_by_key.into_values().collect::<Vec<_>>();
    let principal_bytes =
        capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(&principals)?)?;
    let principal_set = digest_bytes(PREPARED_PRINCIPAL_SET_DOMAIN_V1, &principal_bytes)?;
    Ok((
        semantic_inventory,
        principal_set,
        semantic_digests,
        principals,
    ))
}

fn committed_publication_files(index: &PreparedGraphIndexV2) -> Result<BTreeSet<String>> {
    let mut files = BTreeSet::from(["index.json".to_owned()]);
    let mut insert = |name: &str, role: &str| -> Result<()> {
        if name.is_empty()
            || name.contains(['/', '\\'])
            || name == "."
            || name == ".."
            || !files.insert(name.to_owned())
        {
            bail!(
                "IBEX_PREPARED_COMMITMENT_CORRUPT prepared {role} filename is unsafe or repeated"
            );
        }
        Ok(())
    };
    for carrier in &index.carriers {
        insert(&carrier.manifest_file, "carrier manifest")?;
        insert(&carrier.bytes_file, "carrier bytes")?;
    }
    for candidate in &index.candidate_tables {
        insert(&candidate.file, "candidate table")?;
    }
    Ok(files)
}

/// Transform-fingerprint currency posture for committed admission (LLP 0042
/// algorithm step 6).
///
/// `CurrentIbexToolchain` is the production posture: every record's
/// fingerprint must equal ibex's own configured toolchain fingerprint for
/// its goal. `DevVouchedIndexExternalProducer` is the deliberately-typed
/// interim for the UNARMED development embedder consuming an external
/// producer's publication (Exact's Vite adapter-1): the per-record
/// fingerprint DIGEST is still bound by `DigestBoundPrepared` admission
/// against the vouched index, but no currency check against ibex's own
/// toolchain runs — external transform authorities are LLP 0043 work, and
/// until it lands this posture must be named in every receipt that admits
/// under it. It is only constructible by the dev-unarmed embedder entry.
/// @ref LLP 0043#validation-and-admission — the registry replaces this posture
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommittedFingerprintPosture {
    CurrentIbexToolchain,
    DevVouchedIndexExternalProducer,
}

/// One committed publication admitted against an independent commitment,
/// before any Host/armed-snapshot projection: the snapshot-free core of
/// `load_prepared_graph_committed_v1`, shared with the dev-unarmed embedder
/// entry (`dev_committed_embedder`). Everything here has passed the LLP 0042
/// steps 1-5 (+ step 6 per the posture): retained canonical index bytes,
/// root-digest independence gate, facet cross-checks, exact file inventory,
/// and real carrier/artifact admission.
pub(crate) struct CommittedPublicationAdmissionV1 {
    pub(crate) entry: SourceId,
    pub(crate) records: BTreeMap<SourceId, SourceGraphRecordV1>,
    pub(crate) principals: Vec<Principal>,
    pub(crate) carrier_count: usize,
    /// Carriers admitted under carrier v2's `hermes-bytecode` encoding
    /// (Exact LLP 0413 §10 Phase 3). Receipts name the encoding split so a
    /// "parse-free" claim is checkable against what was actually admitted.
    #[cfg_attr(not(feature = "dev-committed-embedder"), allow(dead_code))]
    pub(crate) hbc_carrier_count: usize,
    /// Carriers admitted under `javascript-factory-table`.
    #[cfg_attr(not(feature = "dev-committed-embedder"), allow(dead_code))]
    pub(crate) javascript_carrier_count: usize,
}

/// Parameterized commitment facets for one package admission.
///
/// The existing publication arm retains the exact LLP 0042 inputs. The
/// composition arm is added behind `dev-committed-embedder` by LLP 0056's
/// admission driver and cannot affect callers of the landed arm.
enum PackageAdmissionExpectationsV1<'a> {
    SinglePublication {
        cache_dir: &'a Path,
        commitment: &'a PreparedGraphCommitmentV1,
        project_root: &'a Path,
        fingerprint_posture: CommittedFingerprintPosture,
        hbc_engine: Option<&'a CommittedHbcEngineExpectationV1>,
    },
    #[cfg(feature = "dev-committed-embedder")]
    Composition {
        package_dir: &'a Path,
        role: CompositionRole,
        expected_package_root: &'a Digest,
        producer_generation: u64,
        project_root: &'a Path,
        hbc_engine: Option<&'a CommittedHbcEngineExpectationV1>,
    },
}

/// Typed package-admission capability. No caller can construct an admitted
/// package from raw index records.
enum AdmittedPackageV1 {
    SinglePublication(CommittedPublicationAdmissionV1),
    #[cfg(feature = "dev-committed-embedder")]
    Composition(AdmittedCompositionPackageV1),
}

#[cfg(feature = "dev-committed-embedder")]
#[derive(Debug)]
pub(crate) struct CompositionPackageAdmissionFailureV1 {
    pub(crate) code: CompositionRefusalCode,
    pub(crate) role: CompositionRole,
    pub(crate) detail: String,
}

#[cfg(feature = "dev-committed-embedder")]
impl std::fmt::Display for CompositionPackageAdmissionFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} package {}: {}",
            self.role.as_str(),
            self.code.as_str(),
            self.detail
        )
    }
}

#[cfg(feature = "dev-committed-embedder")]
impl std::error::Error for CompositionPackageAdmissionFailureV1 {}

#[cfg(feature = "dev-committed-embedder")]
#[derive(Debug)]
pub(crate) struct AdmittedCompositionPackageRecordV1 {
    pub(crate) artifact: ModuleArtifactV1,
    pub(crate) bindings: Vec<super::composition::PreparedPackageBindingV1>,
    pub(crate) carrier: Arc<AdmittedPreparedCarrierV3>,
    pub(crate) entry_id: NonEmptyString,
    pub(crate) candidate_tables: Vec<ComputedCandidateTableV1>,
    admission: ArtifactAdmissionV1,
}

#[cfg(feature = "dev-committed-embedder")]
impl AdmittedCompositionPackageRecordV1 {
    pub(crate) fn verified(&self) -> VerifiedModuleArtifactV1<'_> {
        self.artifact
            .verify_for_admission_with_semantic_hint(
                &self.admission,
                self.carrier
                    .verified_entry_semantics(self.entry_id.as_str()),
            )
            .expect("AdmittedCompositionPackageRecordV1 retains its admission proof")
    }
}

#[cfg(feature = "dev-committed-embedder")]
#[derive(Debug)]
pub(crate) struct AdmittedCompositionPackageV1 {
    pub(crate) role: CompositionRole,
    pub(crate) package_root: Digest,
    // slice-3: execution configuration and authorized linking retain this
    // authenticated package semantic-graph identity.
    #[allow(dead_code)]
    pub(crate) package_graph_digest: Digest,
    pub(crate) producer_id: NonEmptyString,
    pub(crate) producer_binary_digest: Digest,
    // slice-3: execution configurations are stamped from this attested value.
    #[allow(dead_code)]
    pub(crate) producer_generation: u64,
    pub(crate) records: BTreeMap<SourceId, AdmittedCompositionPackageRecordV1>,
    pub(crate) principals: Vec<Principal>,
    pub(crate) host_bridged_inventory: Vec<HostBridgedInventoryRowV1>,
    pub(crate) duplicate_source_id: bool,
    pub(crate) carrier_count: usize,
    pub(crate) hbc_carrier_count: usize,
    pub(crate) javascript_carrier_count: usize,
}

/// The loaded-engine identity a committed-admission caller is willing to
/// execute `hermes-bytecode` carriers against (Exact LLP 0413 §12: the
/// engine binding and HBC version are admission expectations owned by the
/// HOST, never trusted from the publication). `None` at the call site means
/// the caller cannot execute prepared bytecode; any `hermes-bytecode`
/// carrier then refuses pre-evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedHbcEngineExpectationV1 {
    pub engine_binding: PreparedCarrierEngineBindingV2,
    pub bytecode_version: u32,
}

/// Admit a prepared publication directly against an independent production
/// commitment authenticated by this Host's armed snapshot. No source file is
/// opened, hashed, transformed, or parsed on this path.
///
/// A refusal is intentionally terminal for this publication. The caller may
/// cold-build from authenticated source before evaluation, but must never
/// rejoin and accept the refused cache generation.
/// @ref LLP 0042#committed-admission-algorithm
/// @ref LLP 0042#migration-and-coexistence
pub fn load_prepared_graph_committed_v1(
    cache_dir: &Path,
    host: &crate::host::Host,
    commitment: &PreparedGraphCommitmentV1,
    entry_vfs_source_id: crate::vfs::SourceId,
    project_root: &Path,
    execution_generation: ExecutionGeneration,
) -> Result<SourceModuleGraphV1> {
    let started = std::time::Instant::now();
    let snapshot = host
        .armed_snapshot()
        .cloned()
        .ok_or_else(|| anyhow!("committed prepared admission requires an armed Host"))?;
    let armed = snapshot
        .prepared_graph_commitment(commitment.entry_source_id.as_str())
        .ok_or_else(|| {
            anyhow!("IBEX_PREPARED_COMMITMENT_MISSING snapshot has no entry commitment")
        })?;
    if armed != commitment {
        bail!("IBEX_PREPARED_COMMITMENT_AUTHORITY caller commitment is not the armed commitment");
    }

    let admitted = admit_committed_publication_v1(
        cache_dir,
        commitment,
        project_root,
        CommittedFingerprintPosture::CurrentIbexToolchain,
        // Production committed admission remains source-carrier-only until
        // its armed HBC engine plumbing lands: any hermes-bytecode carrier
        // refuses pre-evaluation (Exact LLP 0413 §10 Phase 6 work).
        None,
    )?;
    let CommittedPublicationAdmissionV1 {
        entry,
        records,
        principals,
        carrier_count,
        hbc_carrier_count: _,
        javascript_carrier_count: _,
    } = admitted;

    let principal_ids = principals
        .into_iter()
        .map(|principal| {
            Ok((
                principal.clone(),
                host.module_runner_principal_id(&principal)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let graph = SourceModuleGraphV1 {
        entry,
        entry_vfs_source_id: Some(entry_vfs_source_id),
        execution_generation,
        snapshot,
        principal_ids,
        producer_binary_digest: commitment.producer.binary_digest.clone(),
        records,
        activation_host: None,
        project_root: project_root.to_path_buf(),
        candidate_declarations: BTreeMap::new(),
        matched_candidate_declarations: BTreeSet::new(),
        prepared_activation_cache_locator: None,
        _source_access_receipts: Vec::new(),
        _prepared_access_receipts: Vec::new(),
        _activation_receipts: Vec::new(),
    };
    graph.plan()?;
    eprintln!(
        "ibex prepared admission authority=production-armed entry={} root={} carriers={} duration_us={}",
        commitment.entry_source_id,
        &commitment.publication_root_digest.as_str()[..24],
        carrier_count,
        started.elapsed().as_micros(),
    );
    Ok(graph)
}

/// Publication-scoped memo for `TransformFingerprintV1::digest()`. A
/// prepared publication typically carries ONE distinct fingerprint across
/// all of its records (one producer toolchain), but the per-record loops
/// recomputed the JCS + sha256 digest for every record. Keyed by full
/// struct equality — never by producer name or any digest-shaped shortcut —
/// so a publication mixing fingerprints computes one digest per DISTINCT
/// fingerprint and admission outcomes are byte-identical to the unmemoized
/// path (the digest is a pure function of the compared struct).
/// issues/20260730-committed-admission-cost-profile.md (M2 item 5)
#[derive(Default)]
struct FingerprintDigestMemoV1(Vec<(TransformFingerprintV1, Digest)>);

impl FingerprintDigestMemoV1 {
    fn digest_for(&mut self, fingerprint: &TransformFingerprintV1) -> Result<Digest> {
        if let Some((_, digest)) = self.0.iter().find(|(known, _)| known == fingerprint) {
            return Ok(digest.clone());
        }
        let digest = fingerprint.digest()?;
        self.0.push((fingerprint.clone(), digest.clone()));
        Ok(digest)
    }
}

/// The snapshot-free LLP 0042 admission core: steps 1-5 of the committed
/// admission algorithm plus the posture-selected step 6. Callers own the
/// authority question — the production wrapper has already required the
/// armed snapshot to carry this exact commitment; the dev-unarmed embedder
/// entry types its non-production authority explicitly.
pub(crate) fn admit_committed_publication_v1(
    cache_dir: &Path,
    commitment: &PreparedGraphCommitmentV1,
    project_root: &Path,
    fingerprint_posture: CommittedFingerprintPosture,
    hbc_engine: Option<&CommittedHbcEngineExpectationV1>,
) -> Result<CommittedPublicationAdmissionV1> {
    match admit_package_v1(PackageAdmissionExpectationsV1::SinglePublication {
        cache_dir,
        commitment,
        project_root,
        fingerprint_posture,
        hbc_engine,
    })? {
        AdmittedPackageV1::SinglePublication(admitted) => Ok(admitted),
        #[cfg(feature = "dev-committed-embedder")]
        AdmittedPackageV1::Composition(_) => {
            unreachable!("single-publication request returned a composition capability")
        }
    }
}

// @ref LLP 0056#5-the-nine-steps--the-ibex-half — commitment facets select a lane without weakening the frozen LLP 0042 checks.
fn admit_package_v1(expectations: PackageAdmissionExpectationsV1<'_>) -> Result<AdmittedPackageV1> {
    match expectations {
        PackageAdmissionExpectationsV1::SinglePublication {
            cache_dir,
            commitment,
            project_root,
            fingerprint_posture,
            hbc_engine,
        } => admit_single_publication_package_v1(
            cache_dir,
            commitment,
            project_root,
            fingerprint_posture,
            hbc_engine,
        )
        .map(AdmittedPackageV1::SinglePublication),
        #[cfg(feature = "dev-committed-embedder")]
        PackageAdmissionExpectationsV1::Composition {
            package_dir,
            role,
            expected_package_root,
            producer_generation,
            project_root,
            hbc_engine,
        } => admit_composition_package_core_v1(
            package_dir,
            role,
            expected_package_root,
            producer_generation,
            project_root,
            hbc_engine,
        )
        .map(AdmittedPackageV1::Composition)
        .map_err(anyhow::Error::new),
    }
}

#[cfg(feature = "dev-committed-embedder")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn admit_composition_package_v1(
    package_dir: &Path,
    role: CompositionRole,
    expected_package_root: &Digest,
    producer_generation: u64,
    project_root: &Path,
    hbc_engine: Option<&CommittedHbcEngineExpectationV1>,
) -> std::result::Result<AdmittedCompositionPackageV1, CompositionPackageAdmissionFailureV1> {
    match admit_package_v1(PackageAdmissionExpectationsV1::Composition {
        package_dir,
        role,
        expected_package_root,
        producer_generation,
        project_root,
        hbc_engine,
    }) {
        Ok(AdmittedPackageV1::Composition(admitted)) => Ok(admitted),
        Ok(AdmittedPackageV1::SinglePublication(_)) => {
            unreachable!("composition request returned the single-publication capability")
        }
        Err(error) => match error.downcast::<CompositionPackageAdmissionFailureV1>() {
            Ok(failure) => Err(failure),
            Err(error) => Err(package_failure(
                role,
                CompositionRefusalCode::PackageRootMismatch,
                format!("novel package admission failure: {error:#}"),
            )),
        },
    }
}

#[cfg(feature = "dev-committed-embedder")]
fn package_failure(
    role: CompositionRole,
    code: CompositionRefusalCode,
    detail: impl Into<String>,
) -> CompositionPackageAdmissionFailureV1 {
    CompositionPackageAdmissionFailureV1 {
        code,
        role,
        detail: detail.into(),
    }
}

#[cfg(feature = "dev-committed-embedder")]
fn package_file_name_is_safe_v1(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '\\']) && !matches!(name, "." | "..")
}

#[cfg(feature = "dev-committed-embedder")]
fn package_files_v1(
    package: &PreparedPackageV1,
    role: CompositionRole,
) -> std::result::Result<BTreeSet<String>, CompositionPackageAdmissionFailureV1> {
    let mut files = BTreeSet::from(["index.json".to_owned()]);
    let mut insert = |name: &str, file_role: &str| {
        if !package_file_name_is_safe_v1(name) || !files.insert(name.to_owned()) {
            return Err(package_failure(
                role,
                CompositionRefusalCode::IbexPreparedCommitmentCorrupt,
                format!("prepared {file_role} filename is unsafe or repeated"),
            ));
        }
        Ok(())
    };
    for carrier in &package.carriers {
        insert(&carrier.manifest_file, "carrier manifest")?;
        insert(&carrier.bytes_file, "carrier bytes")?;
    }
    for candidate in &package.candidate_tables {
        insert(&candidate.file, "candidate table")?;
    }
    Ok(files)
}

#[cfg(feature = "dev-committed-embedder")]
fn candidate_table_schema_v1(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).context("computed-candidate table is not UTF-8")?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|error| anyhow!("computed-candidate table is not strict JSON: {error}"))?;
    Ok(value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default())
}

#[cfg(feature = "dev-committed-embedder")]
#[allow(clippy::too_many_arguments)]
fn admit_composition_package_core_v1(
    package_dir: &Path,
    role: CompositionRole,
    expected_package_root: &Digest,
    producer_generation: u64,
    project_root: &Path,
    hbc_engine: Option<&CommittedHbcEngineExpectationV1>,
) -> std::result::Result<AdmittedCompositionPackageV1, CompositionPackageAdmissionFailureV1> {
    let corrupt = |detail: String| {
        package_failure(
            role,
            CompositionRefusalCode::IbexPreparedCommitmentCorrupt,
            detail,
        )
    };
    let index_bytes = read_bounded_prepared_file(
        &package_dir.join("index.json"),
        MAX_PACKAGE_INDEX_BYTES_V1,
        "package index",
    )
    .map_err(|error| corrupt(format!("{error:#}")))?;
    let observed_root = digest_bytes(PREPARED_PACKAGE_ROOT_DOMAIN_V1, &index_bytes)
        .map_err(|error| corrupt(format!("cannot digest prepared-package index: {error}")))?;
    if &observed_root != expected_package_root {
        return Err(package_failure(
            role,
            CompositionRefusalCode::PackageRootMismatch,
            "package index digest differs from the envelope attestation",
        ));
    }

    // Schema dispatch precedes the v1 closed-shape decode. This keeps a
    // different prepared index version at #12 rather than #14.
    let text = std::str::from_utf8(&index_bytes)
        .map_err(|error| corrupt(format!("package index is not UTF-8: {error}")))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|error| corrupt(format!("package index is not strict JSON: {error}")))?;
    if value.get("schema").and_then(serde_json::Value::as_str) != Some(PREPARED_PACKAGE_SCHEMA_V1) {
        return Err(package_failure(
            role,
            CompositionRefusalCode::IbexPreparedCommitmentSchema,
            "unsupported prepared-package index schema",
        ));
    }
    if !matches!(
        value.get("role").and_then(serde_json::Value::as_str),
        Some("app" | "agent")
    ) {
        return Err(package_failure(
            role,
            CompositionRefusalCode::IbexPreparedCommitmentSchema,
            "unsupported prepared-package role",
        ));
    }
    // Decode the strict JSON value before enforcing canonicality so every
    // inspectable #12 predicate gets its lower-ordinal turn first. A value
    // that cannot establish the closed package shape remains a #14 failure.
    let package: PreparedPackageV1 = serde_json::from_value(value.clone()).map_err(|error| {
        corrupt(format!(
            "prepared-package index has an invalid shape: {error}"
        ))
    })?;
    if package.role != role {
        return Err(package_failure(
            role,
            CompositionRefusalCode::IbexPreparedCommitmentSchema,
            format!(
                "prepared package role {:?} differs from its served role {:?}",
                package.role, role
            ),
        ));
    }
    if package.records.is_empty() || package.carriers.is_empty() {
        return Err(package_failure(
            role,
            CompositionRefusalCode::IbexPreparedCommitmentSchema,
            "prepared package is empty",
        ));
    }
    if package.records.iter().any(|record| {
        !matches!(
            &record.artifact.producer,
            ProducerIdentityV1::PreparedPackage { .. }
        )
    }) {
        return Err(package_failure(
            role,
            CompositionRefusalCode::IbexPreparedCommitmentSchema,
            "composition package contains a non-prepared-package artifact identity",
        ));
    }
    if package
        .records
        .iter()
        .any(|record| matches!(&record.source_id, SourceId::Synthetic { .. }))
    {
        return Err(package_failure(
            role,
            CompositionRefusalCode::IbexPreparedCommitmentSchema,
            "composition package contains a synthetic record",
        ));
    }
    if package
        .records
        .iter()
        .any(|record| record.artifact.schema != MODULE_ARTIFACT_SCHEMA_V1)
    {
        return Err(package_failure(
            role,
            CompositionRefusalCode::IbexPreparedCommitmentSchema,
            "composition package contains an unsupported artifact schema",
        ));
    }
    if package.records.iter().any(|record| {
        matches!(
            &record.artifact.payload,
            super::artifact::ModulePayloadV1::Inline { .. }
        )
    }) {
        return Err(package_failure(
            role,
            CompositionRefusalCode::IbexPreparedCommitmentSchema,
            "prepared-package artifact carries an inline payload",
        ));
    }

    let root_principal = package
        .records
        .iter()
        .filter_map(|record| record.source_id.defining_principal())
        .find(|principal| principal.is_root())
        .cloned()
        .ok_or_else(|| {
            package_failure(
                role,
                CompositionRefusalCode::IbexPreparedCommitmentSchema,
                "prepared package has no root principal",
            )
        })?;

    let index_structural_failure = PreparedPackageV1::decode_canonical(&index_bytes)
        .err()
        .map(|error| corrupt(format!("{error:#}")));
    // #12 schema dispatch is an outer sweep. Read each schema-bearing sidecar
    // before #13/#14 decisions, but defer structural/read failures until the
    // inventory predicate has had its lower-ordinal turn.
    let mut expected_inventory = BTreeSet::from(["index.json".to_owned()]);
    for carrier in &package.carriers {
        expected_inventory.insert(carrier.manifest_file.clone());
        expected_inventory.insert(carrier.bytes_file.clone());
    }
    for candidate in &package.candidate_tables {
        expected_inventory.insert(candidate.file.clone());
    }
    let mut deferred_corrupt = index_structural_failure.or_else(|| {
        package_files_v1(&package, role).err().map(|error| {
            package_failure(
                role,
                CompositionRefusalCode::IbexPreparedCommitmentCorrupt,
                error.detail,
            )
        })
    });
    let mut candidate_wires = Vec::with_capacity(package.candidate_tables.len());
    let mut carrier_manifest_wires = Vec::with_capacity(package.carriers.len());
    for candidate in &package.candidate_tables {
        if !package_file_name_is_safe_v1(&candidate.file) {
            candidate_wires.push(None);
            continue;
        }
        match read_bounded_prepared_file(
            &package_dir.join(&candidate.file),
            MAX_PACKAGE_CANDIDATE_TABLE_BYTES_V1,
            "computed-candidate table",
        ) {
            Ok(bytes) => match candidate_table_schema_v1(&bytes) {
                Ok(schema) if schema == COMPUTED_CANDIDATES_SCHEMA_V2 => {
                    candidate_wires.push(Some(bytes));
                }
                Ok(schema) => {
                    return Err(package_failure(
                        role,
                        CompositionRefusalCode::IbexPreparedCommitmentSchema,
                        format!("unsupported composition candidate-table schema {schema:?}"),
                    ));
                }
                Err(error) => {
                    deferred_corrupt.get_or_insert_with(|| {
                        corrupt(format!(
                            "candidate-table schema inspection failed: {error:#}"
                        ))
                    });
                    candidate_wires.push(None);
                }
            },
            Err(error) => {
                deferred_corrupt.get_or_insert_with(|| corrupt(format!("{error:#}")));
                candidate_wires.push(None);
            }
        }
    }
    for carrier in &package.carriers {
        if !package_file_name_is_safe_v1(&carrier.manifest_file) {
            carrier_manifest_wires.push(None);
            continue;
        }
        match read_bounded_prepared_file(
            &package_dir.join(&carrier.manifest_file),
            MAX_PACKAGE_MANIFEST_BYTES_V1,
            "carrier manifest",
        ) {
            Ok(bytes) => match PreparedModuleCarrierV3::decode_for_composition_admission(&bytes) {
                Ok(_) => carrier_manifest_wires.push(Some(bytes)),
                Err(error)
                    if error.code == CompositionRefusalCode::IbexPreparedCommitmentSchema =>
                {
                    return Err(package_failure(role, error.code, error.detail));
                }
                Err(error) => {
                    deferred_corrupt
                        .get_or_insert_with(|| package_failure(role, error.code, error.detail));
                    carrier_manifest_wires.push(None);
                }
            },
            Err(error) => {
                deferred_corrupt.get_or_insert_with(|| corrupt(format!("{error:#}")));
                carrier_manifest_wires.push(None);
            }
        }
    }

    let mut actual_files = BTreeSet::new();
    for entry in std::fs::read_dir(package_dir)
        .map_err(|error| corrupt(format!("cannot enumerate package directory: {error}")))?
    {
        let entry = entry
            .map_err(|error| corrupt(format!("cannot enumerate package directory: {error}")))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| corrupt("package contains a non-UTF-8 filename".into()))?;
        if name == "activation" {
            let kind = entry.file_type().map_err(|error| {
                corrupt(format!("cannot inspect activation directory: {error}"))
            })?;
            if !kind.is_dir() || kind.is_symlink() {
                return Err(corrupt("activation root is not a real directory".into()));
            }
            continue;
        }
        actual_files.insert(name);
    }
    if actual_files != expected_inventory {
        return Err(package_failure(
            role,
            CompositionRefusalCode::IbexPackageInventory,
            "package file inventory differs from its index",
        ));
    }
    if let Some(failure) = deferred_corrupt {
        return Err(failure);
    }

    let mut principals_by_key = BTreeMap::new();
    for record in &package.records {
        let principal = record
            .source_id
            .defining_principal()
            .cloned()
            .unwrap_or_else(|| root_principal.clone());
        let key = principal
            .canonical_order_key()
            .map_err(|error| corrupt(format!("cannot canonicalize package principal: {error}")))?;
        principals_by_key.insert(key, principal);
    }
    let principals = principals_by_key.into_values().collect::<Vec<_>>();

    if compute_package_graph_digest_v1(&package.records)
        .map_err(|error| corrupt(format!("cannot derive package graph digest: {error}")))?
        != package.package_graph_digest
    {
        return Err(corrupt(
            "claimed package graph digest differs from the derived semantic graph".into(),
        ));
    }

    let mut candidate_tables = Vec::with_capacity(package.candidate_tables.len());
    let mut candidate_digests = BTreeSet::new();
    for (candidate, bytes) in package.candidate_tables.iter().zip(candidate_wires) {
        if !candidate_digests.insert(candidate.digest.clone()) {
            return Err(corrupt("duplicate candidate-table digest".into()));
        }
        let bytes = bytes.expect("schema sweep retained every candidate-table wire");
        let table = ComputedCandidateTableV2::decode_canonical(&bytes)
            .map_err(|error| corrupt(format!("{error:#}")))?;
        // Authenticate the generation-free WIRE form before stamping.
        if table
            .digest()
            .map_err(|error| corrupt(format!("cannot digest candidate table: {error}")))?
            != candidate.digest
        {
            return Err(corrupt("candidate-table digest differs from index".into()));
        }
        let requester = package
            .records
            .iter()
            .find(|record| record.source_id == table.requester.0)
            .ok_or_else(|| corrupt("candidate requester is absent from package".into()))?;
        table
            .validate_requester(&requester.artifact)
            .map_err(|error| corrupt(format!("{error:#}")))?;
        candidate_tables.push(
            table
                .stamp_generation(producer_generation)
                .map_err(|error| corrupt(format!("{error:#}")))?,
        );
    }

    let authorized_semantic_digests = Arc::new(
        package
            .records
            .iter()
            .map(|record| record.artifact.semantic_digest.clone())
            .collect::<BTreeSet<_>>(),
    );

    let carrier_manifests = carrier_manifest_wires
        .iter()
        .map(|bytes| {
            PreparedModuleCarrierV3::decode_for_composition_admission(
                bytes
                    .as_ref()
                    .expect("schema sweep retained every carrier manifest"),
            )
            .expect("schema sweep decoded every carrier manifest")
        })
        .collect::<Vec<_>>();
    let carrier_payload_wires = package
        .carriers
        .iter()
        .map(|carrier| {
            read_bounded_prepared_file(
                &package_dir.join(&carrier.bytes_file),
                MAX_PACKAGE_CARRIER_BYTES_V1,
                "carrier bytes",
            )
            .map_err(|error| corrupt(format!("{error:#}")))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    // #14 structural/internal-consistency sweep. This runs for every record
    // before any #15+ carrier or artifact predicate.
    for record in &package.records {
        if record.carrier_index >= package.carriers.len() {
            return Err(corrupt("record names an absent carrier".into()));
        }
        if record.artifact.semantics.source_id.0 != record.source_id {
            return Err(corrupt("record identity differs from artifact".into()));
        }
        record
            .artifact
            .validate_structure_for_composition()
            .map_err(|error| corrupt(format!("artifact structure is invalid: {error:#}")))?;
        let ProducerIdentityV1::PreparedPackage {
            producer_id,
            producer_binary_digest,
            ..
        } = &record.artifact.producer
        else {
            unreachable!("prepared-package identity checked in the #12 sweep");
        };
        if producer_id != &package.producer_id
            || producer_binary_digest != &package.producer_binary_digest
        {
            return Err(corrupt(
                "artifact producer identity differs from authenticated package index".into(),
            ));
        }
        let mut binding_keys = BTreeSet::new();
        for binding in &record.bindings {
            if !binding_keys.insert(GraphEdgeKey::new(
                binding.specifier.clone(),
                binding.resolution_kind,
            )) {
                return Err(corrupt("record repeats a typed binding".into()));
            }
        }
        let manifest = &carrier_manifests[record.carrier_index];
        if !manifest
            .entries
            .iter()
            .any(|entry| entry.entry_id == record.entry_id)
        {
            return Err(corrupt("prepared carrier has no indexed entry".into()));
        }
        portable_record_display(&record.source_id)
            .map_err(|error| corrupt(format!("{error:#}")))?;
    }

    let mut carrier_principals = vec![None::<Principal>; package.carriers.len()];
    let mut principal_grouping_failure = None;
    for record in &package.records {
        let principal = record
            .source_id
            .defining_principal()
            .cloned()
            .unwrap_or_else(|| root_principal.clone());
        match &carrier_principals[record.carrier_index] {
            Some(prior) if prior != &principal => {
                principal_grouping_failure = Some(package_failure(
                    role,
                    CompositionRefusalCode::IbexPrincipalGrouping,
                    "carrier crosses defining principals",
                ));
            }
            Some(_) => {}
            None => carrier_principals[record.carrier_index] = Some(principal),
        }
    }
    if carrier_principals.iter().any(Option::is_none) {
        return Err(corrupt("package contains an unreferenced carrier".into()));
    }

    let mut classified_failure = principal_grouping_failure;
    for record in &package.records {
        let manifest = &carrier_manifests[record.carrier_index];
        let super::artifact::ModulePayloadV1::Carrier {
            carrier_digest,
            entry_id,
            ..
        } = &record.artifact.payload
        else {
            unreachable!("inline payload refused in the #12 sweep");
        };
        if carrier_digest != &manifest.carrier_digest || entry_id != &record.entry_id {
            let failure = package_failure(
                role,
                CompositionRefusalCode::CarrierIntegrity,
                "record carrier digest or entry binding differs from its manifest",
            );
            if classified_failure
                .as_ref()
                .is_none_or(|current| failure.code.ordinal() < current.code.ordinal())
            {
                classified_failure = Some(failure);
            }
        }
    }

    let mut carriers = Vec::with_capacity(package.carriers.len());
    let mut hbc_carrier_count = 0usize;
    let mut javascript_carrier_count = 0usize;
    for (carrier_index, ((manifest_bytes, carrier_bytes), manifest)) in carrier_manifest_wires
        .into_iter()
        .zip(carrier_payload_wires)
        .zip(&carrier_manifests)
        .enumerate()
    {
        let manifest_bytes = manifest_bytes.expect("schema sweep retained every carrier manifest");
        let declares_hbc = matches!(
            manifest.encoding,
            PreparedCarrierEncodingV2::HermesBytecode { .. }
        );
        let (expected_engine_binding, expected_bytecode_version) = if declares_hbc {
            match hbc_engine {
                Some(engine) => (
                    Some(engine.engine_binding.clone()),
                    Some(engine.bytecode_version),
                ),
                None => (None, None),
            }
        } else {
            (None, None)
        };
        let admission = PreparedCarrierAdmissionV3 {
            expected_principal: carrier_principals[carrier_index]
                .clone()
                .expect("complete package carrier-principal map"),
            expected_producer_id: package.producer_id.clone(),
            producer_binary_digest: package.producer_binary_digest.clone(),
            package_graph_digest: package.package_graph_digest.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            expected_engine_binding,
            expected_bytecode_version,
        };
        let (admitted, native_preflight_eligible) =
            match AdmittedPreparedCarrierV3::decode_and_admit(
                &manifest_bytes,
                &carrier_bytes,
                &admission,
            ) {
                Ok(admitted) => (Some(Arc::new(admitted)), true),
                Err(error) => {
                    let native_preflight_eligible = error.code.ordinal()
                        > CompositionRefusalCode::IbexBytecodePreflight.ordinal();
                    let failure = package_failure(role, error.code, error.detail);
                    if classified_failure
                        .as_ref()
                        .is_none_or(|current| failure.code.ordinal() < current.code.ordinal())
                    {
                        classified_failure = Some(failure);
                    }
                    (None, native_preflight_eligible)
                }
            };
        // Native HBC preflight is an independent #20 predicate. Run it from
        // the already-decoded manifest when rows #14–#19 passed, including
        // when the bundled helper found a later #21 failure. Never expose
        // bytes that failed an earlier integrity/engine row to the decoder.
        match manifest.encoding {
            PreparedCarrierEncodingV2::HermesBytecode { .. } => {
                hbc_carrier_count += 1;
                let preflight_error = if native_preflight_eligible {
                    crate::engine::module_runner::preflight_hermes_bytecode(&carrier_bytes).err()
                } else {
                    None
                };
                if let Some(error) = preflight_error {
                    let failure = package_failure(
                        role,
                        CompositionRefusalCode::IbexBytecodePreflight,
                        format!("Hermes engine preflight rejected carrier: {error}"),
                    );
                    if classified_failure
                        .as_ref()
                        .is_none_or(|current| failure.code.ordinal() < current.code.ordinal())
                    {
                        classified_failure = Some(failure);
                    }
                }
            }
            PreparedCarrierEncodingV2::JavascriptFactoryTable => {
                javascript_carrier_count += 1;
            }
        }
        carriers.push(admitted);
    }
    if let Some(failure) = classified_failure {
        return Err(failure);
    }
    let carriers = carriers
        .into_iter()
        .map(|carrier| carrier.expect("failure-free carrier sweep admitted every carrier"))
        .collect::<Vec<_>>();

    let mut records = BTreeMap::new();
    let mut duplicate_source_id = false;
    let mut fingerprint_digests = FingerprintDigestMemoV1::default();
    for indexed in package.records {
        if indexed.artifact.semantics.source_id.0 != indexed.source_id {
            return Err(corrupt("record identity differs from artifact".into()));
        }
        let mut binding_keys = BTreeSet::new();
        for binding in &indexed.bindings {
            if !binding_keys.insert(GraphEdgeKey::new(
                binding.specifier.clone(),
                binding.resolution_kind,
            )) {
                return Err(corrupt("record repeats a typed binding".into()));
            }
        }
        let carrier = carriers
            .get(indexed.carrier_index)
            .cloned()
            .ok_or_else(|| corrupt("prepared record names an absent carrier".into()))?;
        let ProducerIdentityV1::PreparedPackage {
            producer_id,
            producer_binary_digest,
            package_graph_digest,
        } = &indexed.artifact.producer
        else {
            unreachable!("prepared-package identity checked before carrier admission");
        };
        if producer_id != &package.producer_id
            || producer_binary_digest != &package.producer_binary_digest
        {
            return Err(corrupt(
                "artifact producer identity differs from authenticated package index".into(),
            ));
        }
        if package_graph_digest != &package.package_graph_digest
            || !authorized_semantic_digests.contains(&indexed.artifact.semantic_digest)
        {
            return Err(package_failure(
                role,
                CompositionRefusalCode::IbexPackageGraphBinding,
                "artifact is outside the authenticated package graph",
            ));
        }
        let (artifact_carrier_digest, artifact_entry_id) = match &indexed.artifact.payload {
            super::artifact::ModulePayloadV1::Carrier {
                carrier_digest,
                entry_id,
                ..
            } => (carrier_digest, entry_id),
            super::artifact::ModulePayloadV1::Inline { .. } => {
                return Err(package_failure(
                    role,
                    CompositionRefusalCode::IbexPreparedCommitmentSchema,
                    "prepared-package artifact carries an inline payload",
                ));
            }
        };
        if artifact_carrier_digest != &carrier.manifest().carrier_digest
            || artifact_entry_id != &indexed.entry_id
        {
            return Err(package_failure(
                role,
                CompositionRefusalCode::CarrierIntegrity,
                "record carrier digest or entry binding differs from admitted carrier",
            ));
        }
        let admission = ArtifactAdmissionV1::DigestBoundPreparedPackage {
            expected_source_id: indexed.source_id.clone(),
            expected_source_integrity: indexed.artifact.semantics.source_integrity.clone(),
            expected_producer_id: package.producer_id.clone(),
            producer_binary_digest: package.producer_binary_digest.clone(),
            package_graph_digest: package.package_graph_digest.clone(),
            expected_carrier_digest: carrier.manifest().carrier_digest.clone(),
            expected_entry_id: indexed.entry_id.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            transform_fingerprint_digest: fingerprint_digests
                .digest_for(&indexed.artifact.semantics.transform_fingerprint)
                .map_err(|error| corrupt(format!("{error:#}")))?,
        };
        let verified_semantics = carrier.verified_entry_semantics(indexed.entry_id.as_str());
        indexed
            .artifact
            .verify_for_admission_with_semantic_hint(&admission, verified_semantics)
            .map_err(|error| corrupt(format!("artifact admission failed: {error:#}")))?;
        carrier
            .entry(indexed.entry_id.as_str())
            .map_err(|error| corrupt(format!("{error:#}")))?;
        portable_record_display(&indexed.source_id)
            .map_err(|error| corrupt(format!("{error:#}")))?;
        if let SourceId::File { path, .. } = &indexed.source_id {
            let _path = path
                .iter()
                .fold(project_root.to_path_buf(), |path, component| {
                    path.join(std::ffi::OsString::from(
                        String::from_utf8_lossy(component.bytes()).into_owned(),
                    ))
                });
        }
        let record_candidate_tables = candidate_tables
            .iter()
            .filter(|table| table.requester.0 == indexed.source_id)
            .cloned()
            .collect();
        let source_id = indexed.source_id.clone();
        if records
            .insert(
                source_id,
                AdmittedCompositionPackageRecordV1 {
                    artifact: indexed.artifact,
                    bindings: indexed.bindings,
                    carrier,
                    entry_id: indexed.entry_id,
                    candidate_tables: record_candidate_tables,
                    admission,
                },
            )
            .is_some()
        {
            duplicate_source_id = true;
        }
    }

    Ok(AdmittedCompositionPackageV1 {
        role,
        package_root: observed_root,
        package_graph_digest: package.package_graph_digest,
        producer_id: package.producer_id,
        producer_binary_digest: package.producer_binary_digest,
        producer_generation,
        records,
        principals,
        host_bridged_inventory: package.host_bridged_inventory,
        duplicate_source_id,
        carrier_count: carriers.len(),
        hbc_carrier_count,
        javascript_carrier_count,
    })
}

fn admit_single_publication_package_v1(
    cache_dir: &Path,
    commitment: &PreparedGraphCommitmentV1,
    project_root: &Path,
    fingerprint_posture: CommittedFingerprintPosture,
    hbc_engine: Option<&CommittedHbcEngineExpectationV1>,
) -> Result<CommittedPublicationAdmissionV1> {
    // The index is the first cache byte discovered. Strict parsing and the
    // independent root check happen before any index facet authorizes a file.
    let index_bytes = read_bounded_prepared_file(
        &cache_dir.join("index.json"),
        MAX_PREPARED_INDEX_BYTES_V1,
        "graph index",
    )?;
    let text = std::str::from_utf8(&index_bytes)
        .context("IBEX_PREPARED_COMMITMENT_CORRUPT graph index is not UTF-8")?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|error| anyhow!("IBEX_PREPARED_COMMITMENT_CORRUPT graph index: {error}"))?;
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)?;
    if canonical != index_bytes {
        bail!("IBEX_PREPARED_COMMITMENT_CORRUPT graph index is not canonical JCS");
    }
    let observed_root = digest_bytes(PREPARED_PUBLICATION_ROOT_DOMAIN_V1, &index_bytes)?;
    if observed_root != commitment.publication_root_digest {
        bail!("IBEX_PREPARED_COMMITMENT_MISMATCH publication root differs from armed commitment");
    }
    let index: PreparedGraphIndexV2 = serde_json::from_value(value)
        .context("IBEX_PREPARED_COMMITMENT_CORRUPT graph index shape")?;
    if index.schema != PREPARED_GRAPH_INDEX_SCHEMA_V2 {
        bail!("IBEX_PREPARED_COMMITMENT_SCHEMA unsupported prepared graph index");
    }
    for record in &index.records {
        if matches!(&record.source_id, SourceId::Synthetic { .. }) {
            bail!("IBEX_PREPARED_COMMITMENT_SCHEMA synthetic prepared records are unsupported");
        }
        if matches!(
            &record.artifact.producer,
            ProducerIdentityV1::PreparedPackage { .. }
        ) {
            bail!(
                "IBEX_PREPARED_COMMITMENT_SCHEMA prepared-package producer identity is composition-only"
            );
        }
    }
    if index.records.is_empty() || index.carriers.is_empty() {
        bail!("IBEX_PREPARED_COMMITMENT_CORRUPT prepared graph is empty");
    }
    if index.entry.encode()? != commitment.entry_source_id.as_str() {
        bail!("IBEX_PREPARED_COMMITMENT_ENTRY prepared entry differs from commitment");
    }
    if index.deployment_graph_digest != commitment.deployment_graph_digest {
        bail!("IBEX_PREPARED_COMMITMENT_DEPLOYMENT deployment graph differs from commitment");
    }
    if index.producer_binary_digest != commitment.producer.binary_digest {
        bail!("IBEX_PREPARED_COMMITMENT_PRODUCER producer binary differs from commitment");
    }
    let (semantic_inventory, principal_set, authorized_semantic_digests, principals) =
        prepared_commitment_facets(&index)?;
    // One shared set for all per-carrier and per-record admission
    // expectations (blog scale: 596 expectations over ~545 digests).
    let authorized_semantic_digests = Arc::new(authorized_semantic_digests);
    if semantic_inventory != commitment.semantic_inventory_digest {
        bail!("IBEX_PREPARED_COMMITMENT_SEMANTICS semantic inventory differs from commitment");
    }
    if principal_set != commitment.principal_set_digest {
        bail!("IBEX_PREPARED_COMMITMENT_PRINCIPALS principal set differs from commitment");
    }

    let expected_files = committed_publication_files(&index)?;
    let mut actual_files = BTreeSet::new();
    for entry in std::fs::read_dir(cache_dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("prepared cache contains a non-UTF-8 filename"))?;
        if name == "activation" {
            let kind = entry.file_type()?;
            if !kind.is_dir() || kind.is_symlink() {
                bail!("IBEX_PREPARED_COMMITMENT_CORRUPT activation root is not a real directory");
            }
            continue;
        }
        actual_files.insert(name);
    }
    if actual_files != expected_files {
        bail!("IBEX_PREPARED_COMMITMENT_INVENTORY publication file inventory differs from index");
    }

    let mut candidate_tables = Vec::with_capacity(index.candidate_tables.len());
    let mut candidate_digests = BTreeSet::new();
    for candidate in &index.candidate_tables {
        if !candidate_digests.insert(candidate.digest.clone()) {
            bail!("IBEX_PREPARED_COMMITMENT_CORRUPT duplicate candidate-table digest");
        }
        let bytes = read_bounded_prepared_file(
            &cache_dir.join(&candidate.file),
            MAX_PREPARED_CANDIDATE_BYTES_V1,
            "computed-candidate table",
        )?;
        let table = ComputedCandidateTableV1::decode_canonical(&bytes)?;
        if table.digest()? != candidate.digest {
            bail!("IBEX_PREPARED_COMMITMENT_CORRUPT candidate-table digest differs from index");
        }
        candidate_tables.push(table);
    }

    let root_principal = principals
        .iter()
        .find(|principal| principal.is_root())
        .cloned()
        .ok_or_else(|| anyhow!("prepared commitment has no root principal"))?;
    let mut carrier_principals: BTreeMap<usize, Principal> = BTreeMap::new();
    for record in &index.records {
        if record.carrier_index >= index.carriers.len() {
            bail!("IBEX_PREPARED_COMMITMENT_CORRUPT record names an absent carrier");
        }
        let principal = record
            .source_id
            .defining_principal()
            .cloned()
            .unwrap_or_else(|| root_principal.clone());
        if carrier_principals
            .insert(record.carrier_index, principal.clone())
            .is_some_and(|prior| prior != principal)
        {
            bail!("IBEX_PREPARED_COMMITMENT_PRINCIPALS carrier crosses defining principals");
        }
    }
    if carrier_principals.len() != index.carriers.len() {
        bail!("IBEX_PREPARED_COMMITMENT_CORRUPT publication contains an unreferenced carrier");
    }

    let producer_id = commitment.producer.id.clone();
    let mut carriers = Vec::with_capacity(index.carriers.len());
    let mut hbc_carrier_count = 0usize;
    let mut javascript_carrier_count = 0usize;
    for (carrier_index, carrier) in index.carriers.iter().enumerate() {
        let manifest_bytes = read_bounded_prepared_file(
            &cache_dir.join(&carrier.manifest_file),
            MAX_PREPARED_MANIFEST_BYTES_V1,
            "carrier manifest",
        )?;
        let carrier_bytes = read_bounded_prepared_file(
            &cache_dir.join(&carrier.bytes_file),
            MAX_PREPARED_CARRIER_BYTES_V1,
            "carrier bytes",
        )?;
        // Select the admission expectation from the manifest's DECLARED
        // encoding kind. This peek only chooses which host expectation
        // applies; `decode_and_admit` still performs every strict check
        // (canonical JCS, digests, principal, producer, encoding/bytes
        // agreement), and the carrier digest the index commits to binds the
        // declared encoding transitively — a swapped declaration changes the
        // manifest and carrier bytes and refuses downstream. The engine
        // identity itself always comes from the CALLER (the loaded engine),
        // never from the publication (Exact LLP 0413 §14 item 12).
        let declares_hermes_bytecode = serde_json::from_slice::<serde_json::Value>(&manifest_bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("encoding")
                    .and_then(|encoding| encoding.get("kind"))
                    .and_then(serde_json::Value::as_str)
                    .map(|kind| kind == "hermes-bytecode")
            })
            .unwrap_or(false);
        let (expected_engine_binding, expected_bytecode_version) = if declares_hermes_bytecode {
            let engine = hbc_engine.ok_or_else(|| {
                anyhow!(
                    "IBEX_PREPARED_ENGINE_UNAVAILABLE publication carries a hermes-bytecode \
                     carrier but this admission context declared no loaded-engine identity"
                )
            })?;
            (
                Some(engine.engine_binding.clone()),
                Some(engine.bytecode_version),
            )
        } else {
            (None, None)
        };
        let admission = PreparedCarrierAdmissionV2 {
            expected_principal: carrier_principals
                .get(&carrier_index)
                .cloned()
                .expect("complete carrier-principal map"),
            expected_producer_id: producer_id.clone(),
            producer_binary_digest: commitment.producer.binary_digest.clone(),
            deployment_graph_digest: commitment.deployment_graph_digest.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            expected_engine_binding,
            expected_bytecode_version,
        };
        let admitted_carrier = Arc::new(AdmittedPreparedCarrierV2::decode_and_admit(
            &manifest_bytes,
            &carrier_bytes,
            &admission,
        )?);
        match admitted_carrier.manifest().encoding {
            PreparedCarrierEncodingV2::HermesBytecode { .. } => hbc_carrier_count += 1,
            PreparedCarrierEncodingV2::JavascriptFactoryTable => javascript_carrier_count += 1,
        }
        carriers.push(admitted_carrier);
    }

    let mut records = BTreeMap::new();
    let mut fingerprint_digests = FingerprintDigestMemoV1::default();
    for indexed in index.records {
        if indexed.artifact.semantics.source_id.0 != indexed.source_id {
            bail!("IBEX_PREPARED_COMMITMENT_CORRUPT record identity differs from artifact");
        }
        // LLP 0042 step 6, posture-selected (see CommittedFingerprintPosture):
        // production requires ibex-toolchain currency; the dev-unarmed
        // embedder posture relies on the DigestBoundPrepared fingerprint
        // binding below until LLP 0043's registered external authorities.
        match fingerprint_posture {
            CommittedFingerprintPosture::CurrentIbexToolchain => {
                verify_current_transform_fingerprint_v1(&indexed.artifact.semantics)?;
            }
            CommittedFingerprintPosture::DevVouchedIndexExternalProducer => {}
        }
        let mut bindings = BTreeMap::new();
        for binding in indexed.bindings {
            if bindings
                .insert(
                    GraphEdgeKey::new(binding.specifier, binding.resolution_kind),
                    binding.target,
                )
                .is_some()
            {
                bail!("IBEX_PREPARED_COMMITMENT_CORRUPT record repeats a typed binding");
            }
        }
        let carrier = carriers
            .get(indexed.carrier_index)
            .cloned()
            .ok_or_else(|| anyhow!("prepared record names an absent carrier"))?;
        let admission = ArtifactAdmissionV1::DigestBoundPrepared {
            expected_source_id: indexed.source_id.clone(),
            expected_source_integrity: indexed.artifact.semantics.source_integrity.clone(),
            expected_producer_id: producer_id.clone(),
            producer_binary_digest: commitment.producer.binary_digest.clone(),
            deployment_graph_digest: commitment.deployment_graph_digest.clone(),
            expected_carrier_digest: carrier.manifest().carrier_digest.clone(),
            expected_entry_id: indexed.entry_id.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            transform_fingerprint_digest: fingerprint_digests
                .digest_for(&indexed.artifact.semantics.transform_fingerprint)?,
        };
        // The carrier entry's (semantics, digest) pair was recomputed and
        // matched during carrier admission; when it equals this record's
        // pair, verify skips one redundant JCS+sha256 recompute. Pure
        // recompute-skip: outcomes are identical either way, and the
        // mandatory `carrier.entry(...)?` refusal below keeps its position.
        let verified_semantics = carrier.verified_entry_semantics(indexed.entry_id.as_str());
        indexed
            .artifact
            .verify_for_admission_with_semantic_hint(&admission, verified_semantics)?;
        carrier.entry(indexed.entry_id.as_str())?;
        let (source_label, virtual_path) = portable_record_display(&indexed.source_id)?;
        let path = match &indexed.source_id {
            SourceId::File { path, .. } => {
                path.iter()
                    .fold(project_root.to_path_buf(), |path, component| {
                        path.join(std::ffi::OsString::from(
                            String::from_utf8_lossy(component.bytes()).into_owned(),
                        ))
                    })
            }
            SourceId::Builtin { source_key, .. } => {
                PathBuf::from(format!("builtin:{}.js", source_key.as_str()))
            }
            SourceId::Synthetic { .. } => {
                bail!("IBEX_PREPARED_COMMITMENT_SCHEMA synthetic prepared records are unsupported")
            }
        };
        let record_candidate_tables = candidate_tables
            .iter()
            .filter(|table| table.requester.0 == indexed.source_id)
            .cloned()
            .collect();
        let bootstrap_internal_commonjs_requires =
            bootstrap_internal_commonjs_require_specifiers(&indexed.artifact);
        let source_id = indexed.source_id.clone();
        if records
            .insert(
                source_id,
                SourceGraphRecordV1 {
                    path,
                    source_label,
                    virtual_path,
                    artifact: indexed.artifact,
                    bindings,
                    candidate_tables: record_candidate_tables,
                    deferred_dynamic: DeferredSourceDynamicBindingsV1::default(),
                    deferred_commonjs_requires: BTreeSet::new(),
                    bootstrap_internal_commonjs_requires,
                    prepared: Some(PreparedRecordV1 {
                        carrier,
                        entry_id: indexed.entry_id,
                        admission,
                    }),
                },
            )
            .is_some()
        {
            bail!("IBEX_PREPARED_COMMITMENT_CORRUPT publication repeats a SourceId");
        }
    }

    Ok(CommittedPublicationAdmissionV1 {
        entry: index.entry,
        records,
        principals,
        carrier_count: carriers.len(),
        hbc_carrier_count,
        javascript_carrier_count,
    })
}

/// Consume the authenticated entry join before discovering any prepared-cache
/// bytes, then revalidate the exact graph identity the join authorized.
/// @ref LLP 0026#authenticate-before-discovery-and-execute-under-derived-identity
pub fn load_prepared_source_graph_v1(
    cache_dir: &Path,
    authenticated_source_graph: &SourceModuleGraphV1,
    entry_join: &AuthenticatedEntryJoinV1,
    expected_deployment_graph_digest: &Digest,
) -> Result<SourceModuleGraphV1> {
    let entry_record = authenticated_source_graph
        .records
        .get(&authenticated_source_graph.entry)
        .ok_or_else(|| anyhow!("authenticated native source graph omitted its entry record"))?;
    let entry_artifact = verify_record(
        entry_record,
        &authenticated_source_graph.producer_binary_digest,
    )?
    .artifact();
    if entry_join.entry != authenticated_source_graph.entry
        || Some(&entry_join.entry_vfs_source_id)
            != authenticated_source_graph.entry_vfs_source_id.as_ref()
        || entry_join.source_integrity != entry_artifact.semantics.source_integrity
        || entry_join.snapshot_digest != *authenticated_source_graph.snapshot.digest()
        || entry_join.producer_binary_digest != authenticated_source_graph.producer_binary_digest
    {
        bail!("prepared graph entry join does not authenticate this source graph");
    }
    let expected = render_prepared_source_graph_v2(
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
    for carrier in &expected.carriers {
        expected_files.insert(carrier.manifest_file.clone());
        expected_files.insert(carrier.bytes_file.clone());
    }
    let mut retained_candidate_files = BTreeMap::new();
    for candidate in &expected.candidate_tables {
        expected_files.insert(candidate.file.clone());
        let bytes = read_authenticated_prepared_file(
            &cache_dir.join(&candidate.file),
            &candidate.bytes,
            "computed-candidate table",
        )?;
        if retained_candidate_files
            .insert(candidate.file.clone(), bytes)
            .is_some()
        {
            bail!("prepared candidate-table publication repeats a filename");
        }
    }
    let mut actual_files = BTreeSet::new();
    for entry in std::fs::read_dir(cache_dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("prepared cache contains a non-UTF-8 filename"))?;
        if name == "activation" {
            // Invocation-time carriers share the graph-digest cache directory
            // but are not members of the initial publication. Permit only
            // their fixed real-directory root; the reached-edge loader later
            // authenticates every selected member against source-derived
            // manifest and payload bytes.
            // @ref LLP 0026#authenticate-before-discovery-and-execute-under-derived-identity
            let kind = entry.file_type()?;
            if !kind.is_dir() || kind.is_symlink() {
                bail!("prepared activation cache root is not a real directory");
            }
            continue;
        }
        if !actual_files.insert(name) {
            bail!("prepared cache file inventory repeats a filename");
        }
    }
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
        let bytes = retained_candidate_files
            .get(&candidate.file)
            .ok_or_else(|| anyhow!("prepared candidate table was not retained"))?;
        let table = ComputedCandidateTableV1::decode_canonical(bytes)?;
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
    let authorized_semantic_digests = Arc::new(
        authenticated_source_graph
            .records
            .values()
            .map(|record| record.artifact.semantic_digest.clone())
            .collect::<BTreeSet<_>>(),
    );
    let producer_id =
        NonEmptyString::new(PREPARED_GRAPH_PRODUCER_ID).map_err(anyhow::Error::msg)?;
    let authorizer = ModuleGraphAuthorizer::new(authenticated_source_graph.snapshot.as_ref());
    let mut prepared_access_receipts = Vec::new();
    let mut carriers = Vec::with_capacity(index.carriers.len());
    for (carrier_index, carrier) in index.carriers.iter().enumerate() {
        if carrier.manifest_file.contains('/')
            || carrier.manifest_file.contains('\\')
            || carrier.bytes_file.contains('/')
            || carrier.bytes_file.contains('\\')
        {
            bail!("prepared carrier filename escapes its cache directory");
        }
        let expected_carrier = expected
            .carriers
            .get(carrier_index)
            .ok_or_else(|| anyhow!("prepared graph names an unexpected carrier"))?;
        let dependency_source_receipt =
            expected_carrier
                .member_source_ids
                .iter()
                .find_map(|source_id| {
                    let record = authenticated_source_graph.records.get(source_id)?;
                    authenticated_source_graph
                        ._source_access_receipts
                        .iter()
                        .find(|receipt| {
                            receipt.decision().kind == GraphOperationKind::SourceAcquisition
                                && receipt.decision().resource.target == *source_id
                                && receipt.decision().resource.source_integrity.as_ref()
                                    == Some(&record.artifact.semantics.source_integrity)
                        })
                        .map(|receipt| {
                            (receipt, record.artifact.semantics.source_integrity.clone())
                        })
                });
        let read_carrier = || {
            Ok((
                read_authenticated_prepared_file(
                    &cache_dir.join(&carrier.manifest_file),
                    &expected_carrier.manifest_bytes,
                    "carrier manifest",
                )?,
                read_authenticated_prepared_file(
                    &cache_dir.join(&carrier.bytes_file),
                    &expected_carrier.bytes,
                    "carrier bytes",
                )?,
            ))
        };
        let (manifest_bytes, carrier_bytes) =
            if let Some((source_receipt, source_integrity)) = dependency_source_receipt {
                let (bytes, receipt) = authorizer.authorize_then_read_prepared_carrier(
                    source_receipt,
                    &source_integrity,
                    expected_carrier.carrier_digest.clone(),
                    read_carrier,
                )?;
                prepared_access_receipts.push(receipt);
                bytes
            } else {
                // A carrier with no dependency source receipt is admissible
                // only when it contains the separately authenticated launch
                // entry. Production reaches this function after the structured
                // entry request has joined to this exact source graph.
                // @ref LLP 0026#authenticate-before-discovery-and-execute-under-derived-identity
                if !expected_carrier
                    .member_source_ids
                    .contains(&authenticated_source_graph.entry)
                {
                    bail!("prepared dependency carrier has no retained source-access receipt");
                }
                read_carrier()?
            };
        let admission = PreparedCarrierAdmissionV2 {
            expected_principal: expected_carrier.defining_principal.clone(),
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
    let mut fingerprint_digests = FingerprintDigestMemoV1::default();
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
        if !path.is_absolute() && !matches!(indexed.source_id, SourceId::Builtin { .. }) {
            bail!("authenticated native source path is not absolute");
        }
        if !matches!(indexed.source_id, SourceId::Builtin { .. }) {
            crate::host::abi::authenticate_prepared_module_record(
                &path,
                &indexed.source_id,
                &trusted_record.artifact.semantics.source_integrity,
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
            expected_source_integrity: trusted_record.artifact.semantics.source_integrity.clone(),
            expected_producer_id: producer_id.clone(),
            producer_binary_digest: authenticated_source_graph.producer_binary_digest.clone(),
            deployment_graph_digest: expected_deployment_graph_digest.clone(),
            expected_carrier_digest: carrier_manifest.carrier_digest.clone(),
            expected_entry_id: indexed.entry_id.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            transform_fingerprint_digest: fingerprint_digests
                .digest_for(&trusted_record.artifact.semantics.transform_fingerprint)?,
        };
        // Same recompute-skip as the committed loop: the carrier entry's
        // pair was verified at carrier admission; equality forces the
        // skipped recompute's success, everything else recomputes.
        let verified_semantics = carrier.verified_entry_semantics(indexed.entry_id.as_str());
        indexed
            .artifact
            .verify_for_admission_with_semantic_hint(&admission, verified_semantics)?;
        carrier.entry(indexed.entry_id.as_str())?;
        let record_candidate_tables = candidate_tables
            .iter()
            .filter(|table| table.requester.0 == indexed.source_id)
            .cloned()
            .collect::<Vec<_>>();
        let bootstrap_internal_commonjs_requires =
            bootstrap_internal_commonjs_require_specifiers(&indexed.artifact);
        records.insert(
            indexed.source_id,
            SourceGraphRecordV1 {
                path,
                source_label: trusted_record.source_label.clone(),
                virtual_path: trusted_record.virtual_path.clone(),
                artifact: indexed.artifact,
                bindings,
                candidate_tables: record_candidate_tables,
                deferred_dynamic: trusted_record.deferred_dynamic.clone(),
                deferred_commonjs_requires: trusted_record.deferred_commonjs_requires.clone(),
                bootstrap_internal_commonjs_requires,
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
        execution_generation: authenticated_source_graph.execution_generation,
        snapshot: authenticated_source_graph.snapshot.clone(),
        principal_ids: authenticated_source_graph.principal_ids.clone(),
        producer_binary_digest: authenticated_source_graph.producer_binary_digest.clone(),
        records,
        activation_host: authenticated_source_graph.activation_host.clone(),
        project_root: authenticated_source_graph.project_root.clone(),
        candidate_declarations: authenticated_source_graph.candidate_declarations.clone(),
        matched_candidate_declarations: authenticated_source_graph
            .matched_candidate_declarations
            .clone(),
        prepared_activation_cache_locator: authenticated_source_graph
            .prepared_activation_cache_locator
            .clone(),
        _source_access_receipts: authenticated_source_graph._source_access_receipts.clone(),
        _prepared_access_receipts: prepared_access_receipts,
        _activation_receipts: authenticated_source_graph._activation_receipts.clone(),
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

// Measurement-only committed-admission cost profile (Exact LLP 0413 Phase 3:
// admission is the dominant prepared-startup phase at blog scale). Test-only;
// no production semantics live there.
#[cfg(test)]
#[path = "admission_cost_profile.rs"]
mod admission_cost_profile;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use capsec_semantics::model::PathComponent;

    #[cfg(feature = "dev-committed-embedder")]
    #[test]
    fn frozen_composition_channel_seam_parses_golden_records_as_values() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/prepared-composition/v1/vectors/canonical-bytes.json"
        )))
        .unwrap();
        let vector = |name: &str| {
            corpus["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|vector| vector["name"] == name)
                .unwrap()["canonicalBytes"]
                .as_str()
                .unwrap()
        };

        // The unchecked half: the armed-context gate on the public seam is
        // process-global state that sibling lib tests mutate concurrently
        // (see the helper's doc); parsing behavior is what this golden test
        // pins, and the gate keeps its own coverage on the integration lane.
        let parsed = parse_dev_composition_channel_records_unchecked_v1(
            vector("prepared-composition-commitment-record"),
            vector("composition-verifier-expectations"),
        );
        let (commitment, expectations) = parsed.unwrap();
        assert_eq!(commitment.workflow, "production");
        assert_eq!(expectations.expected_target, "exact-dev:mac");
    }

    struct CountingPreparedActivationLocator {
        probes: Arc<std::sync::atomic::AtomicUsize>,
        candidates: Vec<PreparedActivationCacheCandidateV1>,
    }

    impl PreparedActivationCacheLocatorV1 for CountingPreparedActivationLocator {
        fn locate(&self, _target: &SourceId) -> Result<Vec<PreparedActivationCacheCandidateV1>> {
            self.probes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.candidates.clone())
        }
    }

    #[cfg(unix)]
    fn armed_file_host(project_root: &Path) -> crate::host::Host {
        armed_file_host_with_prepared(project_root, Vec::new())
    }

    #[cfg(unix)]
    fn armed_file_host_with_prepared(
        project_root: &Path,
        prepared_graphs: Vec<PreparedGraphCommitmentV1>,
    ) -> crate::host::Host {
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
        value["preparedGraphs"] = serde_json::to_value(prepared_graphs).unwrap();

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
                    ProtectedArtifactRole::ArmedPolicy => digest_at(&["policyDigest"]),
                    ProtectedArtifactRole::PackageGraph => digest_at(&["packageGraph", "digest"]),
                    ProtectedArtifactRole::Registry => digest_at(&["registryDigest"]),
                    ProtectedArtifactRole::RuntimeExtensionAuthorityCapsule => {
                        digest_at(&["runtimeExtensions", "authorityCapsuleDigest"])
                    }
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
            embedded_protected_artifacts: Vec::new(),
            runtime_extension_authority_digest: None,
            runtime_extension_mapped_executable: None,
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
    fn committed_prepared_graph_admits_without_source_and_refuses_substitution() {
        let project = tempfile::tempdir().unwrap();
        let entry = project.path().join("entry.mjs");
        std::fs::write(&entry, "export const value = 1;\n").unwrap();
        let entry = std::fs::canonicalize(&entry).unwrap();
        let producer = Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let deployment = Digest::new("sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA").unwrap();
        let bootstrap_host = armed_file_host(project.path());
        let graph_a = match build_authenticated_source_graph_v1_for_host(
            &bootstrap_host,
            &entry,
            producer.clone(),
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!("fixture unexpectedly required legacy: {requirement}")
            }
        };
        let publication_a = tempfile::tempdir().unwrap();
        let cache_a =
            publish_prepared_source_graph_v1(&graph_a, publication_a.path(), deployment.clone())
                .unwrap();
        let commitment_a = prepared_graph_commitment_v1(
            &graph_a,
            deployment.clone(),
            bootstrap_host
                .armed_snapshot()
                .unwrap()
                .engine_target()
                .unwrap(),
            bootstrap_host
                .armed_snapshot()
                .unwrap()
                .semantic_identity()
                .unwrap()
                .policy_digest,
        )
        .unwrap();

        // A genuine sibling publication is fully self-consistent. It differs
        // only in source behavior, so its own local digests cannot help it
        // satisfy publication A's independent root.
        std::fs::write(&entry, "export const value = 2;\n").unwrap();
        let graph_b = match build_authenticated_source_graph_v1_for_host(
            &bootstrap_host,
            &entry,
            producer,
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!("fixture unexpectedly required legacy: {requirement}")
            }
        };
        let publication_b = tempfile::tempdir().unwrap();
        let cache_b =
            publish_prepared_source_graph_v1(&graph_b, publication_b.path(), deployment).unwrap();

        let committed_host =
            armed_file_host_with_prepared(project.path(), vec![commitment_a.clone()]);
        let request = authenticated_file_request(&committed_host);
        let entry_vfs_source_id = request.source_id().cloned().unwrap();
        std::fs::remove_file(&entry).unwrap();

        let admitted = load_prepared_graph_committed_v1(
            &cache_a,
            &committed_host,
            &commitment_a,
            entry_vfs_source_id.clone(),
            project.path(),
            ExecutionGeneration::INITIAL,
        )
        .expect("committed admission must not reacquire application source");
        assert!(admitted.prepared_entries().unwrap().is_some());
        assert_eq!(admitted.source_access_receipt_count(), 0);

        let error = match load_prepared_graph_committed_v1(
            &cache_b,
            &committed_host,
            &commitment_a,
            entry_vfs_source_id,
            project.path(),
            ExecutionGeneration::INITIAL,
        ) {
            Ok(_) => panic!("self-consistent sibling publication was admitted"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("IBEX_PREPARED_COMMITMENT_MISMATCH"),
            "substitution refused for the wrong reason: {error:#}"
        );
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
            ExecutionGeneration::INITIAL,
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
        let mut entry_join = graph
            .validate_authenticated_entry_request(&request)
            .unwrap();
        entry_join.source_integrity =
            Digest::new("sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA").unwrap();
        let absent_cache = tempfile::tempdir().unwrap();
        let deployment = producer_digest.clone();
        let error = match load_prepared_source_graph_v1(
            absent_cache.path(),
            &graph,
            &entry_join,
            &deployment,
        ) {
            Ok(_) => panic!("mismatched entry join read a prepared cache"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("entry join does not authenticate"),
            "prepared cache was probed before entry-join refusal: {error:#}"
        );

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
            ExecutionGeneration::INITIAL,
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

    #[cfg(unix)]
    pub(crate) fn build_test_source_graph(
        project_root: &Path,
        entry_source: &str,
    ) -> Result<SourceModuleGraphV1> {
        let entry = project_root.join("entry.mjs");
        std::fs::write(&entry, entry_source)?;
        let entry = std::fs::canonicalize(entry)?;
        let host = armed_file_host(project_root);
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest,
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )? {
            SourceModuleGraphBuildV1::Native(graph) => Ok(graph),
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                bail!("test graph unexpectedly required legacy: {requirement:?}")
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn single_publication_refuses_composition_only_prepared_package_identity_early() {
        let project = tempfile::tempdir().unwrap();
        let graph = build_test_source_graph(project.path(), "export const value = 1;\n").unwrap();
        let deployment = Digest::new("sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA").unwrap();
        let publication = tempfile::tempdir().unwrap();
        let cache =
            publish_prepared_source_graph_v1(&graph, publication.path(), deployment.clone())
                .unwrap();
        let mut commitment = prepared_graph_commitment_v1(
            &graph,
            deployment,
            "hermes-test".into(),
            source_integrity(b"single-publication-policy").unwrap(),
        )
        .unwrap();

        let index_path = cache.join("index.json");
        let mut index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
        let producer = index["records"][0]["artifact"]["producer"]
            .as_object_mut()
            .unwrap();
        producer.insert("kind".into(), serde_json::json!("prepared-package"));
        let graph_digest = producer.remove("deploymentGraphDigest").unwrap();
        producer.insert("packageGraphDigest".into(), graph_digest);
        let index_bytes = capsec_semantics::canonical::to_jcs_bytes(&index).unwrap();
        std::fs::write(&index_path, &index_bytes).unwrap();
        commitment.publication_root_digest =
            digest_bytes(PREPARED_PUBLICATION_ROOT_DOMAIN_V1, &index_bytes).unwrap();

        let error = match admit_committed_publication_v1(
            &cache,
            &commitment,
            project.path(),
            CommittedFingerprintPosture::DevVouchedIndexExternalProducer,
            None,
        ) {
            Ok(_) => panic!("composition-only producer identity was admitted"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("IBEX_PREPARED_COMMITMENT_SCHEMA"),
            "composition-only identity refused with the wrong token: {error:#}"
        );
    }

    #[cfg(feature = "dev-committed-embedder")]
    struct CompositionPackageFixtureV1 {
        directory: tempfile::TempDir,
        package: PreparedPackageV1,
        manifest: PreparedModuleCarrierV3,
        carrier_bytes: Vec<u8>,
    }

    #[cfg(feature = "dev-committed-embedder")]
    impl CompositionPackageFixtureV1 {
        fn new() -> Self {
            use super::super::artifact::CanonicalSourceId;
            use super::super::carrier::{
                PreparedCarrierEntryV2, PREPARED_CARRIER_BYTES_DOMAIN_V1,
                PREPARED_CARRIER_SCHEMA_V3,
            };

            let directory = tempfile::tempdir().unwrap();
            let owner = Principal::Root {
                identity: NonEmptyString::new("composition-package-fixture").unwrap(),
            };
            let source_id = SourceId::file(
                owner.clone(),
                vec![PathComponent::utf8("entry.mjs").unwrap()],
            )
            .unwrap();
            let producer_id = NonEmptyString::new("composition-fixture-producer").unwrap();
            let producer_binary_digest = source_integrity(b"composition-fixture-producer").unwrap();
            let source_artifact = produce_module_artifact_v1(
                source_id.clone(),
                "entry.mjs",
                Path::new("entry.mjs"),
                "export const value = 1;",
                producer_binary_digest.clone(),
            )
            .unwrap();
            let carrier_bytes = b"(function(){return Object.freeze({});})()".to_vec();
            let carrier_digest =
                digest_bytes(PREPARED_CARRIER_BYTES_DOMAIN_V1, &carrier_bytes).unwrap();
            let entry_id = NonEmptyString::new("entry").unwrap();
            let placeholder_graph = source_integrity(b"placeholder-package-graph").unwrap();
            let artifact = ModuleArtifactV1::new_carrier(
                source_artifact.semantics.clone(),
                carrier_digest.clone(),
                entry_id.clone(),
                ProducerIdentityV1::PreparedPackage {
                    producer_id: producer_id.clone(),
                    producer_binary_digest: producer_binary_digest.clone(),
                    package_graph_digest: placeholder_graph.clone(),
                },
            )
            .unwrap();
            let mut records = vec![super::super::composition::PreparedPackageRecordV1 {
                source_id,
                bindings: Vec::new(),
                artifact,
                carrier_index: 0,
                entry_id: entry_id.clone(),
            }];
            let package_graph_digest = compute_package_graph_digest_v1(&records).unwrap();
            let ProducerIdentityV1::PreparedPackage {
                package_graph_digest: artifact_graph,
                ..
            } = &mut records[0].artifact.producer
            else {
                unreachable!()
            };
            *artifact_graph = package_graph_digest.clone();
            let manifest = PreparedModuleCarrierV3 {
                schema: PREPARED_CARRIER_SCHEMA_V3.into(),
                encoding: PreparedCarrierEncodingV2::JavascriptFactoryTable,
                carrier_digest,
                defining_principal: owner,
                producer_id: producer_id.clone(),
                producer_binary_digest: producer_binary_digest.clone(),
                package_graph_digest: package_graph_digest.clone(),
                entries: vec![PreparedCarrierEntryV2 {
                    entry_id,
                    semantics: source_artifact.semantics,
                    semantic_digest: source_artifact.semantic_digest,
                }],
            };
            let package = PreparedPackageV1 {
                schema: PREPARED_PACKAGE_SCHEMA_V1.into(),
                role: CompositionRole::App,
                producer_id,
                producer_binary_digest,
                package_graph_digest,
                records,
                carriers: vec![super::super::composition::PreparedPackageCarrierIndexV1 {
                    manifest_file: "carrier.json".into(),
                    bytes_file: "carrier.bin".into(),
                }],
                candidate_tables: Vec::new(),
                host_bridged_inventory: Vec::new(),
            };
            assert_eq!(
                package.records[0].artifact.semantics.source_id,
                CanonicalSourceId(package.records[0].source_id.clone())
            );
            Self {
                directory,
                package,
                manifest,
                carrier_bytes,
            }
        }

        fn persist(&self) -> Digest {
            let manifest_bytes = self.manifest.encode_canonical().unwrap();
            std::fs::write(self.directory.path().join("carrier.json"), manifest_bytes).unwrap();
            std::fs::write(
                self.directory.path().join("carrier.bin"),
                &self.carrier_bytes,
            )
            .unwrap();
            let index_bytes = capsec_semantics::canonical::to_jcs_bytes(
                &serde_json::to_value(&self.package).unwrap(),
            )
            .unwrap();
            std::fs::write(self.directory.path().join("index.json"), &index_bytes).unwrap();
            digest_bytes(PREPARED_PACKAGE_ROOT_DOMAIN_V1, &index_bytes).unwrap()
        }

        fn admit(
            &self,
            package_root: &Digest,
        ) -> std::result::Result<AdmittedCompositionPackageV1, CompositionPackageAdmissionFailureV1>
        {
            self.admit_with_engine(package_root, None)
        }

        fn admit_with_engine(
            &self,
            package_root: &Digest,
            hbc_engine: Option<&CommittedHbcEngineExpectationV1>,
        ) -> std::result::Result<AdmittedCompositionPackageV1, CompositionPackageAdmissionFailureV1>
        {
            admit_composition_package_v1(
                self.directory.path(),
                CompositionRole::App,
                package_root,
                1,
                self.directory.path(),
                hbc_engine,
            )
        }
    }

    #[cfg(feature = "dev-committed-embedder")]
    #[test]
    fn composition_package_fixture_admits() {
        let fixture = CompositionPackageFixtureV1::new();
        let root = fixture.persist();
        fixture.admit(&root).unwrap();
    }

    #[cfg(feature = "dev-committed-embedder")]
    #[test]
    fn composition_carrier_v2_schema_routes_to_registry_row_12() {
        let fixture = CompositionPackageFixtureV1::new();
        let root = fixture.persist();
        let mut manifest = serde_json::to_value(&fixture.manifest).unwrap();
        manifest["schema"] = serde_json::json!(super::super::carrier::PREPARED_CARRIER_SCHEMA_V2);
        let object = manifest.as_object_mut().unwrap();
        let graph = object.remove("packageGraphDigest").unwrap();
        object.insert("deploymentGraphDigest".into(), graph);
        std::fs::write(
            fixture.directory.path().join("carrier.json"),
            capsec_semantics::canonical::to_jcs_bytes(&manifest).unwrap(),
        )
        .unwrap();

        let error = fixture.admit(&root).unwrap_err();
        assert_eq!(
            error.code,
            CompositionRefusalCode::IbexPreparedCommitmentSchema
        );
    }

    #[cfg(feature = "dev-committed-embedder")]
    #[test]
    fn composition_synthetic_record_routes_to_registry_row_12() {
        let mut fixture = CompositionPackageFixtureV1::new();
        fixture.package.records[0].source_id =
            SourceId::synthetic("composition-fixture", "synthetic").unwrap();
        let root = fixture.persist();

        let error = fixture.admit(&root).unwrap_err();
        assert_eq!(
            error.code,
            CompositionRefusalCode::IbexPreparedCommitmentSchema
        );
    }

    #[cfg(feature = "dev-committed-embedder")]
    #[test]
    fn composition_multifault_schema_row_12_precedes_noncanonical_index_row_14() {
        let fixture = CompositionPackageFixtureV1::new();
        fixture.persist();
        let mut manifest = serde_json::to_value(&fixture.manifest).unwrap();
        manifest["schema"] = serde_json::json!(super::super::carrier::PREPARED_CARRIER_SCHEMA_V2);
        std::fs::write(
            fixture.directory.path().join("carrier.json"),
            capsec_semantics::canonical::to_jcs_bytes(&manifest).unwrap(),
        )
        .unwrap();
        let index_bytes = serde_json::to_vec_pretty(&fixture.package).unwrap();
        std::fs::write(fixture.directory.path().join("index.json"), &index_bytes).unwrap();
        let root = digest_bytes(PREPARED_PACKAGE_ROOT_DOMAIN_V1, &index_bytes).unwrap();

        let error = fixture.admit(&root).unwrap_err();
        assert_eq!(
            error.code,
            CompositionRefusalCode::IbexPreparedCommitmentSchema
        );
    }

    #[cfg(feature = "dev-committed-embedder")]
    #[test]
    fn composition_multifault_row_14_precedes_carrier_integrity_row_15() {
        let mut fixture = CompositionPackageFixtureV1::new();
        fixture.package.package_graph_digest = source_integrity(b"forged-graph").unwrap();
        fixture.carrier_bytes.push(b'!');
        let root = fixture.persist();

        let error = fixture.admit(&root).unwrap_err();
        assert_eq!(
            error.code,
            CompositionRefusalCode::IbexPreparedCommitmentCorrupt
        );
    }

    #[cfg(feature = "dev-committed-embedder")]
    #[test]
    fn composition_multifault_row_17_precedes_package_graph_binding_row_21() {
        use super::super::carrier::PREPARED_CARRIER_BYTES_DOMAIN_V1;

        let mut fixture = CompositionPackageFixtureV1::new();
        fixture.carrier_bytes = 0x1F1903C103BC1FC6_u64.to_le_bytes().to_vec();
        let carrier_digest =
            digest_bytes(PREPARED_CARRIER_BYTES_DOMAIN_V1, &fixture.carrier_bytes).unwrap();
        fixture.manifest.carrier_digest = carrier_digest.clone();
        let super::super::artifact::ModulePayloadV1::Carrier {
            carrier_digest: artifact_carrier_digest,
            ..
        } = &mut fixture.package.records[0].artifact.payload
        else {
            unreachable!()
        };
        *artifact_carrier_digest = carrier_digest;
        fixture.manifest.package_graph_digest = source_integrity(b"forged-graph").unwrap();
        let root = fixture.persist();

        let error = fixture.admit(&root).unwrap_err();
        assert_eq!(error.code, CompositionRefusalCode::IbexEncodingIncompatible);
    }

    #[cfg(feature = "dev-committed-embedder")]
    #[test]
    fn composition_multifault_carrier_integrity_row_15_precedes_artifact_row_21() {
        let mut fixture = CompositionPackageFixtureV1::new();
        let super::super::artifact::ModulePayloadV1::Carrier { carrier_digest, .. } =
            &mut fixture.package.records[0].artifact.payload
        else {
            unreachable!()
        };
        *carrier_digest = source_integrity(b"forged-carrier").unwrap();
        let ProducerIdentityV1::PreparedPackage {
            package_graph_digest,
            ..
        } = &mut fixture.package.records[0].artifact.producer
        else {
            unreachable!()
        };
        *package_graph_digest = source_integrity(b"forged-artifact-graph").unwrap();
        let root = fixture.persist();

        let error = fixture.admit(&root).unwrap_err();
        assert_eq!(error.code, CompositionRefusalCode::CarrierIntegrity);
    }

    #[cfg(feature = "dev-committed-embedder")]
    #[test]
    fn composition_multifault_preflight_row_20_precedes_manifest_row_21() {
        use super::super::carrier::PREPARED_CARRIER_BYTES_DOMAIN_V1;

        let mut fixture = CompositionPackageFixtureV1::new();
        let version = 96_u32;
        fixture.carrier_bytes = vec![0; 128];
        fixture.carrier_bytes[0..8].copy_from_slice(&0x1F1903C103BC1FC6_u64.to_le_bytes());
        fixture.carrier_bytes[8..12].copy_from_slice(&version.to_le_bytes());
        fixture.carrier_bytes[32..36].copy_from_slice(&128_u32.to_le_bytes());
        let carrier_digest =
            digest_bytes(PREPARED_CARRIER_BYTES_DOMAIN_V1, &fixture.carrier_bytes).unwrap();
        fixture.manifest.carrier_digest = carrier_digest.clone();
        let engine_binding = PreparedCarrierEngineBindingV2::LoadedFile {
            binary_digest: source_integrity(b"composition-fixture-engine").unwrap(),
        };
        fixture.manifest.encoding = PreparedCarrierEncodingV2::HermesBytecode {
            engine_binding: engine_binding.clone(),
            bytecode_version: version,
        };
        fixture.manifest.package_graph_digest = source_integrity(b"forged-graph").unwrap();
        let super::super::artifact::ModulePayloadV1::Carrier {
            carrier_digest: artifact_carrier_digest,
            ..
        } = &mut fixture.package.records[0].artifact.payload
        else {
            unreachable!()
        };
        *artifact_carrier_digest = carrier_digest;
        let root = fixture.persist();
        let hbc_engine = CommittedHbcEngineExpectationV1 {
            engine_binding,
            bytecode_version: version,
        };

        let error = fixture
            .admit_with_engine(&root, Some(&hbc_engine))
            .unwrap_err();
        assert_eq!(error.code, CompositionRefusalCode::IbexBytecodePreflight);
    }

    #[cfg(unix)]
    #[test]
    fn generation_graph_v2_is_plan_derived_stable_and_surface_ready() {
        let project = tempfile::tempdir().unwrap();
        let graph = build_test_source_graph(
            project.path(),
            "export const value = 1; export async function later() { return import('./entry.mjs'); }\n",
        )
        .unwrap();

        let first = graph.generation_graph_v2().unwrap();
        let second = graph.generation_graph_v2().unwrap();
        assert_eq!(first.digest(), second.digest());

        let generations = super::super::generation::ModuleExecutionGenerationsV2::new(
            super::super::generation::GenerationMode::Development,
            graph.execution_generation(),
            graph.snapshot(),
            first,
        )
        .unwrap();
        let direct = super::super::hot_revision::HotRevisionSurfaceV1::new(generations);
        assert_eq!(direct.graph_digest(), second.digest());

        let derived = super::super::hot_revision::HotRevisionSurfaceV1::for_source_graph(
            super::super::generation::GenerationMode::Development,
            graph.execution_generation(),
            &graph,
        )
        .unwrap();
        assert_eq!(derived.graph_digest(), second.digest());
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_source_graph_binds_native_inputs_to_its_execution_generation() {
        let project = tempfile::tempdir().unwrap();
        let entry = project.path().join("entry.mjs");
        std::fs::write(&entry, "export const value = 7;\n").unwrap();
        let entry = std::fs::canonicalize(entry).unwrap();
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let execution_generation = ExecutionGeneration::new(7).unwrap();
        let host = armed_file_host(project.path());

        let graph = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest,
            "hermes-test",
            execution_generation,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!("generation fixture unexpectedly required legacy: {requirement:?}")
            }
        };

        assert_eq!(graph.execution_generation(), execution_generation);
        let (_, contexts) = graph.native_execution_inputs(7).unwrap();
        assert!(!contexts.is_empty());
        assert!(contexts
            .values()
            .all(|context| context.graph_generation == 7));

        let error = match graph.native_execution_inputs(1) {
            Ok(_) => panic!("native inputs accepted a mismatched execution generation"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "native execution inputs generation 1 does not match the graph's execution generation 7"
        );
    }

    #[cfg(unix)]
    #[test]
    fn initial_source_graph_coalesces_identical_literal_dynamic_import_attributes() {
        let project = tempfile::tempdir().unwrap();
        let graph = build_test_source_graph(
            project.path(),
            "if (false) { import('./repeat.json'); import('./repeat.json'); }\n",
        )
        .unwrap();

        let deferred = graph.deferred_dynamic_links();
        let entry = deferred.get(graph.entry()).unwrap();
        assert_eq!(entry.literal_specifiers.len(), 1);
        assert!(entry.literal_specifiers.contains("./repeat.json"));
    }

    #[cfg(unix)]
    #[test]
    fn initial_source_graph_refuses_conflicting_literal_dynamic_import_attributes() {
        let project = tempfile::tempdir().unwrap();
        let error = match build_test_source_graph(
            project.path(),
            "if (false) { import('./repeat.json'); import('./repeat.json', { with: { type: 'json' } }); }\n",
        ) {
            Ok(_) => panic!("conflicting initial literal dynamic-import attributes were accepted"),
            Err(error) => error,
        };

        let diagnostic = error.to_string();
        assert!(
            diagnostic.contains(
                "authenticated artifact literal dynamic-import spelling \"./repeat.json\" carries conflicting attributes"
            ),
            "unexpected conflicting-attributes refusal: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn activated_source_graph_coalesces_identical_literal_dynamic_import_attributes() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("target.mjs"),
            "if (false) { import('./repeat.json'); import('./repeat.json'); }\nexport const value = 1;\n",
        )
        .unwrap();
        let mut graph = build_test_source_graph(
            project.path(),
            "export const target = import('./target.mjs');\n",
        )
        .unwrap();
        let request = DynamicModuleActivationRequest::for_test(
            1,
            graph.entry().clone(),
            DynamicModuleActivationKind::Literal,
            "./target.mjs",
        );

        let target = graph.activate_dynamic_target(&request).unwrap();
        let deferred = graph.deferred_dynamic_links();
        let target = deferred.get(&target).unwrap();
        assert_eq!(target.literal_specifiers.len(), 1);
        assert!(target.literal_specifiers.contains("./repeat.json"));
    }

    #[cfg(unix)]
    #[test]
    fn activated_source_graph_refuses_conflicting_literal_dynamic_import_attributes() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("target.mjs"),
            "if (false) { import('./repeat.json'); import('./repeat.json', { with: { type: 'json' } }); }\nexport const value = 1;\n",
        )
        .unwrap();
        let mut graph = build_test_source_graph(
            project.path(),
            "export const target = import('./target.mjs');\n",
        )
        .unwrap();
        let request = DynamicModuleActivationRequest::for_test(
            1,
            graph.entry().clone(),
            DynamicModuleActivationKind::Literal,
            "./target.mjs",
        );

        let error = graph.activate_dynamic_target(&request).unwrap_err();
        let diagnostic = error.to_string();
        assert!(
            diagnostic.contains(
                "activated artifact literal dynamic-import spelling \"./repeat.json\" carries conflicting attributes"
            ),
            "unexpected conflicting-attributes refusal: {error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn authored_call_time_edges_never_resolve_before_invocation() {
        let project = tempfile::tempdir().unwrap();
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let host = armed_file_host(project.path());

        let entry = project.path().join("entry.mjs");
        std::fs::write(
            &entry,
            "if (false) import('./target-that-must-not-be-probed.mjs'); export const value = 1;\n",
        )
        .unwrap();
        let entry = std::fs::canonicalize(entry).unwrap();
        let graph = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest.clone(),
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!("dead dynamic import required legacy execution: {requirement:?}")
            }
        };
        assert_eq!(graph.records().count(), 1);
        assert!(graph.plan().unwrap().defers_dynamic_edges(graph.entry()));
        assert!(graph
            .deferred_dynamic_links()
            .get(graph.entry())
            .unwrap()
            .literal_specifiers
            .contains("./target-that-must-not-be-probed.mjs"));

        let cjs_entry = project.path().join("entry.cjs");
        std::fs::write(
            &cjs_entry,
            "if (false) require('./target-that-must-not-be-probed.cjs'); exports.value = 1;\n",
        )
        .unwrap();
        let cjs_entry = std::fs::canonicalize(cjs_entry).unwrap();
        let cjs_graph = match build_authenticated_source_graph_v1_for_host(
            &host,
            &cjs_entry,
            producer_digest,
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!("dead literal require required legacy execution: {requirement:?}")
            }
        };
        assert_eq!(cjs_graph.records().count(), 1);
        assert!(cjs_graph
            .plan()
            .unwrap()
            .defers_commonjs_require_edges(cjs_graph.entry()));
        assert!(cjs_graph
            .records
            .get(cjs_graph.entry())
            .unwrap()
            .deferred_commonjs_requires
            .contains("./target-that-must-not-be-probed.cjs"));
    }

    #[cfg(unix)]
    #[test]
    fn reached_dynamic_import_receipt_gates_only_its_target_static_closure() {
        let project = tempfile::tempdir().unwrap();
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let host = armed_file_host(project.path());
        let entry = project.path().join("entry.mjs");
        let target = project.path().join("target.mjs");
        std::fs::write(&entry, "export const promise = import('./target.mjs');\n").unwrap();
        std::fs::write(&target, "export const value = 42;\n").unwrap();
        let entry = std::fs::canonicalize(entry).unwrap();
        let mut graph = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest,
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "literal dynamic import required legacy execution: {}",
                    requirement.reason
                )
            }
        };
        assert_eq!(graph.records().count(), 1);
        assert_eq!(graph.activation_receipt_count(), 0);
        let request = DynamicModuleActivationRequest::for_test(
            1,
            graph.entry().clone(),
            DynamicModuleActivationKind::Literal,
            "./target.mjs",
        );
        let target_id = graph.activate_dynamic_target(&request).unwrap();
        assert_ne!(&target_id, graph.entry());
        assert_eq!(graph.records().count(), 2);
        assert!(graph.plan().unwrap().contains_record(&target_id));
        assert_eq!(graph.activation_receipt_count(), 1);

        let absent = DynamicModuleActivationRequest::for_test(
            1,
            graph.entry().clone(),
            DynamicModuleActivationKind::Literal,
            "./not-declared.mjs",
        );
        let error = graph.activate_dynamic_target(&absent).unwrap_err();
        assert!(
            error.to_string().contains("not authenticated declarations"),
            "{error:#}"
        );
        assert_eq!(graph.records().count(), 2);
        assert_eq!(graph.activation_receipt_count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn reached_commonjs_require_receipt_gates_only_its_target_static_closure() {
        let project = tempfile::tempdir().unwrap();
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let host = armed_file_host(project.path());
        let entry = project.path().join("entry.cjs");
        let target = project.path().join("target.cjs");
        std::fs::write(
            &entry,
            "exports.load = () => require('./target.cjs'); if (false) require('./dead.cjs');\n",
        )
        .unwrap();
        std::fs::write(
            &target,
            "exports.value = 42; if (false) require('./nested-dead.cjs');\n",
        )
        .unwrap();
        let entry = std::fs::canonicalize(entry).unwrap();
        let mut graph = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest,
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "literal CommonJS require required legacy execution: {}",
                    requirement.reason
                )
            }
        };
        let requester = graph.entry().clone();
        assert_eq!(graph.records().count(), 1);
        assert_eq!(graph.activation_receipt_count(), 0);
        let checkpoint = graph.activation_checkpoint();
        let target_id = graph
            .activate_commonjs_require_target(&requester, "./target.cjs", 1)
            .unwrap();
        assert_ne!(target_id, requester);
        assert_eq!(graph.records().count(), 2);
        assert_eq!(graph.activation_receipt_count(), 1);
        let target_record = graph.records.get(&target_id).unwrap();
        assert!(target_record.bindings.is_empty());
        assert!(target_record
            .deferred_commonjs_requires
            .contains("./nested-dead.cjs"));
        assert!(graph
            .plan()
            .unwrap()
            .defers_commonjs_require_edges(&target_id));
        graph.rollback_activation(checkpoint);
        assert_eq!(graph.records().count(), 1);
        assert_eq!(graph.activation_receipt_count(), 0);
        let _target_id = graph
            .activate_commonjs_require_target(&requester, "./target.cjs", 1)
            .unwrap();
        assert_eq!(graph.records().count(), 2);
        assert_eq!(graph.activation_receipt_count(), 1);

        let error = graph
            .activate_commonjs_require_target(&requester, "./not-declared.cjs", 1)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not an authenticated declaration"),
            "{error:#}"
        );
        assert_eq!(graph.records().count(), 2);
        assert_eq!(graph.activation_receipt_count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn invocation_time_prepared_carrier_is_discovered_only_after_exact_reached_edge() {
        let project = tempfile::tempdir().unwrap();
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let host = armed_file_host(project.path());
        let entry = project.path().join("entry.cjs");
        std::fs::write(&entry, "exports.load = () => require('./target.cjs');\n").unwrap();
        std::fs::write(
            project.path().join("target.cjs"),
            "module.exports = { value: 42 };\n",
        )
        .unwrap();
        let entry = std::fs::canonicalize(entry).unwrap();
        let deployment = digest_bytes("prepared-activation-test", b"deployment").unwrap();
        let artifact_dir = project.path().join("bundle-artifact");
        std::fs::create_dir(&artifact_dir).unwrap();

        let mut publisher = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest.clone(),
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "prepared activation publisher required legacy execution: {}",
                    requirement.reason
                )
            }
        };
        let publisher_entry = publisher.entry().clone();
        let target_id = publisher
            .activate_commonjs_require_target(&publisher_entry, "./target.cjs", 1)
            .unwrap();
        let activated = BTreeSet::from([target_id]);
        let cache_dir = publish_prepared_activation_records_v1(
            &publisher,
            &activated,
            &artifact_dir,
            deployment.clone(),
        )
        .unwrap();
        load_prepared_activation_records_v1(&mut publisher, &activated, &cache_dir, &deployment)
            .unwrap();

        let mut graph = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest,
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "prepared activation consumer required legacy execution: {}",
                    requirement.reason
                )
            }
        };
        let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        graph.set_prepared_activation_cache_locator(Arc::new(CountingPreparedActivationLocator {
            probes: probes.clone(),
            candidates: vec![PreparedActivationCacheCandidateV1 {
                cache_dir,
                deployment_graph_digest: deployment,
            }],
        }));
        assert_eq!(
            probes.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "constructing the graph probed the prepared activation cache"
        );
        let requester = graph.entry().clone();
        let error = graph
            .activate_commonjs_require_target(&requester, "./not-declared.cjs", 1)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not an authenticated declaration"),
            "{error:#}"
        );
        assert_eq!(
            probes.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a candidate spelling miss probed the prepared activation cache"
        );

        let target_id = graph
            .activate_commonjs_require_target(&requester, "./target.cjs", 1)
            .unwrap();
        assert_eq!(
            probes.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the reached exact edge did not invoke prepared discovery exactly once"
        );
        assert!(
            graph
                .available_prepared_entries()
                .unwrap()
                .contains_key(&target_id),
            "the invocation-time carrier was not admitted for the reached target"
        );
        assert_eq!(graph.prepared_access_receipt_count(), 1);
        let repeated = graph
            .activate_commonjs_require_target(&requester, "./target.cjs", 1)
            .unwrap();
        assert_eq!(repeated, target_id);
        assert_eq!(
            probes.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a repeated binding re-probed the prepared activation cache"
        );
        assert_eq!(graph.prepared_access_receipt_count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn invocation_time_prepared_dynamic_import_uses_the_same_receipt_boundary() {
        let project = tempfile::tempdir().unwrap();
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let host = armed_file_host(project.path());
        let entry = project.path().join("entry.mjs");
        std::fs::write(
            &entry,
            "export const load = () => import('./target.mjs');\n",
        )
        .unwrap();
        std::fs::write(
            project.path().join("target.mjs"),
            "export const value = 42;\n",
        )
        .unwrap();
        let entry = std::fs::canonicalize(entry).unwrap();
        let deployment = digest_bytes("prepared-dynamic-activation-test", b"deployment").unwrap();
        let artifact_dir = project.path().join("bundle-artifact");
        std::fs::create_dir(&artifact_dir).unwrap();

        let mut publisher = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest.clone(),
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "prepared dynamic publisher required legacy execution: {}",
                    requirement.reason
                )
            }
        };
        let publisher_request = DynamicModuleActivationRequest::for_test(
            1,
            publisher.entry().clone(),
            DynamicModuleActivationKind::Literal,
            "./target.mjs",
        );
        let target_id = publisher
            .activate_dynamic_target(&publisher_request)
            .unwrap();
        let activated = BTreeSet::from([target_id]);
        let cache_dir = publish_prepared_activation_records_v1(
            &publisher,
            &activated,
            &artifact_dir,
            deployment.clone(),
        )
        .unwrap();

        let mut graph = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest,
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "prepared dynamic consumer required legacy execution: {}",
                    requirement.reason
                )
            }
        };
        let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        graph.set_prepared_activation_cache_locator(Arc::new(CountingPreparedActivationLocator {
            probes: probes.clone(),
            candidates: vec![PreparedActivationCacheCandidateV1 {
                cache_dir,
                deployment_graph_digest: deployment,
            }],
        }));
        let absent = DynamicModuleActivationRequest::for_test(
            1,
            graph.entry().clone(),
            DynamicModuleActivationKind::Literal,
            "./not-declared.mjs",
        );
        graph.activate_dynamic_target(&absent).unwrap_err();
        assert_eq!(probes.load(std::sync::atomic::Ordering::SeqCst), 0);

        let request = DynamicModuleActivationRequest::for_test(
            1,
            graph.entry().clone(),
            DynamicModuleActivationKind::Literal,
            "./target.mjs",
        );
        let target_id = graph.activate_dynamic_target(&request).unwrap();
        assert_eq!(probes.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(graph
            .available_prepared_entries()
            .unwrap()
            .contains_key(&target_id));
        assert_eq!(graph.prepared_access_receipt_count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn invalid_invocation_time_prepared_closure_falls_back_atomically_to_inline() {
        let project = tempfile::tempdir().unwrap();
        let producer_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let host = armed_file_host(project.path());
        let entry = project.path().join("entry.cjs");
        std::fs::write(&entry, "exports.load = () => require('./target.mjs');\n").unwrap();
        std::fs::write(
            project.path().join("target.mjs"),
            "import { value } from './dependency.mjs'; export { value };\n",
        )
        .unwrap();
        std::fs::write(
            project.path().join("dependency.mjs"),
            "export const value = 42;\n",
        )
        .unwrap();
        let entry = std::fs::canonicalize(entry).unwrap();
        let deployment = digest_bytes("prepared-activation-failure-test", b"deployment").unwrap();
        let artifact_dir = project.path().join("bundle-artifact");
        std::fs::create_dir(&artifact_dir).unwrap();

        let mut publisher = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest.clone(),
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "prepared failure publisher required legacy execution: {}",
                    requirement.reason
                )
            }
        };
        let initial_ids = publisher.records.keys().cloned().collect::<BTreeSet<_>>();
        let publisher_entry = publisher.entry().clone();
        publisher
            .activate_commonjs_require_target(&publisher_entry, "./target.mjs", 1)
            .unwrap();
        let activated = publisher
            .records
            .keys()
            .filter(|source_id| !initial_ids.contains(*source_id))
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(activated.len(), 2);
        let cache_dir = publish_prepared_activation_records_v1(
            &publisher,
            &activated,
            &artifact_dir,
            deployment.clone(),
        )
        .unwrap();
        let tampered_id = activated.iter().next_back().unwrap();
        let tampered_record = publisher.records.get(tampered_id).unwrap();
        let tampered_dir = prepared_activation_record_cache_dir(
            &cache_dir,
            tampered_id,
            &tampered_record.artifact.semantic_digest,
        )
        .unwrap();
        std::fs::write(tampered_dir.join("payload.js"), b"tampered").unwrap();

        let mut graph = match build_authenticated_source_graph_v1_for_host(
            &host,
            &entry,
            producer_digest,
            "hermes-test",
            ExecutionGeneration::INITIAL,
        )
        .unwrap()
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "prepared failure consumer required legacy execution: {}",
                    requirement.reason
                )
            }
        };
        let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        graph.set_prepared_activation_cache_locator(Arc::new(CountingPreparedActivationLocator {
            probes: probes.clone(),
            candidates: vec![PreparedActivationCacheCandidateV1 {
                cache_dir,
                deployment_graph_digest: deployment,
            }],
        }));
        let requester = graph.entry().clone();
        let target_id = graph
            .activate_commonjs_require_target(&requester, "./target.mjs", 1)
            .unwrap();
        assert_eq!(probes.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(graph.plan().unwrap().contains_record(&target_id));
        assert_eq!(graph.records().count(), 3);
        assert!(
            graph.available_prepared_entries().unwrap().is_empty(),
            "one valid member of a failed prepared closure was partially adopted"
        );
        assert_eq!(
            graph.prepared_access_receipt_count(),
            0,
            "failed prepared closure receipts escaped atomic admission"
        );
    }

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

        let shared: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../schemas/prepared-module-graph-v1.schema.json"
        ))
        .unwrap();
        let record = &shared["$defs"]["record"];
        assert_eq!(record["additionalProperties"], false);
        assert!(record["properties"].get("path").is_none());
        assert!(!record["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "path"));
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
    fn package_compartment_identity_is_the_authenticated_locator() {
        let package = Principal::Package {
            name: NonEmptyString::new("image-lib").unwrap(),
            integrity: Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            locator: PackageLocator::new("image-lib@2.4.1").unwrap(),
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
        let record = |name: &str, artifact: ModuleArtifactV1, bindings| {
            let (source_label, virtual_path) = match &artifact.semantics.source_id.0 {
                SourceId::Builtin { domain, source_key } => (
                    format!("builtin:{}:{}", domain.as_str(), source_key.as_str()),
                    None,
                ),
                _ => (
                    format!("file:///project/{name}"),
                    Some(format!("/project/{name}")),
                ),
            };
            SourceGraphRecordV1 {
                path: PathBuf::from(checkout).join(name),
                source_label,
                virtual_path,
                artifact,
                bindings,
                candidate_tables: Vec::new(),
                deferred_dynamic: DeferredSourceDynamicBindingsV1::default(),
                deferred_commonjs_requires: BTreeSet::new(),
                bootstrap_internal_commonjs_requires: BTreeSet::new(),
                prepared: None,
            }
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
    fn compiled_project_root_prefers_the_outer_workspace_over_a_member_package() {
        let temporary = tempfile::tempdir().unwrap();
        let member = temporary.path().join("packages/app");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(
            temporary.path().join("package.json"),
            r#"{"name":"workspace","workspaces":["packages/*"]}"#,
        )
        .unwrap();
        std::fs::write(member.join("package.json"), r#"{"name":"app"}"#).unwrap();
        let entry = member.join("entry.mjs");
        std::fs::write(&entry, "export default 1;").unwrap();

        assert_eq!(
            discover_compiled_project_root(&entry).unwrap(),
            temporary.path()
        );
    }

    #[test]
    fn production_capture_keeps_builtin_bootstrap_objects_out_of_the_app_graph() {
        let root = tempfile::tempdir().unwrap();
        let entry = root.path().join("entry.mjs");
        std::fs::write(
            &entry,
            "import http from 'node:http'; export const kind = typeof http.createServer;",
        )
        .unwrap();
        let producer =
            super::super::artifact::source_integrity(b"builtin-bootstrap-producer").unwrap();

        let captured = capture_embedded_source_graph_v1(&entry, producer).unwrap();

        assert!(captured
            .prepared
            .graph
            .records
            .iter()
            .any(|record| matches!(
                &record.source_id.0,
                SourceId::Builtin { source_key, .. } if source_key.as_str() == "node_http"
            )));
        assert!(!captured
            .prepared
            .graph
            .records
            .iter()
            .any(|record| matches!(
                &record.source_id.0,
                SourceId::Builtin { source_key, .. } if source_key.as_str() == "internal/options"
            )));
    }

    #[test]
    fn production_capture_preserves_explicit_mts_top_level_await() {
        let root = tempfile::tempdir().unwrap();
        let entry = root.path().join("entry.mts");
        std::fs::write(
            &entry,
            "const value: string = await Promise.resolve('ok'); export { value };",
        )
        .unwrap();
        let producer = super::super::artifact::source_integrity(b"mts-tla-producer").unwrap();

        let captured = capture_embedded_source_graph_v1(&entry, producer).unwrap();
        let semantics = captured
            .prepared
            .carriers
            .iter()
            .flat_map(|carrier| carrier.manifest.entries.iter())
            .find(|entry| entry.semantics.source_id.0 == captured.prepared.graph.entry.0)
            .map(|entry| &entry.semantics)
            .unwrap();

        assert_eq!(
            semantics.source_goal,
            super::super::artifact::SourceGoalV1::Module
        );
        assert_eq!(
            semantics.dialect,
            Some(super::super::artifact::SourceDialectV1::Ts)
        );
        assert!(semantics.has_top_level_await);
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

/// Parse half of LLP 0056 §5 step 0 for the two independent channel records.
///
/// The step-0 composition driver calls this before reading any served bytes.
/// The seam exists only where the dev embedder feature provides the
/// armed-context query, so the documented order (armed exclusion BEFORE
/// channel parsing) holds unconditionally wherever this function compiles.
// @ref LLP 0056#5-the-nine-steps--the-ibex-half — step 0 excludes armed context before channel parsing.
#[cfg(feature = "dev-committed-embedder")]
pub(crate) fn parse_dev_composition_channel_records_v1(
    commitment_text: &str,
    expectations_text: &str,
) -> Result<(
    PreparedCompositionCommitmentV1,
    CompositionVerifierExpectationsV1,
)> {
    if crate::host::abi::installed_host_is_armed_for_dev_exclusion() {
        bail!(
            "{} dev-unarmed composition parsing refused: \
             an armed Host is installed in this process",
            super::composition::IBEX_DEV_COMPOSITION_ARMED_CONTEXT
        );
    }
    parse_dev_composition_channel_records_unchecked_v1(commitment_text, expectations_text)
}

/// The pure channel-parsing half of the step-0 seam, with the ambient
/// armed-context gate factored out so the golden-vector unit test is not
/// raced by sibling lib tests that install an armed process-global Host
/// (`install_host` replaces the process host; the lib suite runs many
/// arming tests in parallel). Every non-test caller goes through
/// `parse_dev_composition_channel_records_v1`, which applies the
/// unconditional armed exclusion FIRST — never call this directly from
/// admission code.
#[cfg(feature = "dev-committed-embedder")]
pub(crate) fn parse_dev_composition_channel_records_unchecked_v1(
    commitment_text: &str,
    expectations_text: &str,
) -> Result<(
    PreparedCompositionCommitmentV1,
    CompositionVerifierExpectationsV1,
)> {
    let commitment = parse_prepared_composition_commitment_v1(commitment_text)?;
    let expectations = parse_composition_verifier_expectations_v1(expectations_text)?;
    Ok((commitment, expectations))
}

/// LLP 0413 §10 Phase 2 / LLP 0042 development posture: UNARMED development
/// embedder admission + evaluation of a committed prepared publication.
///
/// This module is the deliberately-typed dev interim the Exact LLP 0416 D3
/// decision names: armed Debug remains the durable posture; this entry
/// exists so the Exact macOS Debug DIAGNOSTIC runtime (an unarmed embedding)
/// can run prepared JS factory-table carriers through the REAL committed
/// admission core and the REAL native module runner today. Its authority is
/// the production-SHAPED `ibex/prepared-graph-commitment/1` record delivered
/// over the same authenticated dev channel as the publication (the
/// `dev-served` trust seam); no `ibex/prepared-graph-commitment-dev/1`
/// session credential is minted here — that work stays gated on the open
/// transport question in
/// `issues/20260729-prepared-graph-development-session-commitment.md`.
///
/// Structural non-production guarantees:
/// - only compiled under the `dev-committed-embedder` cargo feature;
/// - refuses at construction time when the installed Host is armed (an
///   armed context can never reach this admission);
/// - every receipt and banner names `authority=dev-unarmed-dev-served
///   (non-production)` and the LLP 0043-pending fingerprint posture;
/// - never advertises prepared production startup.
/// @ref LLP 0042#development-commitment — dev-served channel is the dev trust seam
/// @ref LLP 0042#visible-non-production — receipts name the authority class
#[cfg(feature = "dev-committed-embedder")]
pub mod dev_committed_embedder {
    use std::ffi::{c_char, c_void, CStr, CString};
    use std::ptr::NonNull;

    use super::*;
    use crate::engine::module_runner::{
        CompositionDescriptorExecutorV1, CompositionSessionV1, GraphEvaluationContext,
        NativeModuleRecordConfig, NativeModuleRuntime, NativeSynchronousGraph,
    };
    use crate::module_loader::composition::{
        admit_prepared_composition_v1, composition_embedder_channel_error_report_v1,
        CompositionAdmissionOutcomeV1, DevUnarmedCompositionStartupReportV1,
    };

    const DEV_UNARMED_AUTHORITY: &str = "dev-unarmed-dev-served (non-production)";
    const DEV_FINGERPRINT_POSTURE: &str = "dev-vouched-index-external-producer (LLP 0043 pending)";
    const DEV_PREPARED_GRAPH_COMMITMENT_SCHEMA_V1: &str = "ibex/prepared-graph-commitment/1";

    #[cfg(test)]
    thread_local! {
        static LAST_COMPOSITION_SESSION_V1: std::cell::Cell<*const CompositionSessionV1> =
            const { std::cell::Cell::new(std::ptr::null()) };
    }

    #[cfg(test)]
    pub(crate) fn retained_composition_session_for_test_v1() -> Option<&'static CompositionSessionV1>
    {
        LAST_COMPOSITION_SESSION_V1.with(|session| {
            let session = session.get();
            (!session.is_null()).then(|| unsafe { &*session })
        })
    }

    /// Admission + evaluation receipt for one dev-unarmed committed startup.
    /// Serialized to JSON for the embedding host's startup report/banner
    /// (Exact LLP 0413 §13 phase vocabulary).
    #[derive(Debug, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct DevUnarmedCommittedStartupReportV1 {
        pub schema: &'static str,
        pub authority: &'static str,
        pub posture: &'static str,
        pub non_production: bool,
        pub fingerprint_posture: &'static str,
        pub entry_source_id: String,
        pub publication_root_prefix: String,
        pub carrier_count: usize,
        pub record_count: usize,
        pub principal_count: usize,
        pub attribution: &'static str,
        pub commitment_parse_us: u128,
        pub carrier_admission_us: u128,
        pub graph_link_us: u128,
        pub entry_execute_us: u128,
        /// Carrier v2 encoding split (Exact LLP 0413 §10 Phase 3): how many
        /// admitted carriers were `hermes-bytecode` vs
        /// `javascript-factory-table`. Hosts surface this in the startup
        /// report so a parse-free claim names the encoding that actually ran.
        pub hbc_carrier_count: usize,
        pub javascript_carrier_count: usize,
        /// The loaded-engine binding this admission was willing to execute
        /// bytecode against (digest prefix only; receipts are logs, not
        /// admission inputs). `None` when the engine identity was
        /// unavailable — hermes-bytecode carriers refuse in that state.
        pub engine_binding_digest_prefix: Option<String>,
    }

    /// Failure phase classification for the §5.4 fallback boundary: a
    /// pre-evaluation refusal may select the development fallback lane; once
    /// evaluation has begun the generation fails and no encoding switch is
    /// permitted.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum DevCommittedStartupFailurePhase {
        BeforeEvaluation,
        DuringEvaluation,
    }

    pub struct DevCommittedStartupError {
        pub phase: DevCommittedStartupFailurePhase,
        pub error: anyhow::Error,
    }

    fn pre_evaluation(error: anyhow::Error) -> DevCommittedStartupError {
        DevCommittedStartupError {
            phase: DevCommittedStartupFailurePhase::BeforeEvaluation,
            error,
        }
    }

    /// Admit the publication at `publication_dir` against `commitment_text`
    /// (canonical JCS bytes of a production-shaped commitment delivered over
    /// the dev channel), then link and evaluate the prepared graph on the
    /// embedder's OWN unarmed runtime.
    ///
    /// The linked native graph is intentionally retained (leaked) on
    /// success: the evaluated application owns the process from here —
    /// records back the app's live module namespaces and dynamic-import
    /// bindings for the remaining process lifetime (exactly one retention
    /// per startup); dropping the graph would release the engine-side
    /// records out from under the running app.
    pub fn run_prepared_graph_committed_dev_unarmed_v1(
        runtime: NonNull<c_void>,
        runtime_nonce: u64,
        publication_dir: &Path,
        commitment_text: &str,
        expected_target: &str,
        project_root: &Path,
    ) -> Result<DevUnarmedCommittedStartupReportV1, DevCommittedStartupError> {
        // Construction-time armed exclusion: this admission is structurally
        // unreachable from an armed Host context. The check reads the REAL
        // installed-host arming state (never the `insecure` presentation).
        if crate::host::abi::installed_host_is_armed_for_dev_exclusion() {
            return Err(pre_evaluation(anyhow!(
                "IBEX_DEV_COMMITTED_ARMED_CONTEXT dev-unarmed committed admission refused: \
                 an armed Host is installed in this process"
            )));
        }

        let parse_started = std::time::Instant::now();
        let commitment = parse_dev_served_commitment(commitment_text, expected_target)
            .map_err(pre_evaluation)?;
        let commitment_parse_us = parse_started.elapsed().as_micros();

        // Loaded-engine identity for hermes-bytecode carriers (Exact
        // LLP 0413 §10 Phase 3). Best-effort: a runtime that cannot report
        // its engine identity still admits javascript-factory-table
        // publications; HBC carriers then refuse pre-evaluation with the
        // typed engine-unavailable diagnostic.
        let hbc_engine = match (
            crate::engine::loaded_engine_binary_digest(),
            crate::engine::loaded_engine_bytecode_version(),
        ) {
            (Ok(digest), Ok(version)) => match capsec_semantics::model::Digest::new(digest) {
                Ok(binary_digest) => Some(CommittedHbcEngineExpectationV1 {
                    engine_binding: PreparedCarrierEngineBindingV2::LoadedFile { binary_digest },
                    bytecode_version: version,
                }),
                Err(error) => {
                    eprintln!(
                        "ibex dev committed admission: loaded engine digest is not canonical: {error}"
                    );
                    None
                }
            },
            (Err(error), _) | (_, Err(error)) => {
                eprintln!(
                    "ibex dev committed admission: loaded engine identity unavailable: {error}"
                );
                None
            }
        };
        let engine_binding_digest_prefix = hbc_engine.as_ref().map(|engine| {
            let PreparedCarrierEngineBindingV2::LoadedFile { binary_digest } =
                &engine.engine_binding
            else {
                unreachable!("dev embedder binds loaded-file engine identities only");
            };
            binary_digest.as_str().chars().take(24).collect::<String>()
        });

        let admission_started = std::time::Instant::now();
        let admitted = admit_committed_publication_v1(
            publication_dir,
            &commitment,
            project_root,
            CommittedFingerprintPosture::DevVouchedIndexExternalProducer,
            hbc_engine.as_ref(),
        )
        .map_err(pre_evaluation)?;
        let carrier_admission_us = admission_started.elapsed().as_micros();

        let CommittedPublicationAdmissionV1 {
            entry,
            records,
            principals,
            carrier_count,
            hbc_carrier_count,
            javascript_carrier_count,
        } = admitted;
        let record_count = records.len();
        let principal_count = principals.len();

        // Eager engine-level preflight of every admitted hermes-bytecode
        // carrier through the exact linked Hermes decoder, BEFORE any record
        // is created: an engine-specific structural rejection refuses
        // pre-evaluation here instead of surfacing mid-link.
        if hbc_carrier_count > 0 {
            let mut preflighted: BTreeSet<&str> = BTreeSet::new();
            for record in records.values() {
                let Some(prepared) = record.prepared.as_ref() else {
                    continue;
                };
                let manifest = prepared.carrier.manifest();
                if !matches!(
                    manifest.encoding,
                    PreparedCarrierEncodingV2::HermesBytecode { .. }
                ) {
                    continue;
                }
                if !preflighted.insert(manifest.carrier_digest.as_str()) {
                    continue;
                }
                crate::engine::module_runner::preflight_hermes_bytecode(prepared.carrier.bytes())
                    .map_err(pre_evaluation)?;
            }
        }

        let execution_generation = ExecutionGeneration::INITIAL;

        let plan = SynchronousGraphPlan::new_typed_with_private_commonjs_edges(
            records
                .iter()
                .map(|(_, record)| {
                    Ok((
                        verify_record(record, &commitment.producer.binary_digest)?,
                        record.bindings.clone(),
                    ))
                })
                .collect::<Result<Vec<_>>>()
                .map_err(pre_evaluation)?,
            computed_candidate_site_map(&records).map_err(pre_evaluation)?,
            BTreeSet::new(),
            BTreeSet::new(),
            records
                .iter()
                .filter(|(_, record)| !record.bootstrap_internal_commonjs_requires.is_empty())
                .map(|(source_id, record)| {
                    (
                        source_id.clone(),
                        record.bootstrap_internal_commonjs_requires.clone(),
                    )
                })
                .collect(),
        )
        .map_err(|error| pre_evaluation(anyhow::Error::from(error)))?;

        let mut configs = BTreeMap::new();
        for source_id in records.keys() {
            // EXECUTION attribution collapses to the root principal on this
            // lane, exactly like every module the diagnostic runtime's
            // legacy compat lanes evaluate today: the unarmed runtime
            // installs no compartment registry (that seal is an armed /
            // IBEX_COMPARTMENTS posture), so package compartments cannot
            // bind. Carrier ADMISSION above remains fully per-principal
            // (grouping, splice refusal, digest binding); the collapse is
            // named in the receipt (`attribution`) and retires with the
            // armed-Debug durable posture (Exact LLP 0416 D3).
            let principal_id: u32 = 0;
            let compartment_identity: Option<String> = None;
            // Native execution requires `/project/`-rooted authenticated
            // virtual labels (`with_authenticated_virtual_path`); the
            // committed records carry the rejoin-oriented `/app/modules/…`
            // portable display, so derive the execution labels from the
            // SourceId's authenticated path components here. Purely a
            // display/observable identity (import.meta, __filename) — never
            // a resolver path or authority.
            let (source_label, virtual_path) =
                dev_execution_display(source_id).map_err(pre_evaluation)?;
            let mut config = NativeModuleRecordConfig::new(
                principal_id,
                compartment_identity,
                GraphEvaluationContext::new(
                    source_id.clone(),
                    principal_id,
                    principal_id,
                    [principal_id],
                    execution_generation.get(),
                )
                .map_err(pre_evaluation)?,
                source_label.clone(),
                source_label,
            )
            .map_err(pre_evaluation)?;
            if let Some(virtual_path) = virtual_path {
                config = config
                    .with_authenticated_virtual_path(virtual_path)
                    .map_err(pre_evaluation)?;
            }
            configs.insert(source_id.clone(), config);
        }

        let mut prepared_entries = BTreeMap::new();
        for (source_id, record) in &records {
            let prepared = record.prepared.as_ref().ok_or_else(|| {
                pre_evaluation(anyhow!(
                    "committed publication record has no prepared carrier entry"
                ))
            })?;
            prepared_entries.insert(
                source_id.clone(),
                prepared
                    .carrier
                    .entry(prepared.entry_id.as_str())
                    .map_err(pre_evaluation)?,
            );
        }

        let link_started = std::time::Instant::now();
        // SAFETY: the embedder passes the live runtime pointer plus the nonce
        // read from `ex_hermes_runtime_nonce` on the runtime's owner thread
        // (the C-ABI contract of `ibex_dev_unarmed_committed_prepared_startup_v1`).
        let native_runtime = Box::leak(Box::new(
            unsafe { NativeModuleRuntime::from_raw(runtime, runtime_nonce) }
                .map_err(pre_evaluation)?,
        ));
        let mut linked = NativeSynchronousGraph::link_prepared(
            native_runtime,
            &plan,
            &entry,
            configs,
            &prepared_entries,
        )
        .map_err(pre_evaluation)?;
        let graph_link_us = link_started.elapsed().as_micros();

        // §5.4 boundary: application factories begin evaluating here. Any
        // failure past this point fails the generation — the caller must not
        // restart the same graph through another encoding.
        let evaluate_started = std::time::Instant::now();
        let evaluation = linked.evaluate();
        let entry_execute_us = evaluate_started.elapsed().as_micros();
        // Records back the running application from here (see doc comment).
        std::mem::forget(linked);
        drop(plan);
        if let Err(error) = evaluation {
            return Err(DevCommittedStartupError {
                phase: DevCommittedStartupFailurePhase::DuringEvaluation,
                error,
            });
        }

        let report = DevUnarmedCommittedStartupReportV1 {
            schema: "ibex/dev-unarmed-committed-startup-report/1",
            authority: DEV_UNARMED_AUTHORITY,
            posture: "dev-unarmed",
            non_production: true,
            fingerprint_posture: DEV_FINGERPRINT_POSTURE,
            entry_source_id: commitment.entry_source_id.as_str().to_owned(),
            publication_root_prefix: commitment.publication_root_digest.as_str()[..24].to_owned(),
            carrier_count,
            record_count,
            principal_count,
            attribution: "collapsed-to-root (dev-unarmed; no compartment registry)",
            commitment_parse_us,
            carrier_admission_us,
            graph_link_us,
            entry_execute_us,
            hbc_carrier_count,
            javascript_carrier_count,
            engine_binding_digest_prefix,
        };
        eprintln!(
            "ibex prepared admission authority={} entry={} root={} carriers={} (hbc={} js={}) records={} admission_us={} link_us={} evaluate_us={}",
            DEV_UNARMED_AUTHORITY,
            report.entry_source_id,
            report.publication_root_prefix,
            carrier_count,
            hbc_carrier_count,
            javascript_carrier_count,
            record_count,
            carrier_admission_us,
            graph_link_us,
            entry_execute_us,
        );
        Ok(report)
    }

    fn apply_composition_execution_metrics(
        report: &mut DevUnarmedCompositionStartupReportV1,
        metrics: &crate::engine::module_runner::CompositionExecutionMetricsV1,
    ) {
        report.set_execution_observations(
            metrics.agent_evaluate,
            metrics.agent_invoke,
            metrics.app_evaluate,
            metrics.agent_evaluated_record_count,
            metrics.app_evaluated_record_count,
            metrics.shared_evaluated_record_count,
            metrics.agent_invoke_returned_thenable,
        );
    }

    /// Admit, atomically link, and execute one package-aware composition.
    /// Success leaks exactly one retained session for process lifetime.
    // @ref LLP 0056#5-the-nine-steps--the-ibex-half — the return-code boundary closes after step 8; every descriptor failure is DuringEvaluation.
    fn run_prepared_composition_dev_unarmed_v1(
        runtime: NonNull<c_void>,
        runtime_nonce: u64,
        composition_dir: &Path,
        commitment_text: &str,
        expectations_text: &str,
        project_root: &Path,
    ) -> (i32, DevUnarmedCompositionStartupReportV1, Option<String>) {
        let admitted = match admit_prepared_composition_v1(
            composition_dir,
            commitment_text,
            expectations_text,
            project_root,
        ) {
            CompositionAdmissionOutcomeV1::ChannelError(report)
            | CompositionAdmissionOutcomeV1::Refused(report) => {
                let error = serde_json::to_string(&report).err().map(|serialization| {
                    format!("composition refusal report unavailable: {serialization}")
                });
                return (1, report, error);
            }
            CompositionAdmissionOutcomeV1::Admitted(admitted) => admitted,
        };

        let super::super::composition::AdmittedCompositionV1 {
            authorized,
            envelope,
            mut report,
            ..
        } = *admitted;
        let link_started = std::time::Instant::now();
        let linked = (|| -> Result<(
            NativeSynchronousGraph<'static>,
            *mut NativeModuleRuntime<'static>,
        )> {
            let root_plan = authorized.root_plan()?;
            let plan = authorized.execution_plan(&envelope.alias_table.rows)?;
            let graph_generation = authorized.graph_generation()?;
            let mut configs = BTreeMap::new();
            let mut prepared_entries = BTreeMap::new();
            for package in authorized.packages.values() {
                for (source_id, record) in &package.records {
                    let principal_id = 0;
                    let (source_label, virtual_path) = dev_execution_display(source_id)?;
                    let mut config = NativeModuleRecordConfig::new(
                        principal_id,
                        None,
                        GraphEvaluationContext::new(
                            source_id.clone(),
                            principal_id,
                            principal_id,
                            [principal_id],
                            graph_generation,
                        )?,
                        source_label.clone(),
                        source_label,
                    )?;
                    if let Some(virtual_path) = virtual_path {
                        config = config.with_authenticated_virtual_path(virtual_path)?;
                    }
                    configs.insert(source_id.clone(), config);
                    prepared_entries.insert(
                        source_id.clone(),
                        record.carrier.entry(record.entry_id.as_str())?,
                    );
                }
            }
            // SAFETY: the C entry requires a live pointer/nonce pair on the
            // runtime owner thread. The wrapper becomes the graph's stable
            // self-reference anchor and leaks only with a successful session.
            let native_runtime = Box::new(unsafe {
                NativeModuleRuntime::from_raw(runtime, runtime_nonce)
            }?);
            let runtime_owner = Box::into_raw(native_runtime);
            let linked = NativeSynchronousGraph::link_authorized_prepared_composition(
                unsafe { &*runtime_owner },
                &plan,
                &root_plan,
                configs,
                &authorized,
                &authorized.authority_contexts,
                &prepared_entries,
            );
            match linked {
                Ok(linked) => Ok((linked, runtime_owner)),
                Err(error) => {
                    // No graph escaped, so the self-reference anchor can be
                    // reclaimed. Only a successful retained session leaks it.
                    unsafe { drop(Box::from_raw(runtime_owner)) };
                    Err(error)
                }
            }
        })();
        report.set_graph_link_duration(link_started.elapsed());
        let (linked, runtime_owner) = match linked {
            Ok(linked) => linked,
            Err(error) => {
                let detail = format!("{error:#}");
                return (1, report.into_link_refusal(detail.clone()), Some(detail));
            }
        };

        let agent: Result<Option<(SourceId, String)>> = envelope
            .entry_plan
            .entries
            .iter()
            .find(|entry| entry.role == CompositionRole::Agent)
            .map(|entry| {
                Ok((
                    SourceId::decode(&entry.root)?,
                    entry
                        .export
                        .clone()
                        .ok_or_else(|| anyhow!("admitted agent descriptor has no export"))?,
                ))
            })
            .transpose();
        let agent = match agent {
            Ok(agent) => agent,
            Err(error) => {
                drop(linked);
                unsafe { drop(Box::from_raw(runtime_owner)) };
                let detail = format!("{error:#}");
                return (
                    2,
                    report.into_startup_error(
                        super::super::composition::CompositionStartupPhaseV1::AgentEvaluate,
                        detail.clone(),
                    ),
                    Some(detail),
                );
            }
        };
        let mut executor = match CompositionDescriptorExecutorV1::new(linked, agent) {
            Ok(executor) => executor,
            Err(error) => {
                unsafe { drop(Box::from_raw(runtime_owner)) };
                let detail = format!("{error:#}");
                return (
                    2,
                    report.into_startup_error(
                        super::super::composition::CompositionStartupPhaseV1::AgentEvaluate,
                        detail.clone(),
                    ),
                    Some(detail),
                );
            }
        };
        if let Err(failure) = executor.run() {
            apply_composition_execution_metrics(&mut report, executor.metrics());
            let detail = failure.to_string();
            drop(executor);
            unsafe { drop(Box::from_raw(runtime_owner)) };
            return (
                2,
                report.into_startup_error(failure.phase, detail.clone()),
                Some(detail),
            );
        }
        apply_composition_execution_metrics(&mut report, executor.metrics());
        let admitted_records = authorized.admitted_records();
        match CompositionSessionV1::new(
            executor,
            envelope.alias_table,
            admitted_records,
            report.clone(),
        ) {
            Ok(session) => {
                let session = Box::leak(Box::new(session)) as *const CompositionSessionV1;
                #[cfg(test)]
                LAST_COMPOSITION_SESSION_V1.with(|retained| retained.set(session));
                let _ = session;
                (0, report, None)
            }
            Err(error) => {
                unsafe { drop(Box::from_raw(runtime_owner)) };
                let detail = format!("{error:#}");
                (
                    2,
                    report.into_startup_error(
                        super::super::composition::CompositionStartupPhaseV1::AppEvaluate,
                        detail.clone(),
                    ),
                    Some(detail),
                )
            }
        }
    }

    /// Authenticated execution display labels for a dev-committed record,
    /// derived only from the SourceId's own path components: root files map
    /// to `/project/<components>`, package files to
    /// `/project/node_modules/<package>/<components>`, builtins to their
    /// builtin label with no virtual path.
    fn dev_execution_display(source_id: &SourceId) -> Result<(String, Option<String>)> {
        match source_id {
            SourceId::Builtin { domain, source_key } => Ok((
                format!("builtin:{}:{}", domain.as_str(), source_key.as_str()),
                None,
            )),
            SourceId::File { principal, path } => {
                let mut components = Vec::with_capacity(path.len());
                for component in path {
                    let text = std::str::from_utf8(component.bytes())
                        .map_err(|_| anyhow!("dev committed record path component is not UTF-8"))?;
                    // '?' stays displayable: Vite query-bearing module ids
                    // (`x.contract?import`, `y.wasm?url`) are distinct
                    // modules whose identity includes the query (LLP 0413
                    // Phase 2 M3 blog finding).
                    if text.is_empty()
                        || text
                            .chars()
                            .any(|ch| ch.is_control() || matches!(ch, '%' | '#' | '\\'))
                        || text.contains(char::is_whitespace)
                    {
                        bail!("dev committed record path component is not displayable: {text:?}");
                    }
                    components.push(text.to_owned());
                }
                let joined = components.join("/");
                let virtual_path = match principal {
                    Principal::Package { name, .. } => {
                        format!("/project/node_modules/{}/{joined}", name.as_str())
                    }
                    _ => format!("/project/{joined}"),
                };
                let source_label = format!("file://{virtual_path}");
                Ok((source_label, Some(virtual_path)))
            }
            SourceId::Synthetic { .. } => {
                bail!("synthetic prepared records are unsupported on the dev committed lane")
            }
        }
    }

    /// Parse and precheck the dev-served commitment record: retained exact
    /// bytes must be strict JSON, canonical JCS, carry the production
    /// commitment schema (the production-SHAPED record — the dev posture
    /// lives in this entry's type and receipts, never in a relaxed record),
    /// and name the embedder's expected target byte-for-byte.
    fn parse_dev_served_commitment(
        commitment_text: &str,
        expected_target: &str,
    ) -> Result<capsec_semantics::arming::PreparedGraphCommitmentV1> {
        let value = capsec_semantics::strict_json::parse_strict(commitment_text)
            .map_err(|error| anyhow!("IBEX_DEV_COMMITTED_CORRUPT commitment: {error}"))?;
        let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)?;
        if canonical != commitment_text.trim_end_matches('\n').as_bytes() {
            bail!("IBEX_DEV_COMMITTED_CORRUPT commitment is not canonical JCS");
        }
        let commitment: capsec_semantics::arming::PreparedGraphCommitmentV1 =
            serde_json::from_value(value)
                .map_err(|error| anyhow!("IBEX_DEV_COMMITTED_CORRUPT commitment shape: {error}"))?;
        if commitment.schema != DEV_PREPARED_GRAPH_COMMITMENT_SCHEMA_V1 {
            bail!("IBEX_DEV_COMMITTED_SCHEMA unsupported prepared-graph commitment schema");
        }
        if commitment.workflow != "production" {
            bail!(
                "IBEX_DEV_COMMITTED_SCHEMA dev-served commitment must be the production-shaped \
                 record (workflow=production); a distinct dev credential class is LLP 0042 open work"
            );
        }
        if commitment.target != expected_target {
            bail!(
                "IBEX_DEV_COMMITTED_TARGET commitment target {:?} differs from the embedder \
                 expectation {:?}",
                commitment.target,
                expected_target
            );
        }
        Ok(commitment)
    }

    fn write_out_string(slot: *mut *mut c_char, value: &str) {
        if slot.is_null() {
            return;
        }
        let owned = CString::new(value.replace('\0', "\u{fffd}"))
            .unwrap_or_else(|_| CString::new("invalid diagnostic").expect("static"));
        unsafe { *slot = owned.into_raw() };
    }

    unsafe fn required_utf8<'a>(pointer: *const c_char, role: &str) -> Result<&'a str> {
        if pointer.is_null() {
            bail!("dev committed startup received a null {role}");
        }
        unsafe { CStr::from_ptr(pointer) }
            .to_str()
            .map_err(|_| anyhow!("dev committed startup received a non-UTF-8 {role}"))
    }

    /// C ABI for the Exact Debug diagnostic host (see `exact_runtime.h`).
    /// Returns 0 on success, 1 on a pre-evaluation refusal (the §5.4
    /// development fallback lane may be selected), 2 once evaluation has
    /// begun (the generation is failed; no encoding switch). Out strings are
    /// freed with `ex_host_free_string`. Must be called on the runtime's
    /// owner thread with a live runtime nonce.
    #[no_mangle]
    pub unsafe extern "C" fn ibex_dev_unarmed_committed_prepared_startup_v1(
        runtime: *mut c_void,
        runtime_nonce: u64,
        publication_dir: *const c_char,
        commitment_json: *const c_char,
        expected_target: *const c_char,
        project_root: *const c_char,
        out_report_json: *mut *mut c_char,
        out_error: *mut *mut c_char,
    ) -> i32 {
        if !out_report_json.is_null() {
            unsafe { *out_report_json = std::ptr::null_mut() };
        }
        if !out_error.is_null() {
            unsafe { *out_error = std::ptr::null_mut() };
        }
        let outcome =
            (|| -> Result<DevUnarmedCommittedStartupReportV1, DevCommittedStartupError> {
                let runtime = NonNull::new(runtime).ok_or_else(|| {
                    pre_evaluation(anyhow!("dev committed startup received a null runtime"))
                })?;
                let publication_dir = unsafe { required_utf8(publication_dir, "publication dir") }
                    .map_err(pre_evaluation)?;
                let commitment_json = unsafe { required_utf8(commitment_json, "commitment") }
                    .map_err(pre_evaluation)?;
                let expected_target = unsafe { required_utf8(expected_target, "expected target") }
                    .map_err(pre_evaluation)?;
                let project_root = unsafe { required_utf8(project_root, "project root") }
                    .map_err(pre_evaluation)?;
                run_prepared_graph_committed_dev_unarmed_v1(
                    runtime,
                    runtime_nonce,
                    Path::new(publication_dir),
                    commitment_json,
                    expected_target,
                    Path::new(project_root),
                )
            })();
        match outcome {
            Ok(report) => {
                match serde_json::to_string(&report) {
                    Ok(json) => write_out_string(out_report_json, &json),
                    Err(error) => {
                        // Reporting must never convert a successful startup
                        // into a failure; surface the serialization problem
                        // through the error slot alongside success.
                        write_out_string(
                            out_error,
                            &format!("dev committed startup report serialization failed: {error}"),
                        );
                    }
                }
                0
            }
            Err(failure) => {
                write_out_string(out_error, &format!("{:#}", failure.error));
                match failure.phase {
                    DevCommittedStartupFailurePhase::BeforeEvaluation => 1,
                    DevCommittedStartupFailurePhase::DuringEvaluation => 2,
                }
            }
        }
    }

    unsafe fn required_composition_utf8<'a>(pointer: *const c_char, role: &str) -> Result<&'a str> {
        if pointer.is_null() {
            bail!("IBEX_DEV_COMPOSITION_CORRUPT composition startup received a null {role}");
        }
        unsafe { CStr::from_ptr(pointer) }.to_str().map_err(|_| {
            anyhow!("IBEX_DEV_COMPOSITION_CORRUPT composition startup received a non-UTF-8 {role}")
        })
    }

    /// LLP 0056 package-aware dev-unarmed composition startup. Returns 0 only
    /// after all descriptor transitions complete, 1 for step-0–8 refusal, and
    /// 2 for every step-9-or-later startup failure. The tagged report is total.
    // @ref LLP 0056#34-the-c-abi-entry-dev-unarmed-the-only-v1-posture — this entry preserves the landed phase return codes while adding a total report.
    #[no_mangle]
    pub unsafe extern "C" fn ibex_dev_unarmed_composition_prepared_startup_v1(
        runtime: *mut c_void,
        runtime_nonce: u64,
        composition_dir: *const c_char,
        commitment_json: *const c_char,
        expectations_json: *const c_char,
        project_root: *const c_char,
        out_report_json: *mut *mut c_char,
        out_error: *mut *mut c_char,
    ) -> i32 {
        if !out_report_json.is_null() {
            unsafe { *out_report_json = std::ptr::null_mut() };
        }
        if !out_error.is_null() {
            unsafe { *out_error = std::ptr::null_mut() };
        }

        let parsed = (|| -> Result<(NonNull<c_void>, &str, &str, &str, &str)> {
            let runtime = NonNull::new(runtime).ok_or_else(|| {
                anyhow!("IBEX_DEV_COMPOSITION_CORRUPT composition startup received a null runtime")
            })?;
            let composition_dir =
                unsafe { required_composition_utf8(composition_dir, "composition directory") }?;
            let commitment_json =
                unsafe { required_composition_utf8(commitment_json, "commitment") }?;
            let expectations_json =
                unsafe { required_composition_utf8(expectations_json, "expectations") }?;
            let project_root = unsafe { required_composition_utf8(project_root, "project root") }?;
            Ok((
                runtime,
                composition_dir,
                commitment_json,
                expectations_json,
                project_root,
            ))
        })();
        let (status, report, mut diagnostic) = match parsed {
            Ok((runtime, composition_dir, commitment, expectations, project_root)) => {
                run_prepared_composition_dev_unarmed_v1(
                    runtime,
                    runtime_nonce,
                    Path::new(composition_dir),
                    commitment,
                    expectations,
                    Path::new(project_root),
                )
            }
            Err(error) => {
                let detail = format!("{error:#}");
                (
                    1,
                    composition_embedder_channel_error_report_v1(detail.clone()),
                    Some(detail),
                )
            }
        };
        let outcome_name = match status {
            0 => "admitted",
            1 => "refused",
            2 => "admitted-startup-error",
            _ => "invalid-outcome",
        };
        match serde_json::to_string(&report) {
            Ok(json) if !out_report_json.is_null() => write_out_string(out_report_json, &json),
            Ok(_) => {
                let delivery = format!(
                    "composition {outcome_name} report delivery failed: out_report_json is null"
                );
                diagnostic = Some(match diagnostic {
                    Some(existing) => format!("{existing}; {delivery}"),
                    None => delivery,
                });
            }
            Err(error) => {
                let serialization = format!(
                    "composition {outcome_name} outcome retained but report serialization failed: {error}"
                );
                diagnostic = Some(match diagnostic {
                    Some(existing) => format!("{existing}; {serialization}"),
                    None => serialization,
                });
            }
        }
        if diagnostic.is_none() && status != 0 {
            diagnostic = Some(format!("composition startup ended as {outcome_name}"));
        }
        if let Some(diagnostic) = diagnostic {
            write_out_string(out_error, &diagnostic);
        }
        status
    }
}
