//! Phase-0 LLP 0029 packager for the dynamically linked development stub.
//!
//! This is intentionally not the release `ibex compile` surface. It proves
//! deterministic envelope/carrier construction and relocation before static
//! Hermes, catalog trust, signing, and advertised CapSec arming are available.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{bail, Context, Result};
use capsec_semantics::digest::{compute_checked_contract_digest, DigestKind};
use capsec_semantics::model::{Digest, NonEmptyString, PackageLocator, PathComponent, Principal};
use ibex_runtime::module_loader::artifact::{
    digest_bytes, ArtifactAdmissionV1, CanonicalSourceId, DynamicEdgeV1, ModuleArtifactV1,
};
use ibex_runtime::module_loader::carrier::PreparedModuleCarrierV2;
use ibex_runtime::module_loader::embedded_graph::{
    EmbeddedCarrierBindingV1, EmbeddedCarrierFactV1, EmbeddedModuleEdgeV1, EmbeddedModuleGraphV1,
    EmbeddedModuleRecordV1, VirtualSourceLabelV1, EMBEDDED_MODULE_GRAPH_SCHEMA_V1,
};
use ibex_runtime::module_loader::graph::GraphEdgeKey;
use ibex_runtime::module_loader::identity::{
    ConditionSet, ImportAttributes, ResolutionKind, SourceId,
};
use ibex_runtime::module_loader::producer_spike::{
    produce_builtin_artifact_v1, produce_commonjs_artifact_v1, produce_json_artifact_v1,
    produce_module_artifact_v1,
};
use ibex_runtime::module_loader::runner_pipeline::{
    artifact_edge_attributes, artifact_edge_requests,
};
use ibex_runtime::module_loader::{
    package_tree_integrity, ModuleKind, ModuleLoader, ResolvedModule,
};
use ibex_sfe_format::{build_executable_v1, EntryDesignationV1, SectionInputV1, SectionKindV1};

const PREPARED_PRODUCER_ID: &str = "ibex-sfe-dev-pack";

struct CapturedRecord {
    artifact: ModuleArtifactV1,
    bindings: BTreeMap<GraphEdgeKey, SourceId>,
    virtual_source: VirtualSourceLabelV1,
}

struct CapturedGraph {
    entry: SourceId,
    root_owner: Principal,
    records: BTreeMap<SourceId, CapturedRecord>,
}

struct CarrierOutput {
    pair_id: String,
    manifest: PreparedModuleCarrierV2,
    payload: Vec<u8>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ibex-sfe-dev-pack: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        bail!("usage: ibex-sfe-dev-pack <stub> <entry.mjs> <output>");
    }
    let stub_path = Path::new(&args[0]);
    let entry_path = Path::new(&args[1]);
    let output_path = Path::new(&args[2]);
    let stub = std::fs::read(stub_path)
        .with_context(|| format!("cannot read development stub {}", stub_path.display()))?;
    let producer_digest = digest_bytes(
        "ibex:sfe-development-producer:1",
        env!("CARGO_PKG_VERSION").as_bytes(),
    )?;
    let captured = capture_graph(entry_path, producer_digest.clone())?;
    let entry_source_integrity = captured
        .records
        .get(&captured.entry)
        .ok_or_else(|| anyhow::anyhow!("captured graph lost its entry"))?
        .artifact
        .semantics
        .source_integrity
        .clone();
    let entry_components = match &captured.entry {
        SourceId::File {
            principal: Principal::Root { .. },
            path,
        } => path.clone(),
        _ => bail!("phase-0 development entry is not a project-root file"),
    };
    let mut ordered_records = captured
        .records
        .into_iter()
        .map(|(source_id, record)| Ok((source_id.encode()?, source_id, record)))
        .collect::<Result<Vec<_>>>()?;
    ordered_records.sort_by(|left, right| left.0.cmp(&right.0));
    let ordered_records = ordered_records
        .into_iter()
        .map(|(_, source_id, record)| (source_id, record))
        .collect::<Vec<_>>();

    let mut embedded_records = ordered_records
        .iter()
        .enumerate()
        .map(|(index, (source_id, captured))| {
            let mut edges = captured
                .bindings
                .iter()
                .map(|(key, target)| {
                    Ok(EmbeddedModuleEdgeV1 {
                        specifier: NonEmptyString::new(key.specifier.clone())
                            .map_err(anyhow::Error::msg)?,
                        resolution_kind: key.resolution_kind,
                        conditions: ConditionSet::for_kind(key.resolution_kind),
                        attributes: artifact_edge_attributes(&captured.artifact, key)?,
                        target: CanonicalSourceId(target.clone()),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            sort_edges(&mut edges)?;
            Ok(EmbeddedModuleRecordV1 {
                source_id: CanonicalSourceId(source_id.clone()),
                source_integrity: captured.artifact.semantics.source_integrity.clone(),
                semantic_digest: captured.artifact.semantic_digest.clone(),
                carrier: EmbeddedCarrierBindingV1 {
                    pair_id: NonEmptyString::new(format!("module-{index:04}"))
                        .map_err(anyhow::Error::msg)?,
                    entry_id: NonEmptyString::new(captured.artifact.semantic_digest.as_str())
                        .map_err(anyhow::Error::msg)?,
                },
                edges,
                virtual_source: captured.virtual_source.clone(),
                candidate_table_refs: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let placeholder_identity = digest_bytes("ibex:sfe-graph-placeholder:1", &[])?;
    let mut embedded_graph = EmbeddedModuleGraphV1 {
        schema: EMBEDDED_MODULE_GRAPH_SCHEMA_V1.into(),
        graph_identity: placeholder_identity,
        entry: CanonicalSourceId(captured.entry.clone()),
        records: std::mem::take(&mut embedded_records),
    };
    embedded_graph.validate_contract()?;
    let graph_identity = embedded_graph
        .authenticated_snapshot(Vec::new())?
        .identity()?;
    embedded_graph.graph_identity = graph_identity.clone();

    let mut carriers = Vec::with_capacity(ordered_records.len());
    let mut carrier_facts = BTreeMap::new();
    for ((source_id, captured_record), embedded_record) in
        ordered_records.iter().zip(&embedded_graph.records)
    {
        let verified = captured_record.artifact.verify_for_admission(
            &ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: source_id.clone(),
                expected_source_integrity: captured_record
                    .artifact
                    .semantics
                    .source_integrity
                    .clone(),
                expected_producer_id: NonEmptyString::new("ibex-runtime-oxc")
                    .map_err(anyhow::Error::msg)?,
                producer_binary_digest: producer_digest.clone(),
                transform_fingerprint_digest: captured_record
                    .artifact
                    .semantics
                    .transform_fingerprint
                    .digest()?,
            },
        )?;
        let owner = source_id
            .defining_principal()
            .cloned()
            .unwrap_or_else(|| captured.root_owner.clone());
        let (manifest, payload) = PreparedModuleCarrierV2::from_inline_artifacts(
            owner,
            NonEmptyString::new(PREPARED_PRODUCER_ID).map_err(anyhow::Error::msg)?,
            producer_digest.clone(),
            graph_identity.clone(),
            [(embedded_record.carrier.entry_id.clone(), verified)],
        )?;
        let pair_id = embedded_record.carrier.pair_id.as_str().to_owned();
        carrier_facts.insert(
            pair_id.clone(),
            EmbeddedCarrierFactV1 {
                source_id: embedded_record.source_id.clone(),
                semantic_digest: embedded_record.semantic_digest.clone(),
                entry_id: embedded_record.carrier.entry_id.clone(),
            },
        );
        carriers.push(CarrierOutput {
            pair_id,
            manifest,
            payload,
        });
    }
    let graph_bytes = embedded_graph.canonical_bytes()?;
    EmbeddedModuleGraphV1::decode_and_admit(&graph_bytes, &carrier_facts, &[])?;

    let contract = ibex_runtime::compiled_contract::diagnostic_development_stub_contract()?;
    let contract_digest = contract.digest()?;
    let provenance = capsec_semantics::canonical::to_jcs_bytes(&serde_json::json!({
        "schema": "ibex/package-provenance/1",
        "stubContractDigest": contract_digest,
        "graphIdentity": graph_identity,
        "producerId": PREPARED_PRODUCER_ID,
        "producerBinaryDigest": producer_digest,
    }))?;
    let policy = canonical_policy(
        &graph_identity,
        &entry_components,
        &entry_source_integrity,
        &contract.target.triple,
    )?;
    let entry = EntryDesignationV1::one(captured.entry.encode()?).canonical_bytes()?;
    let mut sections = vec![
        SectionInputV1::canonical(
            "stub-contract",
            SectionKindV1::StubContract,
            contract.canonical_bytes()?,
        ),
        SectionInputV1::canonical("provenance", SectionKindV1::ProvenanceManifest, provenance),
        SectionInputV1::canonical("graph", SectionKindV1::EmbeddedModuleGraph, graph_bytes),
        SectionInputV1::canonical("policy", SectionKindV1::ResolvedPolicy, policy),
        SectionInputV1::canonical("entry", SectionKindV1::EntryDesignation, entry),
    ];
    for (index, carrier) in carriers.into_iter().enumerate() {
        sections.push(SectionInputV1::carrier(
            format!("carrier-manifest-{index:04}"),
            SectionKindV1::CarrierManifest,
            carrier.pair_id.clone(),
            carrier.manifest.encode_canonical()?,
        ));
        sections.push(SectionInputV1::carrier(
            format!("carrier-payload-{index:04}"),
            SectionKindV1::CarrierPayload,
            carrier.pair_id,
            carrier.payload,
        ));
    }
    let executable = if stub.get(..4) == Some(&0xfeedfacfu32.to_le_bytes()) {
        let envelope = build_executable_v1(&[], &contract_digest, sections)?;
        ibex_sfe_format::macho::inject_envelope_segment_v1(&stub, &envelope)?
    } else {
        build_executable_v1(&stub, &contract_digest, sections)?
    };
    std::fs::write(output_path, executable)
        .with_context(|| format!("cannot write {}", output_path.display()))?;
    copy_executable_permissions(stub_path, output_path)?;
    Ok(())
}

/// Walk every literal dependency edge with the same resolver conditions the
/// runtime authenticates, while retaining only portable identities and labels
/// in the executable. Computed edges remain outside this diagnostic profile.
/// @ref LLP 0029#1-command-surface-and-producer-pipeline
fn capture_graph(entry: &Path, producer_digest: Digest) -> Result<CapturedGraph> {
    let entry = std::fs::canonicalize(entry)
        .with_context(|| format!("cannot canonicalize entry {}", entry.display()))?;
    let project_root = discover_project_root(&entry)?;
    let root_owner = Principal::Root {
        identity: NonEmptyString::new("project-root").map_err(anyhow::Error::msg)?,
    };
    let loader = ModuleLoader::new();
    let entry_specifier = entry
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("phase-0 entry path is not UTF-8"))?;
    let entry_module = loader.resolve_meta_typed(
        entry_specifier,
        None,
        ResolutionKind::Entry,
        &ConditionSet::for_kind(ResolutionKind::Entry),
        &ImportAttributes::default(),
    )?;
    let mut package_integrities = BTreeMap::new();
    let entry_module = prepare_module(
        &loader,
        entry_module,
        &project_root,
        &root_owner,
        &mut package_integrities,
    )?;
    let entry_id = entry_module
        .artifact_source_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("entry resolution produced no SourceId"))?;
    let mut queue = VecDeque::from([entry_module]);
    let mut records = BTreeMap::new();
    while let Some(module) = queue.pop_front() {
        let source_id = module
            .artifact_source_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("module resolution produced no SourceId"))?;
        if records.contains_key(&source_id) {
            continue;
        }
        let source = module
            .source
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("module resolution produced no source bytes"))?;
        let portable_name = portable_source_name(&source_id)?;
        let portable_path = Path::new(&portable_name);
        let artifact = match module.kind {
            ModuleKind::Esm => produce_module_artifact_v1(
                source_id.clone(),
                &portable_name,
                portable_path,
                source,
                producer_digest.clone(),
            ),
            ModuleKind::CommonJs => produce_commonjs_artifact_v1(
                source_id.clone(),
                &portable_name,
                portable_path,
                source,
                producer_digest.clone(),
            ),
            ModuleKind::Json => {
                produce_json_artifact_v1(source_id.clone(), source, producer_digest.clone())
            }
            ModuleKind::Builtin => produce_builtin_artifact_v1(
                source_id.clone(),
                &portable_name,
                source,
                producer_digest.clone(),
            ),
        }
        .with_context(|| format!("cannot prepare module {portable_name:?}"))?;
        if artifact
            .semantics
            .dynamic_edges
            .iter()
            .any(|edge| matches!(edge, DynamicEdgeV1::Computed { .. }))
        {
            bail!("phase-0 executable graph does not admit computed module edges");
        }
        let mut bindings = BTreeMap::new();
        for key in artifact_edge_requests(&artifact) {
            let attributes = artifact_edge_attributes(&artifact, &key)?;
            let target = loader.resolve_meta_typed(
                &key.specifier,
                module.path.as_deref(),
                key.resolution_kind,
                &ConditionSet::for_kind(key.resolution_kind),
                &attributes,
            )?;
            let target = prepare_module(
                &loader,
                target,
                &project_root,
                &root_owner,
                &mut package_integrities,
            )?;
            let target_id = target
                .artifact_source_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("dependency resolution produced no SourceId"))?;
            if let Some(previous) = bindings.insert(key, target_id.clone()) {
                if previous != target_id {
                    bail!("one typed dependency request resolved to two SourceIds");
                }
            }
            queue.push_back(target);
        }
        let encoded = source_id.encode()?;
        records.insert(
            source_id,
            CapturedRecord {
                artifact,
                bindings,
                virtual_source: VirtualSourceLabelV1::new(format!("/app/modules/{encoded}"))?,
            },
        );
    }
    Ok(CapturedGraph {
        entry: entry_id,
        root_owner,
        records,
    })
}

fn prepare_module(
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
        .ok_or_else(|| anyhow::anyhow!("file module resolution produced no path"))?;
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("cannot canonicalize module {}", path.display()))?;
    module.path = Some(path.clone());
    let source_id = if let (Some(name), Some(package_root)) = (
        module.package_name.as_deref(),
        module.package_root.as_deref(),
    ) {
        let package_root = std::fs::canonicalize(package_root).with_context(|| {
            format!(
                "cannot canonicalize package root {}",
                package_root.display()
            )
        })?;
        let version = module
            .package_version
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("package {name:?} has no version identity"))?;
        let integrity = match package_integrities.get(&package_root) {
            Some(integrity) => integrity.clone(),
            None => {
                let integrity = Digest::new(package_tree_integrity(&package_root)?)
                    .map_err(anyhow::Error::msg)?;
                package_integrities.insert(package_root.clone(), integrity.clone());
                integrity
            }
        };
        let relative = path.strip_prefix(&package_root).with_context(|| {
            format!(
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
            portable_components(relative)?,
        )?
    } else {
        let relative = path.strip_prefix(project_root).with_context(|| {
            format!(
                "first-party module {} escapes project root {}",
                path.display(),
                project_root.display()
            )
        })?;
        SourceId::file(root_owner.clone(), portable_components(relative)?)?
    };
    module.artifact_source_id = Some(source_id);
    loader.load_runner_source(module)
}

fn discover_project_root(entry: &Path) -> Result<PathBuf> {
    let entry_parent = entry
        .parent()
        .ok_or_else(|| anyhow::anyhow!("entry has no parent directory"))?;
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

fn portable_components(path: &Path) -> Result<Vec<PathComponent>> {
    let components = path
        .components()
        .map(|component| {
            let value = component
                .as_os_str()
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("phase-0 source path is not UTF-8"))?;
            PathComponent::utf8(value).map_err(anyhow::Error::msg)
        })
        .collect::<Result<Vec<_>>>()?;
    if components.is_empty() {
        bail!("phase-0 source path has no portable components");
    }
    Ok(components)
}

fn portable_source_name(source_id: &SourceId) -> Result<String> {
    match source_id {
        SourceId::File { path, .. } => path
            .last()
            .and_then(|component| std::str::from_utf8(component.bytes()).ok())
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("source filename is not portable UTF-8")),
        SourceId::Builtin { source_key, .. } => Ok(format!("{}.js", source_key.as_str())),
        SourceId::Synthetic { .. } => bail!("synthetic sources are not packable in phase 0"),
    }
}

fn sort_edges(edges: &mut [EmbeddedModuleEdgeV1]) -> Result<()> {
    let mut keyed = edges
        .iter()
        .cloned()
        .map(|edge| {
            let value = serde_json::to_value(&edge)?;
            let key = capsec_semantics::canonical::to_jcs_bytes(&value)?;
            Ok((key, edge))
        })
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    for (target, (_, edge)) in edges.iter_mut().zip(keyed) {
        *target = edge;
    }
    Ok(())
}

#[cfg(unix)]
fn copy_executable_permissions(stub: &Path, output: &Path) -> Result<()> {
    let mode = std::fs::metadata(stub)?.permissions().mode();
    std::fs::set_permissions(output, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn copy_executable_permissions(_stub: &Path, _output: &Path) -> Result<()> {
    Ok(())
}

fn canonical_policy(
    graph_identity: &Digest,
    entry_components: &[PathComponent],
    source_integrity: &Digest,
    target: &str,
) -> Result<Vec<u8>> {
    let identity: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/canonical-policy.canonical.json"
    )))?;
    let mut policy = serde_json::json!({
        "policySchema": "ibex/capsec-policy/2",
        "capsVocab": "ibex/capsec/1",
        "semanticCore": "capsec/semantics/1",
        "vocabDigest": identity["vocabDigest"],
        "registryDigest": identity["registryDigest"],
        "policyDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "purpose": "production",
        "mode": "enforce",
        "graphIdentity": graph_identity,
        "entryIdentity": {
            "root": "project",
            "components": entry_components,
            "sourceIntegrity": source_integrity,
        },
        "targetProfile": {"kind":"compiled","profile":"sfe-dev-v1","targetTriple":target},
        "mountProfile": "compiled-app-work-v1",
        "rootCeiling": [],
        "computedCandidates": {
            "schema": "ibex/computed-candidate-manifest/1",
            "declarations": [],
            "packageClosureOptIns": [],
            "materializedSites": [],
        },
        // @ref LLP 0022#2-startup-project-identity-and-session-arming — rootImports is the
        // authenticated set of direct package imports; this relative-file fixture has none.
        "rootImports": [],
        "principals": [],
    });
    policy["policyDigest"] = serde_json::Value::String(compute_checked_contract_digest(
        DigestKind::Policy,
        &policy,
    )?);
    Ok(capsec_semantics::canonical::to_jcs_bytes(&policy)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_policy_tracks_the_complete_canonical_schema() -> Result<()> {
        let graph_identity = digest_bytes("ibex:test-graph:1", b"graph")?;
        let source_integrity = digest_bytes("ibex:test-source:1", b"source")?;
        let entry_components = [PathComponent::utf8("entry.mjs").map_err(anyhow::Error::msg)?];
        let bytes = canonical_policy(
            &graph_identity,
            &entry_components,
            &source_integrity,
            "aarch64-apple-darwin",
        )?;
        let policy: capsec_semantics::policy::CanonicalPolicy = serde_json::from_slice(&bytes)?;

        assert!(policy.root_imports.is_empty());
        Ok(())
    }
}
