//! Public production-artifact preparation for native embedders.
//!
//! The caller supplies a paired authenticated snapshot template and expected
//! identity. This module binds the pair to the actually loaded engine and the
//! checked CapSec identities, validates protected files/package roots, replaces
//! the template nonce with OS randomness, and returns a new paired artifact.
//! Target advertisement remains enforced by `Host::new_armed` during install;
//! preparing bytes never promotes an unsupported target.
//! @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine

use anyhow::{Context as _, Result};
use base64::Engine as _;
use capsec_semantics::arming::{
    ArmedSnapshot, ExactEmbedderBinding, ExactEmbedderEndowments, ExpectedArmingIdentity,
    ExpectedProtectedArtifact, ProtectedArtifactRole,
};
use capsec_semantics::digest::{
    compute_checked_contract_digest, compute_domain_digest, DigestKind,
};
use capsec_semantics::model::{Digest, LogicalPath, LogicalRoot};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::Path;

const PRODUCTION_RUN_NONCE_BYTES: usize = 16;
const CONTRACT_FIXTURE_RUN_NONCE: &str = "AQIDBAUGBwgJCgsMDQ4PEA";

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedEmbedderArtifacts {
    pub artifact_schema: &'static str,
    pub armed_snapshot_digest: String,
    pub snapshot: serde_json::Value,
    pub expected_identity: ExpectedArmingIdentity,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExactOperationManifest {
    #[serde(rename = "$schema")]
    schema_path: Option<String>,
    schema: String,
    schema_version: u32,
    operations: Vec<ExactOperation>,
    endowments: ExactOperationEndowments,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactOperation {
    id: u32,
    name: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExactOperationEndowments {
    app: Vec<u32>,
    agent_isolate: Vec<u32>,
    ui_worklet: Vec<u32>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestrictedContractBundleBinding {
    binding_schema: String,
    format: String,
    root_set_digest: Digest,
    contract_ir_digest: Digest,
    module_graph_digest: Digest,
    build_identity_digest: Digest,
    #[serde(default)]
    engine_bytecode_version: Option<u32>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestrictedEngineBinding {
    binary_digest: Digest,
    bytecode_version: u32,
    object: capsec_semantics::model::ObjectIdentity,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestrictedProtectedArtifact {
    host_path: LogicalPath,
    object: capsec_semantics::model::ObjectIdentity,
    content_digest: Digest,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestrictedBundleArtifact {
    host_path: LogicalPath,
    object: capsec_semantics::model::ObjectIdentity,
    content_digest: Digest,
    format: String,
    byte_length: usize,
    root_set_digest: Digest,
    contract_ir_digest: Digest,
    module_graph_digest: Digest,
    build_identity_digest: Digest,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestrictedExactArtifact {
    artifact_schema: String,
    profile: String,
    full_profile: String,
    status: String,
    semantic_core: String,
    vocab_digest: Digest,
    registry_digest: Digest,
    source_edge_set_digest: Digest,
    restricted_surface_closure_digest: Digest,
    profile_definition_raw_content_digest: Digest,
    projection_raw_content_digest: Digest,
    advertisements_raw_content_digest: Digest,
    target: String,
    features: Vec<String>,
    engine: RestrictedEngineBinding,
    operation_manifest: RestrictedProtectedArtifact,
    bundle: RestrictedBundleArtifact,
    package_graph_digest: Digest,
    run_nonce: String,
    artifact_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedRestrictedExactArtifact {
    artifact_digest: Digest,
    target: String,
    features: Vec<String>,
    operation_binding: ExactEmbedderBinding,
    bundle: Vec<u8>,
    bundle_format: String,
}

impl AuthenticatedRestrictedExactArtifact {
    pub fn digest(&self) -> &Digest {
        &self.artifact_digest
    }

    pub fn operation_binding(&self) -> &ExactEmbedderBinding {
        &self.operation_binding
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn features(&self) -> &[String] {
        &self.features
    }

    pub fn bundle(&self) -> &[u8] {
        &self.bundle
    }

    pub fn bundle_format(&self) -> &str {
        &self.bundle_format
    }
}

struct MaterializedArtifact {
    host_path: LogicalPath,
    object: capsec_semantics::model::ObjectIdentity,
    content_digest: Digest,
}

fn valid_operation_name(name: &str) -> bool {
    let mut segments = name.split('.');
    let valid_segment = |segment: &str| {
        let mut characters = segment.chars();
        characters
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic())
            && characters.all(|character| character.is_ascii_alphanumeric())
    };
    let Some(first) = segments.next() else {
        return false;
    };
    valid_segment(first) && segments.clone().next().is_some() && segments.all(valid_segment)
}

fn parse_exact_operation_manifest(bytes: &[u8]) -> Result<ExactEmbedderBinding> {
    let text = std::str::from_utf8(bytes).context("Exact operation manifest is not UTF-8")?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .context("Exact operation manifest is not strict JSON")?;
    let manifest: ExactOperationManifest =
        serde_json::from_value(value).context("invalid Exact operation manifest")?;
    anyhow::ensure!(
        manifest.schema == "exact.host-call-operations/v1" && manifest.schema_version == 1,
        "Exact operation manifest has an unsupported schema"
    );
    anyhow::ensure!(
        manifest
            .schema_path
            .as_deref()
            .is_none_or(|path| path == "./host-call-operations.schema.json"),
        "Exact operation manifest has an unexpected schema path"
    );
    anyhow::ensure!(
        !manifest.operations.is_empty(),
        "Exact operation manifest operations must not be empty"
    );

    let mut previous_id = 0_u32;
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut names_by_id = BTreeMap::new();
    for operation in &manifest.operations {
        anyhow::ensure!(
            operation.id > previous_id,
            "Exact operation IDs must be strictly increasing"
        );
        anyhow::ensure!(
            valid_operation_name(&operation.name),
            "Exact operation name is invalid: {}",
            operation.name
        );
        anyhow::ensure!(
            ids.insert(operation.id),
            "Exact operation ID is duplicated: {}",
            operation.id
        );
        anyhow::ensure!(
            names.insert(operation.name.clone()),
            "Exact operation name is duplicated: {}",
            operation.name
        );
        names_by_id.insert(operation.id, operation.name.as_str());
        previous_id = operation.id;
    }

    let mut endowed = BTreeSet::new();
    for (context, context_ids) in [
        ("app", &manifest.endowments.app),
        ("agentIsolate", &manifest.endowments.agent_isolate),
        ("uiWorklet", &manifest.endowments.ui_worklet),
    ] {
        anyhow::ensure!(
            context_ids.len() <= 4096,
            "Exact {context} endowment exceeds the 4096-operation limit"
        );
        let mut previous = 0_u32;
        for id in context_ids {
            anyhow::ensure!(
                ids.contains(id),
                "Exact {context} endowment references unknown operation ID {id}"
            );
            anyhow::ensure!(
                *id > previous,
                "Exact {context} endowment IDs must be strictly increasing"
            );
            anyhow::ensure!(
                endowed.insert(*id),
                "Exact operation ID {id} is endowed to multiple runtime contexts"
            );
            previous = *id;
        }
    }
    anyhow::ensure!(
        !manifest.endowments.app.is_empty(),
        "Exact app endowment must not be empty"
    );
    anyhow::ensure!(
        manifest.endowments.ui_worklet.is_empty(),
        "Exact UI worklet endowment must remain empty"
    );
    anyhow::ensure!(
        endowed == ids,
        "every Exact operation must have exactly one runtime endowment"
    );
    let agent_names = manifest
        .endowments
        .agent_isolate
        .iter()
        .filter_map(|id| names_by_id.get(id).copied())
        .collect::<BTreeSet<_>>();
    let expected_agent_names = [
        "agentIsolate.appRuntimeHealth",
        "agentIsolate.bindFailed",
        "agentIsolate.config",
        "agentIsolate.ready",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        agent_names == expected_agent_names,
        "Exact agent isolate must receive exactly its four control-plane operations"
    );

    let manifest_digest = Digest::new(format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
    .map_err(anyhow::Error::msg)?;
    Ok(ExactEmbedderBinding {
        schema: "exact/host-operation-endowments/1".into(),
        operation_manifest_digest: manifest_digest,
        endowments: ExactEmbedderEndowments {
            app: manifest.endowments.app,
            agent_isolate: manifest.endowments.agent_isolate,
            ui_worklet: manifest.endowments.ui_worklet,
        },
    })
}

fn absolute_artifact_path(path: &Path) -> Result<LogicalPath> {
    Ok(LogicalPath {
        root: LogicalRoot::Absolute,
        components: super::host_path_components(path)?,
        host_bound: Some(true),
    })
}

fn materialize_protected_artifact(
    role: &str,
    bytes: &[u8],
    digest: &Digest,
) -> Result<MaterializedArtifact> {
    let cache_root = crate::runtime_cache_dir()?;
    let directory = cache_root.join("capsec-artifacts");
    std::fs::create_dir_all(&directory)?;
    let directory_metadata = std::fs::symlink_metadata(&directory)?;
    anyhow::ensure!(
        directory_metadata.is_dir() && !directory_metadata.file_type().is_symlink(),
        "protected artifact parent is not a stable directory"
    );
    let directory = std::fs::canonicalize(directory)?;
    let filename = format!(
        "{}.{}.json",
        digest.as_str().trim_start_matches("sha256-"),
        role,
    );
    let path = directory.join(filename);

    let open_existing = || -> Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        options
            .open(&path)
            .with_context(|| format!("failed to pin protected artifact {}", path.display()))
    };
    let validate = |file: &mut std::fs::File| -> Result<()> {
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file(),
            "protected artifact is not a regular file"
        );
        #[cfg(unix)]
        anyhow::ensure!(
            {
                use std::os::unix::fs::PermissionsExt as _;
                metadata.permissions().mode() & 0o222 == 0
            },
            "protected artifact is mutable"
        );
        #[cfg(not(unix))]
        anyhow::ensure!(
            metadata.permissions().readonly(),
            "protected artifact is mutable"
        );
        file.rewind()?;
        let mut observed = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut observed)?;
        anyhow::ensure!(observed == bytes, "protected artifact content mismatch");
        Ok(())
    };

    if path.exists() {
        let mut existing = open_existing()?;
        validate(&mut existing)?;
    } else {
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce).context("failed to name protected staging artifact")?;
        let temporary = directory.join(format!(
            ".{role}.{}.tmp",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
        ));
        let mut staged = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let publish = (|| -> Result<()> {
            staged.write_all(bytes)?;
            staged.sync_all()?;
            let mut permissions = staged.metadata()?.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                permissions.set_mode(0o400);
            }
            #[cfg(not(unix))]
            permissions.set_readonly(true);
            staged.set_permissions(permissions)?;
            staged.sync_all()?;
            validate(&mut staged)?;
            match std::fs::hard_link(&temporary, &path) {
                Ok(()) => std::fs::File::open(&directory)?.sync_all()?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let mut existing = open_existing()?;
                    validate(&mut existing)?;
                }
                Err(error) => return Err(error.into()),
            }
            Ok(())
        })();
        let _ = std::fs::remove_file(&temporary);
        publish?;
    }

    let path = std::fs::canonicalize(path)?;
    let object = super::object_identity_for_host_path(&path)?;
    let content_digest = Digest::new(format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
    .map_err(anyhow::Error::msg)?;
    Ok(MaterializedArtifact {
        host_path: absolute_artifact_path(&path)?,
        object,
        content_digest,
    })
}

fn runtime_target_triple() -> String {
    let architecture = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        "x86" => "i686",
        other => other,
    };
    let suffix = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "ios" => "apple-ios",
        "linux" => "unknown-linux-gnu",
        "android" => "linux-android",
        "windows" => "pc-windows-msvc",
        other => other,
    };
    format!("{architecture}-{suffix}")
}

fn checked_identity_digests() -> Result<(Digest, Digest)> {
    let checked: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/armed-snapshot.canonical.json"
    )))?;
    let digest_at = |field: &str| -> Result<Digest> {
        Digest::new(
            checked[field]
                .as_str()
                .with_context(|| format!("checked CapSec identity lacks {field}"))?,
        )
        .map_err(anyhow::Error::msg)
    };
    Ok((digest_at("vocabDigest")?, digest_at("registryDigest")?))
}

pub fn verify_expected_identity(
    supplied: ExpectedArmingIdentity,
) -> Result<ExpectedArmingIdentity> {
    let (vocab_digest, registry_digest) = checked_identity_digests()?;
    let engine = crate::engine::loaded_engine_binary_identity().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        supplied.profile == crate::capsec_registry_generated::CAPSEC_PROFILE,
        "expected identity profile does not match the checked Ibex profile"
    );
    anyhow::ensure!(
        supplied.semantic_core == crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE,
        "expected identity semantic core does not match the checked Ibex core"
    );
    anyhow::ensure!(
        supplied.vocab_digest == vocab_digest,
        "expected identity vocabulary digest does not match the checked vocabulary"
    );
    anyhow::ensure!(
        supplied.registry_digest == registry_digest,
        "expected identity registry digest does not match the checked registry"
    );
    anyhow::ensure!(
        supplied.target == runtime_target_triple(),
        "expected identity target does not match the running embedder"
    );
    anyhow::ensure!(
        supplied.features == engine.structural_features,
        "expected identity feature set does not match the loaded engine"
    );
    anyhow::ensure!(
        supplied.engine_binary_digest
            == Digest::new(engine.binary_digest).map_err(anyhow::Error::msg)?,
        "expected identity engine digest does not match the loaded engine"
    );
    Ok(supplied)
}

fn fresh_production_nonce() -> Result<String> {
    let mut bytes = [0_u8; PRODUCTION_RUN_NONCE_BYTES];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| anyhow::anyhow!("OS randomness unavailable for run nonce: {error}"))?;
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    anyhow::ensure!(
        nonce != CONTRACT_FIXTURE_RUN_NONCE,
        "OS randomness produced the reserved contract-fixture run nonce"
    );
    Ok(nonce)
}

fn freshen_document(document: &mut serde_json::Value, nonce: String) -> Result<Digest> {
    document["runNonce"] = serde_json::Value::String(nonce);
    let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, document)?;
    document["armedSnapshotDigest"] = serde_json::Value::String(digest.clone());
    Digest::new(digest).map_err(anyhow::Error::msg)
}

fn raw_content_digest(bytes: &[u8]) -> Result<Digest> {
    Digest::new(format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
    .map_err(anyhow::Error::msg)
}

fn validate_restricted_bundle_format(
    format: &str,
    engine_bytecode_version: Option<u32>,
    loaded_bytecode_version: u32,
    bytes: &[u8],
) -> Result<()> {
    match format {
        "source-utf8" => {
            anyhow::ensure!(
                engine_bytecode_version.is_none(),
                "source bundle must not claim a Hermes bytecode version"
            );
            let source =
                std::str::from_utf8(bytes).context("restricted source bundle is not UTF-8")?;
            anyhow::ensure!(
                !source.as_bytes().contains(&0),
                "restricted source bundle contains NUL"
            );
        }
        "hbc-v1" => anyhow::ensure!(
            engine_bytecode_version == Some(loaded_bytecode_version),
            "restricted HBC bundle version does not match the loaded Hermes engine"
        ),
        _ => anyhow::bail!("restricted Contract bundle format is unsupported"),
    }
    Ok(())
}

fn read_restricted_protected_artifact(
    artifact: &RestrictedProtectedArtifact,
    expected_len: Option<usize>,
    label: &str,
) -> Result<Vec<u8>> {
    use std::io::Read as _;

    let path = super::host_path_from_logical_path(&artifact.host_path, label)
        .map_err(anyhow::Error::msg)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(0x0020_0000);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("cannot pin {label} {}", path.display()))?;
    let before = file.metadata()?;
    anyhow::ensure!(before.is_file(), "{label} is not a regular file");
    anyhow::ensure!(
        super::object_identity_for_open_file(&file).map_err(anyhow::Error::msg)? == artifact.object,
        "{label} object identity changed"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        anyhow::ensure!(
            before.permissions().mode() & 0o222 == 0,
            "{label} remains writable"
        );
    }
    #[cfg(not(unix))]
    anyhow::ensure!(before.permissions().readonly(), "{label} remains writable");
    if let Some(expected) = expected_len {
        anyhow::ensure!(before.len() == expected as u64, "{label} length changed");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.read_to_end(&mut bytes)?;
    anyhow::ensure!(
        raw_content_digest(&bytes)? == artifact.content_digest,
        "{label} content digest changed"
    );
    let after = file.metadata()?;
    anyhow::ensure!(
        after.len() == before.len()
            && super::object_identity_for_open_file(&file).map_err(anyhow::Error::msg)?
                == artifact.object,
        "{label} changed while it was authenticated"
    );
    Ok(bytes)
}

/// Authenticate a serialized restricted Exact candidate artifact without
/// installing it. Production installation remains separately gated by the
/// report-derived target advertisement family.
pub fn authenticate_restricted_exact_embedder_artifact(
    artifact_bytes: &[u8],
) -> Result<AuthenticatedRestrictedExactArtifact> {
    super::reject_closed_startup_environment()?;
    let text =
        std::str::from_utf8(artifact_bytes).context("restricted Exact artifact is not UTF-8")?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .context("restricted Exact artifact is not strict JSON")?;
    let artifact: RestrictedExactArtifact =
        serde_json::from_value(value.clone()).context("invalid restricted Exact artifact")?;
    anyhow::ensure!(
        artifact.artifact_schema == "ibex/restricted-exact-artifact/1"
            && artifact.profile == "ibex/exact-embedder-contract/1"
            && artifact.full_profile == crate::capsec_registry_generated::CAPSEC_PROFILE
            && artifact.status == "candidate-unadvertised"
            && artifact.semantic_core == crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE,
        "restricted Exact artifact profile identity mismatch"
    );
    let computed_digest = compute_domain_digest(
        "ibex:restricted-exact-artifact:1",
        &value,
        &["artifactDigest".to_owned()],
    )?;
    anyhow::ensure!(
        computed_digest == artifact.artifact_digest.as_str(),
        "restricted Exact artifact digest is stale or tampered"
    );

    let definition_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/registry/restricted-exact-profile-definition.json"
    ));
    let projection_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/generated/restricted-exact-profile-projection.json"
    ));
    let advertisements_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/generated/restricted-exact-target-advertisements.json"
    ));
    let definition: serde_json::Value = serde_json::from_slice(definition_bytes)?;
    let advertisements: serde_json::Value = serde_json::from_slice(advertisements_bytes)?;
    let (vocab_digest, registry_digest) = checked_identity_digests()?;
    anyhow::ensure!(
        artifact.profile_definition_raw_content_digest == raw_content_digest(definition_bytes)?
            && artifact.projection_raw_content_digest == raw_content_digest(projection_bytes)?
            && artifact.advertisements_raw_content_digest
                == raw_content_digest(advertisements_bytes)?
            && artifact.restricted_surface_closure_digest == raw_content_digest(projection_bytes)?
            && artifact.vocab_digest == vocab_digest
            && artifact.registry_digest == registry_digest
            && artifact.source_edge_set_digest.as_str()
                == definition["sourceEdgeSet"]["digest"]
                    .as_str()
                    .unwrap_or_default(),
        "restricted Exact artifact authority digest mismatch"
    );
    anyhow::ensure!(
        advertisements["advertisements"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "candidate artifact authentication cannot consume an advertised profile"
    );

    let engine = crate::engine::loaded_engine_binary_identity().map_err(anyhow::Error::msg)?;
    let bytecode_version =
        crate::engine::loaded_engine_bytecode_version().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        artifact.target == runtime_target_triple()
            && artifact.features == engine.structural_features
            && artifact.engine.binary_digest.as_str() == engine.binary_digest
            && artifact.engine.object == engine.object
            && artifact.engine.bytecode_version == bytecode_version,
        "restricted Exact artifact does not identify the loaded engine"
    );
    let empty_graph = serde_json::json!({"nodes": [], "importEdges": []});
    anyhow::ensure!(
        artifact.package_graph_digest.as_str()
            == compute_domain_digest("ibex:capsec:package-graph:1", &empty_graph, &[])?,
        "restricted Exact artifact package graph is not the canonical empty graph"
    );
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&artifact.run_nonce)
        .context("restricted Exact artifact run nonce is invalid")?;
    anyhow::ensure!(
        nonce.len() == PRODUCTION_RUN_NONCE_BYTES
            && artifact.run_nonce != CONTRACT_FIXTURE_RUN_NONCE,
        "restricted Exact artifact run nonce is not construction-fresh"
    );

    let operation_bytes = read_restricted_protected_artifact(
        &artifact.operation_manifest,
        None,
        "restricted Exact operation manifest",
    )?;
    let operation_binding = parse_exact_operation_manifest(&operation_bytes)?;
    anyhow::ensure!(
        operation_binding.operation_manifest_digest == artifact.operation_manifest.content_digest,
        "restricted Exact operation manifest binding mismatch"
    );
    let bundle_protected = RestrictedProtectedArtifact {
        host_path: artifact.bundle.host_path.clone(),
        object: artifact.bundle.object.clone(),
        content_digest: artifact.bundle.content_digest.clone(),
    };
    let bundle = read_restricted_protected_artifact(
        &bundle_protected,
        Some(artifact.bundle.byte_length),
        "restricted Contract bundle",
    )?;
    validate_restricted_bundle_format(
        &artifact.bundle.format,
        (artifact.bundle.format == "hbc-v1").then_some(artifact.engine.bytecode_version),
        bytecode_version,
        &bundle,
    )?;
    // These fields are deliberately read through the strict typed artifact;
    // their exact values are authenticated by artifactDigest and consumed by
    // the Exact activation handshake rather than by Ibex policy selection.
    let _activation_identity = (
        artifact.bundle.root_set_digest,
        artifact.bundle.contract_ir_digest,
        artifact.bundle.module_graph_digest,
        artifact.bundle.build_identity_digest,
    );

    Ok(AuthenticatedRestrictedExactArtifact {
        artifact_digest: artifact.artifact_digest,
        target: artifact.target,
        features: artifact.features,
        operation_binding,
        bundle,
        bundle_format: artifact.bundle.format,
    })
}

/// Construct one immutable, target-local candidate artifact for the restricted
/// Exact profile. This operation deliberately does not install a Host or claim
/// target support: the generated advertisement family remains the sole
/// promotion authority and is empty until conformance completes.
///
/// @ref LLP 0026#4-profile-identity-and-anti-confusion-rules — bind the exact
/// profile, engine, registries, operation manifest, Contract bundle, and nonce.
/// @ref LLP 0026#6-authenticated-contract-code-ingress — admit one graph-closed
/// bundle and no path, URL, cwd, or ambient module-loader fallback.
pub fn build_restricted_exact_embedder_artifact(
    operation_manifest_bytes: &[u8],
    bundle_bytes: &[u8],
    bundle_binding_bytes: &[u8],
) -> Result<serde_json::Value> {
    super::reject_closed_startup_environment()?;
    anyhow::ensure!(
        !bundle_bytes.is_empty(),
        "restricted Contract bundle is empty"
    );
    let operation_binding = parse_exact_operation_manifest(operation_manifest_bytes)?;
    let binding_text = std::str::from_utf8(bundle_binding_bytes)
        .context("restricted Contract bundle binding is not UTF-8")?;
    let binding_value = capsec_semantics::strict_json::parse_strict(binding_text)
        .context("restricted Contract bundle binding is not strict JSON")?;
    let binding: RestrictedContractBundleBinding = serde_json::from_value(binding_value)
        .context("invalid restricted Contract bundle binding")?;
    anyhow::ensure!(
        binding.binding_schema == "exact/restricted-contract-bundle-binding/1",
        "restricted Contract bundle binding has an unsupported schema"
    );

    let bytecode_version =
        crate::engine::loaded_engine_bytecode_version().map_err(anyhow::Error::msg)?;
    validate_restricted_bundle_format(
        &binding.format,
        binding.engine_bytecode_version,
        bytecode_version,
        bundle_bytes,
    )?;

    let definition_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/registry/restricted-exact-profile-definition.json"
    ));
    let projection_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/generated/restricted-exact-profile-projection.json"
    ));
    let advertisements_bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/generated/restricted-exact-target-advertisements.json"
    ));
    let definition: serde_json::Value = serde_json::from_slice(definition_bytes)?;
    let projection: serde_json::Value = serde_json::from_slice(projection_bytes)?;
    let advertisements: serde_json::Value = serde_json::from_slice(advertisements_bytes)?;
    anyhow::ensure!(
        definition["profile"] == "ibex/exact-embedder-contract/1"
            && projection["profile"] == definition["profile"]
            && advertisements["profile"] == definition["profile"],
        "restricted profile authority identity mismatch"
    );
    anyhow::ensure!(
        advertisements["advertisements"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "candidate artifact builder must be reviewed before consuming a promoted advertisement"
    );

    let engine = crate::engine::loaded_engine_binary_identity().map_err(anyhow::Error::msg)?;
    let target = runtime_target_triple();
    anyhow::ensure!(
        definition["candidateTargets"]
            .as_array()
            .is_some_and(|targets| targets.iter().any(|row| {
                row["triple"] == target
                    && row["features"] == serde_json::json!(engine.structural_features)
            })),
        "loaded engine target/features are not a restricted profile candidate"
    );
    let (vocab_digest, registry_digest) = checked_identity_digests()?;
    let source_edge_set_digest = Digest::new(
        definition["sourceEdgeSet"]["digest"]
            .as_str()
            .context("restricted profile definition lacks its source-edge-set digest")?,
    )
    .map_err(anyhow::Error::msg)?;
    let restricted_surface_closure_digest = raw_content_digest(projection_bytes)?;

    let manifest_artifact = materialize_protected_artifact(
        "restricted-exact-operation-manifest",
        operation_manifest_bytes,
        &operation_binding.operation_manifest_digest,
    )?;
    let bundle_digest = raw_content_digest(bundle_bytes)?;
    let bundle_artifact =
        materialize_protected_artifact("restricted-contract-bundle", bundle_bytes, &bundle_digest)?;
    let empty_graph = serde_json::json!({"nodes": [], "importEdges": []});
    let package_graph_digest = Digest::new(compute_domain_digest(
        "ibex:capsec:package-graph:1",
        &empty_graph,
        &[],
    )?)
    .map_err(anyhow::Error::msg)?;

    let mut artifact = serde_json::json!({
        "artifactSchema": "ibex/restricted-exact-artifact/1",
        "profile": "ibex/exact-embedder-contract/1",
        "fullProfile": crate::capsec_registry_generated::CAPSEC_PROFILE,
        "status": "candidate-unadvertised",
        "semanticCore": crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE,
        "vocabDigest": vocab_digest,
        "registryDigest": registry_digest,
        "sourceEdgeSetDigest": source_edge_set_digest,
        "restrictedSurfaceClosureDigest": restricted_surface_closure_digest,
        "profileDefinitionRawContentDigest": raw_content_digest(definition_bytes)?,
        "projectionRawContentDigest": raw_content_digest(projection_bytes)?,
        "advertisementsRawContentDigest": raw_content_digest(advertisements_bytes)?,
        "target": target,
        "features": engine.structural_features,
        "engine": {
            "binaryDigest": engine.binary_digest,
            "bytecodeVersion": bytecode_version,
            "object": engine.object,
        },
        "operationManifest": {
            "hostPath": manifest_artifact.host_path,
            "object": manifest_artifact.object,
            "contentDigest": manifest_artifact.content_digest,
        },
        "bundle": {
            "hostPath": bundle_artifact.host_path,
            "object": bundle_artifact.object,
            "contentDigest": bundle_artifact.content_digest,
            "format": binding.format,
            "byteLength": bundle_bytes.len(),
            "rootSetDigest": binding.root_set_digest,
            "contractIrDigest": binding.contract_ir_digest,
            "moduleGraphDigest": binding.module_graph_digest,
            "buildIdentityDigest": binding.build_identity_digest,
        },
        "packageGraphDigest": package_graph_digest,
        "runNonce": fresh_production_nonce()?,
        "artifactDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    let digest = compute_domain_digest(
        "ibex:restricted-exact-artifact:1",
        &artifact,
        &["artifactDigest".to_owned()],
    )?;
    artifact["artifactDigest"] = serde_json::json!(digest);
    Ok(artifact)
}

/// Authenticate, bind, and freshen one embedder artifact pair.
///
/// This validates everything that can be established before installation,
/// including the exact mapped engine object, checked semantic identities,
/// protected artifact bytes, package graph/root bindings, and a construction-
/// fresh nonce. `Host::new_armed` subsequently authenticates the report-derived
/// target advertisement; unsupported targets still refuse there.
pub fn prepare_embedder_artifacts(
    template_bytes: &[u8],
    expected_identity_bytes: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    super::reject_closed_startup_environment()?;
    let expected_text = std::str::from_utf8(expected_identity_bytes)
        .context("expected arming identity is not UTF-8")?;
    let expected_value = capsec_semantics::strict_json::parse_strict(expected_text)
        .context("expected arming identity is not strict JSON")?;
    let supplied: ExpectedArmingIdentity =
        serde_json::from_value(expected_value).context("invalid expected arming identity")?;
    let mut expected = verify_expected_identity(supplied)?;

    // Authenticate the caller's pair before mutating the nonce or digest. A
    // wrong target/engine/registry/graph/identity cannot be rewritten into a
    // valid artifact by this API.
    let template = ArmedSnapshot::load(template_bytes, &expected)
        .context("snapshot template authentication refused")?;
    super::validate_loaded_engine_identity(&template)?;
    super::validate_snapshot_protected_artifacts(&template)?;
    super::validate_snapshot_root_bindings(&template)?;

    let mut document = template.document().clone();
    let digest = freshen_document(&mut document, fresh_production_nonce()?)?;
    expected.armed_snapshot_digest = digest.clone();

    // Re-ingest the freshly serialized pair before returning it. This catches
    // any mismatch between the digest projection and the public output shape.
    let fresh_bytes = serde_json::to_vec(&document)?;
    let fresh = ArmedSnapshot::load(&fresh_bytes, &expected)
        .context("freshened snapshot authentication refused")?;
    super::validate_loaded_engine_identity(&fresh)?;
    super::validate_snapshot_protected_artifacts(&fresh)?;
    super::validate_snapshot_root_bindings(&fresh)?;

    Ok(PreparedEmbedderArtifacts {
        artifact_schema: "ibex/armed-embedder-artifacts/1",
        armed_snapshot_digest: digest.as_str().to_owned(),
        snapshot: document,
        expected_identity: expected,
    })
}

/// Build a complete Exact-bound artifact pair against the engine and project
/// roots installed on this target.
///
/// Exact's packaged application code is a single authenticated root bundle, so
/// this first public producer authors the canonical empty package policy and
/// graph rather than accepting a second, embedder-defined package inventory.
/// Package-bearing applications must use Ibex's canonical policy generator and
/// are refused by this API until that generated policy is an explicit input.
/// The resulting pair is still subject to report-derived target advertisement
/// during `ex_host_install_armed`.
/// @ref LLP 0021#default-and-target-claim — artifact production cannot promote
/// an unsupported target or create a weaker Exact claim plane.
pub fn build_exact_embedder_artifacts(
    project_root: &Path,
    operation_manifest_bytes: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    super::reject_closed_startup_environment()?;
    let project_root = std::fs::canonicalize(project_root).with_context(|| {
        format!(
            "failed to authenticate Exact project root {}",
            project_root.display()
        )
    })?;
    anyhow::ensure!(
        project_root.is_dir(),
        "Exact project root is not a directory"
    );

    let (vocab_digest, registry_digest) = checked_identity_digests()?;
    let expected_policy_identity = capsec_semantics::policy::ExpectedPolicyIdentity {
        profile: crate::capsec_registry_generated::CAPSEC_PROFILE.into(),
        semantic_core: crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE.into(),
        vocab_digest: vocab_digest.clone(),
        registry_digest: registry_digest.clone(),
    };
    let policy_profile = capsec_semantics::registry::ValidatedProfile::from_json(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/capability-definitions.json"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/policy-rules.json"
        )),
    )?;
    let mut policy = serde_json::json!({
        "policySchema": "ibex/capsec-policy/1",
        "capsVocab": crate::capsec_registry_generated::CAPSEC_PROFILE,
        "semanticCore": crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE,
        "vocabDigest": vocab_digest,
        "registryDigest": registry_digest,
        "policyDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "purpose": "production",
        "mode": "enforce",
        "principals": [],
    });
    let policy_digest = compute_checked_contract_digest(DigestKind::Policy, &policy)?;
    policy["policyDigest"] = serde_json::json!(policy_digest);
    let canonical_policy = capsec_semantics::policy::CanonicalPolicy::load(
        &serde_json::to_vec(&policy)?,
        &expected_policy_identity,
        &policy_profile.definitions,
    )
    .context("default Exact production policy failed typed validation")?;
    anyhow::ensure!(
        canonical_policy.principals.is_empty(),
        "target-local Exact builder accepts only the canonical empty package policy"
    );
    policy = serde_json::to_value(&canonical_policy)?;

    let engine = crate::engine::loaded_engine_binary_identity().map_err(anyhow::Error::msg)?;
    let binding = parse_exact_operation_manifest(operation_manifest_bytes)?;
    let mut root_builtins = crate::module_loader::RUNTIME_GATED_NODE_BUILTINS
        .iter()
        .map(|name| format!("node:{name}"))
        .collect::<Vec<_>>();
    root_builtins.sort();

    let mut document: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/armed-snapshot.canonical.json"
    )))?;
    document["workflow"] = serde_json::json!("production");
    document["effectiveMode"] = serde_json::json!("enforce");
    document["policyDigest"] = serde_json::to_value(&canonical_policy.policy_digest)?;
    document["engine"] = serde_json::json!({
        "target": runtime_target_triple(),
        "binaryDigest": engine.binary_digest,
        "features": engine.structural_features,
    });
    document["principals"] = serde_json::json!([{
        "principal": {"kind": "root", "identity": "project-root"},
        "floor": [],
        "denials": [],
        "escalationCeiling": [],
        "imports": {"builtins": root_builtins, "packages": []},
        "endowments": [],
    }]);
    document["packageGraph"] = serde_json::json!({
        "digest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "nodes": [],
        "importEdges": [],
    });
    let graph_digest = compute_domain_digest(
        "ibex:capsec:package-graph:1",
        &document["packageGraph"],
        &["digest".to_owned()],
    )?;
    document["packageGraph"]["digest"] = serde_json::json!(graph_digest);
    let mut epoch = [0_u8; 8];
    getrandom::getrandom(&mut epoch).context("failed to generate CapSec channel epoch")?;
    document["channelEpoch"] = serde_json::json!(u64::from_le_bytes(epoch).max(1).to_string());

    let cache_root = crate::runtime_cache_dir()?;
    std::fs::create_dir_all(&cache_root)?;
    let cache_root = std::fs::canonicalize(cache_root)?;
    document["rootBindings"] = serde_json::json!([
        {
            "logicalRoot": "project",
            "hostPath": absolute_artifact_path(&project_root)?,
            "object": super::object_identity_for_host_path(&project_root)?,
        },
        {
            "logicalRoot": "home",
            "hostPath": absolute_artifact_path(&cache_root)?,
            "object": super::object_identity_for_host_path(&cache_root)?,
        },
    ]);
    document["exactEmbedder"] = serde_json::to_value(&binding)?;

    let policy_bytes = capsec_semantics::canonical::to_jcs_bytes(&policy)?;
    let graph_bytes = capsec_semantics::canonical::to_jcs_bytes(&document["packageGraph"])?;
    let registry_record = serde_json::json!({
        "registryDigest": document["registryDigest"],
        "capabilityDefinitions": serde_json::from_str::<serde_json::Value>(
            crate::capsec_registry_generated::CAPSEC_CAPABILITY_DEFINITIONS_JSON,
        )?,
        "coverageEdges": serde_json::from_str::<serde_json::Value>(
            crate::capsec_registry_generated::CAPSEC_COVERAGE_EDGES_JSON,
        )?,
        "targetCells": serde_json::from_str::<serde_json::Value>(
            crate::capsec_registry_generated::CAPSEC_TARGET_CELLS_JSON,
        )?,
        "policyRules": serde_json::from_str::<serde_json::Value>(
            crate::capsec_registry_generated::CAPSEC_POLICY_RULES_JSON,
        )?,
    });
    let registry_bytes = capsec_semantics::canonical::to_jcs_bytes(&registry_record)?;
    let policy_artifact = materialize_protected_artifact(
        "armed-policy",
        &policy_bytes,
        &canonical_policy.policy_digest,
    )?;
    let graph_artifact = materialize_protected_artifact(
        "package-graph",
        &graph_bytes,
        &Digest::new(&graph_digest).map_err(anyhow::Error::msg)?,
    )?;
    let registry_artifact =
        materialize_protected_artifact("registry", &registry_bytes, &registry_digest)?;
    let manifest_artifact = materialize_protected_artifact(
        "exact-operation-manifest",
        operation_manifest_bytes,
        &binding.operation_manifest_digest,
    )?;
    document["protectedObjects"] = serde_json::json!([
        {"role": "armed-policy", "object": policy_artifact.object, "deniedActions": ["fs:write"]},
        {"role": "engine-binary", "object": engine.object, "deniedActions": ["fs:write"]},
        {"role": "package-graph", "object": graph_artifact.object, "deniedActions": ["fs:write"]},
        {"role": "registry", "object": registry_artifact.object, "deniedActions": ["fs:write"]},
        {"role": "exact-operation-manifest", "object": manifest_artifact.object, "deniedActions": ["fs:write"]},
    ]);
    let armed_digest = freshen_document(&mut document, fresh_production_nonce()?)?;

    let expected = ExpectedArmingIdentity {
        profile: crate::capsec_registry_generated::CAPSEC_PROFILE.into(),
        semantic_core: crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE.into(),
        vocab_digest,
        registry_digest,
        policy_digest: canonical_policy.policy_digest,
        armed_snapshot_digest: armed_digest.clone(),
        target: runtime_target_triple(),
        engine_binary_digest: Digest::new(&engine.binary_digest).map_err(anyhow::Error::msg)?,
        features: engine.structural_features,
        package_graph_digest: Digest::new(graph_digest).map_err(anyhow::Error::msg)?,
        protected_artifacts: vec![
            ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::ArmedPolicy,
                host_path: policy_artifact.host_path,
                object: policy_artifact.object,
                content_digest: policy_artifact.content_digest,
            },
            ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::EngineBinary,
                host_path: absolute_artifact_path(&engine.engine_artifact_path)?,
                object: engine.object,
                content_digest: Digest::new(&engine.binary_digest).map_err(anyhow::Error::msg)?,
            },
            ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::PackageGraph,
                host_path: graph_artifact.host_path,
                object: graph_artifact.object,
                content_digest: graph_artifact.content_digest,
            },
            ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::Registry,
                host_path: registry_artifact.host_path,
                object: registry_artifact.object,
                content_digest: registry_artifact.content_digest,
            },
            ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::ExactOperationManifest,
                host_path: manifest_artifact.host_path,
                object: manifest_artifact.object,
                content_digest: manifest_artifact.content_digest,
            },
        ],
    };
    let snapshot_bytes = serde_json::to_vec(&document)?;
    let snapshot = ArmedSnapshot::load(&snapshot_bytes, &expected)
        .context("built Exact snapshot authentication refused")?;
    super::validate_loaded_engine_identity(&snapshot)?;
    super::validate_snapshot_protected_artifacts(&snapshot)?;
    super::validate_snapshot_root_bindings(&snapshot)?;

    Ok(PreparedEmbedderArtifacts {
        artifact_schema: "ibex/armed-embedder-artifacts/1",
        armed_snapshot_digest: armed_digest.as_str().to_owned(),
        snapshot: document,
        expected_identity: expected,
    })
}

/// Authenticate a generic Ibex artifact pair, bind Exact's checked operation
/// manifest as the fifth protected artifact, and freshen the result.
///
/// This is target-local by design: materializing the protected manifest and
/// authenticating the engine/root objects must happen after application
/// installation, where their real filesystem identities exist. The caller
/// supplies no operation allowlist; all three context endowments are derived
/// from the one strict manifest byte string.
/// @ref LLP 0002#the-exact-embedder-ingress — the manifest digest and complete
/// context projection are authenticated before Exact can install its channel.
pub fn prepare_exact_embedder_artifacts(
    template_bytes: &[u8],
    expected_identity_bytes: &[u8],
    operation_manifest_bytes: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    super::reject_closed_startup_environment()?;
    let expected_text = std::str::from_utf8(expected_identity_bytes)
        .context("expected arming identity is not UTF-8")?;
    let expected_value = capsec_semantics::strict_json::parse_strict(expected_text)
        .context("expected arming identity is not strict JSON")?;
    let supplied: ExpectedArmingIdentity =
        serde_json::from_value(expected_value).context("invalid expected arming identity")?;
    let mut expected = verify_expected_identity(supplied)?;

    let template = ArmedSnapshot::load(template_bytes, &expected)
        .context("snapshot template authentication refused")?;
    super::validate_loaded_engine_identity(&template)?;
    super::validate_snapshot_protected_artifacts(&template)?;
    super::validate_snapshot_root_bindings(&template)?;
    anyhow::ensure!(
        template.document().get("exactEmbedder").is_none(),
        "snapshot template already carries an Exact embedder binding"
    );
    anyhow::ensure!(
        !expected
            .protected_artifacts
            .iter()
            .any(|artifact| artifact.role == ProtectedArtifactRole::ExactOperationManifest),
        "expected identity already carries an Exact operation manifest"
    );

    let binding = parse_exact_operation_manifest(operation_manifest_bytes)?;
    let manifest = materialize_protected_artifact(
        "exact-operation-manifest",
        operation_manifest_bytes,
        &binding.operation_manifest_digest,
    )?;
    let mut document = template.document().clone();
    document["exactEmbedder"] = serde_json::to_value(binding)?;
    document["protectedObjects"]
        .as_array_mut()
        .context("snapshot protectedObjects must be an array")?
        .push(serde_json::json!({
            "role": "exact-operation-manifest",
            "object": manifest.object.clone(),
            "deniedActions": ["fs:write"],
        }));
    expected
        .protected_artifacts
        .push(ExpectedProtectedArtifact {
            role: ProtectedArtifactRole::ExactOperationManifest,
            host_path: manifest.host_path,
            object: manifest.object,
            content_digest: manifest.content_digest,
        });

    let digest = freshen_document(&mut document, fresh_production_nonce()?)?;
    expected.armed_snapshot_digest = digest.clone();
    let fresh_bytes = serde_json::to_vec(&document)?;
    let fresh = ArmedSnapshot::load(&fresh_bytes, &expected)
        .context("Exact-bound snapshot authentication refused")?;
    super::validate_loaded_engine_identity(&fresh)?;
    super::validate_snapshot_protected_artifacts(&fresh)?;
    super::validate_snapshot_root_bindings(&fresh)?;

    Ok(PreparedEmbedderArtifacts {
        artifact_schema: "ibex/armed-embedder-artifacts/1",
        armed_snapshot_digest: digest.as_str().to_owned(),
        snapshot: document,
        expected_identity: expected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsec_semantics::arming::{ExpectedProtectedArtifact, ProtectedArtifactRole};
    use capsec_semantics::model::{LogicalPath, LogicalRoot};
    use sha2::Sha256;

    #[repr(C)]
    struct HermesRuntimeOpaque {
        _private: [u8; 0],
    }

    unsafe extern "C" {
        fn ex_hermes_create_restricted_exact(
            artifact_digest: *const std::ffi::c_char,
        ) -> *mut HermesRuntimeOpaque;
        fn ex_hermes_configure_restricted_exact_activation(
            runtime: *mut HermesRuntimeOpaque,
            checkpoint_data: *const u8,
            checkpoint_len: usize,
            wall_clock_ms: u64,
            rng_seed_0: u64,
            rng_seed_1: u64,
        ) -> i32;
        fn ex_hermes_run_restricted_exact_bundle(
            runtime: *mut HermesRuntimeOpaque,
            out_error: *mut *mut std::ffi::c_char,
        ) -> i32;
        fn ex_hermes_set_restricted_exact_checkpoint_callback(
            runtime: *mut HermesRuntimeOpaque,
            callback: extern "C" fn(*const u8, usize, *mut std::ffi::c_void),
            context: *mut std::ffi::c_void,
        ) -> i32;
        fn ex_hermes_set_dispatch_callback(
            runtime: *mut HermesRuntimeOpaque,
            callback: extern "C" fn(*const u8, usize, *mut std::ffi::c_void),
            context: *mut std::ffi::c_void,
        );
        fn ex_hermes_set_exact_host_call_async(
            runtime: *mut HermesRuntimeOpaque,
            context_kind: i32,
            allowed_operation_ids: *const u32,
            allowed_operation_count: usize,
            operation_manifest_digest: *const std::ffi::c_char,
            callback: extern "C" fn(
                *mut HermesRuntimeOpaque,
                u64,
                u32,
                *const u8,
                usize,
                *mut std::ffi::c_void,
            ),
            context: *mut std::ffi::c_void,
        ) -> i32;
        fn ex_hermes_eval(
            runtime: *mut HermesRuntimeOpaque,
            data: *const u8,
            len: usize,
            source_url: *const std::ffi::c_char,
            is_bytecode: i32,
            out_value: *mut *mut std::ffi::c_char,
        ) -> i32;
        fn ex_hermes_dispatch_event(
            runtime: *mut HermesRuntimeOpaque,
            handler_id: u32,
            payload_json: *const std::ffi::c_char,
        ) -> i32;
        fn ex_hermes_poll(runtime: *mut HermesRuntimeOpaque, now_ms: u64) -> i32;
        fn ex_hermes_free_string(value: *mut std::ffi::c_char);
        fn ex_hermes_destroy(runtime: *mut HermesRuntimeOpaque);
    }

    extern "C" fn capture_dispatch(data: *const u8, len: usize, context: *mut std::ffi::c_void) {
        let output = unsafe { &mut *(context.cast::<Vec<u8>>()) };
        output.extend_from_slice(unsafe { std::slice::from_raw_parts(data, len) });
    }

    extern "C" fn reject_unexpected_host_call(
        _: *mut HermesRuntimeOpaque,
        _: u64,
        _: u32,
        _: *const u8,
        _: usize,
        _: *mut std::ffi::c_void,
    ) {
        panic!("restricted fixture made an unexpected host call");
    }

    struct RealEmbedderFixture {
        _temp: tempfile::TempDir,
        project_root: std::path::PathBuf,
        snapshot: Vec<u8>,
        expected_identity: Vec<u8>,
    }

    fn content_digest(bytes: &[u8]) -> Digest {
        Digest::new(format!(
            "sha256-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
        ))
        .unwrap()
    }

    fn absolute_host_path(path: &std::path::Path) -> LogicalPath {
        LogicalPath {
            root: LogicalRoot::Absolute,
            components: super::super::host_path_components(path).unwrap(),
            host_bound: Some(true),
        }
    }

    fn materialize_test_artifact(
        directory: &std::path::Path,
        name: &str,
        bytes: &[u8],
    ) -> (LogicalPath, capsec_semantics::model::ObjectIdentity, Digest) {
        let path = directory.join(name);
        std::fs::write(&path, bytes).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            permissions.set_mode(0o400);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();
        let path = std::fs::canonicalize(path).unwrap();
        (
            absolute_host_path(&path),
            super::super::object_identity_for_host_path(&path).unwrap(),
            content_digest(bytes),
        )
    }

    fn real_embedder_fixture() -> RealEmbedderFixture {
        let temp = tempfile::tempdir().unwrap();
        let project_root = temp.path().join("project");
        let artifacts = temp.path().join("artifacts");
        std::fs::create_dir(&project_root).unwrap();
        std::fs::create_dir(&artifacts).unwrap();
        let project_root = std::fs::canonicalize(project_root).unwrap();

        let engine = crate::engine::loaded_engine_binary_identity().unwrap();
        let mut snapshot: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        snapshot["workflow"] = serde_json::json!("production");
        snapshot["effectiveMode"] = serde_json::json!("enforce");
        snapshot["engine"] = serde_json::json!({
            "target": runtime_target_triple(),
            "binaryDigest": engine.binary_digest,
            "features": engine.structural_features,
        });

        let root_identity = snapshot["rootIdentity"].clone();
        snapshot["principals"] = serde_json::json!([{
            "principal": root_identity,
            "floor": [],
            "denials": [],
            "escalationCeiling": [],
            "imports": {"builtins": [], "packages": []},
            "endowments": [],
        }]);
        snapshot["packageGraph"]["nodes"] = serde_json::json!([]);
        snapshot["packageGraph"]["importEdges"] = serde_json::json!([]);
        snapshot["packageGraph"]["digest"] =
            serde_json::json!(capsec_semantics::digest::compute_domain_digest(
                "ibex:capsec:package-graph:1",
                &snapshot["packageGraph"],
                &["digest".to_owned()],
            )
            .unwrap());
        snapshot["rootBindings"] = serde_json::json!([{
            "logicalRoot": "project",
            "hostPath": absolute_host_path(&project_root),
            "object": super::super::object_identity_for_host_path(&project_root).unwrap(),
        }]);

        let (policy_path, policy_object, policy_content) = materialize_test_artifact(
            &artifacts,
            "armed-policy.json",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/capsec/examples/canonical-policy.canonical.json"
            )),
        );
        let graph_bytes =
            capsec_semantics::canonical::to_jcs_bytes(&snapshot["packageGraph"]).unwrap();
        let (graph_path, graph_object, graph_content) =
            materialize_test_artifact(&artifacts, "package-graph.json", &graph_bytes);
        let (registry_path, registry_object, registry_content) =
            materialize_test_artifact(&artifacts, "registry.json", b"authenticated registry");
        let protected_objects = [
            ("armed-policy", &policy_object),
            ("engine-binary", &engine.object),
            ("package-graph", &graph_object),
            ("registry", &registry_object),
        ];
        for (role, object) in protected_objects {
            snapshot["protectedObjects"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|row| row["role"] == role)
                .unwrap()["object"] = serde_json::to_value(object).unwrap();
        }

        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &snapshot).unwrap();
        snapshot["armedSnapshotDigest"] = serde_json::json!(digest);
        let digest_at = |path: &[&str]| {
            let field = path
                .iter()
                .fold(&snapshot, |current, segment| &current[*segment]);
            Digest::new(field.as_str().unwrap()).unwrap()
        };
        let expected = ExpectedArmingIdentity {
            profile: snapshot["capsVocab"].as_str().unwrap().into(),
            semantic_core: snapshot["semanticCore"].as_str().unwrap().into(),
            vocab_digest: digest_at(&["vocabDigest"]),
            registry_digest: digest_at(&["registryDigest"]),
            policy_digest: digest_at(&["policyDigest"]),
            armed_snapshot_digest: digest_at(&["armedSnapshotDigest"]),
            target: snapshot["engine"]["target"].as_str().unwrap().into(),
            engine_binary_digest: digest_at(&["engine", "binaryDigest"]),
            features: snapshot["engine"]["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            protected_artifacts: vec![
                ExpectedProtectedArtifact {
                    role: ProtectedArtifactRole::ArmedPolicy,
                    host_path: policy_path,
                    object: policy_object,
                    content_digest: policy_content,
                },
                ExpectedProtectedArtifact {
                    role: ProtectedArtifactRole::EngineBinary,
                    host_path: absolute_host_path(&engine.engine_artifact_path),
                    object: engine.object,
                    content_digest: digest_at(&["engine", "binaryDigest"]),
                },
                ExpectedProtectedArtifact {
                    role: ProtectedArtifactRole::PackageGraph,
                    host_path: graph_path,
                    object: graph_object,
                    content_digest: graph_content,
                },
                ExpectedProtectedArtifact {
                    role: ProtectedArtifactRole::Registry,
                    host_path: registry_path,
                    object: registry_object,
                    content_digest: registry_content,
                },
            ],
        };

        RealEmbedderFixture {
            _temp: temp,
            project_root,
            snapshot: serde_json::to_vec(&snapshot).unwrap(),
            expected_identity: serde_json::to_vec(&expected).unwrap(),
        }
    }

    fn prepare_through_abi(fixture: &RealEmbedderFixture) -> serde_json::Value {
        let output = unsafe {
            crate::host::abi::ex_host_prepare_armed_embedder_artifacts(
                fixture.snapshot.as_ptr(),
                fixture.snapshot.len(),
                fixture.expected_identity.as_ptr(),
                fixture.expected_identity.len(),
            )
        };
        assert!(!output.is_null());
        let bytes = unsafe { std::ffi::CStr::from_ptr(output) }
            .to_bytes()
            .to_vec();
        crate::host::abi::ex_host_free_string(output);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn exact_manifest() -> Vec<u8> {
        br#"{
          "$schema":"./host-call-operations.schema.json",
          "schema":"exact.host-call-operations/v1",
          "schemaVersion":1,
          "operations":[
            {"id":1000,"name":"app.render"},
            {"id":2200,"name":"agentIsolate.appRuntimeHealth"},
            {"id":2201,"name":"agentIsolate.bindFailed"},
            {"id":2202,"name":"agentIsolate.config"},
            {"id":2203,"name":"agentIsolate.ready"}
          ],
          "endowments":{
            "app":[1000],
            "agentIsolate":[2200,2201,2202,2203],
            "uiWorklet":[]
          }
        }"#
        .to_vec()
    }

    fn restricted_bundle_binding(format: &str, engine_bytecode_version: Option<u32>) -> Vec<u8> {
        let digest = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        serde_json::to_vec(&serde_json::json!({
            "bindingSchema": "exact/restricted-contract-bundle-binding/1",
            "format": format,
            "rootSetDigest": digest,
            "contractIrDigest": digest,
            "moduleGraphDigest": digest,
            "buildIdentityDigest": digest,
            "engineBytecodeVersion": engine_bytecode_version,
        }))
        .unwrap()
    }

    unsafe fn configured_restricted_exact_runtime(
        bundle: &[u8],
    ) -> (*mut HermesRuntimeOpaque, Box<Vec<u8>>, Box<Vec<u8>>) {
        let artifact = build_restricted_exact_embedder_artifact(
            &exact_manifest(),
            bundle,
            &restricted_bundle_binding("source-utf8", None),
        )
        .unwrap();
        let artifact_bytes = serde_json::to_vec(&artifact).unwrap();
        let authenticated =
            authenticate_restricted_exact_embedder_artifact(&artifact_bytes).unwrap();
        let manifest_digest = std::ffi::CString::new(
            authenticated
                .operation_binding()
                .operation_manifest_digest
                .as_str(),
        )
        .unwrap();
        let operations = authenticated.operation_binding().endowments.app.clone();
        let installed_digest = unsafe {
            crate::host::abi::install_restricted_exact_host_for_conformance(&artifact_bytes)
        }
        .unwrap();
        let artifact_digest = std::ffi::CString::new(installed_digest).unwrap();
        let runtime = unsafe { ex_hermes_create_restricted_exact(artifact_digest.as_ptr()) };
        assert!(!runtime.is_null());
        assert_eq!(
            unsafe {
                ex_hermes_configure_restricted_exact_activation(
                    runtime,
                    std::ptr::null(),
                    0,
                    1234,
                    0x1234,
                    0x5678,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_hermes_set_exact_host_call_async(
                    runtime,
                    1,
                    operations.as_ptr(),
                    operations.len(),
                    manifest_digest.as_ptr(),
                    reject_unexpected_host_call,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut dispatch = Box::new(Vec::<u8>::new());
        unsafe {
            ex_hermes_set_dispatch_callback(
                runtime,
                capture_dispatch,
                (&mut *dispatch as *mut Vec<u8>).cast(),
            );
        }
        let mut checkpoints = Box::new(Vec::<u8>::new());
        assert_eq!(
            unsafe {
                ex_hermes_set_restricted_exact_checkpoint_callback(
                    runtime,
                    capture_dispatch,
                    (&mut *checkpoints as *mut Vec<u8>).cast(),
                )
            },
            0
        );
        (runtime, dispatch, checkpoints)
    }

    fn prepare_exact_through_abi(fixture: &RealEmbedderFixture) -> serde_json::Value {
        let manifest = exact_manifest();
        let output = unsafe {
            crate::host::abi::ex_host_prepare_exact_armed_embedder_artifacts(
                fixture.snapshot.as_ptr(),
                fixture.snapshot.len(),
                fixture.expected_identity.as_ptr(),
                fixture.expected_identity.len(),
                manifest.as_ptr(),
                manifest.len(),
            )
        };
        assert!(!output.is_null());
        let bytes = unsafe { std::ffi::CStr::from_ptr(output) }
            .to_bytes()
            .to_vec();
        crate::host::abi::ex_host_free_string(output);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn build_exact_through_abi(project_root: &std::path::Path) -> serde_json::Value {
        let root = project_root.to_str().unwrap().as_bytes();
        let manifest = exact_manifest();
        let output = unsafe {
            crate::host::abi::ex_host_build_exact_armed_embedder_artifacts(
                root.as_ptr(),
                root.len(),
                manifest.as_ptr(),
                manifest.len(),
            )
        };
        assert!(!output.is_null());
        let bytes = unsafe { std::ffi::CStr::from_ptr(output) }
            .to_bytes()
            .to_vec();
        crate::host::abi::ex_host_free_string(output);
        serde_json::from_slice(&bytes).unwrap()
    }

    fn with_exact_embedder_binding(mut fixture: RealEmbedderFixture) -> RealEmbedderFixture {
        let mut snapshot: serde_json::Value = serde_json::from_slice(&fixture.snapshot).unwrap();
        let mut expected: ExpectedArmingIdentity =
            serde_json::from_slice(&fixture.expected_identity).unwrap();
        let manifest_bytes = br#"{"schema":"exact.host-call-operations/v1"}"#;
        let (host_path, object, manifest_digest) = materialize_test_artifact(
            &fixture._temp.path().join("artifacts"),
            "exact-host-call-operations.json",
            manifest_bytes,
        );
        snapshot["exactEmbedder"] = serde_json::json!({
            "schema": "exact/host-operation-endowments/1",
            "operationManifestDigest": manifest_digest,
            "endowments": {
                "app": [7, 11],
                "agentIsolate": [19],
                "uiWorklet": [],
            }
        });
        snapshot["protectedObjects"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "role": "exact-operation-manifest",
                "object": object,
                "deniedActions": ["fs:write"]
            }));
        expected
            .protected_artifacts
            .push(ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::ExactOperationManifest,
                host_path,
                object,
                content_digest: manifest_digest,
            });
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &snapshot).unwrap();
        snapshot["armedSnapshotDigest"] = serde_json::json!(digest);
        expected.armed_snapshot_digest = Digest::new(digest).unwrap();
        fixture.snapshot = serde_json::to_vec(&snapshot).unwrap();
        fixture.expected_identity = serde_json::to_vec(&expected).unwrap();
        fixture
    }

    fn expected_for_static_verification() -> ExpectedArmingIdentity {
        let checked: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        let digest = |path: &[&str]| {
            let value = path
                .iter()
                .fold(&checked, |current, segment| &current[*segment]);
            Digest::new(value.as_str().unwrap()).unwrap()
        };
        let engine = crate::engine::loaded_engine_binary_identity().unwrap();
        ExpectedArmingIdentity {
            profile: checked["capsVocab"].as_str().unwrap().into(),
            semantic_core: checked["semanticCore"].as_str().unwrap().into(),
            vocab_digest: digest(&["vocabDigest"]),
            registry_digest: digest(&["registryDigest"]),
            policy_digest: digest(&["policyDigest"]),
            armed_snapshot_digest: digest(&["armedSnapshotDigest"]),
            target: runtime_target_triple(),
            engine_binary_digest: Digest::new(engine.binary_digest).unwrap(),
            features: engine.structural_features,
            package_graph_digest: digest(&["packageGraph", "digest"]),
            protected_artifacts: Vec::new(),
        }
    }

    #[test]
    fn expected_identity_verification_refuses_wrong_target_and_registry() {
        let expected = expected_for_static_verification();
        assert_eq!(
            verify_expected_identity(expected.clone()).unwrap(),
            expected
        );

        let mut wrong_target = expected.clone();
        wrong_target.target = if runtime_target_triple() == "x86_64-unknown-linux-gnu" {
            "aarch64-apple-darwin"
        } else {
            "x86_64-unknown-linux-gnu"
        }
        .into();
        assert!(verify_expected_identity(wrong_target)
            .unwrap_err()
            .to_string()
            .contains("target does not match"));

        let mut wrong_registry = expected;
        wrong_registry.registry_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert!(verify_expected_identity(wrong_registry)
            .unwrap_err()
            .to_string()
            .contains("registry digest does not match"));
    }

    #[test]
    fn freshening_replaces_reserved_nonce_and_is_replay_distinct() {
        let source = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        ));
        let original: serde_json::Value = serde_json::from_slice(source).unwrap();
        let mut first = original.clone();
        let mut second = original;
        let first_digest = freshen_document(&mut first, fresh_production_nonce().unwrap()).unwrap();
        let second_digest =
            freshen_document(&mut second, fresh_production_nonce().unwrap()).unwrap();
        assert_ne!(first["runNonce"], CONTRACT_FIXTURE_RUN_NONCE);
        assert_ne!(second["runNonce"], CONTRACT_FIXTURE_RUN_NONCE);
        assert_ne!(first["runNonce"], second["runNonce"]);
        assert_ne!(first_digest, second_digest);
    }

    #[test]
    fn freshening_binds_nonce_into_checked_digest() {
        let source = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        ));
        let mut document: serde_json::Value = serde_json::from_slice(source).unwrap();
        let digest = freshen_document(&mut document, "EREREREREREREREREREREQ".to_owned()).unwrap();
        assert_eq!(document["armedSnapshotDigest"], digest.as_str());
        assert_eq!(
            compute_checked_contract_digest(DigestKind::ArmedSnapshot, &document).unwrap(),
            digest.as_str()
        );
    }

    #[test]
    fn public_prepare_round_trips_a_real_authenticated_pair() {
        let fixture = real_embedder_fixture();
        let envelope = prepare_through_abi(&fixture);
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        assert_eq!(
            artifacts["artifactSchema"],
            "ibex/armed-embedder-artifacts/1"
        );
        assert_ne!(
            artifacts["snapshot"]["runNonce"],
            CONTRACT_FIXTURE_RUN_NONCE
        );
        assert_eq!(
            artifacts["snapshot"]["armedSnapshotDigest"],
            artifacts["armedSnapshotDigest"]
        );

        let returned_expected: ExpectedArmingIdentity =
            serde_json::from_value(artifacts["expectedIdentity"].clone()).unwrap();
        let returned_snapshot = serde_json::to_vec(&artifacts["snapshot"]).unwrap();
        let reingested = ArmedSnapshot::load(&returned_snapshot, &returned_expected).unwrap();
        super::super::validate_loaded_engine_identity(&reingested).unwrap();
        super::super::validate_snapshot_protected_artifacts(&reingested).unwrap();
        super::super::validate_snapshot_root_bindings(&reingested).unwrap();
        assert_eq!(
            reingested.digest().as_str(),
            artifacts["armedSnapshotDigest"].as_str().unwrap()
        );
    }

    #[test]
    fn target_local_exact_builder_authenticates_a_complete_pair() {
        let project = tempfile::tempdir().unwrap();
        let envelope = build_exact_through_abi(project.path());
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        assert_eq!(
            artifacts["artifactSchema"],
            "ibex/armed-embedder-artifacts/1"
        );
        assert_eq!(artifacts["snapshot"]["workflow"], "production");
        assert_eq!(artifacts["snapshot"]["effectiveMode"], "enforce");
        assert_eq!(
            artifacts["snapshot"]["packageGraph"]["nodes"],
            serde_json::json!([])
        );
        assert_eq!(
            artifacts["expectedIdentity"]["protectedArtifacts"]
                .as_array()
                .unwrap()
                .len(),
            5
        );
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["endowments"]["agentIsolate"],
            serde_json::json!([2200, 2201, 2202, 2203])
        );
        let expected: ExpectedArmingIdentity =
            serde_json::from_value(artifacts["expectedIdentity"].clone()).unwrap();
        ArmedSnapshot::load(
            &serde_json::to_vec(&artifacts["snapshot"]).unwrap(),
            &expected,
        )
        .unwrap();
    }

    #[test]
    fn restricted_exact_builder_binds_one_immutable_candidate_bundle() {
        let _guard = crate::host::abi::host_test_lock();
        let bundle = b"globalThis.__restrictedContractLoaded = true;";
        let result = build_restricted_exact_embedder_artifact(
            &exact_manifest(),
            bundle,
            &restricted_bundle_binding("source-utf8", None),
        );
        if crate::engine::loaded_engine_structural_features()
            != [
                "hermes-frame-attribution",
                "native-compartments",
                "native-lockdown",
            ]
        {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("not a restricted profile candidate"));
            return;
        }
        let artifact = result.unwrap();
        assert_eq!(artifact["profile"], "ibex/exact-embedder-contract/1");
        assert_eq!(artifact["status"], "candidate-unadvertised");
        assert_eq!(artifact["bundle"]["format"], "source-utf8");
        assert_eq!(artifact["bundle"]["byteLength"], bundle.len());
        assert_eq!(
            artifact["bundle"]["contentDigest"],
            serde_json::to_value(raw_content_digest(bundle).unwrap()).unwrap()
        );
        assert_ne!(
            artifact["artifactDigest"],
            "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_ne!(artifact["runNonce"], CONTRACT_FIXTURE_RUN_NONCE);
        let authenticated = authenticate_restricted_exact_embedder_artifact(
            &serde_json::to_vec(&artifact).unwrap(),
        )
        .unwrap();
        assert_eq!(authenticated.bundle(), bundle);
        assert_eq!(authenticated.bundle_format(), "source-utf8");
        assert_eq!(
            authenticated.digest().as_str(),
            artifact["artifactDigest"].as_str().unwrap()
        );
        assert!(crate::host::abi::install_restricted_exact_host(
            &serde_json::to_vec(&artifact).unwrap(),
        )
        .unwrap_err()
        .contains("not advertised"));

        let installed_digest = unsafe {
            crate::host::abi::install_restricted_exact_host_for_conformance(
                &serde_json::to_vec(&artifact).unwrap(),
            )
        }
        .unwrap();
        let digest_c = std::ffi::CString::new(installed_digest).unwrap();
        assert_eq!(crate::host::abi::ex_host_claim_diagnostic_context(), 0);
        assert_eq!(
            unsafe { crate::host::abi::ex_host_claim_armed_context(digest_c.as_ptr()) },
            0
        );
        let context =
            unsafe { crate::host::abi::ex_host_claim_restricted_exact_context(digest_c.as_ptr()) };
        assert_ne!(context, 0);
        crate::host::abi::ex_host_release_context(context);

        let mut tampered = artifact;
        tampered["bundle"]["rootSetDigest"] =
            serde_json::json!("sha256-__________________________________________8");
        assert!(authenticate_restricted_exact_embedder_artifact(
            &serde_json::to_vec(&tampered).unwrap(),
        )
        .unwrap_err()
        .to_string()
        .contains("stale or tampered"));
    }

    #[test]
    fn restricted_exact_runtime_has_authenticated_single_use_ingress() {
        let _guard = crate::host::abi::host_test_lock();
        let bundle = br#"
          (() => {
            const checkpoint = exact.takeCheckpointBytes();
            if (checkpoint.length !== 3 || checkpoint[0] !== 7 ||
                Date.now() !== 1234 || new Date().getTime() !== 1234 ||
                typeof Math.random() !== 'number') {
              throw new Error('activation mismatch');
            }
            for (const name of [
              'require', 'process', 'Bun', 'Deno', 'Ibex', 'Exact', 'fetch',
              'WebSocket', 'XMLHttpRequest', 'WebAssembly', 'SharedArrayBuffer',
              'Atomics', '__hostCall', '__hostCallAsync', '__compartments',
              '__exactCapabilityCheck', '__exactGetEnv', '__exactResolveModule',
              '__exactTimerRef', '__exactTimerUnref'
            ]) {
              if (typeof globalThis[name] !== 'undefined') {
                throw new Error(`forbidden global ${name}`);
              }
            }
            const constructors = [
              Function,
              (async function () {}).constructor,
              (function* () {}).constructor
            ];
            for (const constructor of constructors) {
              let refused = false;
              try { constructor('return globalThis')(); } catch (_) { refused = true; }
              if (!refused) throw new Error('dynamic constructor escaped lockdown');
            }
            if (typeof exact.invokeHostAsync !== 'function' ||
                typeof exact.dispatch !== 'function') {
              throw new Error('restricted callbacks missing');
            }
            exact.dispatch(new Uint8Array([9, 4, 1]));
            exact.publishCheckpoint(new Uint8Array([1, 2, 3, 4]));
          })();
        "#;
        let result = build_restricted_exact_embedder_artifact(
            &exact_manifest(),
            bundle,
            &restricted_bundle_binding("source-utf8", None),
        );
        if crate::engine::loaded_engine_structural_features()
            != [
                "hermes-frame-attribution",
                "native-compartments",
                "native-lockdown",
            ]
        {
            assert!(result.is_err());
            return;
        }
        let artifact = result.unwrap();
        let artifact_bytes = serde_json::to_vec(&artifact).unwrap();
        let authenticated =
            authenticate_restricted_exact_embedder_artifact(&artifact_bytes).unwrap();
        let manifest_digest = std::ffi::CString::new(
            authenticated
                .operation_binding()
                .operation_manifest_digest
                .as_str(),
        )
        .unwrap();
        let installed_digest = unsafe {
            crate::host::abi::install_restricted_exact_host_for_conformance(&artifact_bytes)
        }
        .unwrap();
        let artifact_digest = std::ffi::CString::new(installed_digest).unwrap();

        unsafe {
            let wrong_digest =
                std::ffi::CString::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap();
            assert!(ex_hermes_create_restricted_exact(wrong_digest.as_ptr()).is_null());
            let runtime = ex_hermes_create_restricted_exact(artifact_digest.as_ptr());
            assert!(!runtime.is_null());

            let checkpoint = [7_u8, 8, 9];
            assert_eq!(
                ex_hermes_configure_restricted_exact_activation(
                    runtime,
                    checkpoint.as_ptr(),
                    checkpoint.len(),
                    1234,
                    0x1234,
                    0x5678,
                ),
                0
            );
            assert_eq!(
                ex_hermes_configure_restricted_exact_activation(
                    runtime,
                    checkpoint.as_ptr(),
                    checkpoint.len(),
                    1234,
                    0x1234,
                    0x5678,
                ),
                -3
            );
            let mut premature_error = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_run_restricted_exact_bundle(runtime, &mut premature_error),
                1
            );
            assert!(!premature_error.is_null());
            assert!(std::ffi::CStr::from_ptr(premature_error)
                .to_string_lossy()
                .contains("callbacks must be installed"));
            ex_hermes_free_string(premature_error);
            let operations = [1000_u32];
            assert_eq!(
                ex_hermes_set_exact_host_call_async(
                    runtime,
                    2,
                    operations.as_ptr(),
                    operations.len(),
                    manifest_digest.as_ptr(),
                    reject_unexpected_host_call,
                    std::ptr::null_mut(),
                ),
                -3
            );
            assert_eq!(
                ex_hermes_set_exact_host_call_async(
                    runtime,
                    1,
                    operations.as_ptr(),
                    operations.len(),
                    manifest_digest.as_ptr(),
                    reject_unexpected_host_call,
                    std::ptr::null_mut(),
                ),
                0
            );
            let mut dispatched = Vec::<u8>::new();
            ex_hermes_set_dispatch_callback(
                runtime,
                capture_dispatch,
                (&mut dispatched as *mut Vec<u8>).cast(),
            );
            let mut replacement_dispatch = Vec::<u8>::new();
            ex_hermes_set_dispatch_callback(
                runtime,
                capture_dispatch,
                (&mut replacement_dispatch as *mut Vec<u8>).cast(),
            );
            let mut published_checkpoint = Vec::<u8>::new();
            assert_eq!(
                ex_hermes_set_restricted_exact_checkpoint_callback(
                    runtime,
                    capture_dispatch,
                    (&mut published_checkpoint as *mut Vec<u8>).cast(),
                ),
                0
            );
            let mut replacement_checkpoint = Vec::<u8>::new();
            assert_eq!(
                ex_hermes_set_restricted_exact_checkpoint_callback(
                    runtime,
                    capture_dispatch,
                    (&mut replacement_checkpoint as *mut Vec<u8>).cast(),
                ),
                -5
            );

            let mut error = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_run_restricted_exact_bundle(runtime, &mut error),
                0,
                "{}",
                if error.is_null() {
                    String::new()
                } else {
                    std::ffi::CStr::from_ptr(error)
                        .to_string_lossy()
                        .into_owned()
                }
            );
            if !error.is_null() {
                ex_hermes_free_string(error);
            }
            assert_eq!(dispatched, [9, 4, 1]);
            assert!(replacement_dispatch.is_empty());
            assert_eq!(published_checkpoint, [1, 2, 3, 4]);
            assert!(replacement_checkpoint.is_empty());

            let mut replay_error = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_run_restricted_exact_bundle(runtime, &mut replay_error),
                1
            );
            assert!(!replay_error.is_null());
            ex_hermes_free_string(replay_error);

            let source = b"1 + 1";
            let source_url = std::ffi::CString::new("forbidden.js").unwrap();
            let mut eval_error = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_eval(
                    runtime,
                    source.as_ptr(),
                    source.len(),
                    source_url.as_ptr(),
                    0,
                    &mut eval_error,
                ),
                1
            );
            assert!(!eval_error.is_null());
            ex_hermes_free_string(eval_error);
            ex_hermes_destroy(runtime);
        }
    }

    #[test]
    fn restricted_exact_startup_checkpoint_failures_poison_the_runtime() {
        let _guard = crate::host::abi::host_test_lock();
        if crate::engine::loaded_engine_structural_features()
            != [
                "hermes-frame-attribution",
                "native-compartments",
                "native-lockdown",
            ]
        {
            return;
        }
        let fixtures: &[(&str, &[u8])] = &[
            (
                "missing-initial-checkpoint",
                br#"(() => { exact.takeCheckpointBytes(); })();"#,
            ),
            (
                "duplicate-initial-checkpoint",
                br#"(() => {
                  exact.takeCheckpointBytes();
                  exact.publishCheckpoint(new Uint8Array([1]));
                  exact.publishCheckpoint(new Uint8Array([2]));
                })();"#,
            ),
            (
                "malformed-initial-checkpoint",
                br#"(() => {
                  exact.takeCheckpointBytes();
                  exact.publishCheckpoint({});
                })();"#,
            ),
            (
                "oversize-initial-checkpoint",
                br#"(() => {
                  exact.takeCheckpointBytes();
                  exact.publishCheckpoint(new Uint8Array(16 * 1024 * 1024 + 1));
                })();"#,
            ),
        ];
        for (name, bundle) in fixtures {
            let (runtime, _dispatch, mut checkpoints) =
                unsafe { configured_restricted_exact_runtime(bundle) };
            unsafe {
                let mut error = std::ptr::null_mut();
                assert_ne!(
                    ex_hermes_run_restricted_exact_bundle(runtime, &mut error),
                    0,
                    "{name} unexpectedly succeeded"
                );
                assert!(!error.is_null(), "{name} returned no error");
                ex_hermes_free_string(error);
                assert_eq!(ex_hermes_poll(runtime, 1234), -1, "{name} still polled");
                let payload = std::ffi::CString::new("{}").unwrap();
                assert_eq!(
                    ex_hermes_dispatch_event(runtime, 1, payload.as_ptr()),
                    -1,
                    "{name} still accepted events"
                );
                assert_eq!(
                    ex_hermes_set_restricted_exact_checkpoint_callback(
                        runtime,
                        capture_dispatch,
                        (&mut *checkpoints as *mut Vec<u8>).cast(),
                    ),
                    -9,
                    "{name} allowed callback replacement after poison"
                );
                let mut replay_error = std::ptr::null_mut();
                assert_ne!(
                    ex_hermes_run_restricted_exact_bundle(runtime, &mut replay_error),
                    0,
                    "{name} allowed replay after poison"
                );
                assert!(!replay_error.is_null());
                ex_hermes_free_string(replay_error);
                ex_hermes_destroy(runtime);
            }
        }
    }

    #[test]
    fn restricted_exact_event_checkpoint_failures_poison_the_runtime() {
        let _guard = crate::host::abi::host_test_lock();
        if crate::engine::loaded_engine_structural_features()
            != [
                "hermes-frame-attribution",
                "native-compartments",
                "native-lockdown",
            ]
        {
            return;
        }
        let bundle = br#"(() => {
          exact.takeCheckpointBytes();
          exact.publishCheckpoint(new Uint8Array([7]));
          Object.defineProperty(globalThis, '__exactDispatchEvent', {
            value: (handler) => {
              if (handler === 1) return;
              if (handler === 2) {
                exact.publishCheckpoint(new Uint8Array([8]));
                exact.publishCheckpoint(new Uint8Array([8]));
                return;
              }
              if (handler === 3) throw new Error('hostile event');
              if (handler === 4) {
                exact.publishCheckpoint({});
                return;
              }
              exact.publishCheckpoint(new Uint8Array([9]));
            },
            writable: false,
            configurable: false
          });
        })();"#;
        let payload = std::ffi::CString::new("{}").unwrap();

        let (runtime, _dispatch, checkpoints) =
            unsafe { configured_restricted_exact_runtime(bundle) };
        unsafe {
            let mut error = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_run_restricted_exact_bundle(runtime, &mut error),
                0
            );
            assert!(error.is_null());
            assert_eq!(ex_hermes_dispatch_event(runtime, 5, payload.as_ptr()), 0);
            assert_eq!(*checkpoints, [7, 9]);
            ex_hermes_destroy(runtime);
        }

        for handler in [1_u32, 2, 3, 4] {
            let (runtime, _dispatch, _checkpoints) =
                unsafe { configured_restricted_exact_runtime(bundle) };
            unsafe {
                let mut error = std::ptr::null_mut();
                assert_eq!(
                    ex_hermes_run_restricted_exact_bundle(runtime, &mut error),
                    0
                );
                assert!(error.is_null());
                assert_eq!(
                    ex_hermes_dispatch_event(runtime, handler, payload.as_ptr()),
                    -1,
                    "hostile handler {handler} unexpectedly succeeded"
                );
                assert_eq!(ex_hermes_poll(runtime, 1234), -1);
                assert_eq!(ex_hermes_dispatch_event(runtime, 5, payload.as_ptr()), -1);
                ex_hermes_destroy(runtime);
            }
        }

        let (missing_handler_runtime, _dispatch, _checkpoints) = unsafe {
            configured_restricted_exact_runtime(
                br#"(() => {
                  exact.takeCheckpointBytes();
                  exact.publishCheckpoint(new Uint8Array([7]));
                })();"#,
            )
        };
        unsafe {
            let mut error = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_run_restricted_exact_bundle(missing_handler_runtime, &mut error),
                0
            );
            assert!(error.is_null());
            assert_eq!(
                ex_hermes_dispatch_event(missing_handler_runtime, 1, payload.as_ptr()),
                -1
            );
            assert_eq!(ex_hermes_poll(missing_handler_runtime, 1234), -1);
            ex_hermes_destroy(missing_handler_runtime);
        }

        let (malformed_payload_runtime, _dispatch, _checkpoints) =
            unsafe { configured_restricted_exact_runtime(bundle) };
        unsafe {
            let mut error = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_run_restricted_exact_bundle(malformed_payload_runtime, &mut error),
                0
            );
            assert!(error.is_null());
            let malformed = std::ffi::CString::new("{").unwrap();
            assert_eq!(
                ex_hermes_dispatch_event(malformed_payload_runtime, 5, malformed.as_ptr()),
                -1
            );
            assert_eq!(ex_hermes_poll(malformed_payload_runtime, 1234), -1);
            ex_hermes_destroy(malformed_payload_runtime);
        }
    }

    #[test]
    fn restricted_exact_builder_rejects_format_and_engine_confusion() {
        let _guard = crate::host::abi::host_test_lock();
        let manifest = exact_manifest();
        assert!(build_restricted_exact_embedder_artifact(
            &manifest,
            b"source",
            &restricted_bundle_binding("source-utf8", Some(1)),
        )
        .unwrap_err()
        .to_string()
        .contains("must not claim"));
        assert!(build_restricted_exact_embedder_artifact(
            &manifest,
            &[0xff],
            &restricted_bundle_binding("source-utf8", None),
        )
        .unwrap_err()
        .to_string()
        .contains("not UTF-8"));
        assert!(build_restricted_exact_embedder_artifact(
            &manifest,
            b"hbc",
            &restricted_bundle_binding("hbc-v1", Some(u32::MAX)),
        )
        .unwrap_err()
        .to_string()
        .contains("does not match"));
    }

    #[test]
    fn public_exact_prepare_derives_and_protects_manifest_endowments() {
        let fixture = real_embedder_fixture();
        let envelope = prepare_exact_through_abi(&fixture);
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["schema"],
            "exact/host-operation-endowments/1"
        );
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["endowments"]["app"],
            serde_json::json!([1000])
        );
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["endowments"]["agentIsolate"],
            serde_json::json!([2200, 2201, 2202, 2203])
        );
        assert_eq!(
            artifacts["snapshot"]["exactEmbedder"]["endowments"]["uiWorklet"],
            serde_json::json!([])
        );
        assert!(artifacts["snapshot"]["protectedObjects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["role"] == "exact-operation-manifest"));
        assert!(artifacts["expectedIdentity"]["protectedArtifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["role"] == "exact-operation-manifest"));
        let digest = artifacts["snapshot"]["exactEmbedder"]["operationManifestDigest"]
            .as_str()
            .unwrap();
        assert_eq!(
            artifacts["expectedIdentity"]["protectedArtifacts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["role"] == "exact-operation-manifest")
                .unwrap()["contentDigest"],
            digest
        );
    }

    #[test]
    fn exact_manifest_validation_refuses_noncanonical_or_ambient_endowments() {
        let mut reordered: serde_json::Value = serde_json::from_slice(&exact_manifest()).unwrap();
        reordered["endowments"]["agentIsolate"] = serde_json::json!([2201, 2200, 2202, 2203]);
        assert!(
            parse_exact_operation_manifest(&serde_json::to_vec(&reordered).unwrap())
                .unwrap_err()
                .to_string()
                .contains("strictly increasing")
        );

        let mut worklet: serde_json::Value = serde_json::from_slice(&exact_manifest()).unwrap();
        worklet["operations"]
            .as_array_mut()
            .unwrap()
            .insert(1, serde_json::json!({"id": 1001, "name": "app.measure"}));
        worklet["endowments"]["uiWorklet"] = serde_json::json!([1001]);
        assert!(
            parse_exact_operation_manifest(&serde_json::to_vec(&worklet).unwrap())
                .unwrap_err()
                .to_string()
                .contains("UI worklet endowment must remain empty")
        );
    }

    #[test]
    fn public_prepare_preserves_the_protected_exact_endowment_binding() {
        let fixture = with_exact_embedder_binding(real_embedder_fixture());
        let envelope = prepare_through_abi(&fixture);
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        let returned_expected: ExpectedArmingIdentity =
            serde_json::from_value(artifacts["expectedIdentity"].clone()).unwrap();
        let returned_snapshot = serde_json::to_vec(&artifacts["snapshot"]).unwrap();
        let reingested = ArmedSnapshot::load(&returned_snapshot, &returned_expected).unwrap();
        let binding = reingested.exact_embedder_binding().unwrap().unwrap();
        assert_eq!(binding.endowments.app, [7, 11]);
        assert_eq!(binding.endowments.agent_isolate, [19]);
        assert!(returned_expected
            .protected_artifacts
            .iter()
            .any(|artifact| artifact.role == ProtectedArtifactRole::ExactOperationManifest));
        super::super::validate_snapshot_protected_artifacts(&reingested).unwrap();
    }

    #[test]
    fn public_prepare_refuses_an_authenticated_root_replacement() {
        let fixture = real_embedder_fixture();
        let original_root = fixture._temp.path().join("original-project");
        std::fs::rename(&fixture.project_root, &original_root).unwrap();
        std::fs::create_dir(&fixture.project_root).unwrap();

        let envelope = prepare_through_abi(&fixture);
        assert_eq!(envelope["ok"], false, "{envelope}");
        assert!(
            envelope["error"]
                .as_str()
                .unwrap()
                .contains("armed root object changed after arming"),
            "{envelope}"
        );
    }
}
