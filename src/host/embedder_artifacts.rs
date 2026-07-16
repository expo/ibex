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
use capsec_semantics::digest::{compute_checked_contract_digest, DigestKind};
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

struct MaterializedManifest {
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

fn manifest_artifact_path(path: &Path) -> Result<LogicalPath> {
    Ok(LogicalPath {
        root: LogicalRoot::Absolute,
        components: super::host_path_components(path)?,
        host_bound: Some(true),
    })
}

fn materialize_exact_operation_manifest(
    bytes: &[u8],
    digest: &Digest,
) -> Result<MaterializedManifest> {
    let cache_root = crate::runtime_cache_dir()?;
    let directory = cache_root.join("capsec-artifacts");
    std::fs::create_dir_all(&directory)?;
    let directory_metadata = std::fs::symlink_metadata(&directory)?;
    anyhow::ensure!(
        directory_metadata.is_dir() && !directory_metadata.file_type().is_symlink(),
        "Exact manifest artifact parent is not a stable directory"
    );
    let directory = std::fs::canonicalize(directory)?;
    let filename = format!(
        "{}.exact-operation-manifest.json",
        digest.as_str().trim_start_matches("sha256-")
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
            .with_context(|| format!("failed to pin Exact manifest artifact {}", path.display()))
    };
    let validate = |file: &mut std::fs::File| -> Result<()> {
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file(),
            "Exact manifest artifact is not a regular file"
        );
        #[cfg(unix)]
        anyhow::ensure!(
            {
                use std::os::unix::fs::PermissionsExt as _;
                metadata.permissions().mode() & 0o222 == 0
            },
            "Exact manifest artifact is mutable"
        );
        #[cfg(not(unix))]
        anyhow::ensure!(
            metadata.permissions().readonly(),
            "Exact manifest artifact is mutable"
        );
        file.rewind()?;
        let mut observed = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut observed)?;
        anyhow::ensure!(
            observed == bytes,
            "Exact manifest artifact content mismatch"
        );
        Ok(())
    };

    if path.exists() {
        let mut existing = open_existing()?;
        validate(&mut existing)?;
    } else {
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .context("failed to name Exact manifest staging artifact")?;
        let temporary = directory.join(format!(
            ".exact-operation-manifest.{}.tmp",
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
    Ok(MaterializedManifest {
        host_path: manifest_artifact_path(&path)?,
        object,
        content_digest: digest.clone(),
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
    let manifest = materialize_exact_operation_manifest(
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
