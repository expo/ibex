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
use capsec_semantics::model::{Digest, LogicalPath, LogicalRoot, ObjectIdentity, ObjectPlatform};
use capsec_semantics::path_alias::{BoundVolumePathCanonicalizer, PathAliasCanonicalizerIdentity};
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

/// Select the same per-volume alias identity as the ordinary armed launcher.
/// The public Exact builder is target-local, so it must probe the authenticated
/// bound paths rather than inheriting canonicalizer rows from the template.
/// @ref LLP 0023#3-path-grammar-normalization-aliasing-and-containment
fn bound_volume_path_canonicalizers<'a>(
    bindings: impl IntoIterator<Item = (&'a Path, &'a ObjectIdentity)>,
) -> Result<Vec<BoundVolumePathCanonicalizer>> {
    let mut rows = BTreeMap::new();
    for (path, object) in bindings {
        let observed = super::object_identity_for_host_path(path)?;
        anyhow::ensure!(
            &observed == object,
            "bound-volume adapter object mismatch for {}",
            path.display()
        );
        let identity = match object.platform {
            ObjectPlatform::Apple => apple_volume_path_canonicalizer(path)?,
            ObjectPlatform::Unix | ObjectPlatform::Windows | ObjectPlatform::Android => {
                PathAliasCanonicalizerIdentity::ByteIdentityV1
            }
        };
        let row = BoundVolumePathCanonicalizer {
            platform: object.platform,
            volume: object.volume.clone(),
            identity,
        };
        let key = (row.platform, row.volume.clone());
        if rows
            .insert(key, row.clone())
            .is_some_and(|prior| prior != row)
        {
            anyhow::bail!("one bound volume reported inconsistent path canonicalizers");
        }
    }
    let mut rows = rows.into_values().collect::<Vec<_>>();
    rows.sort_by_cached_key(|row| {
        capsec_semantics::canonical::to_jcs_bytes(
            &serde_json::to_value(row).expect("canonicalizer row serializes"),
        )
        .expect("canonicalizer row is valid JCS")
    });
    Ok(rows)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn apple_volume_path_canonicalizer(path: &Path) -> Result<PathAliasCanonicalizerIdentity> {
    use std::os::unix::ffi::OsStrExt as _;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .context("bound Apple volume path contains NUL")?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut filesystem) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot inspect bound Apple volume filesystem");
    }
    let filesystem_name = unsafe { std::ffi::CStr::from_ptr(filesystem.f_fstypename.as_ptr()) }
        .to_str()
        .context("bound Apple volume filesystem name is not UTF-8")?;
    anyhow::ensure!(
        filesystem_name == "apfs",
        "armed Apple path canonicalization supports APFS only; bound volume uses {filesystem_name}"
    );
    let case_sensitive = unsafe { libc::pathconf(path.as_ptr(), libc::_PC_CASE_SENSITIVE) };
    match case_sensitive {
        0 => Ok(PathAliasCanonicalizerIdentity::AppleApfsUnicode9SafeCasefoldNfdV1),
        1 => Ok(PathAliasCanonicalizerIdentity::AppleApfsUnicode9NfdV1),
        _ => Err(std::io::Error::last_os_error())
            .context("cannot determine whether the bound APFS volume is case-sensitive"),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn apple_volume_path_canonicalizer(_path: &Path) -> Result<PathAliasCanonicalizerIdentity> {
    anyhow::bail!("an Apple object identity cannot be bound on this target")
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
/// @ref LLP 0033#4-profile-identity-and-anti-confusion-rules — bind the exact
/// profile, engine, registries, operation manifest, Contract bundle, and nonce.
/// @ref LLP 0033#6-authenticated-contract-code-ingress — admit one graph-closed
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
    // @ref LLP 0022#11-delegated-obligations — the public embedder output keeps
    // OBL-ENV-BASE explicit. ArmedSnapshot::load already refused any supplied
    // non-empty base; values are admitted only through principal overlays.
    document["environmentBase"] = serde_json::json!([]);
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
        "rootImports": [],
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
    let project_host_path = absolute_artifact_path(&project_root)?;
    let cache_host_path = absolute_artifact_path(&cache_root)?;
    let project_object = super::object_identity_for_host_path(&project_root)?;
    let cache_object = super::object_identity_for_host_path(&cache_root)?;
    document["rootBindings"] = serde_json::json!([
        {
            "logicalRoot": "project",
            "hostPath": project_host_path,
            "object": project_object,
        },
        {
            "logicalRoot": "home",
            "hostPath": cache_host_path,
            "object": cache_object,
        },
    ]);
    document["projectRootDiscovery"] =
        serde_json::to_value(capsec_semantics::arming::ArmedProjectRootDiscovery {
            origin: project_host_path.clone(),
            selected_root: project_host_path.clone(),
            marker_kind: capsec_semantics::arming::ArmedProjectRootMarkerKind::ExplicitProject,
            marker_path: Some(project_host_path),
            marker_set_version: capsec_semantics::arming::PROJECT_ROOT_MARKER_SET_VERSION.into(),
        })?;
    document["pathCanonicalizers"] = serde_json::to_value(bound_volume_path_canonicalizers([
        (project_root.as_path(), &project_object),
        (cache_root.as_path(), &cache_object),
    ])?)?;
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
        entry: serde_json::from_value(document["entry"].clone())?,
        project_root_discovery: serde_json::from_value(document["projectRootDiscovery"].clone())?,
        path_canonicalizers: serde_json::from_value(document["pathCanonicalizers"].clone())?,
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
        .map_err(|error| anyhow::anyhow!("built Exact snapshot authentication refused: {error}"))?;
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
        fn ex_hermes_has_pending_tasks(runtime: *mut HermesRuntimeOpaque) -> i32;
        fn ex_hermes_next_timer(runtime: *mut HermesRuntimeOpaque) -> i64;
        fn ex_hermes_now_ms() -> u64;
        fn ex_hermes_notify_callback();
        fn ex_hermes_set_keep_alive_on_async_error(runtime: *mut HermesRuntimeOpaque, enabled: i32);
        fn ibex_test_root_global_logical_path_absent(
            runtime: *mut HermesRuntimeOpaque,
            path: *const std::ffi::c_char,
        ) -> u32;
        fn ibex_test_reset_exact_host_completion_observer();
        fn ibex_test_exact_host_completion_observation(
            targets_consumed: *mut u64,
            callbacks_queued: *mut u64,
            callbacks_delivered: *mut u64,
        ) -> i32;
        fn ibex_test_restricted_exact_conformance_trace(runtime: *mut HermesRuntimeOpaque) -> u64;
        fn ibex_test_runtime_registered(runtime: *mut HermesRuntimeOpaque) -> i32;
        fn ibex_test_keep_alive_on_async_error(runtime: *mut HermesRuntimeOpaque) -> i32;
        fn ex_hermes_resolve_exact_host_call(
            runtime: *mut HermesRuntimeOpaque,
            call_id: u64,
            status: i32,
            payload: *const u8,
            payload_len: usize,
        );
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

    #[derive(Default)]
    struct RestrictedHostCallCapture {
        calls: Vec<(u64, u32, Vec<u8>)>,
    }

    extern "C" fn resolve_restricted_host_call(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        operation_id: u32,
        data: *const u8,
        len: usize,
        context: *mut std::ffi::c_void,
    ) {
        let capture = unsafe { &mut *context.cast::<RestrictedHostCallCapture>() };
        let payload = if data.is_null() || len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
        };
        capture.calls.push((call_id, operation_id, payload));
        const COMPLETION: &[u8] = b"restricted-conformance-completion";
        unsafe {
            ex_hermes_resolve_exact_host_call(
                runtime,
                call_id,
                0,
                COMPLETION.as_ptr(),
                COMPLETION.len(),
            );
        }
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
        snapshot["environmentBase"] = serde_json::json!([]);
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
        let project_path = absolute_host_path(&project_root);
        snapshot["projectRootDiscovery"] = serde_json::json!({
            "origin": project_path,
            "selectedRoot": absolute_host_path(&project_root),
            "markerKind": "explicit-project",
            "markerPath": absolute_host_path(&project_root),
            "markerSetVersion": capsec_semantics::arming::PROJECT_ROOT_MARKER_SET_VERSION,
        });
        let fixture_bindings: Vec<capsec_semantics::arming::ArmedRootBinding> =
            serde_json::from_value(snapshot["rootBindings"].clone()).unwrap();
        snapshot["pathCanonicalizers"] = serde_json::to_value(
            capsec_semantics::path_alias::contract_fixture_canonicalizer_rows(
                fixture_bindings
                    .iter()
                    .map(|binding| (binding.object.platform, binding.object.volume.clone())),
            )
            .unwrap(),
        )
        .unwrap();

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
            entry: serde_json::from_value(snapshot["entry"].clone()).unwrap(),
            project_root_discovery: serde_json::from_value(
                snapshot["projectRootDiscovery"].clone(),
            )
            .unwrap(),
            path_canonicalizers: serde_json::from_value(snapshot["pathCanonicalizers"].clone())
                .unwrap(),
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

    type ExactHostCallCallback =
        extern "C" fn(*mut HermesRuntimeOpaque, u64, u32, *const u8, usize, *mut std::ffi::c_void);

    unsafe fn configured_restricted_exact_runtime_with_host_callback(
        bundle: &[u8],
        host_callback: ExactHostCallCallback,
        host_context: *mut std::ffi::c_void,
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
                    host_callback,
                    host_context,
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

    unsafe fn configured_restricted_exact_runtime(
        bundle: &[u8],
    ) -> (*mut HermesRuntimeOpaque, Box<Vec<u8>>, Box<Vec<u8>>) {
        unsafe {
            configured_restricted_exact_runtime_with_host_callback(
                bundle,
                reject_unexpected_host_call,
                std::ptr::null_mut(),
            )
        }
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
            entry: serde_json::from_value(checked["entry"].clone()).unwrap(),
            project_root_discovery: serde_json::from_value(checked["projectRootDiscovery"].clone())
                .unwrap(),
            path_canonicalizers: serde_json::from_value(checked["pathCanonicalizers"].clone())
                .unwrap(),
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
    fn restricted_exact_control_plane_edges_enforce_lifecycle_refusals() {
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

        let projection: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/restricted-exact-profile-projection.json"
        )))
        .unwrap();
        let control_ids = projection["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| {
                let row = row.as_array().unwrap();
                (row[1].as_str() == Some("trusted-control-plane"))
                    .then(|| row[0].as_str().unwrap().to_owned())
            })
            .collect::<std::collections::BTreeSet<_>>();
        let coverage: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/coverage-edges.json"
        )))
        .unwrap();
        let observed_identities = coverage["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| {
                (
                    edge["id"].as_str().unwrap().to_owned(),
                    format!(
                        "{}:{}",
                        edge["surface"]["kind"].as_str().unwrap(),
                        edge["surface"]["name"].as_str().unwrap()
                    ),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(control_ids.len(), 22);

        let bundle = br#"(() => {
          exact.takeCheckpointBytes();
          globalThis.__exactDispatchEvent = (handlerId) => {
            exact.publishCheckpoint(new Uint8Array([handlerId & 255]));
          };
          exact.dispatch(new Uint8Array([9]));
          exact.invokeHostAsync(1000, new Uint8Array([1])).then(() => {}, () => {});
          exact.publishCheckpoint(new Uint8Array([0]));
        })();"#;
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
        let wrong_digest =
            std::ffi::CString::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();

        let mut proofs = std::collections::BTreeMap::<String, serde_json::Value>::new();
        let mut record = |edge_id: &str, accepted: &str, refusal: &str| {
            assert!(
                control_ids.contains(edge_id),
                "unknown control edge {edge_id}"
            );
            assert!(
                proofs
                    .insert(
                        edge_id.to_owned(),
                        serde_json::json!({
                            "observer": "native-abi-lifecycle",
                            "accepted": accepted,
                            "refusal": refusal,
                        }),
                    )
                    .is_none(),
                "duplicate control edge {edge_id}"
            );
        };

        // Exercise the Rust Host control plane independently from engine
        // construction so release and wrong-context refusal are observable.
        let installed_digest = unsafe {
            crate::host::abi::install_restricted_exact_host_for_conformance(&artifact_bytes)
        }
        .unwrap();
        let artifact_digest = std::ffi::CString::new(installed_digest).unwrap();
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_claim_restricted_exact_context(wrong_digest.as_ptr())
            },
            0
        );
        let context_id = unsafe {
            crate::host::abi::ex_host_claim_restricted_exact_context(artifact_digest.as_ptr())
        };
        assert_ne!(context_id, 0);
        record(
            "surface.host.abi.ex.host.claim.restricted.exact.context.13osz2b",
            "matching artifact claimed once",
            "wrong artifact digest returned zero",
        );

        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_authorize_exact_endowment(
                    context_id,
                    2,
                    manifest_digest.as_ptr(),
                    operations.as_ptr(),
                    operations.len(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_authorize_exact_endowment(
                    context_id,
                    1,
                    manifest_digest.as_ptr(),
                    operations.as_ptr(),
                    operations.len(),
                )
            },
            1
        );
        record(
            "surface.host.abi.ex.host.authorize.exact.endowment.035a1se",
            "bound app operation set authorized",
            "wrong context kind denied",
        );

        let mut copied_len = 0_u64;
        let mut copied_format = 0_u32;
        assert!(unsafe {
            crate::host::abi::ex_host_copy_restricted_exact_bundle(
                u64::MAX,
                &mut copied_len,
                &mut copied_format,
            )
        }
        .is_null());
        let copied = unsafe {
            crate::host::abi::ex_host_copy_restricted_exact_bundle(
                context_id,
                &mut copied_len,
                &mut copied_format,
            )
        };
        assert!(!copied.is_null());
        assert_eq!(copied_len as usize, bundle.len());
        assert_eq!(copied_format, 1);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(copied, copied_len as usize) },
            bundle
        );
        record(
            "surface.host.abi.ex.host.copy.restricted.exact.bundle.09bbsk3",
            "authenticated bundle copied from claimed context",
            "unknown context returned null",
        );
        crate::host::abi::ex_host_free_buffer(copied, copied_len);
        crate::host::abi::ex_host_free_buffer(std::ptr::null_mut(), 0);
        record(
            "surface.host.abi.ex.host.free.buffer.0c4fojc",
            "exact returned allocation released",
            "null zero-length release was a bounded no-op",
        );
        crate::host::abi::ex_host_release_context(context_id);
        assert_eq!(
            unsafe {
                crate::host::abi::ex_host_authorize_exact_endowment(
                    context_id,
                    1,
                    manifest_digest.as_ptr(),
                    operations.as_ptr(),
                    operations.len(),
                )
            },
            0
        );
        record(
            "surface.host.abi.ex.host.release.context.0ozp44g",
            "claimed context released",
            "released context denied later authorization",
        );

        // Reinstall for the engine-owned, single-use claim path.
        let installed_digest = unsafe {
            crate::host::abi::install_restricted_exact_host_for_conformance(&artifact_bytes)
        }
        .unwrap();
        let artifact_digest = std::ffi::CString::new(installed_digest).unwrap();
        assert!(unsafe { ex_hermes_create_restricted_exact(wrong_digest.as_ptr()) }.is_null());
        let runtime = unsafe { ex_hermes_create_restricted_exact(artifact_digest.as_ptr()) };
        assert!(!runtime.is_null());
        record(
            "surface.host.abi.ex.hermes.create.restricted.exact.0ef6yrt",
            "matching restricted artifact created runtime",
            "wrong artifact digest returned null before allocation",
        );

        let checkpoint = [7_u8, 8, 9];
        assert_eq!(
            unsafe {
                ex_hermes_configure_restricted_exact_activation(
                    runtime,
                    checkpoint.as_ptr(),
                    checkpoint.len(),
                    1234,
                    0x1234,
                    0x5678,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_hermes_configure_restricted_exact_activation(
                    runtime,
                    checkpoint.as_ptr(),
                    checkpoint.len(),
                    1234,
                    0x1234,
                    0x5678,
                )
            },
            -3
        );
        record(
            "surface.host.abi.ex.hermes.configure.restricted.exact.activation.12kr2mk",
            "single activation configured",
            "replay returned -3",
        );

        let mut premature_error = std::ptr::null_mut();
        assert_eq!(
            unsafe { ex_hermes_run_restricted_exact_bundle(runtime, &mut premature_error) },
            1
        );
        assert!(!premature_error.is_null());
        unsafe { ex_hermes_free_string(premature_error) };
        record(
            "surface.host.abi.ex.hermes.free.string.123yf3v",
            "owned refusal string released",
            "null is separately accepted as a no-op",
        );
        unsafe { ex_hermes_free_string(std::ptr::null_mut()) };

        let mut host_calls = Box::<RestrictedHostCallCapture>::default();
        assert_eq!(
            unsafe {
                ex_hermes_set_exact_host_call_async(
                    runtime,
                    2,
                    operations.as_ptr(),
                    operations.len(),
                    manifest_digest.as_ptr(),
                    resolve_restricted_host_call,
                    (&mut *host_calls as *mut RestrictedHostCallCapture).cast(),
                )
            },
            -3
        );
        assert_eq!(
            unsafe {
                ex_hermes_set_exact_host_call_async(
                    runtime,
                    1,
                    operations.as_ptr(),
                    operations.len(),
                    manifest_digest.as_ptr(),
                    resolve_restricted_host_call,
                    (&mut *host_calls as *mut RestrictedHostCallCapture).cast(),
                )
            },
            0
        );
        record(
            "surface.host.abi.ex.hermes.set.exact.host.call.async.0cynsb2",
            "bound app callback installed",
            "wrong context kind returned -3",
        );

        let mut dispatch = Vec::<u8>::new();
        let mut replacement_dispatch = Vec::<u8>::new();
        unsafe {
            ex_hermes_set_dispatch_callback(
                runtime,
                capture_dispatch,
                (&mut dispatch as *mut Vec<u8>).cast(),
            );
            ex_hermes_set_dispatch_callback(
                runtime,
                capture_dispatch,
                (&mut replacement_dispatch as *mut Vec<u8>).cast(),
            );
        }
        record(
            "surface.host.abi.ex.hermes.set.dispatch.callback.0vppy3m",
            "first dispatch sink installed",
            "replacement ignored and later received no bytes",
        );
        let mut checkpoints = Vec::<u8>::new();
        let mut replacement_checkpoints = Vec::<u8>::new();
        assert_eq!(
            unsafe {
                ex_hermes_set_restricted_exact_checkpoint_callback(
                    runtime,
                    capture_dispatch,
                    (&mut checkpoints as *mut Vec<u8>).cast(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                ex_hermes_set_restricted_exact_checkpoint_callback(
                    runtime,
                    capture_dispatch,
                    (&mut replacement_checkpoints as *mut Vec<u8>).cast(),
                )
            },
            -5
        );
        record(
            "surface.host.abi.ex.hermes.set.restricted.exact.checkpoint.callback.1p8dplw",
            "first checkpoint sink installed",
            "replacement returned -5",
        );

        assert_eq!(unsafe { ibex_test_keep_alive_on_async_error(runtime) }, 0);
        let runtime_address = runtime as usize;
        std::thread::spawn(move || unsafe {
            ex_hermes_set_keep_alive_on_async_error(runtime_address as *mut HermesRuntimeOpaque, 1)
        })
        .join()
        .unwrap();
        assert_eq!(unsafe { ibex_test_keep_alive_on_async_error(runtime) }, 0);
        unsafe { ex_hermes_set_keep_alive_on_async_error(runtime, 1) };
        assert_eq!(unsafe { ibex_test_keep_alive_on_async_error(runtime) }, 1);
        record(
            "surface.host.abi.ex.hermes.set.keep.alive.on.async.error.0pw9oqp",
            "restricted runtime policy set before execution",
            "non-owner call returned without changing policy",
        );
        let now_0 = unsafe { ex_hermes_now_ms() };
        let now_1 = unsafe { ex_hermes_now_ms() };
        assert!(now_1 >= now_0);
        record(
            "surface.host.abi.ex.hermes.now.ms.027oxfa",
            "monotonic clock read twice",
            "no caller-controlled clock input exists",
        );
        assert_eq!(unsafe { ex_hermes_next_timer(runtime) }, -1);
        assert_eq!(unsafe { ex_hermes_next_timer(std::ptr::null_mut()) }, -1);
        record(
            "surface.host.abi.ex.hermes.next.timer.0ae38c4",
            "live idle runtime returned -1",
            "null or stale drive gates also return -1",
        );
        assert_eq!(unsafe { ex_hermes_has_pending_tasks(runtime) }, 0);
        assert_eq!(
            unsafe { ex_hermes_has_pending_tasks(std::ptr::null_mut()) },
            0
        );
        record(
            "surface.host.abi.ex.hermes.has.pending.tasks.18qm35c",
            "live idle runtime returned zero",
            "null or stale drive gates return zero",
        );
        unsafe { ex_hermes_notify_callback() };
        record(
            "surface.host.abi.ex.hermes.notify.callback.1l1b7ho",
            "bounded global wake notification invoked",
            "operation accepts no runtime, generation, or caller payload",
        );

        // Unknown completion IDs are ignored before target consumption.
        unsafe { ex_hermes_resolve_exact_host_call(runtime, u64::MAX, 0, std::ptr::null(), 0) };
        let mut error = std::ptr::null_mut();
        assert_eq!(
            unsafe { ex_hermes_run_restricted_exact_bundle(runtime, &mut error) },
            0
        );
        assert!(error.is_null());
        assert_eq!(dispatch, [9]);
        assert!(replacement_dispatch.is_empty());
        assert_eq!(checkpoints, [0]);
        assert!(replacement_checkpoints.is_empty());
        assert_eq!(host_calls.calls.len(), 1);
        record(
            "surface.callback.restricted.exact.checkpoint.output.1al4vku",
            "initial checkpoint reached the first immutable sink",
            "replacement sink received no bytes",
        );
        record(
            "surface.host.abi.ex.hermes.resolve.exact.host.call.081d2k5",
            "matching call target consumed and queued",
            "unknown call ID was ignored",
        );
        record(
            "surface.host.abi.ex.hermes.run.restricted.exact.bundle.1y309kh",
            "authenticated bundle ran once",
            "premature run refused before callbacks",
        );

        assert!(unsafe { ex_hermes_poll(runtime, now_1) } >= 1);
        record(
            "surface.host.abi.ex.hermes.poll.02ylspu",
            "owner poll delivered queued completion",
            "poisoned runtime later returned -1",
        );
        let payload = std::ffi::CString::new("{}").unwrap();
        assert_eq!(
            unsafe { ex_hermes_dispatch_event(runtime, 5, payload.as_ptr()) },
            0
        );
        let malformed = std::ffi::CString::new("{").unwrap();
        assert_eq!(
            unsafe { ex_hermes_dispatch_event(runtime, 5, malformed.as_ptr()) },
            -1
        );
        assert_eq!(
            unsafe { ex_hermes_dispatch_event(runtime, 5, payload.as_ptr()) },
            -1
        );
        record(
            "surface.host.abi.ex.hermes.dispatch.event.0lbx6vi",
            "valid event published one successor checkpoint",
            "malformed event poisoned runtime and post-poison event returned -1",
        );
        assert_eq!(unsafe { ex_hermes_poll(runtime, now_1) }, -1);

        let mut replay_error = std::ptr::null_mut();
        assert_eq!(
            unsafe { ex_hermes_run_restricted_exact_bundle(runtime, &mut replay_error) },
            1
        );
        assert!(!replay_error.is_null());
        unsafe { ex_hermes_free_string(replay_error) };
        assert_eq!(unsafe { ibex_test_runtime_registered(runtime) }, 1);
        unsafe { ex_hermes_destroy(runtime) };
        assert_eq!(unsafe { ibex_test_runtime_registered(runtime) }, 0);
        record(
            "surface.host.abi.ex.hermes.destroy.0m27uxn",
            "runtime destroyed after poisoned lifecycle",
            "teardown removes runtime registry and Host context ownership",
        );

        assert_eq!(proofs.len(), control_ids.len());
        assert_eq!(
            proofs
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            control_ids
        );

        if let Ok(output_path) = std::env::var("IBEX_RESTRICTED_CONTROL_EVIDENCE_OUTPUT") {
            assert!(
                !cfg!(debug_assertions),
                "restricted evidence publication requires a release build"
            );
            let git = |args: &[&str]| {
                let output = std::process::Command::new("git")
                    .args(args)
                    .output()
                    .unwrap_or_else(|error| panic!("run git {}: {error}", args.join(" ")));
                assert!(
                    output.status.success(),
                    "git {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr)
                );
                output.stdout
            };
            assert!(
                git(&["status", "--porcelain", "--untracked-files=no"]).is_empty(),
                "restricted evidence run requires a clean tracked source tree"
            );
            let source_revision = String::from_utf8(git(&["rev-parse", "HEAD"]))
                .unwrap()
                .trim()
                .to_owned();
            let source_tree_bytes = git(&["rev-parse", "HEAD^{tree}"]);
            let tagged_digest = |bytes: &[u8]| {
                format!(
                    "sha256-{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
                )
            };
            let engine = crate::engine::loaded_engine_binary_identity()
                .expect("attest loaded engine for restricted control evidence");
            crate::engine::verify_loaded_engine_binary_identity(&engine)
                .expect("reverify loaded engine for restricted control evidence");
            let provenance_path = std::env::var_os("HERMES_PROFILE_PROVENANCE_RECEIPT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("ios/Frameworks/hermes-profile-provenance.json")
                });
            let provenance_bytes = std::fs::read(&provenance_path)
                .expect("read Hermes profile provenance for restricted control evidence");
            let provenance: serde_json::Value = serde_json::from_slice(&provenance_bytes)
                .expect("parse Hermes profile provenance for restricted control evidence");
            let observations = proofs
                .iter()
                .map(|(edge_id, proof)| {
                    serde_json::json!({
                        "edgeId": edge_id,
                        "kind": "control-plane-negative",
                        "outcome": "passed",
                        "observedIdentity": observed_identities[edge_id],
                        "proof": proof,
                    })
                })
                .collect::<Vec<_>>();
            let mut nonce = [0_u8; 16];
            getrandom::getrandom(&mut nonce).expect("mint restricted control evidence run ID");
            let run_id = nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let target_triple =
                std::env::var("IBEX_RESTRICTED_TARGET_TRIPLE").unwrap_or_else(|_| {
                    match (std::env::consts::ARCH, std::env::consts::OS) {
                        ("aarch64", "macos") => "aarch64-apple-darwin".to_owned(),
                        ("x86_64", "linux") => "x86_64-unknown-linux-gnu".to_owned(),
                        (arch, os) => format!("{arch}-unknown-{os}"),
                    }
                });
            let artifact = serde_json::json!({
                "evidenceSchema": "ibex/restricted-profile-control-evidence/1",
                "profile": "ibex/exact-embedder-contract/1",
                "runId": format!("restricted-control-{run_id}"),
                "sourceRevision": source_revision,
                "sourceTreeDigest": tagged_digest(&source_tree_bytes),
                "target": {"triple": target_triple, "features": engine.structural_features.clone()},
                "engine": engine,
                "hermesProfileProvenance": {
                    "path": provenance_path,
                    "rawContentDigest": tagged_digest(&provenance_bytes),
                    "receipt": provenance,
                },
                "authorityDigests": {
                    "definitionRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/registry/restricted-exact-profile-definition.json"))),
                    "projectionRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/generated/restricted-exact-profile-projection.json"))),
                    "coverageRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/registry/coverage-edges.json"))),
                    "implementationManifestRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/generated/implementation-manifest.json"))),
                    "fixturePlanRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/registry/restricted-exact-fixture-plan.json"))),
                    "reportSchemaRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/schema/restricted-profile-target-report.schema.json"))),
                },
                "command": [
                    "cargo", "test", "-p", "ibex-runtime", "--release",
                    "--features", "capsec-conformance-observer",
                    "restricted_exact_control_plane_edges_enforce_lifecycle_refusals",
                    "--", "--nocapture",
                ],
                "exitCode": 0,
                "resultMarker": "ibex-restricted-control-evidence:passed",
                "observations": observations,
            });
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output_path)
                .expect("create restricted control evidence output");
            serde_json::to_writer_pretty(&mut output, &artifact)
                .expect("serialize restricted control evidence");
            output
                .write_all(b"\n")
                .expect("finish restricted control evidence");
        }
    }

    #[test]
    fn restricted_exact_structural_absences_match_live_root_reachability() {
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
          exact.publishCheckpoint(new Uint8Array([0]));
        })();"#;
        let (runtime, _dispatch, _checkpoints) =
            unsafe { configured_restricted_exact_runtime(bundle) };
        let root_manifest: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/root-global-disposition-manifest.json"
        )))
        .unwrap();
        let projection: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/restricted-exact-profile-projection.json"
        )))
        .unwrap();
        let dispositions = projection["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let row = row.as_array().unwrap();
                (
                    row[0].as_str().unwrap().to_owned(),
                    row[1].as_str().unwrap().to_owned(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();

        let mut reachable_paths = std::collections::BTreeMap::<String, Vec<String>>::new();
        for row in root_manifest["rows"].as_array().unwrap() {
            let root = &row["property"]["root"];
            if root["kind"].as_str() != Some("string") {
                continue;
            }
            let mut segments = vec![root["value"].as_str().unwrap().to_owned()];
            for segment in row["property"]["path"].as_array().unwrap() {
                if segment["kind"].as_str() != Some("string") {
                    break;
                }
                segments.push(segment["value"].as_str().unwrap().to_owned());
            }
            let path = segments.join(".");
            let path_c = std::ffi::CString::new(path.as_str()).unwrap();
            if unsafe { ibex_test_root_global_logical_path_absent(runtime, path_c.as_ptr()) } == 0 {
                reachable_paths
                    .entry(row["registryEdgeId"].as_str().unwrap().to_owned())
                    .or_default()
                    .push(path);
            }
        }
        unsafe { ex_hermes_destroy(runtime) };

        let mismatches = reachable_paths
            .into_iter()
            .filter(|(edge_id, _)| {
                dispositions.get(edge_id).map(String::as_str) == Some("structurally-absent")
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert!(
            mismatches.is_empty(),
            "restricted Exact projection marks live root paths structurally absent:\n{}",
            serde_json::to_string_pretty(&mismatches).unwrap()
        );
    }

    #[test]
    fn restricted_exact_absence_edges_close_source_and_live_routes() {
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
          exact.publishCheckpoint(new Uint8Array([0]));
        })();"#;
        unsafe { ibex_test_reset_exact_host_completion_observer() };
        let (runtime, _dispatch, _checkpoints) =
            unsafe { configured_restricted_exact_runtime(bundle) };
        unsafe {
            let mut error = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_run_restricted_exact_bundle(runtime, &mut error),
                0
            );
            assert!(error.is_null());
        }

        let projection: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/restricted-exact-profile-projection.json"
        )))
        .unwrap();
        let absent_ids = projection["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| {
                let row = row.as_array().unwrap();
                (row[1].as_str() == Some("structurally-absent"))
                    .then(|| row[0].as_str().unwrap().to_owned())
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(absent_ids.len(), 7152);
        let coverage: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/coverage-edges.json"
        )))
        .unwrap();
        let edges = coverage["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| (edge["id"].as_str().unwrap().to_owned(), edge.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        let implementation: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/implementation-manifest.json"
        )))
        .unwrap();
        let mut implementations =
            std::collections::BTreeMap::<String, Vec<serde_json::Value>>::new();
        for surface in implementation["surfaces"].as_array().unwrap() {
            implementations
                .entry(surface["edgeId"].as_str().unwrap().to_owned())
                .or_default()
                .push(serde_json::json!({
                    "branchId": surface["branchId"],
                    "enforcementBranchId": surface["enforcementBranchId"],
                    "sourceRefs": surface["sourceRefs"],
                    "targetApplicability": surface["targetApplicability"],
                }));
        }

        let root_manifest: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/root-global-disposition-manifest.json"
        )))
        .unwrap();
        let mut descriptor_prefixes =
            std::collections::BTreeMap::<String, Vec<serde_json::Value>>::new();
        for row in root_manifest["rows"].as_array().unwrap() {
            let edge_id = row["registryEdgeId"].as_str().unwrap();
            if !absent_ids.contains(edge_id) {
                continue;
            }
            let root = &row["property"]["root"];
            if root["kind"].as_str() != Some("string") {
                continue;
            }
            let mut segments = vec![root["value"].as_str().unwrap().to_owned()];
            let mut unresolved_segment = None;
            for segment in row["property"]["path"].as_array().unwrap() {
                if segment["kind"].as_str() != Some("string") {
                    unresolved_segment = Some(serde_json::json!({
                        "kind": segment["kind"],
                        "value": segment["value"],
                    }));
                    break;
                }
                segments.push(segment["value"].as_str().unwrap().to_owned());
            }
            let path = segments.join(".");
            let path_c = std::ffi::CString::new(path.as_str()).unwrap();
            assert_eq!(
                unsafe { ibex_test_root_global_logical_path_absent(runtime, path_c.as_ptr()) },
                1,
                "restricted descriptor prefix unexpectedly resolved for {edge_id}: {path}"
            );
            descriptor_prefixes
                .entry(edge_id.to_owned())
                .or_default()
                .push(serde_json::json!({
                    "path": path,
                    "unresolvedSegment": unresolved_segment,
                }));
        }

        let forbidden_roots = [
            "Atomics",
            "Bun",
            "Deno",
            "Exact",
            "Ibex",
            "SharedArrayBuffer",
            "WebAssembly",
            "WebSocket",
            "XMLHttpRequest",
            "__compartments",
            "__exactCapabilityCheck",
            "__exactGetEnv",
            "__exactResolveModule",
            "__exactTimerRef",
            "__exactTimerUnref",
            "__hostCall",
            "__hostCallAsync",
            "fetch",
            "process",
            "require",
        ];
        let forbidden_root_results = forbidden_roots
            .iter()
            .map(|root| {
                let root_c = std::ffi::CString::new(*root).unwrap();
                let absent =
                    unsafe { ibex_test_root_global_logical_path_absent(runtime, root_c.as_ptr()) };
                assert_eq!(absent, 1, "restricted ambient root resolved: {root}");
                serde_json::json!({"path": root, "absent": true})
            })
            .collect::<Vec<_>>();
        assert_eq!(
            unsafe { ibex_test_restricted_exact_conformance_trace(runtime) },
            0x1ff
        );
        let mut targets_consumed = 0;
        let mut callbacks_queued = 0;
        let mut callbacks_delivered = 0;
        assert_eq!(
            unsafe {
                ibex_test_exact_host_completion_observation(
                    &mut targets_consumed,
                    &mut callbacks_queued,
                    &mut callbacks_delivered,
                )
            },
            1
        );
        assert_eq!(
            (targets_consumed, callbacks_queued, callbacks_delivered),
            (0, 0, 0)
        );
        unsafe { ex_hermes_destroy(runtime) };

        let barrier_for = |kind: &str| match kind {
            "builtin" | "loader" | "cli" => "no-general-loader-or-cli-root",
            "host-abi" => "no-javascript-native-abi-bridge",
            "startup" => "not-selected-by-restricted-bootstrap",
            "callback" => "no-installed-producer-or-retained-callback",
            "native-op" => "descriptor-path-or-ambient-installer-absent",
            _ => panic!("unexpected absent surface kind {kind}"),
        };
        let barrier_attestation = serde_json::json!({
            "observer": "exact-engine-closed-world-barriers",
            "forbiddenRoots": forbidden_root_results,
            "restrictedStartupTrace": 0x1ff_u64,
            "completionObserver": {
                "targetsConsumed": targets_consumed,
                "callbacksQueued": callbacks_queued,
                "callbacksDelivered": callbacks_delivered,
            },
            "descriptorProbedEdges": descriptor_prefixes.len(),
        });
        let barrier_bytes =
            capsec_semantics::canonical::to_jcs_bytes(&barrier_attestation).unwrap();
        let barrier_digest = format!(
            "sha256-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&barrier_bytes))
        );

        let mut observations = Vec::<serde_json::Value>::with_capacity(absent_ids.len() * 2);
        for edge_id in &absent_ids {
            let edge = &edges[edge_id];
            let kind = edge["surface"]["kind"].as_str().unwrap();
            let identity = format!("{}:{}", kind, edge["surface"]["name"].as_str().unwrap());
            let branches = implementations
                .get(edge_id)
                .unwrap_or_else(|| panic!("missing implementation rows for {edge_id}"));
            observations.push(serde_json::json!({
                "edgeId": edge_id,
                "kind": "source-install",
                "outcome": "passed",
                "observedIdentity": identity,
                "proof": {
                    "observer": "source-install-closure",
                    "surfaceKind": kind,
                    "barrier": barrier_for(kind),
                    "barrierAttestationDigest": barrier_digest,
                    "implementationBranches": branches,
                },
            }));
            observations.push(serde_json::json!({
                "edgeId": edge_id,
                "kind": "live-reachability",
                "outcome": "passed",
                "observedIdentity": identity,
                "proof": {
                    "observer": "exact-engine-reachability",
                    "surfaceKind": kind,
                    "barrier": barrier_for(kind),
                    "barrierAttestationDigest": barrier_digest,
                    "descriptorPrefixes": descriptor_prefixes.get(edge_id).cloned().unwrap_or_default(),
                },
            }));
        }
        observations.sort_by(|left, right| {
            (left["edgeId"].as_str(), left["kind"].as_str())
                .cmp(&(right["edgeId"].as_str(), right["kind"].as_str()))
        });
        assert_eq!(observations.len(), 14_304);

        if let Ok(output_path) = std::env::var("IBEX_RESTRICTED_ABSENCE_EVIDENCE_OUTPUT") {
            assert!(
                !cfg!(debug_assertions),
                "restricted evidence publication requires a release build"
            );
            let git = |args: &[&str]| {
                let output = std::process::Command::new("git")
                    .args(args)
                    .output()
                    .unwrap_or_else(|error| panic!("run git {}: {error}", args.join(" ")));
                assert!(
                    output.status.success(),
                    "git {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr)
                );
                output.stdout
            };
            assert!(
                git(&["status", "--porcelain", "--untracked-files=no"]).is_empty(),
                "restricted evidence run requires a clean tracked source tree"
            );
            let source_revision = String::from_utf8(git(&["rev-parse", "HEAD"]))
                .unwrap()
                .trim()
                .to_owned();
            let source_tree_bytes = git(&["rev-parse", "HEAD^{tree}"]);
            let tagged_digest = |bytes: &[u8]| {
                format!(
                    "sha256-{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
                )
            };
            let engine = crate::engine::loaded_engine_binary_identity()
                .expect("attest loaded engine for restricted absence evidence");
            crate::engine::verify_loaded_engine_binary_identity(&engine)
                .expect("reverify loaded engine for restricted absence evidence");
            let provenance_path = std::env::var_os("HERMES_PROFILE_PROVENANCE_RECEIPT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("ios/Frameworks/hermes-profile-provenance.json")
                });
            let provenance_bytes = std::fs::read(&provenance_path)
                .expect("read Hermes profile provenance for restricted absence evidence");
            let provenance: serde_json::Value = serde_json::from_slice(&provenance_bytes)
                .expect("parse Hermes profile provenance for restricted absence evidence");
            let mut nonce = [0_u8; 16];
            getrandom::getrandom(&mut nonce).expect("mint restricted absence evidence run ID");
            let run_id = nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let target_triple =
                std::env::var("IBEX_RESTRICTED_TARGET_TRIPLE").unwrap_or_else(|_| {
                    match (std::env::consts::ARCH, std::env::consts::OS) {
                        ("aarch64", "macos") => "aarch64-apple-darwin".to_owned(),
                        ("x86_64", "linux") => "x86_64-unknown-linux-gnu".to_owned(),
                        (arch, os) => format!("{arch}-unknown-{os}"),
                    }
                });
            let artifact = serde_json::json!({
                "evidenceSchema": "ibex/restricted-profile-absence-evidence/1",
                "profile": "ibex/exact-embedder-contract/1",
                "runId": format!("restricted-absence-{run_id}"),
                "sourceRevision": source_revision,
                "sourceTreeDigest": tagged_digest(&source_tree_bytes),
                "target": {"triple": target_triple, "features": engine.structural_features.clone()},
                "engine": engine,
                "hermesProfileProvenance": {
                    "path": provenance_path,
                    "rawContentDigest": tagged_digest(&provenance_bytes),
                    "receipt": provenance,
                },
                "authorityDigests": {
                    "definitionRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/registry/restricted-exact-profile-definition.json"))),
                    "projectionRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/generated/restricted-exact-profile-projection.json"))),
                    "coverageRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/registry/coverage-edges.json"))),
                    "implementationManifestRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/generated/implementation-manifest.json"))),
                    "fixturePlanRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/registry/restricted-exact-fixture-plan.json"))),
                    "reportSchemaRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/schema/restricted-profile-target-report.schema.json"))),
                },
                "barrierAttestation": barrier_attestation,
                "barrierAttestationDigest": barrier_digest,
                "command": [
                    "cargo", "test", "-p", "ibex-runtime", "--lib", "--release",
                    "--features", "capsec-conformance-observer",
                    "restricted_exact_absence_edges_close_source_and_live_routes",
                    "--", "--exact", "--nocapture", "--test-threads=1",
                ],
                "exitCode": 0,
                "resultMarker": "ibex-restricted-absence-evidence:passed",
                "observations": observations,
            });
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output_path)
                .expect("create restricted absence evidence output");
            serde_json::to_writer_pretty(&mut output, &artifact)
                .expect("serialize restricted absence evidence");
            output
                .write_all(b"\n")
                .expect("finish restricted absence evidence");
        }
    }

    #[test]
    fn restricted_exact_reachable_edges_execute_on_the_bound_engine() {
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

        let projection: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/restricted-exact-profile-projection.json"
        )))
        .unwrap();
        let reachable_ids = projection["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| {
                let row = row.as_array().unwrap();
                (row[1].as_str() == Some("reachable")).then(|| row[0].as_str().unwrap().to_owned())
            })
            .collect::<std::collections::BTreeSet<_>>();
        let native_ids = reachable_ids
            .iter()
            .filter(|id| id.starts_with("surface.native.op."))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let startup_ids = reachable_ids
            .iter()
            .filter(|id| id.starts_with("surface.startup."))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let callback_ids = reachable_ids
            .iter()
            .filter(|id| id.starts_with("surface.callback."))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(native_ids.len(), 115);
        let startup_trace_edges = [
            "surface.startup.runtime.create.09gd22j",
            "surface.startup.install.route.ex.hermes.create.impl.installrestrictedexactglobals.17p1el8",
            "surface.startup.installer.installrestrictedexactglobals.17llg9x",
            "surface.startup.install.route.installrestrictedexactglobals.installtimerglobals.1kww2tg",
            "surface.startup.installer.installtimerglobals.1qth84q",
            "surface.startup.script.restricted.exact.lockdown.1wpbysw",
            "surface.startup.evaluation.installrestrictedexactglobals.restricted.exact.lockdown.0xlst78",
            "surface.startup.script.authenticated.restricted.exact.bundle.1v2bh2d",
            "surface.startup.evaluation.ex.hermes.run.restricted.exact.bundle.authenticated.restricte.1e57hbx",
        ];
        assert_eq!(
            startup_ids,
            startup_trace_edges
                .into_iter()
                .map(str::to_owned)
                .collect::<std::collections::BTreeSet<_>>()
        );
        assert_eq!(
            callback_ids,
            [
                "surface.callback.exact.host.call.async.resolve.0f9z2o3",
                "surface.callback.producer.src.engine.hermes.runtime.cc.ex.hermes.resolve.exact.host.call.0n49v9x",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<std::collections::BTreeSet<_>>()
        );

        let root_manifest: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/root-global-disposition-manifest.json"
        )))
        .unwrap();
        let coverage: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/coverage-edges.json"
        )))
        .unwrap();
        let observed_identities = coverage["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| {
                (
                    edge["id"].as_str().unwrap().to_owned(),
                    format!(
                        "{}:{}",
                        edge["surface"]["kind"].as_str().unwrap(),
                        edge["surface"]["name"].as_str().unwrap()
                    ),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut probes = std::collections::BTreeMap::<String, serde_json::Value>::new();
        for row in root_manifest["rows"].as_array().unwrap() {
            let edge_id = row["registryEdgeId"].as_str().unwrap();
            if !native_ids.contains(edge_id) || probes.contains_key(edge_id) {
                continue;
            }
            let root = &row["property"]["root"];
            assert_eq!(root["kind"].as_str(), Some("string"), "{edge_id}");
            let mut path = row["property"]["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|segment| {
                    assert_eq!(segment["kind"].as_str(), Some("string"), "{edge_id}");
                    segment["value"].as_str().unwrap().to_owned()
                })
                .collect::<Vec<_>>();
            // The root-global authority preserves these two historical
            // display paths as dot-split strings. Reconstitute the symbol key
            // for the live engine probe; the exact registry edge ID remains
            // the evidence identity.
            if edge_id == "surface.native.op.global.iterator.prototype.symbol.iterator.0k8w72b" {
                path = vec!["prototype".to_owned(), "[[Symbol.iterator]]".to_owned()];
            } else if edge_id
                == "surface.native.op.global.iterator.prototype.symbol.tostringtag.0qheaf3"
            {
                path = vec!["prototype".to_owned(), "[[Symbol.toStringTag]]".to_owned()];
            }
            probes.insert(
                edge_id.to_owned(),
                serde_json::json!({
                    "edgeId": edge_id,
                    "root": root["value"].as_str().unwrap(),
                    "path": path,
                }),
            );
        }
        assert_eq!(probes.len(), native_ids.len());

        let mut bundle = br#"((specs) => {
          'use strict';
          const results = [];
          const ingress = exact.takeCheckpointBytes();
          if (!(ingress instanceof Uint8Array)) throw new Error('checkpoint ingress was not bytes');

          const keyFor = (segment) => {
            if (segment === '[[Symbol.iterator]]') return Symbol.iterator;
            if (segment === '[[Symbol.toStringTag]]') return Symbol.toStringTag;
            return segment;
          };
          const descriptorFor = (object, key) => {
            for (let cursor = object; cursor !== null; cursor = Object.getPrototypeOf(cursor)) {
              const descriptor = Object.getOwnPropertyDescriptor(cursor, key);
              if (descriptor !== undefined) return descriptor;
            }
            return undefined;
          };
          const resolve = (spec) => {
            const segments = [spec.root, ...spec.path];
            let receiver = globalThis;
            let value = globalThis;
            for (let index = 0; index < segments.length; index += 1) {
              receiver = value;
              if ((typeof receiver !== 'object' || receiver === null) && typeof receiver !== 'function') {
                throw new Error(`non-object receiver before ${segments[index]}`);
              }
              const key = keyFor(segments[index]);
              const descriptor = descriptorFor(receiver, key);
              if (descriptor === undefined) throw new Error(`missing ${segments[index]}`);
              if ('value' in descriptor) {
                value = descriptor.value;
              } else {
                if (typeof descriptor.get !== 'function') {
                  return {receiver, value: undefined, accessor: 'observed-no-getter'};
                }
                try {
                  value = Reflect.apply(descriptor.get, receiver, []);
                } catch (error) {
                  return {receiver, value: descriptor.get, accessor: 'invoked-threw', error};
                }
                if (index === segments.length - 1) {
                  return {receiver, value, accessor: 'invoked-returned'};
                }
              }
            }
            return {receiver, value, accessor: null};
          };
          const logicalPath = (spec) => [spec.root, ...spec.path].join('.');
          const invoke = (spec, value, defaultReceiver) => {
            const path = logicalPath(spec);
            let receiver = defaultReceiver;
            let args = [];
            if (path === 'exact.invokeHostAsync') {
              const promise = Reflect.apply(value, receiver, [1000, new Uint8Array([1, 2, 3])]);
              promise.then(() => {}, () => {});
              return;
            }
            if (path === 'exact.dispatch') args = [new Uint8Array([9])];
            else if (path === 'atob' || path === 'btoa') args = [''];
            else if (path === 'clearInterval' || path === 'clearTimeout') args = [0];
            else if (path === 'setInterval' || path === 'setTimeout' || path === 'queueMicrotask') args = [null, 0];
            else if (path === 'Intl.getCanonicalLocales') args = [[]];
            else if (path.endsWith('.supportedLocalesOf')) args = [[]];
            else if (path === 'Promise.reject') {
              const promise = Reflect.apply(value, Promise, ['restricted-conformance']);
              promise.catch(() => {});
              return;
            } else if (path.startsWith('Promise.prototype.')) {
              receiver = Promise.resolve(1);
              args = path.endsWith('.then')
                ? [() => {}, () => {}]
                : [() => {}];
            } else if (path === 'Intl.DateTimeFormat.prototype.formatToParts') {
              receiver = new Intl.DateTimeFormat('en-US');
              args = [new Date(0)];
            } else if (path.endsWith('.prototype.subarray')) {
              receiver = new globalThis[spec.root](0);
              args = [0, 0];
            } else if (path === 'Iterator.from') {
              args = [[]];
            } else if (path.startsWith('Iterator.prototype.')) {
              receiver = Iterator.from([]);
              if (path.endsWith('.map') || path.endsWith('.filter') || path.endsWith('.flatMap')) args = [(value) => [value]];
              else if (path.endsWith('.every') || path.endsWith('.some') || path.endsWith('.find') || path.endsWith('.forEach')) args = [() => true];
              else if (path.endsWith('.reduce')) args = [(left) => left, 0];
              else if (path.endsWith('.drop') || path.endsWith('.take')) args = [0];
            }
            Reflect.apply(value, receiver, args);
          };

          let publishEdge = null;
          for (const spec of specs) {
            const path = logicalPath(spec);
            if (path === 'exact.takeCheckpointBytes') {
              results.push({edgeId: spec.edgeId, status: 'invoked-returned'});
              continue;
            }
            if (path === 'exact.publishCheckpoint') {
              publishEdge = spec.edgeId;
              continue;
            }
            try {
              const resolved = resolve(spec);
              if (resolved.accessor !== null) {
                results.push({
                  edgeId: spec.edgeId,
                  status: resolved.accessor,
                  valueType: typeof resolved.value,
                });
              } else if (typeof resolved.value === 'function') {
                try {
                  invoke(spec, resolved.value, resolved.receiver);
                  results.push({edgeId: spec.edgeId, status: 'invoked-returned'});
                } catch (error) {
                  results.push({edgeId: spec.edgeId, status: 'invoked-threw', errorName: error?.name ?? 'Error'});
                }
              } else {
                results.push({edgeId: spec.edgeId, status: 'observed-noncallable', valueType: typeof resolved.value});
              }
            } catch (error) {
              results.push({edgeId: spec.edgeId, status: 'unresolved', errorName: error?.name ?? 'Error'});
            }
          }
          if (publishEdge === null) throw new Error('publishCheckpoint edge missing from probe plan');
          results.push({edgeId: publishEdge, status: 'invoked-returned'});
          const payload = new TextEncoder().encode(JSON.stringify(results));
          exact.publishCheckpoint(payload);
        })("#
            .to_vec();
        bundle.extend_from_slice(
            serde_json::to_string(&probes.values().collect::<Vec<_>>())
                .unwrap()
                .as_bytes(),
        );
        bundle.extend_from_slice(b");");

        let mut host_calls = Box::<RestrictedHostCallCapture>::default();
        unsafe { ibex_test_reset_exact_host_completion_observer() };
        let (runtime, dispatch, checkpoints) = unsafe {
            configured_restricted_exact_runtime_with_host_callback(
                &bundle,
                resolve_restricted_host_call,
                (&mut *host_calls as *mut RestrictedHostCallCapture).cast(),
            )
        };
        unsafe {
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
            assert_eq!(ibex_test_restricted_exact_conformance_trace(runtime), 0x1ff);
            assert_eq!(dispatch.as_slice(), [9]);
            assert_eq!(host_calls.calls.len(), 1);
            assert_eq!(host_calls.calls[0].1, 1000);
            assert_eq!(host_calls.calls[0].2, [1, 2, 3]);

            let results: Vec<serde_json::Value> = serde_json::from_slice(&checkpoints).unwrap();
            assert_eq!(results.len(), native_ids.len());
            let result_ids = results
                .iter()
                .map(|row| row["edgeId"].as_str().unwrap().to_owned())
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(result_ids, native_ids);
            let unresolved = results
                .iter()
                .filter(|row| row["status"].as_str() == Some("unresolved"))
                .collect::<Vec<_>>();
            assert!(
                unresolved.is_empty(),
                "reachable native edges failed exact resolution: {}",
                serde_json::to_string_pretty(&unresolved).unwrap()
            );

            assert!(ex_hermes_poll(runtime, 1234) >= 1);
            let mut targets_consumed = 0;
            let mut callbacks_queued = 0;
            let mut callbacks_delivered = 0;
            assert_eq!(
                ibex_test_exact_host_completion_observation(
                    &mut targets_consumed,
                    &mut callbacks_queued,
                    &mut callbacks_delivered,
                ),
                1
            );
            assert_eq!(
                (targets_consumed, callbacks_queued, callbacks_delivered),
                (1, 1, 1)
            );

            if let Ok(output_path) = std::env::var("IBEX_RESTRICTED_REACHABLE_EVIDENCE_OUTPUT") {
                assert!(
                    !cfg!(debug_assertions),
                    "restricted evidence publication requires a release build"
                );
                let git = |args: &[&str]| {
                    let output = std::process::Command::new("git")
                        .args(args)
                        .output()
                        .unwrap_or_else(|error| panic!("run git {}: {error}", args.join(" ")));
                    assert!(
                        output.status.success(),
                        "git {} failed: {}",
                        args.join(" "),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    output.stdout
                };
                assert!(
                    git(&["status", "--porcelain", "--untracked-files=no"]).is_empty(),
                    "restricted evidence run requires a clean tracked source tree"
                );
                let source_revision = String::from_utf8(git(&["rev-parse", "HEAD"]))
                    .unwrap()
                    .trim()
                    .to_owned();
                let source_tree_bytes = git(&["rev-parse", "HEAD^{tree}"]);
                let tagged_digest = |bytes: &[u8]| {
                    format!(
                        "sha256-{}",
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(Sha256::digest(bytes))
                    )
                };
                let engine = crate::engine::loaded_engine_binary_identity()
                    .expect("attest loaded engine for restricted evidence");
                crate::engine::verify_loaded_engine_binary_identity(&engine)
                    .expect("reverify loaded engine for restricted evidence");
                let provenance_path = std::env::var_os("HERMES_PROFILE_PROVENANCE_RECEIPT")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| {
                        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join("ios/Frameworks/hermes-profile-provenance.json")
                    });
                let provenance_bytes = std::fs::read(&provenance_path)
                    .expect("read Hermes profile provenance for restricted evidence");
                let provenance: serde_json::Value = serde_json::from_slice(&provenance_bytes)
                    .expect("parse Hermes profile provenance for restricted evidence");

                let mut observations = results
                    .iter()
                    .map(|proof| {
                        let edge_id = proof["edgeId"].as_str().unwrap();
                        serde_json::json!({
                            "edgeId": edge_id,
                            "kind": "live-invocation",
                            "outcome": "passed",
                            "observedIdentity": observed_identities[edge_id],
                            "proof": proof,
                        })
                    })
                    .collect::<Vec<_>>();
                for (bit, edge_id) in startup_trace_edges.iter().enumerate() {
                    observations.push(serde_json::json!({
                        "edgeId": edge_id,
                        "kind": "live-invocation",
                        "outcome": "passed",
                        "observedIdentity": observed_identities[*edge_id],
                        "proof": {
                            "observer": "restricted-exact-startup-trace",
                            "bit": bit,
                            "trace": 0x1ff_u64,
                        },
                    }));
                }
                for (edge_id, observer) in [
                    (
                        "surface.callback.exact.host.call.async.resolve.0f9z2o3",
                        "completion-callback-delivered",
                    ),
                    (
                        "surface.callback.producer.src.engine.hermes.runtime.cc.ex.hermes.resolve.exact.host.call.0n49v9x",
                        "completion-target-consumed-and-callback-queued",
                    ),
                ] {
                    observations.push(serde_json::json!({
                        "edgeId": edge_id,
                        "kind": "live-invocation",
                        "outcome": "passed",
                        "observedIdentity": observed_identities[edge_id],
                        "proof": {
                            "observer": observer,
                            "targetsConsumed": targets_consumed,
                            "callbacksQueued": callbacks_queued,
                            "callbacksDelivered": callbacks_delivered,
                        },
                    }));
                }
                observations
                    .sort_by(|left, right| left["edgeId"].as_str().cmp(&right["edgeId"].as_str()));
                assert_eq!(observations.len(), reachable_ids.len());

                let mut nonce = [0_u8; 16];
                getrandom::getrandom(&mut nonce).expect("mint restricted evidence run ID");
                let run_id = nonce
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let authority_digests = serde_json::json!({
                    "definitionRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/registry/restricted-exact-profile-definition.json"))),
                    "projectionRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/generated/restricted-exact-profile-projection.json"))),
                    "coverageRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/registry/coverage-edges.json"))),
                    "implementationManifestRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/generated/implementation-manifest.json"))),
                    "fixturePlanRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/registry/restricted-exact-fixture-plan.json"))),
                    "reportSchemaRawContentDigest": tagged_digest(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/schema/restricted-profile-target-report.schema.json"))),
                });
                let target_triple =
                    std::env::var("IBEX_RESTRICTED_TARGET_TRIPLE").unwrap_or_else(|_| {
                        match (std::env::consts::ARCH, std::env::consts::OS) {
                            ("aarch64", "macos") => "aarch64-apple-darwin".to_owned(),
                            ("x86_64", "linux") => "x86_64-unknown-linux-gnu".to_owned(),
                            (arch, os) => format!("{arch}-unknown-{os}"),
                        }
                    });
                let artifact = serde_json::json!({
                    "evidenceSchema": "ibex/restricted-profile-reachable-evidence/1",
                    "profile": "ibex/exact-embedder-contract/1",
                    "runId": format!("restricted-reachable-{run_id}"),
                    "sourceRevision": source_revision,
                    "sourceTreeDigest": tagged_digest(&source_tree_bytes),
                    "target": {
                        "triple": target_triple,
                        "features": engine.structural_features.clone(),
                    },
                    "engine": engine,
                    "hermesProfileProvenance": {
                        "path": provenance_path,
                        "rawContentDigest": tagged_digest(&provenance_bytes),
                        "receipt": provenance,
                    },
                    "authorityDigests": authority_digests,
                    "command": [
                        "cargo", "test", "-p", "ibex-runtime", "--release",
                        "--features", "capsec-conformance-observer",
                        "restricted_exact_reachable_edges_execute_on_the_bound_engine",
                        "--", "--nocapture",
                    ],
                    "exitCode": 0,
                    "resultMarker": "ibex-restricted-reachable-evidence:passed",
                    "observations": observations,
                });
                let mut output = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output_path)
                    .expect("create restricted reachable evidence output");
                serde_json::to_writer_pretty(&mut output, &artifact)
                    .expect("serialize restricted reachable evidence");
                output
                    .write_all(b"\n")
                    .expect("finish restricted reachable evidence");
            }
            ex_hermes_destroy(runtime);
        }

        // The real engine observations above cover every reachable projection
        // class: 115 JS/native identities, nine startup edges, and the two
        // native completion callback edges.
        assert_eq!(native_ids.len() + 9 + 2, reachable_ids.len());
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
