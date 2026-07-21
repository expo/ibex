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
use std::path::{Path, PathBuf};

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
struct RestrictedTargetAdvertisementAuthority {
    advertisement_schema: String,
    profile: String,
    projection_raw_content_digest: Digest,
    advertisements: Vec<RestrictedTargetAdvertisement>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestrictedTargetAdvertisement {
    target: RestrictedAdvertisedTarget,
    report_digest: Digest,
    report_raw_content_digest: Digest,
    source_revision: String,
    source_tree_digest: Digest,
    engine_binary_digest: Digest,
    projection_raw_content_digest: Digest,
    fixture_plan_raw_content_digest: Digest,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestrictedAdvertisedTarget {
    triple: String,
    features: Vec<String>,
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
    advertised: bool,
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

    pub fn is_advertised(&self) -> bool {
        self.advertised
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
    materialize_protected_artifact_at(&cache_root, role, bytes, digest)
}

fn materialize_protected_artifact_at(
    cache_root: &Path,
    role: &str,
    bytes: &[u8],
    digest: &Digest,
) -> Result<MaterializedArtifact> {
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

/// Authenticate an embedder-supplied cache root before it becomes the parent
/// of protected restricted-profile artifacts. The cell supervisor creates
/// this directory before worker launch; Ibex never derives it from an ambient
/// home or cache environment.
///
/// @ref LLP 0033#6-authenticated-contract-code-ingress — restricted code
/// ingress cannot fall back to cwd, a host path, or an ambient loader root.
fn validate_restricted_exact_cache_root(cache_root: &Path) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(cache_root).with_context(|| {
        format!(
            "restricted Exact cache root is unavailable: {}",
            cache_root.display()
        )
    })?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "restricted Exact cache root is not a stable directory"
    );
    validate_restricted_exact_cache_root_permissions(&metadata)?;
    let canonical = std::fs::canonicalize(cache_root).with_context(|| {
        format!(
            "restricted Exact cache root cannot be canonicalized: {}",
            cache_root.display()
        )
    })?;
    let canonical_metadata = std::fs::symlink_metadata(&canonical)?;
    anyhow::ensure!(
        canonical_metadata.is_dir() && !canonical_metadata.file_type().is_symlink(),
        "restricted Exact canonical cache root is not a stable directory"
    );
    validate_restricted_exact_cache_root_permissions(&canonical_metadata)?;
    Ok(canonical)
}

#[cfg(unix)]
fn validate_restricted_exact_cache_root_permissions(metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    anyhow::ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "restricted Exact cache root is not owned by the worker uid"
    );
    anyhow::ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "restricted Exact cache root permits group or other access"
    );
    Ok(())
}

#[cfg(not(unix))]
fn validate_restricted_exact_cache_root_permissions(_metadata: &std::fs::Metadata) -> Result<()> {
    Ok(())
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

fn restricted_target_is_advertised(
    authority_bytes: &[u8],
    projection_digest: &Digest,
    target: &str,
    features: &[String],
    engine_binary_digest: &Digest,
) -> Result<bool> {
    let text = std::str::from_utf8(authority_bytes)
        .context("restricted target advertisement authority is not UTF-8")?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .context("restricted target advertisement authority is not strict JSON")?;
    let authority: RestrictedTargetAdvertisementAuthority = serde_json::from_value(value)
        .context("invalid restricted target advertisement authority")?;
    anyhow::ensure!(
        authority.advertisement_schema == "ibex/restricted-profile-advertisements/1"
            && authority.profile == "ibex/exact-embedder-contract/1"
            && authority.projection_raw_content_digest == *projection_digest,
        "restricted target advertisement authority identity mismatch"
    );

    let mut target_keys = BTreeSet::new();
    let mut matched = false;
    for advertisement in authority.advertisements {
        anyhow::ensure!(
            !advertisement.target.triple.is_empty()
                && !advertisement.target.features.is_empty()
                && advertisement
                    .target
                    .features
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && advertisement.projection_raw_content_digest == *projection_digest
                && advertisement.source_revision.len() == 40
                && advertisement
                    .source_revision
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && !advertisement.report_digest.as_str().is_empty()
                && !advertisement.report_raw_content_digest.as_str().is_empty()
                && !advertisement.source_tree_digest.as_str().is_empty()
                && !advertisement
                    .fixture_plan_raw_content_digest
                    .as_str()
                    .is_empty(),
            "restricted target advertisement row is malformed"
        );
        let key = (
            advertisement.target.triple.clone(),
            advertisement.target.features.clone(),
        );
        anyhow::ensure!(
            target_keys.insert(key),
            "restricted target advertisement authority contains duplicate targets"
        );
        if advertisement.target.triple == target && advertisement.target.features == features {
            anyhow::ensure!(
                advertisement.engine_binary_digest == *engine_binary_digest,
                "restricted target advertisement engine identity mismatch"
            );
            matched = true;
        }
    }
    Ok(matched)
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
    let projection_digest = raw_content_digest(projection_bytes)?;
    let (vocab_digest, registry_digest) = checked_identity_digests()?;
    anyhow::ensure!(
        artifact.profile_definition_raw_content_digest == raw_content_digest(definition_bytes)?
            && artifact.projection_raw_content_digest == projection_digest
            && artifact.advertisements_raw_content_digest
                == raw_content_digest(advertisements_bytes)?
            && artifact.restricted_surface_closure_digest == projection_digest
            && artifact.vocab_digest == vocab_digest
            && artifact.registry_digest == registry_digest
            && artifact.source_edge_set_digest.as_str()
                == definition["sourceEdgeSet"]["digest"]
                    .as_str()
                    .unwrap_or_default(),
        "restricted Exact artifact authority digest mismatch"
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
    let engine_binary_digest =
        Digest::new(engine.binary_digest.clone()).map_err(anyhow::Error::msg)?;
    let advertised = restricted_target_is_advertised(
        advertisements_bytes,
        &projection_digest,
        &artifact.target,
        &artifact.features,
        &engine_binary_digest,
    )?;
    let expected_status = if advertised {
        "target-advertised"
    } else {
        "candidate-unadvertised"
    };
    anyhow::ensure!(
        artifact.status == expected_status,
        "restricted Exact artifact advertisement status mismatched generated authority"
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
        advertised,
    })
}

/// Construct one immutable, target-local artifact for the restricted Exact
/// profile. It remains a candidate unless the generated report-derived
/// authority advertises this exact target, feature set, engine, and projection.
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
    let cache_root = crate::runtime_cache_dir()?;
    build_restricted_exact_embedder_artifact_at(
        &cache_root,
        operation_manifest_bytes,
        bundle_bytes,
        bundle_binding_bytes,
    )
}

/// Construct a restricted Exact artifact under an embedder-owned private
/// cache root. This is the native cell-worker path: the root must already
/// exist, must not be a symlink, and must be private to the worker uid. The
/// API does not consult HOME or any platform cache environment.
///
/// @ref LLP 0033#7-construction-and-lifecycle — the target-local worker
/// constructs and validates the fresh restricted artifact before Hermes.
pub fn build_restricted_exact_embedder_artifact_in_cache(
    cache_root: &Path,
    operation_manifest_bytes: &[u8],
    bundle_bytes: &[u8],
    bundle_binding_bytes: &[u8],
) -> Result<serde_json::Value> {
    super::reject_closed_startup_environment()?;
    let cache_root = validate_restricted_exact_cache_root(cache_root)?;
    build_restricted_exact_embedder_artifact_at(
        &cache_root,
        operation_manifest_bytes,
        bundle_bytes,
        bundle_binding_bytes,
    )
}

fn build_restricted_exact_embedder_artifact_at(
    cache_root: &Path,
    operation_manifest_bytes: &[u8],
    bundle_bytes: &[u8],
    bundle_binding_bytes: &[u8],
) -> Result<serde_json::Value> {
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
    let projection_digest = raw_content_digest(projection_bytes)?;
    anyhow::ensure!(
        definition["profile"] == "ibex/exact-embedder-contract/1"
            && projection["profile"] == definition["profile"]
            && serde_json::from_slice::<serde_json::Value>(advertisements_bytes)?["profile"]
                == definition["profile"],
        "restricted profile authority identity mismatch"
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
    let engine_binary_digest =
        Digest::new(engine.binary_digest.clone()).map_err(anyhow::Error::msg)?;
    let advertised = restricted_target_is_advertised(
        advertisements_bytes,
        &projection_digest,
        &target,
        &engine.structural_features,
        &engine_binary_digest,
    )?;
    let artifact_status = if advertised {
        "target-advertised"
    } else {
        "candidate-unadvertised"
    };
    let (vocab_digest, registry_digest) = checked_identity_digests()?;
    let source_edge_set_digest = Digest::new(
        definition["sourceEdgeSet"]["digest"]
            .as_str()
            .context("restricted profile definition lacks its source-edge-set digest")?,
    )
    .map_err(anyhow::Error::msg)?;
    let restricted_surface_closure_digest = raw_content_digest(projection_bytes)?;

    let manifest_artifact = materialize_protected_artifact_at(
        cache_root,
        "restricted-exact-operation-manifest",
        operation_manifest_bytes,
        &operation_binding.operation_manifest_digest,
    )?;
    let bundle_digest = raw_content_digest(bundle_bytes)?;
    let bundle_artifact = materialize_protected_artifact_at(
        cache_root,
        "restricted-contract-bundle",
        bundle_bytes,
        &bundle_digest,
    )?;
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
        "status": artifact_status,
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

    fn restricted_conformance_target() -> serde_json::Value {
        let triple = std::env::var("IBEX_RESTRICTED_TARGET_TRIPLE").unwrap_or_else(|_| {
            match (std::env::consts::ARCH, std::env::consts::OS) {
                ("aarch64", "macos") => "aarch64-apple-darwin".to_owned(),
                ("x86_64", "linux") => "x86_64-unknown-linux-gnu".to_owned(),
                (arch, os) => format!("{arch}-unknown-{os}"),
            }
        });
        serde_json::json!({
            "triple": triple,
            "features": [
                "hermes-frame-attribution",
                "native-compartments",
                "native-lockdown",
            ],
        })
    }

    fn effective_restricted_projection_rows() -> Vec<(String, String)> {
        let projection: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/restricted-exact-profile-projection.json"
        )))
        .unwrap();
        let definition: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/restricted-exact-profile-definition.json"
        )))
        .unwrap();
        let target = restricted_conformance_target();
        assert!(definition["candidateTargets"]
            .as_array()
            .unwrap()
            .contains(&target));
        let overrides = definition["targetDispositionOverrides"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["target"] == target)
            .map(|row| {
                (
                    row["edgeId"].as_str().unwrap().to_owned(),
                    row["disposition"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        projection["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let row = row.as_array().unwrap();
                let edge_id = row[0].as_str().unwrap().to_owned();
                let disposition = overrides
                    .get(&edge_id)
                    .cloned()
                    .unwrap_or_else(|| row[1].as_str().unwrap().to_owned());
                (edge_id, disposition)
            })
            .collect()
    }

    fn restricted_advertisement_fixture(
        projection_digest: &Digest,
        engine_digest: &Digest,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "advertisementSchema": "ibex/restricted-profile-advertisements/1",
            "profile": "ibex/exact-embedder-contract/1",
            "projectionRawContentDigest": projection_digest,
            "advertisements": [{
                "target": {
                    "triple": "x86_64-unknown-linux-gnu",
                    "features": ["release", "restricted-exact"]
                },
                "reportDigest": projection_digest,
                "reportRawContentDigest": projection_digest,
                "sourceRevision": "0123456789abcdef0123456789abcdef01234567",
                "sourceTreeDigest": projection_digest,
                "engineBinaryDigest": engine_digest,
                "projectionRawContentDigest": projection_digest,
                "fixturePlanRawContentDigest": projection_digest
            }]
        }))
        .unwrap()
    }

    #[test]
    fn restricted_production_authority_matches_target_features_engine_and_projection() {
        let projection_digest = raw_content_digest(b"projection").unwrap();
        let engine_digest = raw_content_digest(b"engine").unwrap();
        let authority = restricted_advertisement_fixture(&projection_digest, &engine_digest);
        let features = vec!["release".to_owned(), "restricted-exact".to_owned()];
        assert!(restricted_target_is_advertised(
            &authority,
            &projection_digest,
            "x86_64-unknown-linux-gnu",
            &features,
            &engine_digest,
        )
        .unwrap());

        let wrong_engine = raw_content_digest(b"wrong-engine").unwrap();
        assert!(restricted_target_is_advertised(
            &authority,
            &projection_digest,
            "x86_64-unknown-linux-gnu",
            &features,
            &wrong_engine,
        )
        .unwrap_err()
        .to_string()
        .contains("engine identity mismatch"));
    }

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
        fn ex_hermes_dispatch_restricted_exact_event(
            runtime: *mut HermesRuntimeOpaque,
            binding_json: *const std::ffi::c_char,
            payload_json: *const std::ffi::c_char,
        ) -> i32;
        fn ex_hermes_poll(runtime: *mut HermesRuntimeOpaque, now_ms: u64) -> i32;
        fn ex_hermes_free_string(value: *mut std::ffi::c_char);
        fn ex_hermes_destroy(runtime: *mut HermesRuntimeOpaque);
    }

    #[cfg(feature = "capsec-conformance-observer")]
    unsafe extern "C" {
        fn ex_hermes_has_pending_tasks(runtime: *mut HermesRuntimeOpaque) -> i32;
        fn ex_hermes_next_timer(runtime: *mut HermesRuntimeOpaque) -> i64;
        fn ex_hermes_now_ms() -> u64;
        fn ex_hermes_notify_callback();
        fn ex_hermes_set_keep_alive_on_async_error(runtime: *mut HermesRuntimeOpaque, enabled: i32);
        fn ibex_test_root_global_logical_path_absent(
            runtime: *mut HermesRuntimeOpaque,
            path: *const std::ffi::c_char,
        ) -> u32;
        fn ibex_test_root_global_logical_path_probe(
            runtime: *mut HermesRuntimeOpaque,
            path: *const std::ffi::c_char,
            undefined_terminal_is_unreachable: u32,
            out_last_resolved_segment: *mut u32,
            out_first_blocked_segment: *mut u32,
            out_boundary: *mut u32,
        ) -> u32;
        fn ibex_test_reset_exact_host_completion_observer();
        fn ibex_test_exact_host_completion_observation(
            targets_consumed: *mut u64,
            callbacks_queued: *mut u64,
            callbacks_delivered: *mut u64,
        ) -> i32;
        fn ibex_test_restricted_callback_observation(
            microtask_drains: *mut u64,
            native_principal_restores: *mut u64,
            timer_invocations: *mut u64,
        ) -> i32;
        fn ibex_test_restricted_exact_conformance_trace(runtime: *mut HermesRuntimeOpaque) -> u64;
        fn ibex_test_restricted_exact_cutset_observation(
            runtime: *mut HermesRuntimeOpaque,
            cutset: u32,
            runtime_nonce: *mut u64,
            sequence: *mut u64,
        ) -> i32;
        fn ibex_test_runtime_registered(runtime: *mut HermesRuntimeOpaque) -> i32;
        fn ibex_test_runtime_host_context_id(runtime: *mut HermesRuntimeOpaque) -> u64;
        fn ibex_test_keep_alive_on_async_error(runtime: *mut HermesRuntimeOpaque) -> i32;
        fn ibex_test_arm_exact_host_completion_pause() -> i32;
        fn ibex_test_exact_host_completion_paused() -> i32;
        fn ibex_test_release_exact_host_completion_pause() -> i32;
        fn ibex_test_structured_control_teardown_wait_observed() -> i32;
        fn ibex_test_reset_structured_control_teardown_wait_observer() -> i32;
        fn ex_hermes_runtime_nonce(runtime: *mut HermesRuntimeOpaque) -> u64;
        fn ex_hermes_resolve_exact_host_call(
            runtime: *mut HermesRuntimeOpaque,
            call_id: u64,
            status: i32,
            payload: *const u8,
            payload_len: usize,
        );
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

    #[cfg(feature = "capsec-conformance-observer")]
    #[derive(Default)]
    struct RestrictedHostCallCapture {
        calls: Vec<(u64, u32, Vec<u8>)>,
    }

    #[cfg(feature = "capsec-conformance-observer")]
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

    #[cfg(feature = "capsec-conformance-observer")]
    #[derive(Default)]
    struct PendingRestrictedHostCall {
        call_id: u64,
        operation_id: u32,
        payload: Vec<u8>,
    }

    #[cfg(feature = "capsec-conformance-observer")]
    extern "C" fn capture_pending_restricted_host_call(
        _: *mut HermesRuntimeOpaque,
        call_id: u64,
        operation_id: u32,
        data: *const u8,
        len: usize,
        context: *mut std::ffi::c_void,
    ) {
        let capture = unsafe { &mut *context.cast::<PendingRestrictedHostCall>() };
        assert_eq!(
            capture.call_id, 0,
            "fixture observed duplicate pending call"
        );
        capture.call_id = call_id;
        capture.operation_id = operation_id;
        capture.payload = if data.is_null() || len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
        };
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
    fn restricted_exact_builder_uses_embedder_owned_private_cache() {
        let _guard = crate::host::abi::host_test_lock();
        let temp = tempfile::tempdir().unwrap();
        let cache_root = temp.path().join("cell-cache");
        std::fs::create_dir(&cache_root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(&cache_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bundle = b"globalThis.__restrictedContractLoaded = true;";
        let result = build_restricted_exact_embedder_artifact_in_cache(
            &cache_root,
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
        let bundle_digest = raw_content_digest(bundle).unwrap();
        let bundle_path = std::fs::canonicalize(cache_root.join("capsec-artifacts").join(format!(
            "{}.restricted-contract-bundle.json",
            bundle_digest.as_str().trim_start_matches("sha256-")
        )))
        .unwrap();
        assert_eq!(
            artifact["bundle"]["hostPath"],
            serde_json::to_value(absolute_artifact_path(&bundle_path).unwrap()).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn restricted_exact_builder_rejects_non_private_cache_roots() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let temp = tempfile::tempdir().unwrap();
        let permissive = temp.path().join("permissive-cache");
        std::fs::create_dir(&permissive).unwrap();
        std::fs::set_permissions(&permissive, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_restricted_exact_cache_root(&permissive)
            .unwrap_err()
            .to_string()
            .contains("group or other"));

        let private = temp.path().join("private-cache");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = temp.path().join("cache-alias");
        symlink(&private, &alias).unwrap();
        assert!(validate_restricted_exact_cache_root(&alias)
            .unwrap_err()
            .to_string()
            .contains("not a stable directory"));
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

    #[cfg(feature = "capsec-conformance-observer")]
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
        assert_eq!(control_ids.len(), 23);

        let bundle = br#"(() => {
          exact.takeCheckpointBytes();
          globalThis.__exactDispatchEvent = (handlerId) => {
            exact.publishCheckpoint(new Uint8Array([handlerId & 255]));
          };
          Object.defineProperty(globalThis, '__exactDispatchStableEvent', {
            value: (binding, payload) => {
              if (!binding || binding.actionIdentity !== 'increment' ||
                  !Array.isArray(binding.instancePath) || payload.delta !== 1) {
                throw new Error('stale stable binding');
              }
              exact.publishCheckpoint(new Uint8Array([6]));
            },
            writable: false,
            configurable: false
          });
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
        let stable_binding = std::ffi::CString::new(
            r#"{"instancePath":["Counter#0"],"nodeIdentity":"up","event":"press","actionIdentity":"increment"}"#,
        )
        .unwrap();
        let stable_payload = std::ffi::CString::new(r#"{"delta":1}"#).unwrap();
        assert_eq!(
            unsafe {
                ex_hermes_dispatch_restricted_exact_event(
                    runtime,
                    stable_binding.as_ptr(),
                    stable_payload.as_ptr(),
                )
            },
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
        assert_eq!(
            unsafe {
                ex_hermes_dispatch_restricted_exact_event(
                    runtime,
                    stable_binding.as_ptr(),
                    stable_payload.as_ptr(),
                )
            },
            -1
        );
        record(
            "surface.host.abi.ex.hermes.dispatch.event.0lbx6vi",
            "valid event published one successor checkpoint",
            "malformed event poisoned runtime and post-poison event returned -1",
        );
        record(
            "surface.host.abi.ex.hermes.dispatch.restricted.exact.event.0qonogo",
            "valid structural binding published one successor checkpoint",
            "post-poison structural event returned -1",
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

    #[cfg(feature = "capsec-conformance-observer")]
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

    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn restricted_exact_teardown_drains_admitted_completion_and_refuses_stale_generation() {
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
          exact.invokeHostAsync(1000, new Uint8Array([7, 8, 9])).then(() => {
            throw new Error('completion reached destroyed user code');
          });
          exact.publishCheckpoint(new Uint8Array([0]));
        })();"#;
        let mut pending = Box::<PendingRestrictedHostCall>::default();
        unsafe { ibex_test_reset_exact_host_completion_observer() };
        let (runtime, _dispatch, _checkpoints) = unsafe {
            configured_restricted_exact_runtime_with_host_callback(
                bundle,
                capture_pending_restricted_host_call,
                (&mut *pending as *mut PendingRestrictedHostCall).cast(),
            )
        };
        let mut error = std::ptr::null_mut();
        let run_status = unsafe { ex_hermes_run_restricted_exact_bundle(runtime, &mut error) };
        if run_status != 0 {
            let message = if error.is_null() {
                "missing restricted teardown fixture error".to_owned()
            } else {
                unsafe { std::ffi::CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned()
            };
            unsafe { ex_hermes_free_string(error) };
            panic!("restricted teardown fixture failed: {message}");
        }
        assert!(error.is_null());
        assert_ne!(pending.call_id, 0);
        assert_eq!(pending.operation_id, 1000);
        assert_eq!(pending.payload, [7, 8, 9]);
        let runtime_nonce = unsafe { ex_hermes_runtime_nonce(runtime) };
        let host_context_id = unsafe { ibex_test_runtime_host_context_id(runtime) };
        assert_ne!(runtime_nonce, 0);
        assert_ne!(host_context_id, 0);

        assert_eq!(
            unsafe { ibex_test_reset_structured_control_teardown_wait_observer() },
            1
        );
        assert_eq!(unsafe { ibex_test_arm_exact_host_completion_pause() }, 1);
        let runtime_address = runtime as usize;
        let call_id = pending.call_id;
        let completion = std::thread::spawn(move || {
            const PAYLOAD: &[u8] = b"late-completion";
            unsafe {
                ex_hermes_resolve_exact_host_call(
                    runtime_address as *mut HermesRuntimeOpaque,
                    call_id,
                    0,
                    PAYLOAD.as_ptr(),
                    PAYLOAD.len(),
                );
            }
        });
        let pause_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while unsafe { ibex_test_exact_host_completion_paused() } != 1 {
            assert!(
                std::time::Instant::now() < pause_deadline,
                "completion did not reach the synchronized teardown edge"
            );
            std::thread::yield_now();
        }
        let release = std::thread::spawn(|| {
            let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while unsafe { ibex_test_structured_control_teardown_wait_observed() } != 1 {
                assert!(
                    std::time::Instant::now() < wait_deadline,
                    "destroy did not wait for the admitted completion producer"
                );
                std::thread::yield_now();
            }
            assert_eq!(
                unsafe { ibex_test_release_exact_host_completion_pause() },
                1
            );
        });
        unsafe { ex_hermes_destroy(runtime) };
        completion.join().unwrap();
        release.join().unwrap();

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
            (1, 1, 0),
            "teardown must drain admitted completion captures without user delivery"
        );
        assert_eq!(unsafe { ibex_test_runtime_registered(runtime) }, 0);
        assert_eq!(unsafe { ex_hermes_runtime_nonce(runtime) }, 0);
        assert_eq!(
            crate::host::abi::ex_host_enter_context(host_context_id),
            u64::MAX,
            "destroyed Host context was reusable"
        );
        let event = std::ffi::CString::new("{}").unwrap();
        assert_eq!(
            unsafe { ex_hermes_dispatch_event(runtime, 1, event.as_ptr()) },
            -1,
            "destroyed runtime accepted an event"
        );
        assert_eq!(unsafe { ex_hermes_next_timer(runtime) }, -1);
        assert_eq!(unsafe { ex_hermes_has_pending_tasks(runtime) }, 0);

        // A duplicate/late producer publication carries only the stale pointer
        // and old call id. It must be rejected by generation registries before
        // any runtime dereference or callback delivery.
        const STALE: &[u8] = b"stale";
        unsafe {
            ex_hermes_resolve_exact_host_call(runtime, call_id, 0, STALE.as_ptr(), STALE.len());
        }
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
            (1, 1, 0)
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
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
          const assertClosed = () => {
            for (const name of [
              'require', 'process', 'Bun', 'Deno', 'Ibex', 'fetch',
              'WebSocket', '__hostCall', '__hostCallAsync',
              '__exactResolveModule', '__exactRegisterPackage',
              '__exactDeepFreeze', '__exactNativeFreeze'
            ]) {
              if (typeof globalThis[name] !== 'undefined') {
                throw new Error(`a forbidden route reached the Contract bundle: ${name}`);
              }
            }
          };
          assertClosed();
          queueMicrotask(assertClosed);
          setTimeout(assertClosed, 0);
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
            assert!(error.is_null());
        }
        let poll_result = unsafe { ex_hermes_poll(runtime, ex_hermes_now_ms() + 1_000) };
        assert!(poll_result >= 0, "restricted temporal proof poll failed");
        let cutset_names = [
            "profile-selected",
            "full-installer-skipped",
            "bootstrap-posture-sealed",
            "bundle-posture-sealed",
            "temporal-poll-posture-sealed",
        ];
        let mut prior_cutset_sequence = 0_u64;
        let actual_cutset_observations = cutset_names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let mut runtime_nonce = 0_u64;
                let mut sequence = 0_u64;
                assert_eq!(
                    unsafe {
                        ibex_test_restricted_exact_cutset_observation(
                            runtime,
                            index as u32,
                            &mut runtime_nonce,
                            &mut sequence,
                        )
                    },
                    1,
                    "actual restricted cut-set site was not observed: {name}"
                );
                assert_eq!(runtime_nonce, unsafe { ex_hermes_runtime_nonce(runtime) });
                assert!(sequence > prior_cutset_sequence);
                prior_cutset_sequence = sequence;
                serde_json::json!({
                    "observationId": format!("restricted-exact.{name}"),
                    "runtimeGeneration": runtime_nonce,
                    "sequence": sequence,
                })
            })
            .collect::<Vec<_>>();

        let projection: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/restricted-exact-profile-projection.json"
        )))
        .unwrap();
        let planned_absent_ids = projection["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| {
                let row = row.as_array().unwrap();
                (row[1].as_str() == Some("structurally-absent"))
                    .then(|| row[0].as_str().unwrap().to_owned())
            })
            .collect::<std::collections::BTreeSet<_>>();
        let absent_ids = effective_restricted_projection_rows()
            .into_iter()
            .filter_map(|(edge_id, disposition)| {
                (disposition == "structurally-absent").then_some(edge_id)
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert!(absent_ids.is_subset(&planned_absent_ids));
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

        let probe_plan_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/restricted-exact-absence-probe-plan.json"
        ));
        let probe_plan: serde_json::Value = serde_json::from_slice(probe_plan_bytes).unwrap();
        let planned_edges = probe_plan["edges"].as_array().unwrap();
        assert_eq!(planned_edges.len(), planned_absent_ids.len());
        assert_eq!(
            probe_plan["counts"]["edges"].as_u64(),
            Some(planned_absent_ids.len() as u64)
        );
        let probe_plan_digest = format!(
            "sha256-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(probe_plan_bytes))
        );
        let fixture_plan: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/restricted-exact-fixture-plan.json"
        )))
        .unwrap();
        assert_eq!(
            fixture_plan["absenceProbePlan"]["rawContentDigest"].as_str(),
            Some(probe_plan_digest.as_str())
        );
        let route_graph_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/restricted-exact-absence-route-graph.json"
        ));
        let route_graph: serde_json::Value = serde_json::from_slice(route_graph_bytes).unwrap();
        let route_graph_digest = format!(
            "sha256-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(route_graph_bytes))
        );
        assert_eq!(
            fixture_plan["absenceRouteGraph"]["rawContentDigest"].as_str(),
            Some(route_graph_digest.as_str())
        );
        assert_eq!(
            route_graph["authorityDigests"]["probePlan"].as_str(),
            Some(probe_plan_digest.as_str())
        );
        assert_eq!(
            route_graph["target"]["triple"].as_str(),
            Some("aarch64-apple-darwin")
        );
        let routes = route_graph["routes"].as_array().unwrap();
        assert_eq!(
            routes.len() as u64,
            route_graph["counts"]["routes"].as_u64().unwrap()
        );
        let route_by_source_probe = routes
            .iter()
            .map(|route| (route["sourceProbeId"].as_str().unwrap().to_owned(), route))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(route_by_source_probe.len(), routes.len());
        let mut routes_by_live_probe =
            std::collections::BTreeMap::<String, Vec<&serde_json::Value>>::new();
        for route in routes {
            for probe_id in route["liveProbeIds"].as_array().unwrap() {
                routes_by_live_probe
                    .entry(probe_id.as_str().unwrap().to_owned())
                    .or_default()
                    .push(route);
            }
        }
        assert_eq!(
            routes_by_live_probe.len() as u64,
            probe_plan["counts"]["liveReachabilityProbes"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            routes_by_live_probe.values().map(Vec::len).sum::<usize>() as u64,
            route_graph["counts"]["liveProbeBindings"].as_u64().unwrap()
        );

        let probe_logical_path = |path: &str, undefined_terminal_is_unreachable: bool| {
            let path_c = std::ffi::CString::new(path).unwrap();
            let mut last_resolved_segment = u32::MAX;
            let mut first_blocked_segment = u32::MAX;
            let mut boundary = u32::MAX;
            let unreachable = unsafe {
                ibex_test_root_global_logical_path_probe(
                    runtime,
                    path_c.as_ptr(),
                    u32::from(undefined_terminal_is_unreachable),
                    &mut last_resolved_segment,
                    &mut first_blocked_segment,
                    &mut boundary,
                )
            } == 1;
            if !unreachable {
                return None;
            }
            let segments = path.split('.').collect::<Vec<_>>();
            let segment = |index: u32| {
                usize::try_from(index)
                    .ok()
                    .and_then(|index| segments.get(index))
                    .copied()
            };
            let boundary_kind = match boundary {
                1 => "missing-descriptor",
                2 => "undefined-terminal-value",
                _ => {
                    panic!("unreachable logical path reported invalid boundary {boundary}: {path}")
                }
            };
            Some(serde_json::json!({
                "requestedPath": path,
                "mode": if undefined_terminal_is_unreachable { "unreachable" } else { "absent" },
                "boundaryKind": boundary_kind,
                "lastResolvedSegmentIndex": if last_resolved_segment == u32::MAX {
                    serde_json::Value::Null
                } else {
                    serde_json::json!(last_resolved_segment)
                },
                "lastResolvedSegment": segment(last_resolved_segment),
                "firstBlockedSegmentIndex": first_blocked_segment,
                "firstBlockedSegment": segment(first_blocked_segment),
            }))
        };
        let probe_roots = |roots: &[&str]| {
            roots
                .iter()
                .map(|root| probe_logical_path(root, false))
                .collect::<Option<Vec<_>>>()
        };
        let selected_startup_identities = [
            "startup:runtime-create",
            "startup:install-route:ex_hermes_create_impl->installRestrictedExactGlobals",
            "startup:installer:installRestrictedExactGlobals",
            "startup:install-route:installRestrictedExactGlobals->installTimerGlobals",
            "startup:installer:installTimerGlobals",
            "startup:script:<restricted-exact-lockdown>",
            "startup:evaluation:installRestrictedExactGlobals:<restricted-exact-lockdown>",
            "startup:script:<authenticated-restricted-exact-bundle>",
            "startup:evaluation:ex_hermes_run_restricted_exact_bundle:<authenticated-restricted-exact-bundle>",
        ];
        let route_traversal = |route_kind: &str, target: &str| -> Option<serde_json::Value> {
            if target.is_empty() {
                return None;
            }
            let boundary = match route_kind {
                "descriptor-prefix" => serde_json::json!({
                    "kind": "root-descriptor",
                    "receipts": [probe_logical_path(target, false)?],
                }),
                "restricted-module-resolution" | "restricted-loader-entry" => serde_json::json!({
                    "kind": "module-loader-roots",
                    "receipts": probe_roots(&[
                        "require",
                        "__exactResolveModule",
                        "__exactResolveManifestBuiltinInternal",
                        "__exactRegisterPackage",
                    ])?,
                }),
                "restricted-cli-entry" => serde_json::json!({
                    "kind": "cli-ingress-roots",
                    "receipts": probe_roots(&["process", "Bun", "Deno", "Ibex", "require"])?,
                }),
                "restricted-js-native-abi" => serde_json::json!({
                    "kind": "javascript-native-abi-roots",
                    "receipts": probe_roots(&[
                        "__hostCall", "__hostCallAsync", "process", "require", "Bun",
                    ])?,
                }),
                "restricted-callback-route" => {
                    let receipts = probe_roots(&[
                        "__hostCall",
                        "__hostCallAsync",
                        "fetch",
                        "WebSocket",
                        "process",
                    ])?;
                    if targets_consumed != 0 || callbacks_queued != 0 || callbacks_delivered != 0 {
                        return None;
                    }
                    serde_json::json!({
                        "kind": "callback-producer-roots-and-slots",
                        "receipts": receipts,
                        "completionSlots": {
                            "targetsConsumed": targets_consumed,
                            "callbacksQueued": callbacks_queued,
                            "callbacksDelivered": callbacks_delivered,
                        },
                    })
                }
                "restricted-startup-route" => {
                    let trace = unsafe { ibex_test_restricted_exact_conformance_trace(runtime) };
                    if trace != 0x1ff || selected_startup_identities.contains(&target) {
                        return None;
                    }
                    serde_json::json!({
                        "kind": "startup-selection",
                        "restrictedTrace": trace,
                        "selected": false,
                    })
                }
                "restricted-native-installer-route" => {
                    let name = target.strip_prefix("native-op:").unwrap_or(target);
                    let logical = name.strip_prefix("global:").unwrap_or(name);
                    if logical == "[[dynamic-table:native-global-name]]" {
                        let trace =
                            unsafe { ibex_test_restricted_exact_conformance_trace(runtime) };
                        if trace != 0x1ff {
                            return None;
                        }
                        return Some(serde_json::json!({
                            "routeKind": route_kind,
                            "exactTarget": target,
                            "boundary": {
                                "kind": "dynamic-native-installer-roots",
                                "receipts": probe_roots(&[
                                    "__hostCall", "__hostCallAsync", "__exactResolveModule", "process",
                                ])?,
                                "restrictedTrace": trace,
                            },
                        }));
                    }
                    let direct_probe = logical.starts_with("__")
                        || logical
                            .as_bytes()
                            .first()
                            .is_some_and(u8::is_ascii_alphabetic);
                    if !direct_probe {
                        return None;
                    }
                    serde_json::json!({
                        "kind": "native-logical-path",
                        "receipts": [probe_logical_path(logical, true)?],
                    })
                }
                _ => return None,
            };
            Some(serde_json::json!({
                "routeKind": route_kind,
                "exactTarget": target,
                "boundary": boundary,
            }))
        };

        let barrier_for = |kind: &str| match kind {
            "builtin" | "loader" | "cli" => "no-general-loader-or-cli-root",
            "host-abi" => "no-javascript-native-abi-bridge",
            "startup" => "not-selected-by-restricted-bootstrap",
            "callback" => "no-installed-producer-or-retained-callback",
            "native-op" => "descriptor-path-or-ambient-installer-absent",
            _ => panic!("unexpected absent surface kind {kind}"),
        };
        let cutset_observation_by_id = actual_cutset_observations
            .iter()
            .map(|observation| {
                (
                    observation["observationId"].as_str().unwrap().to_owned(),
                    observation.clone(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let barrier_attestation = serde_json::json!({
            "observer": "exact-engine-closed-world-barriers",
            "rootGlobalManifestRawContentDigest": format!(
                "sha256-{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(
                    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/capsec/generated/root-global-disposition-manifest.json"))
                ))
            ),
            "forbiddenRoots": forbidden_root_results,
            "restrictedStartupTrace": 0x1ff_u64,
            "completionObserver": {
                "targetsConsumed": targets_consumed,
                "callbacksQueued": callbacks_queued,
                "callbacksDelivered": callbacks_delivered,
            },
            "actualCutsetObservations": actual_cutset_observations,
            "descriptorProbedEdges": descriptor_prefixes.len(),
        });
        let barrier_bytes =
            capsec_semantics::canonical::to_jcs_bytes(&barrier_attestation).unwrap();
        let barrier_digest = format!(
            "sha256-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&barrier_bytes))
        );
        let runtime_generation = unsafe { ex_hermes_runtime_nonce(runtime) };
        assert_ne!(runtime_generation, 0);
        let execute_cutset = |route: &serde_json::Value,
                              probe_id: &str,
                              route_kind: &str,
                              target: &str,
                              source_selection: bool| {
            let route_id = route["routeId"].as_str().unwrap();
            let selected_target = route["observedIdentity"].as_str().unwrap();
            let path_key = if source_selection {
                "sourcePath"
            } else {
                "livePath"
            };
            let cutset_key = if source_selection {
                "sourceCutsetObservationIds"
            } else {
                "liveCutsetObservationIds"
            };
            let path = route[path_key].as_array().unwrap();
            assert!(
                path.len() >= 5,
                "route graph path is incomplete: {route_id}"
            );
            let cutset_observations = route[cutset_key]
                .as_array()
                .unwrap()
                .iter()
                .map(|observation_id| {
                    cutset_observation_by_id
                        .get(observation_id.as_str().unwrap())
                        .unwrap_or_else(|| {
                            panic!("route references an unobserved production cut set: {route_id}")
                        })
                        .clone()
                })
                .collect::<Vec<_>>();
            if source_selection {
                assert_eq!(
                    target, selected_target,
                    "source route target substitution: {route_id}"
                );
            } else {
                let attacker_identity = format!("{route_kind}:{target}");
                assert!(
                    route["attackerRoots"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|root| root.as_str() == Some(attacker_identity.as_str())),
                    "live target is not an attacker root for {route_id}: {attacker_identity}"
                );
            }
            let actual_boundary_observation = if source_selection {
                serde_json::Value::Null
            } else {
                route_traversal(route_kind, target).unwrap_or_else(|| {
                    panic!(
                        "target-specific live traversal did not fail {route_id}: {route_kind} {target}"
                    )
                })
            };
            serde_json::json!({
                "routeId": route_id,
                "probeId": probe_id,
                "selectedTarget": selected_target,
                "probeTarget": target,
                "branchId": route["branchId"],
                "proofKind": if source_selection { "source-selection" } else { "live-reachability" },
                "cutsetObservations": cutset_observations,
                "actualBoundaryObservation": actual_boundary_observation,
                "lastObservedNode": path[path.len() - 3],
                "blockedEdge": {
                    "from": path[path.len() - 3],
                    "to": path[path.len() - 2],
                },
                "runtimeGeneration": runtime_generation,
                "outcome": if source_selection { "not-selected-or-retained" } else { "unreachable" },
            })
        };

        let mut observations = Vec::<serde_json::Value>::with_capacity(absent_ids.len() * 2);
        for planned in planned_edges {
            let edge_id = planned["edgeId"].as_str().unwrap();
            assert!(planned_absent_ids.contains(edge_id));
            if !absent_ids.contains(edge_id) {
                continue;
            }
            let edge = &edges[edge_id];
            let kind = edge["surface"]["kind"].as_str().unwrap();
            let identity = format!("{}:{}", kind, edge["surface"]["name"].as_str().unwrap());
            assert_eq!(
                planned["observedIdentity"].as_str(),
                Some(identity.as_str())
            );
            let source_route_kind = match kind {
                "builtin" => "restricted-module-resolution",
                "callback" => "restricted-callback-route",
                "cli" => "restricted-cli-entry",
                "host-abi" => "restricted-js-native-abi",
                "loader" => "restricted-loader-entry",
                "native-op" => "restricted-native-installer-route",
                "startup" => "restricted-startup-route",
                _ => panic!("unexpected absent surface kind {kind}"),
            };
            let source_probe_results = planned["sourceInstall"]
                .as_array()
                .unwrap()
                .iter()
                .map(|probe| {
                    let probe_id = probe["probeId"].as_str().unwrap();
                    let route = route_by_source_probe.get(probe_id).unwrap_or_else(|| {
                        panic!("source probe lacks dominance route: {probe_id}")
                    });
                    assert_eq!(route["edgeId"].as_str(), Some(edge_id));
                    assert_eq!(route["branchId"], probe["branchId"]);
                    let receipt =
                        execute_cutset(route, probe_id, source_route_kind, &identity, true);
                    serde_json::json!({
                        "probeId": probe["probeId"],
                        "branchId": probe["branchId"],
                        "enforcementBranchId": probe["enforcementBranchId"],
                        "outcome": "not-selected-or-retained",
                        "routeReceipt": receipt,
                    })
                })
                .collect::<Vec<_>>();
            let live_probe_results = planned["liveReachability"]
                .as_array()
                .unwrap()
                .iter()
                .map(|probe| {
                    let probe_id = probe["probeId"].as_str().unwrap();
                    let route_kind = probe["routeKind"].as_str().unwrap();
                    let target = probe["target"].as_str().unwrap();
                    let bound_routes = routes_by_live_probe
                        .get(probe_id)
                        .unwrap_or_else(|| panic!("live probe lacks dominance route: {probe_id}"));
                    let receipts = bound_routes
                        .iter()
                        .map(|route| {
                            assert_eq!(route["edgeId"].as_str(), Some(edge_id));
                            execute_cutset(route, probe_id, route_kind, target, false)
                        })
                        .collect::<Vec<_>>();
                    serde_json::json!({
                        "probeId": probe["probeId"],
                        "routeKind": route_kind,
                        "target": target,
                        "outcome": "unreachable",
                        "routeReceipts": receipts,
                    })
                })
                .collect::<Vec<_>>();
            observations.push(serde_json::json!({
                "edgeId": edge_id,
                "kind": "source-install",
                "outcome": "passed",
                "observedIdentity": identity,
                "proof": {
                    "observer": "executed-edge-source-install-closure",
                    "surfaceKind": kind,
                    "barrier": barrier_for(kind),
                    "barrierAttestationDigest": barrier_digest,
                    "probePlanRawContentDigest": probe_plan_digest,
                    "routeGraphRawContentDigest": route_graph_digest,
                    "probeResults": source_probe_results,
                },
            }));
            observations.push(serde_json::json!({
                "edgeId": edge_id,
                "kind": "live-reachability",
                "outcome": "passed",
                "observedIdentity": identity,
                "proof": {
                    "observer": "executed-exact-engine-edge-routes",
                    "surfaceKind": kind,
                    "barrier": barrier_for(kind),
                    "barrierAttestationDigest": barrier_digest,
                    "probePlanRawContentDigest": probe_plan_digest,
                    "routeGraphRawContentDigest": route_graph_digest,
                    "probeResults": live_probe_results,
                },
            }));
        }
        unsafe { ex_hermes_destroy(runtime) };
        observations.sort_by(|left, right| {
            (left["edgeId"].as_str(), left["kind"].as_str())
                .cmp(&(right["edgeId"].as_str(), right["kind"].as_str()))
        });
        assert_eq!(observations.len(), absent_ids.len() * 2);

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
                    "--", "--nocapture", "--test-threads=1",
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

    #[cfg(feature = "capsec-conformance-observer")]
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

        let reachable_ids = effective_restricted_projection_rows()
            .into_iter()
            .filter_map(|(edge_id, disposition)| (disposition == "reachable").then_some(edge_id))
            .collect::<std::collections::BTreeSet<_>>();
        let native_ids = reachable_ids
            .iter()
            .filter(|id| id.starts_with("surface.native.op."))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let stable_event_edge_id = "surface.native.op.exactdispatchstableevent.1qe8h6w";
        assert!(native_ids.contains(stable_event_edge_id));
        let root_probe_native_ids = native_ids
            .iter()
            .filter(|id| id.as_str() != stable_event_edge_id)
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
        let target = restricted_conformance_target();
        assert_eq!(
            native_ids.len(),
            if target["triple"] == "x86_64-unknown-linux-gnu" {
                117
            } else {
                116
            }
        );
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
                "surface.callback.microtask.drain.0u9pqfm",
                "surface.callback.native.principal.restore.0qxvk73",
                "surface.callback.producer.src.engine.hermes.runtime.cc.ex.hermes.resolve.exact.host.call.0n49v9x",
                "surface.callback.queue.drain.0hyao68",
                "surface.callback.queue.enqueue.0uj36yk",
                "surface.callback.timer.invoke.1qq42bc",
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
        assert_eq!(probes.len(), root_probe_native_ids.len());

        let mut bundle = br#"((specs) => {
          'use strict';
          const results = [];
          const ingress = exact.takeCheckpointBytes();
          if (!(ingress instanceof Uint8Array)) throw new Error('checkpoint ingress was not bytes');
          Object.defineProperty(globalThis, '__exactDispatchStableEvent', {
            value: (binding, payload) => {
              if (!binding || binding.actionIdentity !== 'stable-probe' ||
                  !Array.isArray(binding.instancePath) || payload.marker !== 83) {
                throw new Error('invalid stable event probe');
              }
              exact.publishCheckpoint(new Uint8Array([83]));
            },
            writable: false,
            configurable: false
          });

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
            else if (path === 'setTimeout') args = [() => {}, 0];
            else if (path === 'setInterval' || path === 'queueMicrotask') args = [null, 0];
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
            } else if (path === 'Intl.NumberFormat.prototype.formatToParts') {
              receiver = new Intl.NumberFormat('en-US');
              args = [0];
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

            let initial_checkpoint_len = checkpoints.len();
            let results: Vec<serde_json::Value> = serde_json::from_slice(&checkpoints).unwrap();
            assert_eq!(results.len(), root_probe_native_ids.len());
            let result_ids = results
                .iter()
                .map(|row| row["edgeId"].as_str().unwrap().to_owned())
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(result_ids, root_probe_native_ids);
            let unresolved = results
                .iter()
                .filter(|row| row["status"].as_str() == Some("unresolved"))
                .collect::<Vec<_>>();
            assert!(
                unresolved.is_empty(),
                "reachable native edges failed exact resolution: {}",
                serde_json::to_string_pretty(&unresolved).unwrap()
            );

            let stable_binding = std::ffi::CString::new(
                r#"{"instancePath":["Probe#0"],"nodeIdentity":"probe","event":"press","actionIdentity":"stable-probe"}"#,
            )
            .unwrap();
            let stable_payload = std::ffi::CString::new(r#"{"marker":83}"#).unwrap();
            assert_eq!(
                ex_hermes_dispatch_restricted_exact_event(
                    runtime,
                    stable_binding.as_ptr(),
                    stable_payload.as_ptr(),
                ),
                0
            );
            assert_eq!(checkpoints.len(), initial_checkpoint_len + 1);
            assert_eq!(checkpoints[initial_checkpoint_len], 83);
            let stable_event_proof = serde_json::json!({
                "edgeId": stable_event_edge_id,
                "status": "invoked-returned",
                "bindingResolution": "new-realm-structural-identity",
                "successorCheckpointByte": 83,
            });

            let next_timer_ms = ex_hermes_next_timer(runtime);
            assert!(next_timer_ms >= 0, "reachable timer edge did not arm");
            assert!(ex_hermes_poll(runtime, next_timer_ms as u64) >= 1);
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
            let mut microtask_drains = 0;
            let mut native_principal_restores = 0;
            let mut timer_invocations = 0;
            assert_eq!(
                ibex_test_restricted_callback_observation(
                    &mut microtask_drains,
                    &mut native_principal_restores,
                    &mut timer_invocations,
                ),
                1
            );
            assert!(microtask_drains > 0);
            assert!(native_principal_restores > 0);
            assert!(timer_invocations > 0);

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
                observations.push(serde_json::json!({
                    "edgeId": stable_event_edge_id,
                    "kind": "live-invocation",
                    "outcome": "passed",
                    "observedIdentity": observed_identities[stable_event_edge_id],
                    "proof": stable_event_proof,
                }));
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
                for (edge_id, observer, observed_count) in [
                    (
                        "surface.callback.microtask.drain.0u9pqfm",
                        "restricted-microtask-drain",
                        microtask_drains,
                    ),
                    (
                        "surface.callback.native.principal.restore.0qxvk73",
                        "restricted-native-principal-restored",
                        native_principal_restores,
                    ),
                    (
                        "surface.callback.queue.drain.0hyao68",
                        "restricted-callback-queue-drained",
                        callbacks_delivered,
                    ),
                    (
                        "surface.callback.queue.enqueue.0uj36yk",
                        "restricted-callback-queue-enqueued",
                        callbacks_queued,
                    ),
                    (
                        "surface.callback.timer.invoke.1qq42bc",
                        "restricted-timer-invoked",
                        timer_invocations,
                    ),
                ] {
                    observations.push(serde_json::json!({
                        "edgeId": edge_id,
                        "kind": "live-invocation",
                        "outcome": "passed",
                        "observedIdentity": observed_identities[edge_id],
                        "proof": {
                            "observer": observer,
                            "observedCount": observed_count,
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
        // class: the target-effective JS/native identities, nine startup
        // edges, and seven lifecycle callback edges.
        assert_eq!(native_ids.len() + 9 + 7, reachable_ids.len());
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
    fn restricted_exact_stable_event_resolves_new_realm_binding_and_poison_stale() {
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
          exact.publishCheckpoint(new Uint8Array([1]));
          Object.defineProperty(globalThis, '__exactDispatchStableEvent', {
            value: (binding, payload) => {
              if (!binding || binding.actionIdentity !== 'increment' ||
                  !Array.isArray(binding.instancePath) ||
                  payload.delta !== 1) {
                throw new Error('stale stable binding');
              }
              exact.publishCheckpoint(new Uint8Array([2]));
            },
            writable: false,
            configurable: false
          });
        })();"#;
        let binding = std::ffi::CString::new(
            r#"{"instancePath":["Counter#0"],"nodeIdentity":"up","event":"press","actionIdentity":"increment"}"#,
        )
        .unwrap();
        let stale = std::ffi::CString::new(
            r#"{"instancePath":["Counter#0"],"nodeIdentity":"up","event":"press","actionIdentity":"stale"}"#,
        )
        .unwrap();
        let payload = std::ffi::CString::new(r#"{"delta":1}"#).unwrap();

        let (runtime, _dispatch, checkpoints) =
            unsafe { configured_restricted_exact_runtime(bundle) };
        unsafe {
            let mut error = std::ptr::null_mut();
            assert_eq!(
                ex_hermes_run_restricted_exact_bundle(runtime, &mut error),
                0
            );
            assert!(error.is_null());
            assert_eq!(
                ex_hermes_dispatch_restricted_exact_event(
                    runtime,
                    binding.as_ptr(),
                    payload.as_ptr(),
                ),
                0
            );
            assert_eq!(*checkpoints, [1, 2]);
            ex_hermes_destroy(runtime);
        }

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
                ex_hermes_dispatch_restricted_exact_event(
                    runtime,
                    stale.as_ptr(),
                    payload.as_ptr(),
                ),
                -1
            );
            assert_eq!(
                ex_hermes_dispatch_restricted_exact_event(
                    runtime,
                    binding.as_ptr(),
                    payload.as_ptr(),
                ),
                -1
            );
            assert_eq!(ex_hermes_poll(runtime, 1234), -1);
            ex_hermes_destroy(runtime);
        }

        for use_null_binding in [true, false] {
            let oversized_binding = std::ffi::CString::new(vec![b'a'; 64 * 1024 + 1]).unwrap();
            let invalid_binding = if use_null_binding {
                std::ptr::null()
            } else {
                oversized_binding.as_ptr()
            };
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
                    ex_hermes_dispatch_restricted_exact_event(
                        runtime,
                        invalid_binding,
                        payload.as_ptr(),
                    ),
                    -1
                );
                assert_eq!(
                    ex_hermes_dispatch_restricted_exact_event(
                        runtime,
                        binding.as_ptr(),
                        payload.as_ptr(),
                    ),
                    -1
                );
                ex_hermes_destroy(runtime);
            }
        }
    }

    #[test]
    fn restricted_exact_stable_event_requires_exactly_one_successor_checkpoint() {
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
        let binding = std::ffi::CString::new(
            r#"{"instancePath":["Counter#0"],"nodeIdentity":"up","event":"press","actionIdentity":"increment"}"#,
        )
        .unwrap();
        let payload = std::ffi::CString::new("{}").unwrap();
        for (fixture, bundle) in [
            (
                "missing-successor",
                br#"(() => {
                  exact.takeCheckpointBytes();
                  exact.publishCheckpoint(new Uint8Array([1]));
                  globalThis.__exactDispatchStableEvent = () => {};
                })();"#
                    .as_slice(),
            ),
            (
                "duplicate-successor",
                br#"(() => {
                  exact.takeCheckpointBytes();
                  exact.publishCheckpoint(new Uint8Array([1]));
                  globalThis.__exactDispatchStableEvent = () => {
                    exact.publishCheckpoint(new Uint8Array([2]));
                    exact.publishCheckpoint(new Uint8Array([3]));
                  };
                })();"#
                    .as_slice(),
            ),
        ] {
            let (runtime, _dispatch, _checkpoints) =
                unsafe { configured_restricted_exact_runtime(bundle) };
            unsafe {
                let mut error = std::ptr::null_mut();
                assert_eq!(
                    ex_hermes_run_restricted_exact_bundle(runtime, &mut error),
                    0,
                    "{fixture}"
                );
                assert!(error.is_null(), "{fixture}");
                assert_eq!(
                    ex_hermes_dispatch_restricted_exact_event(
                        runtime,
                        binding.as_ptr(),
                        payload.as_ptr(),
                    ),
                    -1,
                    "{fixture}"
                );
                assert_eq!(ex_hermes_poll(runtime, 1234), -1, "{fixture}");
                ex_hermes_destroy(runtime);
            }
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
