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
    ArmedSnapshot, ExactEmbedderBinding, ExactEmbedderEndowments, ExactGpuProviderBinding,
    ExpectedArmingIdentity, ExpectedProtectedArtifact, ProtectedArtifactRole,
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

fn parse_exact_gpu_provider_binding(bytes: &[u8]) -> Result<ExactGpuProviderBinding> {
    let text = std::str::from_utf8(bytes).context("Exact GPU provider binding is not UTF-8")?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .context("Exact GPU provider binding is not strict JSON")?;
    let binding: ExactGpuProviderBinding =
        serde_json::from_value(value).context("invalid Exact GPU provider binding")?;
    capsec_semantics::arming::validate_exact_gpu_provider_binding(&binding)
        .map_err(anyhow::Error::msg)
        .context("Exact GPU provider binding refused")?;
    Ok(binding)
}

fn digest_bytes(bytes: &[u8]) -> Result<Digest> {
    Digest::new(format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
    .map_err(anyhow::Error::msg)
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
            ObjectPlatform::Windows => PathAliasCanonicalizerIdentity::WindowsAsciiCasefoldV1,
            ObjectPlatform::Unix | ObjectPlatform::Android => {
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

// @ref LLP 0021#default-and-target-claim — artifact publication uses each
// target's supported durability boundary without weakening byte/object checks.
fn sync_published_artifact(directory: &Path, _artifact: &std::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(directory)?
            .sync_all()
            .context("failed to sync protected artifact directory")?;
    }
    #[cfg(not(unix))]
    {
        // Windows does not let `std::fs::File` open a directory for `sync_all`.
        // The hard link names this same file object, so flush that pinned object
        // again after publication instead of treating the directory as a file.
        let _ = directory;
        _artifact
            .sync_all()
            .context("failed to sync published protected artifact")?;
    }
    Ok(())
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
                Ok(()) => sync_published_artifact(&directory, &staged)?,
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
    dev_project_root: Option<&Path>,
    operation_manifest_bytes: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    build_exact_embedder_artifacts_with_gpu(
        project_root,
        dev_project_root,
        operation_manifest_bytes,
        None,
        None,
        false,
    )
}

/// Build the target-local Exact artifact pair with the optional GPU service
/// identity and its exact, independently protected WebGPU profile.
///
/// The binding is strict JSON and the profile bytes must hash to its declared
/// `profileDigest`. The existing non-GPU builder remains unchanged so clients
/// cannot accidentally acquire the provider seam by calling the legacy path.
/// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam — the
/// provider identity and profile artifact are authenticated before runtime
/// construction can install the optional service.
pub fn build_exact_gpu_embedder_artifacts(
    project_root: &Path,
    dev_project_root: Option<&Path>,
    operation_manifest_bytes: &[u8],
    gpu_provider_binding_bytes: &[u8],
    webgpu_profile_bytes: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    build_exact_embedder_artifacts_with_gpu(
        project_root,
        dev_project_root,
        operation_manifest_bytes,
        Some(gpu_provider_binding_bytes),
        Some(webgpu_profile_bytes),
        false,
    )
}

/// Build the named Exact WebGPU Pre-1A artifact pair. Unlike the ordinary GPU
/// builder, this path writes the checked private registry's exact positive
/// selectors into both the authenticated root ceiling and floor. The
/// companion experimental installer re-proves that exact set and installs the
/// private cells while keeping every ordinary target cell closed.
/// @ref LLP 0002#the-optional-exact-gpu-service-registration-seam
pub fn build_exact_experimental_webgpu_pre1a_embedder_artifacts(
    project_root: &Path,
    dev_project_root: Option<&Path>,
    operation_manifest_bytes: &[u8],
    gpu_provider_binding_bytes: &[u8],
    webgpu_profile_bytes: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    build_exact_embedder_artifacts_with_gpu(
        project_root,
        dev_project_root,
        operation_manifest_bytes,
        Some(gpu_provider_binding_bytes),
        Some(webgpu_profile_bytes),
        true,
    )
}

fn build_exact_embedder_artifacts_with_gpu(
    project_root: &Path,
    dev_project_root: Option<&Path>,
    operation_manifest_bytes: &[u8],
    gpu_provider_binding_bytes: Option<&[u8]>,
    webgpu_profile_bytes: Option<&[u8]>,
    experimental_webgpu_pre1a: bool,
) -> Result<PreparedEmbedderArtifacts> {
    anyhow::ensure!(
        gpu_provider_binding_bytes.is_some() == webgpu_profile_bytes.is_some(),
        "Exact GPU provider binding and WebGPU profile must be supplied together"
    );
    if let Some(profile_bytes) = webgpu_profile_bytes {
        anyhow::ensure!(
            !profile_bytes.is_empty(),
            "Exact WebGPU profile must not be empty"
        );
    }
    super::reject_closed_startup_environment()?;
    let installed_project_root = std::fs::canonicalize(project_root).with_context(|| {
        format!(
            "failed to authenticate Exact project root {}",
            project_root.display()
        )
    })?;
    anyhow::ensure!(
        installed_project_root.is_dir(),
        "Exact project root is not a directory"
    );
    let dev_project_root = dev_project_root
        .map(|root| {
            std::fs::canonicalize(root).with_context(|| {
                format!(
                    "failed to authenticate Exact dev project root {}",
                    root.display()
                )
            })
        })
        .transpose()?;
    if let Some(root) = dev_project_root.as_ref() {
        anyhow::ensure!(root.is_dir(), "Exact dev project root is not a directory");
    }
    let project_root = dev_project_root.as_ref().unwrap_or(&installed_project_root);

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
    let entry_identity = serde_json::json!({
        "root": "project",
        "components": [{"encoding": "utf8", "value": "exact-operation-manifest.json"}],
        "sourceIntegrity": format!(
            "sha256-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(operation_manifest_bytes))
        ),
    });
    let graph_snapshot = serde_json::json!({
        "graphSnapshotSchema": "ibex/authenticated-graph-snapshot/1",
        "entryIdentity": entry_identity,
        "nodes": [{
            "principal": "<root>",
            "modulePath": "exact-operation-manifest.json",
            "sourceIntegrity": entry_identity["sourceIntegrity"],
        }],
        "packages": [],
        "edges": [],
        "candidateSets": [],
    });
    let graph_identity =
        compute_domain_digest("ibex/authenticated-graph-snapshot/1", &graph_snapshot, &[])?;
    let mut policy = serde_json::json!({
        "policySchema": "ibex/capsec-policy/2",
        "capsVocab": crate::capsec_registry_generated::CAPSEC_PROFILE,
        "semanticCore": crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE,
        "vocabDigest": vocab_digest,
        "registryDigest": registry_digest,
        "policyDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "purpose": "production",
        "mode": "enforce",
        "graphIdentity": graph_identity,
        "entryIdentity": entry_identity,
        "targetProfile": {"kind": "source", "profile": "portable-v1"},
        "mountProfile": "project-v1",
        "rootCeiling": [],
        "computedCandidates": {
            "schema": "ibex/computed-candidate-manifest/1",
            "declarations": [],
            "packageClosureOptIns": [],
            "materializedSites": [],
        },
        "rootImports": [],
        "principals": [],
    });
    if dev_project_root.is_some() {
        policy["rootCeiling"] = serde_json::json!([{
            "authority": super::exact_dev_served_agent_listener_selector()
                .map_err(|error| anyhow::anyhow!(error))?,
            "provenance": [{
                "kind": "direct",
                "source": "Exact dev-served agent listener"
            }]
        }]);
    }
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
    let gpu_binding = gpu_provider_binding_bytes
        .map(parse_exact_gpu_provider_binding)
        .transpose()?;
    if let (Some(gpu_binding), Some(profile_bytes)) = (gpu_binding.as_ref(), webgpu_profile_bytes) {
        anyhow::ensure!(
            digest_bytes(profile_bytes)? == gpu_binding.profile_digest,
            "Exact WebGPU profile bytes do not match the provider profile digest"
        );
    }
    let experimental_private_arming = if experimental_webgpu_pre1a {
        let binding = gpu_binding.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "experimental WebGPU Pre-1A construction requires a GPU provider binding"
            )
        })?;
        Some(
            super::gpu_authority::experimental_webgpu_pre1a_arming(binding).ok_or_else(|| {
                anyhow::anyhow!(
                    "experimental WebGPU Pre-1A provider or checked private registry is unavailable"
                )
            })?,
        )
    } else {
        None
    };
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
    let mut root_authorities = canonical_policy
        .root_ceiling
        .iter()
        .map(|row| row.authority.clone())
        .collect::<Vec<_>>();
    if let Some(arming) = experimental_private_arming.as_ref() {
        root_authorities.extend(arming.positive_selectors.iter().cloned());
    }
    root_authorities.sort();
    anyhow::ensure!(
        root_authorities.windows(2).all(|pair| pair[0] != pair[1]),
        "target-local Exact root authority set contains a duplicate selector"
    );
    document["rootAuthorityCeiling"] = serde_json::json!({
        "kind": "bounded",
        "authorities": root_authorities.clone(),
    });
    // @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine — the
    // current bootstrap has no root-attributed capability effect, so its exact
    // least-authority floor is empty; future effects must add source-derived
    // selectors and retained-callback denial evidence together.
    document["bootstrapAuthorityFloor"] = serde_json::json!([]);
    document["engine"] = serde_json::json!({
        "target": runtime_target_triple(),
        "binaryDigest": engine.binary_digest,
        "features": engine.structural_features,
    });
    let root_floor = serde_json::to_value(&root_authorities)?;
    document["principals"] = serde_json::json!([{
        "principal": {"kind": "root", "identity": "project-root"},
        "floor": root_floor,
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
    let project_host_path = absolute_artifact_path(project_root)?;
    let cache_host_path = absolute_artifact_path(&cache_root)?;
    let project_object = super::object_identity_for_host_path(project_root)?;
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
            marker_path: Some(project_host_path.clone()),
            marker_set_version: capsec_semantics::arming::PROJECT_ROOT_MARKER_SET_VERSION.into(),
        })?;
    if dev_project_root.is_some() {
        document["bootstrapCompatibilityModes"] = serde_json::json!(["dev-served"]);
        document["devServedProjectRoot"] = serde_json::to_value(&project_host_path)?;
    }
    document["pathCanonicalizers"] = serde_json::to_value(bound_volume_path_canonicalizers([
        (project_root.as_path(), &project_object),
        (cache_root.as_path(), &cache_object),
    ])?)?;
    document["exactEmbedder"] = serde_json::to_value(&binding)?;
    if let Some(gpu_binding) = gpu_binding.as_ref() {
        document["exactGpuProvider"] = serde_json::to_value(gpu_binding)?;
    }

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
    let gpu_profile_artifact = match (gpu_binding.as_ref(), webgpu_profile_bytes) {
        (Some(gpu_binding), Some(profile_bytes)) => Some(materialize_protected_artifact(
            "exact-webgpu-profile",
            profile_bytes,
            &gpu_binding.profile_digest,
        )?),
        (None, None) => None,
        _ => unreachable!("GPU artifact inputs were checked as a pair"),
    };
    let mut protected_objects = vec![
        serde_json::json!({"role": "armed-policy", "object": policy_artifact.object, "deniedActions": ["fs:write"]}),
        serde_json::json!({"role": "engine-binary", "object": engine.object, "deniedActions": ["fs:write"]}),
        serde_json::json!({"role": "package-graph", "object": graph_artifact.object, "deniedActions": ["fs:write"]}),
        serde_json::json!({"role": "registry", "object": registry_artifact.object, "deniedActions": ["fs:write"]}),
        serde_json::json!({"role": "exact-operation-manifest", "object": manifest_artifact.object, "deniedActions": ["fs:write"]}),
    ];
    if let Some(profile_artifact) = gpu_profile_artifact.as_ref() {
        protected_objects.push(serde_json::json!({
            "role": "exact-webgpu-profile",
            "object": profile_artifact.object,
            "deniedActions": ["fs:write"],
        }));
    }
    document["protectedObjects"] = serde_json::Value::Array(protected_objects);
    let armed_digest = freshen_document(&mut document, fresh_production_nonce()?)?;

    let mut expected = ExpectedArmingIdentity {
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
        embedded_protected_artifacts: Vec::new(),
    };
    if let Some(profile_artifact) = gpu_profile_artifact {
        expected
            .protected_artifacts
            .push(ExpectedProtectedArtifact {
                role: ProtectedArtifactRole::ExactWebgpuProfile,
                host_path: profile_artifact.host_path,
                object: profile_artifact.object,
                content_digest: profile_artifact.content_digest,
            });
    }
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
            embedded_protected_artifacts: Vec::new(),
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

    fn exact_webgpu_profile() -> Vec<u8> {
        br#"{"schema":"exact/webgpu-profile/1","profileId":"bone-tide-v1","operations":[1,2]}"#
            .to_vec()
    }

    fn exact_gpu_provider_binding(profile: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": "exact/webgpu-provider/1",
            "abiVersion": 0x0001_0000_u32,
            "profileId": "bone-tide-v1",
            "profileDigest": content_digest(profile),
            "webgpuCVocabularyDigest": content_digest(b"webgpu-c-vocabulary"),
            "operationSetDigest": content_digest(b"operation-set"),
            "semanticProgramDigest": content_digest(b"semantic-program"),
            "operationIds": [1, 2],
            "topology": "isolated-per-logical-v1",
        }))
        .unwrap()
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
                std::ptr::null(),
                0,
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

    fn build_exact_dev_through_abi(
        project_root: &std::path::Path,
        dev_project_root: &std::path::Path,
    ) -> serde_json::Value {
        let root = project_root.to_str().unwrap().as_bytes();
        let dev_root = dev_project_root.to_str().unwrap().as_bytes();
        let manifest = exact_manifest();
        let output = unsafe {
            crate::host::abi::ex_host_build_exact_armed_embedder_artifacts(
                root.as_ptr(),
                root.len(),
                dev_root.as_ptr(),
                dev_root.len(),
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

    fn build_exact_gpu_through_abi(project_root: &std::path::Path) -> serde_json::Value {
        let root = project_root.to_str().unwrap().as_bytes();
        let manifest = exact_manifest();
        let profile = exact_webgpu_profile();
        let binding = exact_gpu_provider_binding(&profile);
        let output = unsafe {
            crate::host::abi::ex_host_build_exact_gpu_armed_embedder_artifacts(
                root.as_ptr(),
                root.len(),
                std::ptr::null(),
                0,
                manifest.as_ptr(),
                manifest.len(),
                binding.as_ptr(),
                binding.len(),
                profile.as_ptr(),
                profile.len(),
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
            embedded_protected_artifacts: Vec::new(),
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
    fn target_local_exact_dev_builder_pairs_mode_with_the_explicit_dev_root() {
        let installed = tempfile::tempdir().unwrap();
        let dev = tempfile::tempdir().unwrap();
        let envelope = build_exact_dev_through_abi(installed.path(), dev.path());
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        assert_eq!(
            artifacts["snapshot"]["bootstrapCompatibilityModes"],
            serde_json::json!(["dev-served"])
        );
        assert_eq!(
            artifacts["snapshot"]["devServedProjectRoot"],
            artifacts["snapshot"]["rootBindings"][0]["hostPath"]
        );
        assert_eq!(
            artifacts["snapshot"]["devServedProjectRoot"],
            artifacts["snapshot"]["projectRootDiscovery"]["selectedRoot"]
        );
        assert_eq!(
            artifacts["snapshot"]["principals"][0]["floor"],
            serde_json::json!([{
                "cap": "network:listen",
                "resource": {
                    "kind": "listen-inet",
                    "transport": "tcp",
                    "bind": {"kind": "loopback"},
                    "port": {"kind": "ephemeral"},
                    "dualStack": false,
                    "peerClasses": ["loopback"],
                },
            }]),
            "dev-served Exact grants only the loopback ephemeral listener used by the agent"
        );
        assert_eq!(
            artifacts["snapshot"]["rootAuthorityCeiling"]["authorities"],
            artifacts["snapshot"]["principals"][0]["floor"],
            "the immutable root ceiling admits exactly the scoped dev listener floor"
        );
        let mut expected: ExpectedArmingIdentity =
            serde_json::from_value(artifacts["expectedIdentity"].clone()).unwrap();
        let snapshot = ArmedSnapshot::load(
            &serde_json::to_vec(&artifacts["snapshot"]).unwrap(),
            &expected,
        )
        .unwrap();
        crate::host::abi::validate_dev_served_project_root_pairing(&snapshot).unwrap();

        let mut unpaired = artifacts["snapshot"].clone();
        unpaired
            .as_object_mut()
            .unwrap()
            .remove("devServedProjectRoot");
        let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, &unpaired).unwrap();
        unpaired["armedSnapshotDigest"] = serde_json::json!(digest.clone());
        expected.armed_snapshot_digest = Digest::new(digest).unwrap();
        let unpaired =
            ArmedSnapshot::load(&serde_json::to_vec(&unpaired).unwrap(), &expected).unwrap();
        assert!(
            crate::host::abi::validate_dev_served_project_root_pairing(&unpaired)
                .unwrap_err()
                .contains("requires an explicit dev project root binding")
        );
    }

    #[test]
    fn target_local_exact_gpu_builder_protects_the_bound_profile() {
        let project = tempfile::tempdir().unwrap();
        let envelope = build_exact_gpu_through_abi(project.path());
        assert_eq!(envelope["ok"], true, "{envelope}");
        let artifacts = &envelope["artifacts"];
        assert_eq!(
            artifacts["expectedIdentity"]["protectedArtifacts"]
                .as_array()
                .unwrap()
                .len(),
            6
        );
        assert_eq!(
            artifacts["snapshot"]["exactGpuProvider"]["topology"],
            "isolated-per-logical-v1"
        );
        assert_eq!(
            artifacts["snapshot"]["exactGpuProvider"]["profileDigest"],
            serde_json::to_value(content_digest(&exact_webgpu_profile())).unwrap()
        );
        assert_eq!(
            artifacts["snapshot"]["principals"][0]["floor"],
            serde_json::json!([]),
            "the canonical GPU builder must not opt into private WebGPU selectors"
        );
        assert!(artifacts["snapshot"]["protectedObjects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["role"] == "exact-webgpu-profile"));
        assert!(artifacts["expectedIdentity"]["protectedArtifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["role"] == "exact-webgpu-profile"));
        let expected: ExpectedArmingIdentity =
            serde_json::from_value(artifacts["expectedIdentity"].clone()).unwrap();
        let snapshot = ArmedSnapshot::load(
            &serde_json::to_vec(&artifacts["snapshot"]).unwrap(),
            &expected,
        )
        .unwrap();
        assert_eq!(
            snapshot
                .exact_gpu_provider_binding()
                .unwrap()
                .unwrap()
                .profile_id,
            "bone-tide-v1"
        );
    }

    #[test]
    fn target_local_exact_gpu_builder_refuses_profile_digest_mismatch() {
        let project = tempfile::tempdir().unwrap();
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let profile = format!(
            "{{\"schema\":\"exact/webgpu-profile/1\",\"nonce\":\"{}\"}}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
        )
        .into_bytes();
        let binding = exact_gpu_provider_binding(&profile);
        let profile_digest = content_digest(&profile);
        let profile_artifact = crate::runtime_cache_dir()
            .unwrap()
            .join("capsec-artifacts")
            .join(format!(
                "{}.exact-webgpu-profile.json",
                profile_digest.as_str().trim_start_matches("sha256-")
            ));
        assert!(!profile_artifact.exists());
        let error = build_exact_gpu_embedder_artifacts(
            project.path(),
            None,
            &exact_manifest(),
            &binding,
            b"different profile bytes",
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("profile bytes do not match the provider profile digest"));
        assert!(
            !profile_artifact.exists(),
            "a refused profile must not be published into the artifact cache"
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

    #[cfg(windows)]
    #[test]
    fn windows_publishes_a_new_protected_artifact_without_opening_its_directory() {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).unwrap();
        let digest = content_digest(&bytes);
        let artifact =
            materialize_protected_artifact("windows-directory-sync-regression", &bytes, &digest)
                .unwrap();
        assert_eq!(artifact.content_digest, digest);
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
