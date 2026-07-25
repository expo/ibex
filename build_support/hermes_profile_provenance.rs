use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

// @ref LLP 0013#artifact-provenance-and-remaining-trust-boundaries — receipts
// are installer assertions; build.rs independently reconstructs the exact
// reviewed package/source identity before it may embed one.

fn exact_object_fields(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    actual == expected
}

fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| {
        format!(
            "read reviewed profile authority {}: {error}",
            path.display()
        )
    })
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_authority_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|error| {
        format!(
            "hash reviewed profile authority {}: {error}",
            path.display()
        )
    })?;
    Ok(format!("sha256-{}", sha256_hex_bytes(&bytes)))
}

fn assignment_value<'a>(text: &'a str, prefix: &str, suffix: &str) -> Result<&'a str, String> {
    let matches = text
        .lines()
        .filter_map(|line| line.strip_prefix(prefix)?.strip_suffix(suffix))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [value] if !value.is_empty() => Ok(value),
        _ => Err(format!(
            "reviewed authority must contain exactly one non-empty {prefix}…{suffix} assignment"
        )),
    }
}

fn shell_self_default<'a>(text: &'a str, variable: &str) -> Result<&'a str, String> {
    assignment_value(text, &format!("{variable}=\"${{{variable}:-"), "}\"")
}

fn shell_literal<'a>(text: &'a str, variable: &str) -> Result<&'a str, String> {
    assignment_value(text, &format!("{variable}=\""), "\"")
}

fn checked_digest_hex<'a>(
    value: &'a str,
    algorithm: &str,
    digits: usize,
) -> Result<&'a str, String> {
    let prefix = format!("{algorithm}-");
    let Some(hex) = value.strip_prefix(&prefix) else {
        return Err(format!("reviewed digest must begin with {prefix}"));
    };
    if hex.len() != digits || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "reviewed {algorithm} digest must contain exactly {digits} hexadecimal digits"
        ));
    }
    Ok(hex)
}

fn patch_stack_authority(repo_root: &Path) -> Result<String, String> {
    let directory = repo_root.join("patches/hermes");
    let entries = std::fs::read_dir(&directory).map_err(|error| {
        format!(
            "read reviewed Hermes patch stack {}: {error}",
            directory.display()
        )
    })?;
    let mut patches = Vec::<(String, PathBuf)>::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("read reviewed Hermes patch entry: {error}"))?
            .path();
        if path.extension().and_then(|value| value.to_str()) != Some("patch") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "reviewed Hermes patch filename is not UTF-8".to_owned())?;
        patches.push((format!("patches/hermes/{name}"), path));
    }
    patches.sort_by(|left, right| left.0.cmp(&right.0));
    if patches.is_empty() {
        return Err("reviewed Hermes patch stack is empty".to_owned());
    }
    let mut manifest = Vec::new();
    for (relative, path) in patches {
        let bytes = std::fs::read(&path)
            .map_err(|error| format!("hash reviewed Hermes patch {}: {error}", path.display()))?;
        manifest.extend_from_slice(sha256_hex_bytes(&bytes).as_bytes());
        manifest.extend_from_slice(b"  ");
        manifest.extend_from_slice(relative.as_bytes());
        manifest.push(b'\n');
    }
    Ok(format!("sha256-{}", sha256_hex_bytes(&manifest)))
}

fn source_profile_identity(repo_root: &Path) -> Result<Value, String> {
    let version_path = repo_root.join("scripts/hermes-version.sh");
    let version_script = read_text(&version_path)?;
    let source_version = shell_self_default(&version_script, "IBEX_HERMES_VERSION")?;
    let source_commit = shell_self_default(&version_script, "IBEX_HERMES_SOURCE_COMMIT")?;
    let source_ref_expression = shell_self_default(&version_script, "IBEX_HERMES_SOURCE_REF")?;
    if source_ref_expression != "${IBEX_HERMES_VERSION}-stable" {
        return Err(
            "reviewed source ref must remain derived from the reviewed Hermes version".to_owned(),
        );
    }
    if source_commit.len() != 40 || !source_commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("reviewed Hermes source commit must be a 40-digit Git object ID".to_owned());
    }

    let patch_identity_start = version_script
        .find("ibex_sha256() {\n")
        .ok_or_else(|| "Hermes patch-identity authority function is absent".to_owned())?;
    let patch_identity = format!(
        "sha256-{}",
        sha256_hex_bytes(&version_script.as_bytes()[patch_identity_start..])
    );
    let patch_application =
        sha256_authority_file(&repo_root.join("scripts/apply-hermes-patches.sh"))?;
    let patch_stack = patch_stack_authority(repo_root)?;
    let apple_build = sha256_authority_file(&repo_root.join("scripts/build-hermes.sh"))?;
    let linux_build = sha256_authority_file(&repo_root.join("scripts/build-hermes-linux.sh"))?;

    Ok(json!({
        "artifact": "facebook/hermes",
        "patchApplicationAuthorityDigest": patch_application,
        "patchIdentityAuthorityDigest": patch_identity,
        "patchStackDigest": patch_stack,
        "sourceBuildAuthorityDigests": {
            "scripts/build-hermes-linux.sh": linux_build,
            "scripts/build-hermes.sh": apple_build,
        },
        "sourceCommit": source_commit,
        "sourceRef": format!("{source_version}-stable"),
        "sourceVersion": source_version,
    }))
}

fn android_profile_identity(repo_root: &Path) -> Result<Value, String> {
    let version_script = read_text(&repo_root.join("scripts/hermes-version.sh"))?;
    let version = shell_self_default(&version_script, "IBEX_HERMES_ANDROID_VERSION")?;
    let dependency_version = shell_self_default(&version_script, "IBEX_REACT_ANDROID_VERSION")?;
    let package_hex = shell_literal(&version_script, "IBEX_HERMES_ANDROID_DEBUG_AAR_SHA256")?;
    let dependency_hex = shell_literal(&version_script, "IBEX_REACT_ANDROID_DEBUG_AAR_SHA256")?;
    checked_digest_hex(&format!("sha256-{package_hex}"), "sha256", 64)?;
    checked_digest_hex(&format!("sha256-{dependency_hex}"), "sha256", 64)?;

    Ok(json!({
        "artifact": "com.facebook.hermes:hermes-android",
        "packageDigest": format!("sha256-{package_hex}"),
        "linkedDependency": {
            "artifact": "com.facebook.react:react-android",
            "packageDigest": format!("sha256-{dependency_hex}"),
            "variant": "debug",
            "version": dependency_version,
        },
        "variant": "debug",
        "version": version,
    }))
}

fn windows_profile_identity(repo_root: &Path) -> Result<Value, String> {
    let source = source_profile_identity(repo_root)?;
    let build_authority =
        sha256_authority_file(&repo_root.join("scripts/build-hermes-windows.ps1"))?;
    let installer_authority =
        sha256_authority_file(&repo_root.join("scripts/install-windows-hermes.ps1"))?;

    Ok(json!({
        "artifact": source["artifact"],
        "patchApplicationAuthorityDigest": source["patchApplicationAuthorityDigest"],
        "patchIdentityAuthorityDigest": source["patchIdentityAuthorityDigest"],
        "patchStackDigest": source["patchStackDigest"],
        "sourceBuildAuthorityDigest": build_authority,
        "sourceCommit": source["sourceCommit"],
        "sourceInstallerAuthorityDigest": installer_authority,
        "sourceRef": source["sourceRef"],
        "sourceVersion": source["sourceVersion"],
    }))
}

pub fn reviewed_profile_identity(repo_root: &Path, target_os: &str) -> Result<Value, String> {
    match target_os {
        "android" => android_profile_identity(repo_root),
        "windows" => windows_profile_identity(repo_root),
        _ => source_profile_identity(repo_root),
    }
}

/// Match the receipt architecture to the artifact Cargo selected for linking.
/// Only the macOS source framework may legitimately be a fat/universal binary;
/// Android Prefab and Windows source artifacts are selected per target ABI.
pub fn artifact_architecture_matches(
    target_os: &str,
    target_arch: &str,
    receipt_arch: &str,
) -> bool {
    !target_arch.is_empty()
        && (receipt_arch == target_arch || (target_os == "macos" && receipt_arch == "universal"))
}

pub fn validate_windows_link_library_name(configured: Option<&str>) -> Result<(), String> {
    if configured.is_none() || configured == Some("hermes") {
        Ok(())
    } else {
        Err(
            "reviewed Windows Hermes provenance requires the exact hermes import library name"
                .to_owned(),
        )
    }
}

pub fn windows_pinned_import_library_name(binding_digest: &str) -> Result<String, String> {
    let digest = checked_digest_hex(binding_digest, "sha256", 64)?;
    Ok(format!("hermes-{digest}.lib"))
}

pub fn windows_pinned_import_library_relative_path(
    binding_digest: &str,
) -> Result<PathBuf, String> {
    // Keep the full digest in the verbatim filename, but use a deliberately
    // short staging directory: link.exe still rejects otherwise valid paths
    // beyond its legacy path ceiling.
    Ok(PathBuf::from("h").join(windows_pinned_import_library_name(binding_digest)?))
}

pub fn windows_import_library_link_directives(
    import_library: &Path,
) -> Result<(String, String), String> {
    let directory = import_library.parent().ok_or_else(|| {
        "reviewed Windows Hermes import library has no parent directory".to_owned()
    })?;
    let name = import_library
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            "reviewed Windows Hermes import library filename is not valid Unicode".to_owned()
        })?;
    Ok((
        format!("native={}", directory.display()),
        format!("dylib:+verbatim={name}"),
    ))
}

pub fn read_validated_artifact_binding(
    binding: &Value,
    selected_path: &Path,
    target_os: &str,
    target_arch: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    if !exact_object_fields(binding, &["binaryDigest", "fileName", "targetArchitecture"]) {
        return Err(format!("{label} has malformed exact fields"));
    }
    let selected_name = selected_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("selected {label} filename is not UTF-8"))?;
    let receipt_arch = binding["targetArchitecture"].as_str().unwrap_or_default();
    if binding["fileName"] != selected_name
        || !artifact_architecture_matches(target_os, target_arch, receipt_arch)
    {
        return Err(format!(
            "{label} names a different artifact or target architecture"
        ));
    }
    let bytes = std::fs::read(selected_path)
        .map_err(|error| format!("read selected {label} {}: {error}", selected_path.display()))?;
    let digest = format!("sha256-{}", sha256_hex_bytes(&bytes));
    if binding["binaryDigest"] != digest {
        return Err(format!(
            "{label} digest does not match the exact artifact selected for linking"
        ));
    }
    Ok(bytes)
}

pub fn read_validated_windows_link_artifact(
    receipt: &Value,
    selected_path: &Path,
    target_arch: &str,
) -> Result<Vec<u8>, String> {
    let binding = receipt
        .get("linkArtifact")
        .ok_or_else(|| "Windows profile receipt has no linkArtifact".to_owned())?;
    read_validated_artifact_binding(
        binding,
        selected_path,
        "windows",
        target_arch,
        "Windows Hermes import-library binding",
    )
}

pub fn source_profile_cache_keys(
    repo_root: &Path,
    selected_file_name: &str,
) -> Result<Vec<String>, String> {
    let identity = source_profile_identity(repo_root)?;
    let commit = identity["sourceCommit"]
        .as_str()
        .ok_or_else(|| "source profile commit is not text".to_owned())?;
    let patch_hex = checked_digest_hex(
        identity["patchStackDigest"]
            .as_str()
            .ok_or_else(|| "source profile patch digest is not text".to_owned())?,
        "sha256",
        64,
    )?;
    let apple_build_hex = checked_digest_hex(
        identity["sourceBuildAuthorityDigests"]["scripts/build-hermes.sh"]
            .as_str()
            .ok_or_else(|| "source profile Apple build-authority digest is not text".to_owned())?,
        "sha256",
        64,
    )?;
    let linux_build_hex = checked_digest_hex(
        identity["sourceBuildAuthorityDigests"]["scripts/build-hermes-linux.sh"]
            .as_str()
            .ok_or_else(|| "source profile Linux build-authority digest is not text".to_owned())?,
        "sha256",
        64,
    )?;
    let patch_application_hex = checked_digest_hex(
        identity["patchApplicationAuthorityDigest"]
            .as_str()
            .ok_or_else(|| {
                "source profile patch-application-authority digest is not text".to_owned()
            })?,
        "sha256",
        64,
    )?;
    let patch_identity_hex = checked_digest_hex(
        identity["patchIdentityAuthorityDigest"]
            .as_str()
            .ok_or_else(|| {
                "source profile patch-identity-authority digest is not text".to_owned()
            })?,
        "sha256",
        64,
    )?;
    let authority_key = format!(
        "p{}-ba{}-bl{}-a{}-i{}",
        &patch_hex[..12],
        &apple_build_hex[..12],
        &linux_build_hex[..12],
        &patch_application_hex[..12],
        &patch_identity_hex[..12]
    );
    if selected_file_name == "libhermesvm.so" {
        Ok(vec![format!("{}-{}-olinux", &commit[..12], authority_key)])
    } else {
        Ok(vec![
            format!("{}-debug-{}-oapple", &commit[..12], authority_key),
            format!("{}-{}-oapple", &commit[..12], authority_key),
        ])
    }
}

pub fn validate_reviewed_profile_identity(
    repo_root: &Path,
    receipt: &Value,
    target_os: &str,
    selected_file_name: &str,
) -> Result<(), String> {
    let origin = receipt
        .get("origin")
        .ok_or_else(|| "profile receipt has no origin".to_owned())?;
    let reviewed = origin
        .get("reviewedProfileIdentity")
        .ok_or_else(|| "profile receipt has no reviewedProfileIdentity".to_owned())?;
    let expected = reviewed_profile_identity(repo_root, target_os)?;
    if reviewed != &expected {
        return Err(
            "reviewedProfileIdentity does not equal the checked-in profile authorities".to_owned(),
        );
    }

    match target_os {
        "android" => validate_android_origin(origin, &expected),
        "windows" => validate_windows_origin(origin, &expected),
        _ => {
            if !exact_object_fields(origin, &["cacheKey", "kind", "reviewedProfileIdentity"])
                || origin["kind"] != "source-patched-cache"
            {
                return Err("source profile origin has malformed exact fields".to_owned());
            }
            let cache_key = origin["cacheKey"]
                .as_str()
                .ok_or_else(|| "source profile cacheKey is not text".to_owned())?;
            if !source_profile_cache_keys(repo_root, selected_file_name)?
                .iter()
                .any(|expected| expected == cache_key)
            {
                return Err(
                    "source profile cacheKey does not bind the reviewed pin, patch stack, both build authorities, patch-application authority, and patch-identity authority"
                        .to_owned(),
                );
            }
            Ok(())
        }
    }
}

fn validate_android_origin(origin: &Value, reviewed: &Value) -> Result<(), String> {
    if !exact_object_fields(
        origin,
        &[
            "kind",
            "linkedDependency",
            "packageCoordinate",
            "packageDigest",
            "packageRepository",
            "reviewedProfileIdentity",
        ],
    ) || origin["kind"] != "maven-aar"
    {
        return Err("Android profile origin has malformed exact fields".to_owned());
    }
    let dependency = &origin["linkedDependency"];
    if !exact_object_fields(
        dependency,
        &[
            "artifact",
            "packageCoordinate",
            "packageDigest",
            "packageRepository",
        ],
    ) {
        return Err("Android linked dependency has malformed exact fields".to_owned());
    }
    let repository = origin["packageRepository"]
        .as_str()
        .ok_or_else(|| "Android package repository is not text".to_owned())?;
    if repository.is_empty() || dependency["packageRepository"] != repository {
        return Err("Android package repositories are empty or inconsistent".to_owned());
    }
    let coordinate = format!(
        "{}:{}:{}",
        reviewed["artifact"].as_str().unwrap_or_default(),
        reviewed["version"].as_str().unwrap_or_default(),
        reviewed["variant"].as_str().unwrap_or_default()
    );
    let dependency_coordinate = format!(
        "{}:{}:{}",
        reviewed["linkedDependency"]["artifact"]
            .as_str()
            .unwrap_or_default(),
        reviewed["linkedDependency"]["version"]
            .as_str()
            .unwrap_or_default(),
        reviewed["linkedDependency"]["variant"]
            .as_str()
            .unwrap_or_default()
    );
    if origin["packageCoordinate"] != coordinate
        || origin["packageDigest"] != reviewed["packageDigest"]
        || dependency["packageCoordinate"] != dependency_coordinate
        || dependency["packageDigest"] != reviewed["linkedDependency"]["packageDigest"]
    {
        return Err(
            "Android receipt package facts do not match the reviewed identities".to_owned(),
        );
    }
    Ok(())
}

fn validate_windows_origin(origin: &Value, _reviewed: &Value) -> Result<(), String> {
    if !exact_object_fields(
        origin,
        &[
            "configuration",
            "debugger",
            "kind",
            "reviewedProfileIdentity",
        ],
    ) || origin["kind"] != "source-patched-build"
        || origin["configuration"] != "Release"
        || origin["debugger"] != false
    {
        return Err("Windows profile origin has malformed exact fields".to_owned());
    }
    Ok(())
}
