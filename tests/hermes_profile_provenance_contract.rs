#[path = "../build_support/hermes_profile_provenance.rs"]
mod hermes_profile_provenance;

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn source_receipt(root: &Path) -> Value {
    let reviewed = hermes_profile_provenance::reviewed_profile_identity(root, "linux").unwrap();
    let cache_key = hermes_profile_provenance::source_profile_cache_keys(root, "libhermesvm.so")
        .unwrap()
        .remove(0);
    json!({
        "origin": {
            "kind": "source-patched-cache",
            "cacheKey": cache_key,
            "reviewedProfileIdentity": reviewed,
        }
    })
}

fn android_receipt(root: &Path) -> Value {
    let reviewed = hermes_profile_provenance::reviewed_profile_identity(root, "android").unwrap();
    let coordinate = format!(
        "{}:{}:{}",
        reviewed["artifact"].as_str().unwrap(),
        reviewed["version"].as_str().unwrap(),
        reviewed["variant"].as_str().unwrap()
    );
    let dependency_coordinate = format!(
        "{}:{}:{}",
        reviewed["linkedDependency"]["artifact"].as_str().unwrap(),
        reviewed["linkedDependency"]["version"].as_str().unwrap(),
        reviewed["linkedDependency"]["variant"].as_str().unwrap()
    );
    json!({
        "origin": {
            "kind": "maven-aar",
            "packageCoordinate": coordinate,
            "packageDigest": reviewed["packageDigest"],
            "packageRepository": "https://repo1.maven.org/maven2",
            "linkedDependency": {
                "artifact": {
                    "binaryDigest": "sha256-placeholder",
                    "fileName": "libjsi.so",
                    "targetArchitecture": "aarch64",
                },
                "packageCoordinate": dependency_coordinate,
                "packageDigest": reviewed["linkedDependency"]["packageDigest"],
                "packageRepository": "https://repo1.maven.org/maven2",
            },
            "reviewedProfileIdentity": reviewed,
        }
    })
}

fn windows_receipt(root: &Path) -> Value {
    let reviewed = hermes_profile_provenance::reviewed_profile_identity(root, "windows").unwrap();
    let coordinate = format!(
        "{}:{}",
        reviewed["artifact"].as_str().unwrap(),
        reviewed["version"].as_str().unwrap()
    );
    let service_index = reviewed["repositorySignature"]["serviceIndex"]
        .as_str()
        .unwrap();
    json!({
        "linkArtifact": {
            "binaryDigest": "sha256-placeholder",
            "fileName": "hermes.lib",
            "targetArchitecture": "x86_64",
        },
        "origin": {
            "kind": "nuget-package",
            "packageCoordinate": coordinate,
            "packageDigest": reviewed["packageDigest"],
            "packageRepository": service_index,
            "packageSignature": {
                "kind": "nuget-repository-signature",
                "serviceIndex": service_index,
                "verification": "dotnet-nuget-verify-all",
            },
            "reviewedProfileIdentity": reviewed,
        }
    })
}

#[test]
fn exact_checked_in_profile_authorities_are_accepted() {
    let root = repo_root();
    hermes_profile_provenance::validate_reviewed_profile_identity(
        &root,
        &source_receipt(&root),
        "linux",
        "libhermesvm.so",
    )
    .unwrap();
    hermes_profile_provenance::validate_reviewed_profile_identity(
        &root,
        &android_receipt(&root),
        "android",
        "libhermesvm.so",
    )
    .unwrap();
    hermes_profile_provenance::validate_reviewed_profile_identity(
        &root,
        &windows_receipt(&root),
        "windows",
        "hermes.dll",
    )
    .unwrap();
}

#[test]
fn current_installer_receipt_is_accepted_when_the_build_supplies_one() {
    let Some(path) = std::env::var_os("HERMES_PROFILE_PROVENANCE_RECEIPT") else {
        // Ordinary developer builds intentionally have no receipt. Required
        // provenance builds set this and exercise the real installer output.
        return;
    };
    let receipt: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let target_os = match receipt["profileId"].as_str().unwrap() {
        "source-patched" => "macos",
        "android-maven" => "android",
        "windows-nuget" => "windows",
        profile => panic!("unknown Hermes profile fixture {profile}"),
    };
    let selected_file_name = receipt["artifact"]["fileName"].as_str().unwrap();
    hermes_profile_provenance::validate_reviewed_profile_identity(
        &repo_root(),
        &receipt,
        target_os,
        selected_file_name,
    )
    .unwrap();
}

#[test]
fn empty_stale_and_extra_field_reviewed_identities_are_rejected_for_every_profile() {
    let root = repo_root();
    for (target_os, file_name, receipt) in [
        ("linux", "libhermesvm.so", source_receipt(&root)),
        ("android", "libhermesvm.so", android_receipt(&root)),
        ("windows", "hermes.dll", windows_receipt(&root)),
    ] {
        let mut empty = receipt.clone();
        empty["origin"]["reviewedProfileIdentity"] = json!({});
        let mut stale = receipt.clone();
        stale["origin"]["reviewedProfileIdentity"]["artifact"] = json!("stale/profile");
        let mut extra = receipt;
        extra["origin"]["reviewedProfileIdentity"]["unreviewedOverride"] = json!(true);
        for rejected in [empty, stale, extra] {
            let error = hermes_profile_provenance::validate_reviewed_profile_identity(
                &root, &rejected, target_os, file_name,
            )
            .unwrap_err();
            assert!(error.contains("checked-in profile authorities"), "{error}");
        }
    }
}

#[test]
fn origin_facts_must_match_the_reviewed_identity_and_build_authority() {
    let root = repo_root();

    let mut source = source_receipt(&root);
    source["origin"]["cacheKey"] = json!("stale-or-fabricated-cache");
    assert!(
        hermes_profile_provenance::validate_reviewed_profile_identity(
            &root,
            &source,
            "linux",
            "libhermesvm.so",
        )
        .unwrap_err()
        .contains("cacheKey")
    );

    let mut incomplete_authority_key = source_receipt(&root);
    let current_key = incomplete_authority_key["origin"]["cacheKey"]
        .as_str()
        .unwrap()
        .to_owned();
    let application_start = current_key.find("-a").unwrap();
    let identity_start = current_key.find("-i").unwrap();
    let platform_start = current_key.rfind("-o").unwrap();
    let linux_builder_start = current_key.find("-bl").unwrap();

    let historical_single_builder_key = format!(
        "{}{}",
        &current_key[..linux_builder_start],
        &current_key[application_start..]
    );
    let pre_application_authority_key = current_key[..application_start].to_owned();
    let pre_identity_authority_key = format!(
        "{}{}",
        &current_key[..identity_start],
        &current_key[platform_start..]
    );
    for rejected_key in [
        historical_single_builder_key,
        pre_application_authority_key,
        pre_identity_authority_key,
    ] {
        incomplete_authority_key["origin"]["cacheKey"] = json!(rejected_key);
        let error = hermes_profile_provenance::validate_reviewed_profile_identity(
            &root,
            &incomplete_authority_key,
            "linux",
            "libhermesvm.so",
        )
        .unwrap_err();
        assert!(error.contains("both build authorities"), "{error}");
        assert!(error.contains("patch-identity authority"), "{error}");
    }

    let mut android = android_receipt(&root);
    android["origin"]["linkedDependency"]["packageDigest"] = json!("sha256-fabricated");
    assert!(
        hermes_profile_provenance::validate_reviewed_profile_identity(
            &root,
            &android,
            "android",
            "libhermesvm.so",
        )
        .unwrap_err()
        .contains("package facts")
    );
    let mut android_coordinate = android_receipt(&root);
    android_coordinate["origin"]["packageCoordinate"] =
        json!("com.facebook.hermes:hermes-android:0.0.0:debug");
    assert!(
        hermes_profile_provenance::validate_reviewed_profile_identity(
            &root,
            &android_coordinate,
            "android",
            "libhermesvm.so",
        )
        .unwrap_err()
        .contains("package facts")
    );

    let mut windows = windows_receipt(&root);
    windows["origin"]["packageSignature"]["serviceIndex"] =
        json!("https://attacker.invalid/v3/index.json");
    assert!(
        hermes_profile_provenance::validate_reviewed_profile_identity(
            &root,
            &windows,
            "windows",
            "hermes.dll",
        )
        .unwrap_err()
        .contains("package/signature facts")
    );
    for field in ["packageCoordinate", "packageDigest"] {
        let mut invalid = windows_receipt(&root);
        invalid["origin"][field] = json!("fabricated");
        assert!(
            hermes_profile_provenance::validate_reviewed_profile_identity(
                &root,
                &invalid,
                "windows",
                "hermes.dll",
            )
            .unwrap_err()
            .contains("package/signature facts")
        );
    }
}

#[test]
fn profile_origins_are_exact_closed_objects() {
    let root = repo_root();
    let mut receipt = android_receipt(&root);
    receipt["origin"]["unreviewedOverride"] = json!(true);
    assert!(
        hermes_profile_provenance::validate_reviewed_profile_identity(
            &root,
            &receipt,
            "android",
            "libhermesvm.so",
        )
        .unwrap_err()
        .contains("malformed exact fields")
    );
}

#[test]
fn universal_artifacts_are_limited_to_the_macos_fat_framework_profile() {
    use hermes_profile_provenance::artifact_architecture_matches;

    assert!(artifact_architecture_matches(
        "macos",
        "aarch64",
        "universal"
    ));
    assert!(artifact_architecture_matches("macos", "aarch64", "aarch64"));
    assert!(artifact_architecture_matches(
        "android", "aarch64", "aarch64"
    ));
    assert!(artifact_architecture_matches("windows", "x86_64", "x86_64"));

    for target_os in ["android", "windows", "linux", "ios"] {
        assert!(
            !artifact_architecture_matches(target_os, "aarch64", "universal"),
            "{target_os} must require its target-specific artifact architecture"
        );
    }
    assert!(!artifact_architecture_matches("macos", "", "universal"));
}

#[test]
fn windows_link_selection_is_name_fixed_and_exactly_receipt_bound() {
    use sha2::{Digest as _, Sha256};

    assert!(hermes_profile_provenance::validate_windows_link_library_name(None).is_ok());
    assert!(hermes_profile_provenance::validate_windows_link_library_name(Some("hermes")).is_ok());
    for substituted in ["evil", "hermes_debug", "HERMES"] {
        assert!(
            hermes_profile_provenance::validate_windows_link_library_name(Some(substituted))
                .is_err()
        );
    }
    let digest = format!("sha256-{}", "a".repeat(64));
    assert_eq!(
        hermes_profile_provenance::windows_pinned_import_library_name(&digest).unwrap(),
        format!("hermes-{}.lib", "a".repeat(64))
    );
    let pinned = PathBuf::from("reviewed-windows-hermes-import")
        .join("a".repeat(64))
        .join(format!("hermes-{}.lib", "a".repeat(64)));
    assert_eq!(
        hermes_profile_provenance::windows_import_library_link_directives(&pinned).unwrap(),
        (
            format!("native={}", pinned.parent().unwrap().display()),
            format!("dylib:+verbatim=hermes-{}.lib", "a".repeat(64)),
        )
    );
    for malformed in [
        "a".repeat(64),
        format!("sha256-{}", "a".repeat(63)),
        format!("sha256-{}", "g".repeat(64)),
    ] {
        assert!(hermes_profile_provenance::windows_pinned_import_library_name(&malformed).is_err());
    }

    let directory = tempfile::tempdir().unwrap();
    let import_library = directory.path().join("hermes.lib");
    let bytes = b"reviewed Windows Hermes import library";
    std::fs::write(&import_library, bytes).unwrap();
    let digest = format!("sha256-{:x}", Sha256::digest(bytes));
    let mut receipt = windows_receipt(&repo_root());
    receipt["linkArtifact"]["binaryDigest"] = json!(digest);
    assert_eq!(
        hermes_profile_provenance::read_validated_windows_link_artifact(
            &receipt,
            &import_library,
            "x86_64",
        )
        .unwrap(),
        bytes
    );

    for (field, value) in [
        ("binaryDigest", json!("sha256-fabricated")),
        ("fileName", json!("evil.lib")),
        ("targetArchitecture", json!("universal")),
    ] {
        let mut invalid = receipt.clone();
        invalid["linkArtifact"][field] = value;
        assert!(
            hermes_profile_provenance::read_validated_windows_link_artifact(
                &invalid,
                &import_library,
                "x86_64",
            )
            .is_err(),
            "Windows linkArtifact accepted invalid {field}"
        );
    }
    let mut extra = receipt;
    extra["linkArtifact"]["unreviewedOverride"] = json!(true);
    assert!(
        hermes_profile_provenance::read_validated_windows_link_artifact(
            &extra,
            &import_library,
            "x86_64",
        )
        .is_err()
    );
}
