//! Select the exact promoted scoped conformance report and scope artifact for
//! runtime embedding.
//!
//! The promotion verifier has already established Git topology before Cargo
//! starts. This Rust-side join nevertheless reopens no caller-selected path:
//! it recomputes the active catalog admission, derives one fixed report path,
//! verifies both paths' role/blob/raw identity, and rejoins the report and
//! scope to the tracked v3 advertisement before copying their exact bytes into
//! `OUT_DIR`.
//!
//! @ref LLP 0035#promotion-lineage-and-admission — promoted evidence is
//! selected by the checked admission, never by an ambient path.
//! @ref LLP 0035#reports-and-advertisements — the advertisement binds the
//! exact scoped v3 report and its carried scope artifact.

use serde_json::{Map, Value};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

const CATALOG_PATH: &str = "schemas/portable-engine-promotion-admission-catalog-v1.json";
const ADVERTISEMENT_PATH: &str = "capsec/generated/target-advertisements.json";
const CATALOG_SCHEMA: &str = "ibex/portable-engine-promotion-admission-catalog/2";
const ADMISSION_SCHEMA: &str = "ibex/portable-engine-promotion-admission/2";
const ADMISSION_DOMAIN: &str = "ibex.portable-engine-promotion-admission.v2";
const MERGE_TOPOLOGY: &str = "github-pull-request-merge/direct-single-commit-topic/1";
const CHECKED_ADMISSION_SCHEMA: &str = "ibex/portable-engine-checked-promotion-admission/2";
const ADVERTISEMENT_SCHEMA: &str = "ibex/capsec-target-advertisements/3";
const REPORT_SCHEMA: &str = "ibex/capsec-conformance/3";
const REPORT_DOMAIN: &str = "ibex:capsec:conformance:3";
const SCOPE_SCHEMA: &str = "ibex/capsec-scope/1";
const PROFILE: &str = "ibex/capsec/1";
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub struct EmbeddedPromotionReport {
    pub report_bytes: Vec<u8>,
    pub scope_bytes: Vec<u8>,
    pub rerun_if_changed: Vec<PathBuf>,
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} is not an object"))?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(format!("{label} does not have its exact fields"));
    }
    Ok(object)
}

fn text<'a>(object: &'a Map<String, Value>, field: &str, label: &str) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}.{field} is not a string"))
}

fn parse_canonical_line(bytes: &[u8], label: &str) -> Result<Value, String> {
    let canonical = bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| format!("{label} must end in exactly one LF"))?;
    if canonical.ends_with(b"\n") {
        return Err(format!("{label} has more than one trailing LF"));
    }
    crate::portable_engine_build_consumption::parse_canonical(canonical, label)
}

fn safe_repository_path(relative: &str) -> bool {
    let path = Path::new(relative);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !relative.contains('\\')
}

fn read_checked_repository_file(
    repo_root: &Path,
    relative: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    if !safe_repository_path(relative) {
        return Err(format!("{label} path is not one safe repository path"));
    }
    let mut current = repo_root.to_path_buf();
    for component in Path::new(relative).components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("inspect {label} {}: {error}", current.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "{label} path is redirected at {}",
                current.display()
            ));
        }
    }
    let path = repo_root.join(relative);
    let before = fs::symlink_metadata(&path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    let mode = before.mode() & 0o7777;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > MAX_FILE_BYTES
        || mode != 0o644
    {
        return Err(format!(
            "{label} is not one bounded regular non-executable tracked file"
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(&path)
        .map_err(|error| format!("open {label} without following: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("inspect open {label}: {error}"))?;
    if before.dev() != opened.dev() || before.ino() != opened.ino() || before.len() != opened.len()
    {
        return Err(format!("{label} changed while opened"));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read {label}: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("reinspect open {label}: {error}"))?;
    if bytes.len() as u64 != before.len()
        || opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || opened.len() != after.len()
    {
        return Err(format!("{label} changed while read"));
    }
    Ok(bytes)
}

fn raw_digest(bytes: &[u8]) -> String {
    format!("sha256-{:x}", Sha256::digest(bytes))
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let value = ((bytes[index] as u32) << 16)
            | ((bytes[index + 1] as u32) << 8)
            | bytes[index + 2] as u32;
        output.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        output.push(ALPHABET[((value >> 6) & 63) as usize] as char);
        output.push(ALPHABET[(value & 63) as usize] as char);
        index += 3;
    }
    match bytes.len() - index {
        1 => {
            let value = (bytes[index] as u32) << 16;
            output.push(ALPHABET[((value >> 18) & 63) as usize] as char);
            output.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        }
        2 => {
            let value = ((bytes[index] as u32) << 16) | ((bytes[index + 1] as u32) << 8);
            output.push(ALPHABET[((value >> 18) & 63) as usize] as char);
            output.push(ALPHABET[((value >> 12) & 63) as usize] as char);
            output.push(ALPHABET[((value >> 6) & 63) as usize] as char);
        }
        _ => {}
    }
    output
}

fn raw_content_digest(bytes: &[u8]) -> String {
    format!("sha256-{}", base64url(&Sha256::digest(bytes)))
}

fn git_blob_object_id(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn fixed_report_path(source: &str, target: &str, artifact: &str) -> String {
    format!(
        "capsec/conformance/portable-promotions/{source}/{target}/{artifact}/conformance-report.json"
    )
}

fn fixed_scope_path(source: &str, target: &str, artifact: &str) -> String {
    format!("capsec/conformance/portable-promotions/{source}/{target}/{artifact}/capsec-scope.json")
}

fn checked_admission(bytes: &[u8]) -> Result<Value, String> {
    let value = parse_canonical_line(bytes, "checked promotion admission")?;
    let object = exact_object(
        &value,
        &[
            "schema",
            "authorized",
            "currentRevision",
            "sourceRevision",
            "promotionTopicRevision",
            "sourceTreeObjectId",
            "target",
            "portableArtifactId",
            "admissionDigest",
            "admittedScopeDigest",
            "predecessorScopeDigest",
            "verificationDigest",
        ],
        "checked promotion admission",
    )?;
    if text(object, "schema", "checked promotion admission")? != CHECKED_ADMISSION_SCHEMA {
        return Err("checked promotion admission has the wrong schema".to_owned());
    }
    Ok(value)
}

fn selected_admission<'a>(
    catalog: &'a Value,
    checked: &Map<String, Value>,
) -> Result<&'a Value, String> {
    let root = exact_object(
        catalog,
        &["schema", "enabled", "admissionPath", "admissions"],
        "promotion admission catalog",
    )?;
    if text(root, "schema", "promotion admission catalog")? != CATALOG_SCHEMA
        || text(root, "admissionPath", "promotion admission catalog")? != CATALOG_PATH
        || root.get("enabled") != Some(&Value::Bool(true))
    {
        return Err("promotion admission catalog is not the exact active catalog".to_owned());
    }
    let rows = root
        .get("admissions")
        .and_then(Value::as_array)
        .filter(|rows| rows.len() == 1)
        .ok_or_else(|| {
            "active promotion catalog does not carry exactly one admission".to_owned()
        })?;
    let admission = &rows[0];
    let object = exact_object(
        admission,
        &[
            "schema",
            "sourceRevision",
            "sourceTreeObjectId",
            "topology",
            "target",
            "portableArtifactId",
            "artifacts",
            "admittedScopeDigest",
            "admissionDigest",
        ],
        "promotion catalog admission",
    )?;
    for field in [
        "sourceRevision",
        "sourceTreeObjectId",
        "target",
        "portableArtifactId",
        "admittedScopeDigest",
        "admissionDigest",
    ] {
        if object.get(field) != checked.get(field) {
            return Err(format!(
                "promotion catalog {field} differs from the checked admission"
            ));
        }
    }
    if text(object, "schema", "promotion catalog admission")? != ADMISSION_SCHEMA
        || text(object, "topology", "promotion catalog admission")? != MERGE_TOPOLOGY
    {
        return Err("promotion catalog admission has the wrong schema or topology".to_owned());
    }
    let computed = crate::portable_engine_build_consumption::semantic_digest_without(
        ADMISSION_DOMAIN,
        admission,
        "admissionDigest",
    )?;
    if text(object, "admissionDigest", "promotion catalog admission")? != computed {
        return Err("promotion catalog admissionDigest is stale or substituted".to_owned());
    }
    Ok(admission)
}

fn select_artifact<'a>(
    admission: &'a Value,
    expected_path: &str,
    expected_role: &str,
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    let artifacts = admission
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| "promotion admission has no artifact rows".to_owned())?;
    let matching = artifacts
        .iter()
        .filter(|artifact| artifact.get("path").and_then(Value::as_str) == Some(expected_path))
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(format!(
            "promotion admission does not select one fixed {label}"
        ));
    }
    let artifact = exact_object(
        matching[0],
        &["role", "path", "mode", "blobObjectId", "size", "digest"],
        label,
    )?;
    if text(artifact, "role", label)? != expected_role || text(artifact, "mode", label)? != "100644"
    {
        return Err(format!("fixed promoted {label} has the wrong role or mode"));
    }
    Ok(artifact)
}

fn matching_advertisement<'a>(
    advertisements: &'a Value,
    checked: &Map<String, Value>,
) -> Result<&'a Map<String, Value>, String> {
    let root = exact_object(
        advertisements,
        &[
            "targetAdvertisementSchema",
            "profile",
            "targetCellsRawContentDigest",
            "advertisements",
        ],
        "tracked target advertisements",
    )?;
    if text(
        root,
        "targetAdvertisementSchema",
        "tracked target advertisements",
    )? != ADVERTISEMENT_SCHEMA
        || text(root, "profile", "tracked target advertisements")? != PROFILE
    {
        return Err("tracked target advertisements are not exact v3 publication bytes".to_owned());
    }
    let rows = root
        .get("advertisements")
        .and_then(Value::as_array)
        .ok_or_else(|| "tracked target advertisements have no rows".to_owned())?;
    let matching = rows
        .iter()
        .filter_map(Value::as_object)
        .filter(|row| {
            row.get("sourceRevision") == checked.get("sourceRevision")
                && row.get("target") == checked.get("target")
                && row
                    .get("engine")
                    .and_then(|engine| engine.get("artifactId"))
                    == checked.get("portableArtifactId")
        })
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(
            "tracked v3 publication has no unique checked target/artifact/source row".to_owned(),
        );
    }
    Ok(matching[0])
}

fn verify_report_advertisement_join(
    report_bytes: &[u8],
    scope_bytes: &[u8],
    advertisement_catalog: &Value,
    checked: &Map<String, Value>,
) -> Result<(), String> {
    let report = crate::portable_engine_build_consumption::parse_strict(
        report_bytes,
        "promoted conformance report",
    )?;
    let report_root = exact_object(
        &report,
        &[
            "conformanceSchema",
            "profile",
            "status",
            "bindings",
            "summary",
            "executions",
            "cells",
            "conformanceDigest",
        ],
        "promoted conformance report",
    )?;
    if text(
        report_root,
        "conformanceSchema",
        "promoted conformance report",
    )? != REPORT_SCHEMA
        || text(report_root, "profile", "promoted conformance report")? != PROFILE
        || text(report_root, "status", "promoted conformance report")? != "conformant"
    {
        return Err("promoted report is not one conformant v3 report".to_owned());
    }
    let computed = crate::portable_engine_build_consumption::semantic_digest_without(
        REPORT_DOMAIN,
        &report,
        "conformanceDigest",
    )?;
    if text(
        report_root,
        "conformanceDigest",
        "promoted conformance report",
    )? != computed
    {
        return Err("promoted conformance report digest is stale or substituted".to_owned());
    }
    let advertisement = matching_advertisement(advertisement_catalog, checked)?;
    if advertisement.get("reportRawContentDigest")
        != Some(&Value::String(raw_content_digest(report_bytes)))
        || advertisement.get("conformanceDigest") != report_root.get("conformanceDigest")
    {
        return Err(
            "tracked advertisement does not bind the exact promoted report bytes".to_owned(),
        );
    }
    let bindings = report_root
        .get("bindings")
        .and_then(Value::as_object)
        .ok_or_else(|| "promoted report bindings are not an object".to_owned())?;
    let scope = crate::portable_engine_build_consumption::parse_strict(
        scope_bytes,
        "promoted scope artifact",
    )?;
    let scope_root = scope
        .as_object()
        .ok_or_else(|| "promoted scope artifact is not an object".to_owned())?;
    if scope_root.get("scopeSchema").and_then(Value::as_str) != Some(SCOPE_SCHEMA)
        || scope_root.get("profile").and_then(Value::as_str) != Some(PROFILE)
        || scope_root.get("target") != checked.get("target")
        || scope_root.get("scopeDigest") != checked.get("admittedScopeDigest")
        || advertisement.get("scopeDigest") != checked.get("admittedScopeDigest")
        || bindings.get("scopeDigest") != checked.get("admittedScopeDigest")
    {
        return Err(
            "promoted scope/report/advertisement/checked-admission join differs".to_owned(),
        );
    }
    for field in [
        "target",
        "sourceRevision",
        "sourceTreeDigest",
        "engine",
        "mappedEngineExecutionEvidence",
        "vocabularyDigest",
        "registryDigest",
        "implementationManifestDigest",
        "fixtureCatalogDigest",
        "recipeCatalogDigest",
        "recipeCatalogRawContentDigest",
        "publicSurfaceExecutionDigest",
        "publicSurfaceExecutionRawContentDigest",
        "outputDispositionEvidenceRawContentDigest",
    ] {
        if advertisement.get(field) != bindings.get(field) {
            return Err(format!(
                "promoted report binding {field} differs from its advertisement"
            ));
        }
    }
    if advertisement_catalog.get("targetCellsRawContentDigest")
        != bindings.get("targetCellsRawContentDigest")
    {
        return Err(
            "promoted report target-cell identity differs from its advertisement".to_owned(),
        );
    }
    Ok(())
}

pub fn select_embedded_report(
    repo_root: &Path,
    checked_admission_bytes: &[u8],
) -> Result<EmbeddedPromotionReport, String> {
    if checked_admission_bytes == b"null\n" {
        return Ok(EmbeddedPromotionReport {
            report_bytes: b"null\n".to_vec(),
            scope_bytes: b"null\n".to_vec(),
            rerun_if_changed: Vec::new(),
        });
    }
    let checked_value = checked_admission(checked_admission_bytes)?;
    let checked = checked_value
        .as_object()
        .ok_or_else(|| "checked promotion admission is not an object".to_owned())?;
    if checked.get("authorized") == Some(&Value::Bool(false)) {
        return Ok(EmbeddedPromotionReport {
            report_bytes: b"null\n".to_vec(),
            scope_bytes: b"null\n".to_vec(),
            rerun_if_changed: Vec::new(),
        });
    }
    if checked.get("authorized") != Some(&Value::Bool(true)) {
        return Err("checked promotion admission has no boolean authorization".to_owned());
    }
    let catalog_bytes = read_checked_repository_file(
        repo_root,
        CATALOG_PATH,
        "tracked promotion admission catalog",
    )?;
    let catalog = parse_canonical_line(&catalog_bytes, "tracked promotion admission catalog")?;
    let admission = selected_admission(&catalog, checked)?;
    let source = text(checked, "sourceRevision", "checked promotion admission")?;
    let target = checked
        .get("target")
        .and_then(|target| target.get("triple"))
        .and_then(Value::as_str)
        .ok_or_else(|| "checked promotion admission target.triple is not a string".to_owned())?;
    let artifact = text(checked, "portableArtifactId", "checked promotion admission")?;
    let report_path = fixed_report_path(source, target, artifact);
    let report_artifact = select_artifact(
        admission,
        &report_path,
        "conformance-evidence",
        "promoted conformance-report artifact",
    )?;
    let report_bytes =
        read_checked_repository_file(repo_root, &report_path, "promoted conformance report")?;
    if report_artifact.get("size").and_then(Value::as_u64) != Some(report_bytes.len() as u64)
        || text(
            report_artifact,
            "digest",
            "promoted conformance-report artifact",
        )? != raw_digest(&report_bytes)
        || text(
            report_artifact,
            "blobObjectId",
            "promoted conformance-report artifact",
        )? != git_blob_object_id(&report_bytes)
    {
        return Err(
            "promoted report bytes differ from their catalog size/raw/blob binding".to_owned(),
        );
    }
    let scope_path = fixed_scope_path(source, target, artifact);
    let scope_artifact = select_artifact(
        admission,
        &scope_path,
        "scope-artifact",
        "promoted scope artifact",
    )?;
    let scope_bytes =
        read_checked_repository_file(repo_root, &scope_path, "promoted scope artifact")?;
    if scope_artifact.get("size").and_then(Value::as_u64) != Some(scope_bytes.len() as u64)
        || text(scope_artifact, "digest", "promoted scope artifact")? != raw_digest(&scope_bytes)
        || text(scope_artifact, "blobObjectId", "promoted scope artifact")?
            != git_blob_object_id(&scope_bytes)
    {
        return Err(
            "promoted scope bytes differ from their catalog size/raw/blob binding".to_owned(),
        );
    }
    let advertisement_bytes = read_checked_repository_file(
        repo_root,
        ADVERTISEMENT_PATH,
        "tracked target advertisements",
    )?;
    let advertisements = crate::portable_engine_build_consumption::parse_strict(
        &advertisement_bytes,
        "tracked target advertisements",
    )?;
    verify_report_advertisement_join(&report_bytes, &scope_bytes, &advertisements, checked)?;
    Ok(EmbeddedPromotionReport {
        report_bytes,
        scope_bytes,
        rerun_if_changed: vec![
            repo_root.join(CATALOG_PATH),
            repo_root.join(ADVERTISEMENT_PATH),
            repo_root.join(report_path),
            repo_root.join(scope_path),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use tempfile::TempDir;

    const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CURRENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TOPIC: &str = "cccccccccccccccccccccccccccccccccccccccc";
    const TREE: &str = "dddddddddddddddddddddddddddddddddddddddd";
    const TARGET: &str = "aarch64-apple-darwin";

    fn digest(label: &str) -> String {
        crate::portable_engine_build_consumption::semantic_digest_without(
            "ibex.test.promoted-report.v1",
            &serde_json::json!({"label": label, "digest": "placeholder"}),
            "digest",
        )
        .unwrap()
    }

    fn write_tracked(root: &Path, relative: &str, bytes: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    fn pretty_line(value: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn canonical_line(value: &Value) -> Vec<u8> {
        let mut bytes = crate::portable_engine_build_consumption::canonical_json(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    struct Fixture {
        _temporary: TempDir,
        root: PathBuf,
        checked: Vec<u8>,
        report_path: String,
        report_bytes: Vec<u8>,
        scope_bytes: Vec<u8>,
    }

    fn fixture() -> Fixture {
        let temporary = TempDir::new().unwrap();
        let root = temporary.path().join("checkout");
        fs::create_dir(&root).unwrap();
        let artifact = digest("artifact");
        let target = serde_json::json!({
            "triple": TARGET,
            "features": ["native-lockdown"],
        });
        let engine = serde_json::json!({"artifactId": artifact});
        let mapped = serde_json::json!([{
            "evidenceDigest": digest("evidence"),
            "rawContentDigest": digest("evidence-raw"),
            "attemptDigest": digest("attempt"),
            "attemptRawContentDigest": digest("attempt-raw"),
        }]);
        let target_cells_digest = digest("target-cells");
        let scope_digest = digest("scope");
        let scope = serde_json::json!({
            "scopeSchema": SCOPE_SCHEMA,
            "profile": PROFILE,
            "target": target,
            "intensionalDefinition": {
                "capabilityFamilies": ["fs"],
                "surfaceKinds": ["native"]
            },
            "expandedCellIds": ["surface.native.test"],
            "closureEdges": [{
                "fromEdgeId": "surface.native.test",
                "toEdgeId": "surface.native.test",
                "dependencyKind": "source-derived-route",
                "implementationBranchId": "surface.native.test.default",
                "terminalObservedKey": "native-op:scope-fixture",
                "proofPaths": ["native-op:scope-fixture"],
                "sourceRefs": ["build_support/portable_engine_promotion_report.rs#scope-fixture"]
            }],
            "predecessor": {"kind": "genesis"},
            "scopeExpansionDiffDigest": digest("scope-diff"),
            "scopeCellMappingDigest": digest("scope-mapping"),
            "scopeDigest": scope_digest,
        });
        let scope_bytes = crate::portable_engine_build_consumption::canonical_json(&scope).unwrap();
        let mut report = serde_json::json!({
            "conformanceSchema": REPORT_SCHEMA,
            "profile": PROFILE,
            "status": "conformant",
            "bindings": {
                "sourceRevision": SOURCE,
                "sourceTreeDigest": digest("source-tree"),
                "engine": engine,
                "target": target,
                "vocabularyDigest": digest("vocabulary"),
                "registryDigest": digest("registry"),
                "implementationManifestDigest": digest("implementation"),
                "fixtureCatalogDigest": digest("fixtures"),
                "recipeCatalogDigest": digest("recipes"),
                "recipeCatalogRawContentDigest": digest("recipes-raw"),
                "publicSurfaceExecutionDigest": digest("public"),
                "publicSurfaceExecutionRawContentDigest": digest("public-raw"),
                "targetCellsRawContentDigest": target_cells_digest,
                "outputDispositionEvidenceRawContentDigest": digest("output-raw"),
                "mappedEngineExecutionEvidence": mapped,
                "scopeDigest": scope_digest,
            },
            "summary": {},
            "executions": [],
            "cells": [],
            "conformanceDigest": digest("placeholder-report"),
        });
        report["conformanceDigest"] = Value::String(
            crate::portable_engine_build_consumption::semantic_digest_without(
                REPORT_DOMAIN,
                &report,
                "conformanceDigest",
            )
            .unwrap(),
        );
        let report_bytes = pretty_line(&report);
        let advertisement_row = serde_json::json!({
            "target": report["bindings"]["target"],
            "conformanceDigest": report["conformanceDigest"],
            "reportRawContentDigest": raw_content_digest(&report_bytes),
            "sourceRevision": report["bindings"]["sourceRevision"],
            "sourceTreeDigest": report["bindings"]["sourceTreeDigest"],
            "engine": report["bindings"]["engine"],
            "mappedEngineExecutionEvidence": report["bindings"]["mappedEngineExecutionEvidence"],
            "vocabularyDigest": report["bindings"]["vocabularyDigest"],
            "registryDigest": report["bindings"]["registryDigest"],
            "implementationManifestDigest": report["bindings"]["implementationManifestDigest"],
            "fixtureCatalogDigest": report["bindings"]["fixtureCatalogDigest"],
            "recipeCatalogDigest": report["bindings"]["recipeCatalogDigest"],
            "recipeCatalogRawContentDigest": report["bindings"]["recipeCatalogRawContentDigest"],
            "publicSurfaceExecutionDigest": report["bindings"]["publicSurfaceExecutionDigest"],
            "publicSurfaceExecutionRawContentDigest": report["bindings"]["publicSurfaceExecutionRawContentDigest"],
            "outputDispositionEvidenceRawContentDigest": report["bindings"]["outputDispositionEvidenceRawContentDigest"],
            "scopeDigest": report["bindings"]["scopeDigest"],
        });
        let advertisements = serde_json::json!({
            "targetAdvertisementSchema": ADVERTISEMENT_SCHEMA,
            "profile": PROFILE,
            "targetCellsRawContentDigest": target_cells_digest,
            "advertisements": [advertisement_row],
        });
        write_tracked(&root, ADVERTISEMENT_PATH, &pretty_line(&advertisements));

        let report_path = fixed_report_path(SOURCE, TARGET, &artifact);
        write_tracked(&root, &report_path, &report_bytes);
        let scope_path = fixed_scope_path(SOURCE, TARGET, &artifact);
        write_tracked(&root, &scope_path, &scope_bytes);
        let mut admission = serde_json::json!({
            "schema": ADMISSION_SCHEMA,
            "sourceRevision": SOURCE,
            "sourceTreeObjectId": TREE,
            "topology": MERGE_TOPOLOGY,
            "target": target,
            "portableArtifactId": artifact,
            "artifacts": [
                {
                    "role": "conformance-evidence",
                    "path": report_path,
                    "mode": "100644",
                    "blobObjectId": git_blob_object_id(&report_bytes),
                    "size": report_bytes.len(),
                    "digest": raw_digest(&report_bytes),
                },
                {
                    "role": "scope-artifact",
                    "path": scope_path,
                    "mode": "100644",
                    "blobObjectId": git_blob_object_id(&scope_bytes),
                    "size": scope_bytes.len(),
                    "digest": raw_digest(&scope_bytes),
                }
            ],
            "admittedScopeDigest": scope_digest,
            "admissionDigest": digest("placeholder-admission"),
        });
        admission["admissionDigest"] = Value::String(
            crate::portable_engine_build_consumption::semantic_digest_without(
                ADMISSION_DOMAIN,
                &admission,
                "admissionDigest",
            )
            .unwrap(),
        );
        let catalog = serde_json::json!({
            "schema": CATALOG_SCHEMA,
            "enabled": true,
            "admissionPath": CATALOG_PATH,
            "admissions": [admission],
        });
        write_tracked(&root, CATALOG_PATH, &canonical_line(&catalog));
        let checked_value = serde_json::json!({
            "schema": CHECKED_ADMISSION_SCHEMA,
            "authorized": true,
            "currentRevision": CURRENT,
            "sourceRevision": SOURCE,
            "promotionTopicRevision": TOPIC,
            "sourceTreeObjectId": TREE,
            "target": target,
            "portableArtifactId": artifact,
            "admissionDigest": admission["admissionDigest"],
            "admittedScopeDigest": scope_digest,
            "predecessorScopeDigest": "genesis",
            "verificationDigest": digest("checked"),
        });
        Fixture {
            _temporary: temporary,
            root,
            checked: canonical_line(&checked_value),
            report_path,
            report_bytes,
            scope_bytes,
        }
    }

    #[test]
    fn diagnostic_build_emits_the_exact_null_report_marker() {
        let checked = serde_json::json!({
            "schema": CHECKED_ADMISSION_SCHEMA,
            "authorized": false,
            "currentRevision": SOURCE,
            "sourceRevision": SOURCE,
            "promotionTopicRevision": null,
            "sourceTreeObjectId": null,
            "target": {"triple": TARGET, "features": ["native-lockdown"]},
            "portableArtifactId": digest("artifact"),
            "admissionDigest": null,
            "admittedScopeDigest": null,
            "predecessorScopeDigest": null,
            "verificationDigest": digest("checked"),
        });
        let selected =
            select_embedded_report(Path::new("/unused"), &canonical_line(&checked)).unwrap();
        assert_eq!(selected.report_bytes, b"null\n");
        assert_eq!(selected.scope_bytes, b"null\n");
        assert!(selected.rerun_if_changed.is_empty());
    }

    #[test]
    fn active_catalog_selects_one_fixed_blob_and_refuses_mutation() {
        let fixture = fixture();
        let selected = select_embedded_report(&fixture.root, &fixture.checked).unwrap();
        assert_eq!(selected.report_bytes, fixture.report_bytes);
        assert_eq!(selected.scope_bytes, fixture.scope_bytes);
        assert_eq!(selected.rerun_if_changed.len(), 4);

        fs::write(
            fixture.root.join(&fixture.report_path),
            b"substituted report\n",
        )
        .unwrap();
        let error = select_embedded_report(&fixture.root, &fixture.checked).unwrap_err();
        assert!(error.contains("size/raw/blob binding"), "{error}");
    }

    #[test]
    fn advertisement_selection_uses_the_full_target_tuple() {
        let checked_value = serde_json::json!({
            "sourceRevision": SOURCE,
            "target": {
                "triple": TARGET,
                "features": ["native-lockdown"],
            },
            "portableArtifactId": digest("artifact"),
        });
        let checked = checked_value.as_object().unwrap();
        let advertisements = serde_json::json!({
            "targetAdvertisementSchema": ADVERTISEMENT_SCHEMA,
            "profile": PROFILE,
            "targetCellsRawContentDigest": digest("target-cells"),
            "advertisements": [{
                "sourceRevision": SOURCE,
                "target": {
                    "triple": TARGET,
                    "features": ["another-feature"],
                },
                "engine": {"artifactId": digest("artifact")},
            }],
        });

        let error = matching_advertisement(&advertisements, checked).unwrap_err();
        assert!(error.contains("checked target/artifact/source"), "{error}");
    }
}
