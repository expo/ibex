use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub(crate) const SCHEMA: &str = "ibex/hermes-upstream-pinned-receipt/2";
pub(crate) const SOURCE_COMMIT: &str = "d412d3bd851278712c20cca25d094e32641a0465";
pub(crate) const EMPTY_PATCH_SET: &str =
    "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Translate Rust target aliases to the exact target identifier carried by
/// the selected published bundle. Both simulator architectures consume the
/// same universal release artifact and therefore the same receipt identity.
pub(crate) fn bundle_target_for_rust_target(target: &str) -> &str {
    match target {
        "aarch64-apple-ios-sim" | "x86_64-apple-ios" => "universal-apple-ios-simulator",
        target => target,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CanonicalReceipt {
    pub(crate) target: String,
    pub(crate) engine_binary: String,
    pub(crate) engine_digest: String,
    pub(crate) compiler_digest: String,
    pub(crate) bytecode_version: u64,
}

pub(crate) fn validate(
    document: &Value,
    expected_target: Option<&str>,
) -> Result<CanonicalReceipt, String> {
    let root = document
        .as_object()
        .ok_or("receipt root is not an object")?;
    if string(root.get("schema"), "receipt has no schema")? != SCHEMA {
        return Err(format!("receipt is not canonical schema {SCHEMA}"));
    }
    if root.contains_key("producedOn") {
        return Err("v2 receipt contains volatile producedOn".into());
    }

    let upstream = object(root.get("upstream"), "v2 receipt has no upstream object")?;
    let source_commit = string(
        upstream.get("sourceCommit"),
        "v2 receipt has no upstream sourceCommit",
    )?;
    if source_commit != SOURCE_COMMIT {
        return Err(format!(
            "v2 receipt sourceCommit {source_commit} is not pinned Hermes commit {SOURCE_COMMIT}"
        ));
    }

    let patch_set = object(root.get("patchSet"), "v2 receipt has no patchSet object")?;
    if string(
        patch_set.get("digest"),
        "v2 receipt has no patch-set digest",
    )? != EMPTY_PATCH_SET
    {
        return Err("v2 receipt patch-set digest is not the canonical empty set".into());
    }
    let applied = patch_set
        .get("applied")
        .and_then(Value::as_array)
        .ok_or("v2 receipt patchSet.applied is not an array")?;
    if !applied.is_empty() {
        return Err("v2 receipt patchSet.applied is not empty".into());
    }

    let target = string(root.get("target"), "v2 receipt has no target")?;
    if let Some(expected) = expected_target {
        if target != expected {
            return Err(format!(
                "v2 receipt target {target} does not match selected target {expected}"
            ));
        }
    }
    string(root.get("profile"), "v2 receipt has no profile")?;
    let build = object(root.get("build"), "v2 receipt has no build object")?;
    let flags = build
        .get("flags")
        .and_then(Value::as_array)
        .ok_or("v2 receipt build.flags is not an array")?;
    if flags
        .iter()
        .any(|value| value.as_str().filter(|flag| !flag.is_empty()).is_none())
    {
        return Err("v2 receipt build.flags contains an empty or non-string value".into());
    }

    let bytecode = object(root.get("bytecode"), "v2 receipt has no bytecode object")?;
    let bytecode_version = bytecode
        .get("version")
        .and_then(Value::as_u64)
        .filter(|version| *version > 0)
        .ok_or("v2 receipt has no positive HBC bytecode version")?;

    let compiler = object(root.get("compiler"), "v2 receipt has no compiler object")?;
    if let Some(binary) = compiler.get("binary") {
        validate_path(&string(
            Some(binary),
            "v2 receipt compiler has no binary path",
        )?)?;
    }
    let compiler_digest = digest(compiler.get("digest"), "v2 receipt has no compiler digest")?;

    let engine = object(root.get("engine"), "v2 receipt has no engine object")?;
    let engine_binary = string(engine.get("binary"), "v2 receipt has no engine binary path")?;
    validate_path(&engine_binary)?;
    let expected_engine_name = if target.ends_with("-pc-windows-msvc") {
        "hermesvm_a.lib"
    } else {
        "libhermesvm_a.a"
    };
    if engine_binary.rsplit('/').next() != Some(expected_engine_name) {
        return Err(format!(
            "v2 receipt engine binary is not the target's full VM archive {expected_engine_name}"
        ));
    }
    let engine_digest = digest(
        engine.get("binaryDigest"),
        "v2 receipt engine has no binaryDigest",
    )?;
    string(engine.get("variant"), "v2 receipt engine has no variant")?;

    let archives = manifest(root.get("archives"), "archives")?;
    if !archives
        .iter()
        .any(|(path, digest)| path == &engine_binary && digest == &engine_digest)
    {
        return Err("v2 receipt engine is not bound by its archive manifest".into());
    }
    manifest(root.get("headers"), "headers")?;

    let links = root
        .get("linkDirectives")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or("v2 receipt has no ordered link directives")?;
    if links
        .iter()
        .any(|value| value.as_str().filter(|item| !item.is_empty()).is_none())
    {
        return Err("v2 receipt linkDirectives contains an empty or non-string value".into());
    }

    Ok(CanonicalReceipt {
        target,
        engine_binary,
        engine_digest,
        compiler_digest,
        bytecode_version,
    })
}

fn manifest(value: Option<&Value>, name: &str) -> Result<Vec<(String, String)>, String> {
    let entries = value
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or_else(|| format!("v2 receipt has no {name} manifest"))?;
    let mut parsed = Vec::with_capacity(entries.len());
    let mut seen = BTreeSet::new();
    let mut previous: Option<String> = None;
    for entry in entries {
        let item = entry
            .as_object()
            .ok_or_else(|| format!("v2 receipt {name} manifest contains a non-object"))?;
        let path = string(
            item.get("path"),
            &format!("v2 receipt {name} entry has no path"),
        )?;
        validate_path(&path)?;
        if previous
            .as_deref()
            .is_some_and(|value| value >= path.as_str())
        {
            return Err(format!(
                "v2 receipt {name} manifest is not strictly sorted by path"
            ));
        }
        if !seen.insert(path.clone()) {
            return Err(format!("v2 receipt {name} manifest repeats {path}"));
        }
        previous = Some(path.clone());
        let digest = digest(
            item.get("digest"),
            &format!("v2 receipt {name} entry has no digest"),
        )?;
        parsed.push((path, digest));
    }
    Ok(parsed)
}

fn validate_path(path: &str) -> Result<(), String> {
    let first = path.as_bytes().first().copied();
    if path.is_empty()
        || path.contains('\\')
        || matches!(first, Some(b'/'))
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        || path.as_bytes().get(1) == Some(&b':')
    {
        return Err(format!(
            "v2 receipt path {path:?} is not a safe bundle-relative path"
        ));
    }
    Ok(())
}

fn digest(value: Option<&Value>, missing: &str) -> Result<String, String> {
    let value = string(value, missing)?;
    let Some(hex) = value.strip_prefix("sha256-") else {
        return Err(format!("{missing}; expected sha256-<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("invalid SHA-256 digest {value:?}"));
    }
    Ok(value)
}

fn string(value: Option<&Value>, missing: &str) -> Result<String, String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| missing.to_owned())
}

fn object<'a>(value: Option<&'a Value>, missing: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| missing.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = include_str!("testdata/receipt-v2-valid.json");

    fn document() -> Value {
        serde_json::from_str(VALID).expect("shared receipt fixture")
    }

    #[test]
    fn shared_canonical_fixture_is_accepted_for_its_exact_target() {
        let receipt = validate(&document(), Some("aarch64-apple-darwin")).expect("canonical v2");
        assert_eq!(receipt.target, "aarch64-apple-darwin");
        assert_eq!(receipt.bytecode_version, 99);
    }

    #[test]
    fn simulator_aliases_select_the_universal_bundle_receipt_target() {
        assert_eq!(
            bundle_target_for_rust_target("aarch64-apple-ios-sim"),
            "universal-apple-ios-simulator"
        );
        assert_eq!(
            bundle_target_for_rust_target("x86_64-apple-ios"),
            "universal-apple-ios-simulator"
        );
        assert_eq!(
            bundle_target_for_rust_target("aarch64-apple-ios"),
            "aarch64-apple-ios"
        );
    }

    #[test]
    fn shared_fixture_rejects_wrong_target_commit_patches_and_missing_closure() {
        assert!(validate(&document(), Some("aarch64-apple-ios")).is_err());

        let mut wrong_commit = document();
        wrong_commit["upstream"]["sourceCommit"] = Value::String("0".repeat(40));
        assert!(validate(&wrong_commit, None)
            .unwrap_err()
            .contains("pinned"));

        let mut patched = document();
        patched["patchSet"]["applied"] = serde_json::json!(["0001.patch"]);
        assert!(validate(&patched, None).unwrap_err().contains("not empty"));

        for field in ["archives", "headers", "linkDirectives"] {
            let mut missing = document();
            missing.as_object_mut().expect("object").remove(field);
            assert!(
                validate(&missing, None).is_err(),
                "accepted missing {field}"
            );
        }
    }

    #[test]
    fn shared_fixture_requires_compiler_identity_and_positive_hbc() {
        let mut no_compiler = document();
        no_compiler
            .as_object_mut()
            .expect("object")
            .remove("compiler");
        assert!(validate(&no_compiler, None)
            .unwrap_err()
            .contains("compiler object"));

        let mut zero_hbc = document();
        zero_hbc["bytecode"]["version"] = Value::from(0);
        assert!(validate(&zero_hbc, None)
            .unwrap_err()
            .contains("positive HBC"));
    }
}
