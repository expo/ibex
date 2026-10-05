//! Receipts: what an artifact is allowed to claim about itself.
//!
//! LLP 0058.000.001 §5 (tombstoned) defined a four-artifact chain; LLP 0067 §5
//! keeps the first link. This implements the first
//! link, `HermesInputReceipt`, and binds module artifacts to it. The
//! `GraduationManifest` and the post-link `GreenfieldFinalArtifactReceipt` are
//! **not** implemented: the first needs a tier-definition process and the second
//! a linker-closure scanner, neither of which exists. They are absent rather
//! than stubbed, so nothing here can be mistaken for the full chain.
//!
//! The property this buys: "vanilla" stops being a build flag someone
//! remembered to pass and becomes a checkable claim about an artifact —
//! produced by a separate tool, verified here, and refused if the engine
//! carries the patch series' exports.
//!
//! @ref LLP 0067#5-the-engine-and-the-artifacts — the receipt, and what is verified where
//! @ref LLP 0067#5-the-engine-and-the-artifacts — vanilla means zero patches: the claim being checked

use std::path::Path;

#[path = "../../hermes-lean-sys/receipt_schema.rs"]
mod receipt_schema;

/// The canonical release-bundle schema. V1 remains readable so already-built
/// local engines do not become unusable during the crate split.
pub const HERMES_INPUT_SCHEMA: &str = receipt_schema::SCHEMA;
pub const LEGACY_HERMES_INPUT_SCHEMA: &str = "ibex/hermes-upstream-pinned-receipt/1";

/// SHA-256 of no input at all — what an empty patch set must hash to.
pub const CANONICAL_EMPTY_PATCH_SET: &str =
    "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// What a `HermesInputReceipt` asserts about an installed engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HermesInput {
    pub binary_path: Option<String>,
    pub binary_digest: String,
    pub variant: String,
    pub patch_set_digest: String,
    pub patches_applied: usize,
    pub compiler_digest: Option<String>,
    pub bytecode_version: Option<u64>,
    pub target: Option<String>,
}

impl HermesInput {
    pub fn path(engine_dir: &Path) -> std::path::PathBuf {
        engine_dir.join("hermes-input-receipt.json")
    }

    /// Read and check a receipt beside an engine.
    ///
    pub fn read(engine_dir: &Path) -> Result<Self, String> {
        let path = Self::path(engine_dir);
        let text = std::fs::read_to_string(&path)
            .map_err(|_| format!("no HermesInputReceipt at {}", path.display()))?;
        Self::parse(&text)
    }

    pub(crate) fn read_for_target(engine_dir: &Path, target: &str) -> Result<Self, String> {
        let path = Self::path(engine_dir);
        let text = std::fs::read_to_string(&path)
            .map_err(|_| format!("no HermesInputReceipt at {}", path.display()))?;
        Self::parse_for_target(&text, Some(target))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        Self::parse_for_target(text, None)
    }

    fn parse_for_target(text: &str, expected_target: Option<&str>) -> Result<Self, String> {
        let document: serde_json::Value =
            serde_json::from_str(text).map_err(|error| format!("invalid receipt JSON: {error}"))?;
        let root = document
            .as_object()
            .ok_or("receipt root is not an object")?;
        let schema = string(root.get("schema"), "receipt has no schema")?;
        if schema != HERMES_INPUT_SCHEMA && schema != LEGACY_HERMES_INPUT_SCHEMA {
            return Err(format!(
                "unknown receipt schema {schema:?}; expected {HERMES_INPUT_SCHEMA:?} or {LEGACY_HERMES_INPUT_SCHEMA:?}"
            ));
        }

        let canonical = if schema == HERMES_INPUT_SCHEMA {
            let expected_bundle_target =
                expected_target.map(receipt_schema::bundle_target_for_rust_target);
            Some(receipt_schema::validate(&document, expected_bundle_target)?)
        } else {
            None
        };
        let engine = object(root.get("engine"), "receipt has no engine object")?;
        let binary_path = match engine.get("binary") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(string(Some(value), "receipt engine has no binary path")?),
        };
        if let Some(path) = &binary_path {
            validate_engine_path(path)?;
        }
        let binary_digest = string(
            engine.get("binaryDigest"),
            "receipt has no engine binaryDigest",
        )?;
        let variant = string(engine.get("variant"), "receipt has no engine variant")?;
        let patch_set = object(root.get("patchSet"), "receipt has no patchSet object")?;
        let patch_set_digest = string(patch_set.get("digest"), "receipt has no patch-set digest")?;
        let applied = patch_set
            .get("applied")
            .and_then(serde_json::Value::as_array)
            .ok_or("receipt patchSet.applied is not an array")?;
        if applied.iter().any(|value| !value.is_string()) {
            return Err("receipt patchSet.applied contains a non-string".into());
        }
        let compiler_digest = match root.get("compiler") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(string(
                object(Some(value), "receipt compiler is not an object")?.get("digest"),
                "receipt compiler has no digest",
            )?),
        };
        let bytecode_version = root
            .get("bytecode")
            .and_then(serde_json::Value::as_object)
            .and_then(|bytecode| bytecode.get("version"))
            .and_then(serde_json::Value::as_u64);

        if let Some(canonical) = &canonical {
            if binary_path.as_deref() != Some(canonical.engine_binary.as_str())
                || binary_digest != canonical.engine_digest
                || compiler_digest.as_deref() != Some(canonical.compiler_digest.as_str())
                || bytecode_version != Some(canonical.bytecode_version)
            {
                return Err("canonical receipt fields were parsed inconsistently".into());
            }
        }

        Ok(Self {
            binary_path,
            binary_digest,
            variant,
            patch_set_digest,
            patches_applied: applied.len(),
            compiler_digest,
            bytecode_version,
            target: canonical.map(|receipt| receipt.target),
        })
    }

    /// Does this receipt claim an unpatched engine, and is the claim coherent?
    pub fn is_vanilla(&self) -> bool {
        self.patch_set_digest == CANONICAL_EMPTY_PATCH_SET && self.patches_applied == 0
    }

    /// Check the receipt against the engine sitting beside it.
    ///
    /// A receipt that does not describe the bytes actually present is worse
    /// than no receipt: it is a claim someone may rely on.
    pub fn verify_binary(&self, engine_dir: &Path) -> Result<(), String> {
        if let Some(relative) = &self.binary_path {
            let binary = engine_dir.join(relative);
            let metadata = std::fs::symlink_metadata(&binary)
                .map_err(|e| format!("cannot inspect {}: {e}", binary.display()))?;
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "receipt engine archive is not a regular file: {}",
                    binary.display()
                ));
            }
            let bytes = std::fs::read(&binary)
                .map_err(|e| format!("cannot read {}: {e}", binary.display()))?;
            let digest = format!(
                "sha256-{}",
                hex(&<sha2::Sha256 as sha2::Digest>::digest(&bytes))
            );
            if digest == self.binary_digest {
                return Ok(());
            }
            return Err(format!(
                "receipt describes a different engine than the exact archive present\n  \
                 receipt: {}\n  actual:  {}: {digest}",
                self.binary_digest,
                binary.display()
            ));
        }

        // V1 did not require an archive path. Retain its compatibility search;
        // canonical V2 receipts always take the exact-path branch above.
        let binaries = engine_binaries(engine_dir)?;
        let mut actual = Vec::with_capacity(binaries.len());
        for binary in binaries {
            let bytes = std::fs::read(&binary)
                .map_err(|e| format!("cannot read {}: {e}", binary.display()))?;
            let digest = format!(
                "sha256-{}",
                hex(&<sha2::Sha256 as sha2::Digest>::digest(&bytes))
            );
            if digest == self.binary_digest {
                return Ok(());
            }
            actual.push(format!("{}: {digest}", binary.display()));
        }
        Err(format!(
            "receipt describes a different engine than the one present\n  \
             receipt: {}\n  actual:  {}",
            self.binary_digest,
            actual.join("\n           ")
        ))
    }
}

fn string(value: Option<&serde_json::Value>, missing: &str) -> Result<String, String> {
    value
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| missing.to_owned())
}

fn object<'a>(
    value: Option<&'a serde_json::Value>,
    missing: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, String> {
    value
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| missing.to_owned())
}

fn validate_engine_path(path: &str) -> Result<(), String> {
    if Path::new(path).is_absolute()
        || path.contains('\\')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        Err("receipt engine binary path is not a safe bundle-relative path".into())
    } else {
        Ok(())
    }
}

fn engine_binaries(engine_dir: &Path) -> Result<Vec<std::path::PathBuf>, String> {
    let mut binaries = Vec::new();
    for relative in [
        "lib/libhermesvmlean_a.a",
        "lib/hermesvmlean_a.lib",
        "macos-static/libhermesvmlean_a.a",
        "linux-static/libhermesvmlean_a.a",
        "windows-static/hermesvmlean_a.lib",
        "hermesvm.framework/Versions/1/hermesvm",
        "linux-static/libhermesvm_a.a",
        "windows-static/hermesvm_a.lib",
    ] {
        let candidate = engine_dir.join(relative);
        if candidate.is_file() {
            binaries.push(candidate);
        }
    }
    if binaries.is_empty() {
        Err(format!(
            "no Hermes engine binary under {}",
            engine_dir.display()
        ))
    } else {
        Ok(binaries)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY_VANILLA: &str = r#"{
      "schema": "ibex/hermes-upstream-pinned-receipt/1",
      "engine": { "binaryDigest": "sha256-abc", "variant": "release" },
      "patchSet": { "digest": "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "applied": [] },
      "compiler": { "digest": "sha256-def" }
    }"#;

    const VANILLA: &str = include_str!("../../hermes-lean-sys/testdata/receipt-v2-valid.json");

    #[test]
    fn a_v2_vanilla_receipt_parses_and_reads_as_vanilla() {
        let receipt = HermesInput::parse(VANILLA).expect("parse");
        assert_eq!(receipt.binary_path.as_deref(), Some("lib/libhermesvm_a.a"));
        assert_eq!(
            receipt.binary_digest,
            "sha256-2222222222222222222222222222222222222222222222222222222222222222"
        );
        assert_eq!(receipt.variant, "release");
        assert_eq!(receipt.patches_applied, 0);
        assert!(receipt.is_vanilla());
        assert_eq!(
            receipt.compiler_digest.as_deref(),
            Some("sha256-1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert_eq!(receipt.bytecode_version, Some(99));
        assert_eq!(receipt.target.as_deref(), Some("aarch64-apple-darwin"));
    }

    #[test]
    fn a_v1_receipt_remains_readable() {
        let receipt = HermesInput::parse(LEGACY_VANILLA).expect("parse legacy receipt");
        assert_eq!(receipt.binary_path, None);
        assert_eq!(receipt.binary_digest, "sha256-abc");
        assert_eq!(receipt.variant, "release");
        assert!(receipt.is_vanilla());
        assert_eq!(receipt.compiler_digest.as_deref(), Some("sha256-def"));
        assert_eq!(receipt.bytecode_version, None);
    }

    #[test]
    fn a_receipt_claiming_applied_patches_is_not_vanilla() {
        let patched = LEGACY_VANILLA.replace(r#""applied": []"#, r#""applied": ["0001-x.patch"]"#);
        let receipt = HermesInput::parse(&patched).expect("parse");
        assert_eq!(receipt.patches_applied, 1);
        assert!(!receipt.is_vanilla());
    }

    /// The digest is the claim, so a receipt whose digest is not the canonical
    /// empty one is not vanilla even if it says nothing was applied.
    #[test]
    fn an_empty_list_with_a_non_empty_digest_is_not_vanilla() {
        let inconsistent =
            LEGACY_VANILLA.replace(CANONICAL_EMPTY_PATCH_SET, "sha256-something-else");
        assert!(!HermesInput::parse(&inconsistent).unwrap().is_vanilla());
    }

    #[test]
    fn an_unknown_schema_is_refused_rather_than_guessed_at() {
        let future = VANILLA.replace(
            "ibex/hermes-upstream-pinned-receipt/2",
            "ibex/hermes-upstream-pinned-receipt/3",
        );
        let err = HermesInput::parse(&future).unwrap_err();
        assert!(err.contains("unknown receipt schema"), "{err}");
    }

    #[test]
    fn a_receipt_missing_required_fields_is_refused() {
        assert!(HermesInput::parse("{}").is_err());
        assert!(
            HermesInput::parse(r#"{"schema":"ibex/hermes-upstream-pinned-receipt/2"}"#).is_err()
        );
    }

    #[test]
    fn v2_refuses_the_removed_volatile_date() {
        let dated = VANILLA.replace(
            r#""schema": "ibex/hermes-upstream-pinned-receipt/2","#,
            r#""schema": "ibex/hermes-upstream-pinned-receipt/2", "producedOn": "2026-10-04","#,
        );
        let err = HermesInput::parse(&dated).unwrap_err();
        assert!(err.contains("volatile producedOn"), "{err}");
    }

    #[test]
    fn v2_requires_the_engine_digest_in_the_archive_manifest() {
        let mut inconsistent: serde_json::Value = serde_json::from_str(VANILLA).unwrap();
        inconsistent["archives"][0]["digest"] =
            serde_json::Value::String(format!("sha256-{}", "9".repeat(64)));
        let err = HermesInput::parse(&inconsistent.to_string()).unwrap_err();
        assert!(err.contains("archive manifest"), "{err}");
    }

    #[test]
    fn v2_requires_the_target_full_vm_archive() {
        let lean = VANILLA.replace(
            r#""binary": "lib/libhermesvm_a.a""#,
            r#""binary": "lib/libhermesvmlean_a.a""#,
        );
        let err = HermesInput::parse(&lean).unwrap_err();
        assert!(err.contains("full VM archive"), "{err}");
    }

    #[test]
    fn verification_rejects_a_changed_linked_full_archive_even_if_lean_is_unchanged() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let engine = std::env::temp_dir().join(format!(
            "ibex2-exact-engine-archive-{}-{unique}",
            std::process::id()
        ));
        let lib = engine.join("lib");
        std::fs::create_dir_all(&lib).expect("create engine fixture");
        let original = b"original full VM archive bytes";
        std::fs::write(lib.join("libhermesvmlean_a.a"), original).expect("write lean archive");
        std::fs::write(lib.join("libhermesvm_a.a"), original).expect("write full archive");
        let digest = format!(
            "sha256-{}",
            hex(&<sha2::Sha256 as sha2::Digest>::digest(original))
        );
        let receipt = HermesInput {
            binary_path: Some("lib/libhermesvm_a.a".into()),
            binary_digest: digest,
            variant: "release".into(),
            patch_set_digest: CANONICAL_EMPTY_PATCH_SET.into(),
            patches_applied: 0,
            compiler_digest: Some("sha256-compiler".into()),
            bytecode_version: Some(99),
            target: Some("aarch64-apple-darwin".into()),
        };
        receipt
            .verify_binary(&engine)
            .expect("full archive matches");

        std::fs::write(
            lib.join("libhermesvm_a.a"),
            b"mutated full VM archive bytes",
        )
        .expect("mutate linked full archive");
        let err = receipt
            .verify_binary(&engine)
            .expect_err("unchanged lean archive must not satisfy the full archive receipt");
        assert!(err.contains("exact archive"), "{err}");
        std::fs::remove_dir_all(engine).expect("remove engine fixture");
    }

    /// The receipt the build actually produced, checked against the engine it
    /// describes. Skipped where no vanilla engine is installed.
    #[test]
    fn the_installed_receipt_describes_the_installed_engine() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        for dir in [
            "ios/Frameworks-vanilla-nodebug",
            "ios/Frameworks-vanilla",
            "linux/Frameworks-vanilla",
            "tools/hermes-vanilla/windows-x64",
        ] {
            let engine = root.join(dir);
            if !HermesInput::path(&engine).exists() {
                continue;
            }
            let receipt = HermesInput::read(&engine).expect("read");
            assert!(receipt.is_vanilla(), "{dir} receipt is not vanilla");
            receipt.verify_binary(&engine).expect("binary matches");
        }
    }
}
