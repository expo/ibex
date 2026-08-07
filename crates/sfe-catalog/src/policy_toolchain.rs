//! Closed, digest-addressed policy-authoring support shipped with an SFE
//! producer release.
//!
//! The installed toolchain is producer-only. It is not a runtime sidecar for
//! the executable emitted by `ibex compile`.
//! @ref LLP 0047#8-milestone-5--distribution-and-usability

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const POLICY_TOOLCHAIN_SCHEMA_V1: &str = "ibex/sfe-policy-toolchain/1";
pub const POLICY_TOOLCHAIN_DOMAIN_V1: &str = "ibex:sfe-policy-toolchain:1";
pub const POLICY_TOOLCHAIN_MANIFEST: &str = "manifest.json";
pub const POLICY_TOOLCHAIN_DIRECTORY_PREFIX: &str = "ibex-policy-toolchain-";

const MAX_ENTRIES: usize = 8_192;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyToolchainManifestV1 {
    pub schema: String,
    pub target: String,
    pub runner_kind: String,
    pub runner: String,
    pub script: String,
    pub entries: Vec<PolicyToolchainEntryV1>,
    pub toolchain_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PolicyToolchainEntryV1 {
    File {
        path: String,
        digest: String,
        length: u64,
        executable: bool,
    },
    Symlink {
        path: String,
        target: String,
    },
}

impl PolicyToolchainEntryV1 {
    fn path(&self) -> &str {
        match self {
            Self::File { path, .. } | Self::Symlink { path, .. } => path,
        }
    }

    fn is_regular_file(&self) -> bool {
        matches!(self, Self::File { .. })
    }
}

#[derive(Clone, Debug)]
pub struct AdmittedPolicyToolchainV1 {
    pub root: PathBuf,
    pub runner: PathBuf,
    pub script: PathBuf,
    pub target: String,
    pub digest: String,
    pub entry_count: usize,
}

impl PolicyToolchainManifestV1 {
    pub fn assemble(
        root: &Path,
        target: impl Into<String>,
        runner: &Path,
        script: &Path,
    ) -> Result<Self> {
        let target = target.into();
        if target.is_empty() {
            return Err(Error::Manifest("target must not be empty".into()));
        }
        let runner = normalize_relative_argument(runner, "runner")?;
        let script = normalize_relative_argument(script, "script")?;
        let entries = scan_closed_inventory(root)?;
        validate_entry_inventory(root, &entries)?;
        require_regular_member(&entries, &runner, "runner")?;
        require_regular_member(&entries, &script, "script")?;
        let mut manifest = Self {
            schema: POLICY_TOOLCHAIN_SCHEMA_V1.into(),
            target,
            runner_kind: "bun".into(),
            runner,
            script,
            entries,
            toolchain_digest: String::new(),
        };
        manifest.toolchain_digest = manifest.digest()?;
        Ok(manifest)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|error| Error::Manifest(format!("cannot encode manifest: {error}")))
    }

    pub fn digest(&self) -> Result<String> {
        let mut projection = self.clone();
        projection.toolchain_digest.clear();
        let bytes = projection.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(POLICY_TOOLCHAIN_DOMAIN_V1.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
        Ok(format!(
            "sha256-{}",
            URL_SAFE_NO_PAD.encode(hasher.finalize())
        ))
    }

    pub fn load(bytes: &[u8], expected_digest: &str) -> Result<Self> {
        if !valid_digest(expected_digest) {
            return Err(Error::TrustRoot(
                "compiled policy-toolchain digest is malformed".into(),
            ));
        }
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| Error::Manifest(format!("cannot parse manifest: {error}")))?;
        if manifest.schema != POLICY_TOOLCHAIN_SCHEMA_V1 {
            return Err(Error::Manifest(format!(
                "unsupported policy-toolchain schema {:?}",
                manifest.schema
            )));
        }
        if manifest.runner_kind != "bun" {
            return Err(Error::Manifest(format!(
                "unsupported policy-toolchain runner kind {:?}",
                manifest.runner_kind
            )));
        }
        if manifest.canonical_bytes()? != bytes {
            return Err(Error::Manifest(
                "policy-toolchain manifest is not canonical JSON".into(),
            ));
        }
        let actual_digest = manifest.digest()?;
        if manifest.toolchain_digest != actual_digest || actual_digest != expected_digest {
            return Err(Error::TrustRoot(format!(
                "policy-toolchain digest mismatch: expected {expected_digest}, manifest={}, actual={actual_digest}",
                manifest.toolchain_digest
            )));
        }
        validate_manifest_rows(&manifest.entries)?;
        Ok(manifest)
    }
}

pub fn policy_toolchain_store_key(digest: &str) -> Result<&str> {
    if !valid_digest(digest) {
        return Err(Error::TrustRoot(
            "compiled policy-toolchain digest is malformed".into(),
        ));
    }
    Ok(&digest["sha256-".len()..])
}

pub fn policy_toolchain_directory_name(digest: &str) -> Result<String> {
    Ok(format!(
        "{POLICY_TOOLCHAIN_DIRECTORY_PREFIX}{}",
        policy_toolchain_store_key(digest)?
    ))
}

pub fn admit_policy_toolchain_directory(
    root: &Path,
    expected_digest: &str,
    expected_target: &str,
) -> Result<AdmittedPolicyToolchainV1> {
    let root_metadata = std::fs::symlink_metadata(root).map_err(|error| {
        Error::Filesystem(format!(
            "cannot inspect policy-toolchain root {}: {error}",
            root.display()
        ))
    })?;
    if !root_metadata.file_type().is_dir() {
        return Err(Error::Filesystem(format!(
            "policy-toolchain root is not a directory: {}",
            root.display()
        )));
    }
    let manifest_path = root.join(POLICY_TOOLCHAIN_MANIFEST);
    let manifest_bytes = read_regular(&manifest_path, "policy-toolchain manifest")?;
    let manifest = PolicyToolchainManifestV1::load(&manifest_bytes, expected_digest)?;
    if manifest.target != expected_target {
        return Err(Error::TrustRoot(format!(
            "policy-toolchain target mismatch: expected {expected_target}, found {}",
            manifest.target
        )));
    }
    let actual_entries = scan_closed_inventory(root)?;
    validate_entry_inventory(root, &actual_entries)?;
    if actual_entries != manifest.entries {
        return Err(Error::Inventory(
            "installed policy-toolchain inventory differs from its manifest".into(),
        ));
    }
    let runner = confined_member(root, &manifest.runner, "runner")?;
    let script = confined_member(root, &manifest.script, "script")?;
    Ok(AdmittedPolicyToolchainV1 {
        root: root.to_path_buf(),
        runner,
        script,
        target: manifest.target,
        digest: manifest.toolchain_digest,
        entry_count: manifest.entries.len(),
    })
}

fn normalize_relative_argument(path: &Path, label: &str) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| Error::Manifest(format!("{label} path must be Unicode")))?;
    validate_relative_path(text, label)?;
    Ok(text.replace('\\', "/"))
}

fn validate_relative_path(path: &str, label: &str) -> Result<()> {
    if path.is_empty() || path.contains('\\') {
        return Err(Error::Manifest(format!(
            "{label} path must be a non-empty slash-normalized relative path"
        )));
    }
    let parsed = Path::new(path);
    if parsed.is_absolute()
        || parsed.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(Error::Manifest(format!(
            "{label} path is not a confined relative path: {path:?}"
        )));
    }
    Ok(())
}

fn scan_closed_inventory(root: &Path) -> Result<Vec<PolicyToolchainEntryV1>> {
    fn visit(
        root: &Path,
        directory: &Path,
        entries: &mut Vec<PolicyToolchainEntryV1>,
        total_bytes: &mut u64,
    ) -> Result<()> {
        let mut children = std::fs::read_dir(directory)
            .map_err(|error| {
                Error::Filesystem(format!(
                    "cannot read policy-toolchain directory {}: {error}",
                    directory.display()
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| Error::Filesystem(format!("cannot enumerate toolchain: {error}")))?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let path = child.path();
            let relative = path.strip_prefix(root).map_err(|_| {
                Error::Inventory(format!("toolchain member escaped root: {}", path.display()))
            })?;
            let relative_text = normalize_relative_argument(relative, "toolchain member")?;
            if relative_text == POLICY_TOOLCHAIN_MANIFEST {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                Error::Filesystem(format!(
                    "cannot inspect policy-toolchain member {}: {error}",
                    path.display()
                ))
            })?;
            if metadata.file_type().is_dir() {
                visit(root, &path, entries, total_bytes)?;
                continue;
            }
            if entries.len() >= MAX_ENTRIES {
                return Err(Error::Inventory(format!(
                    "policy-toolchain exceeds {MAX_ENTRIES} entries"
                )));
            }
            if metadata.file_type().is_symlink() {
                let target = std::fs::read_link(&path).map_err(|error| {
                    Error::Filesystem(format!(
                        "cannot read policy-toolchain symlink {}: {error}",
                        path.display()
                    ))
                })?;
                let target = target.to_str().ok_or_else(|| {
                    Error::Inventory(format!(
                        "policy-toolchain symlink target is not Unicode: {}",
                        path.display()
                    ))
                })?;
                if Path::new(target).is_absolute() || target.contains('\\') {
                    return Err(Error::Inventory(format!(
                        "policy-toolchain symlink target is not relative and slash-normalized: {} -> {target:?}",
                        path.display()
                    )));
                }
                entries.push(PolicyToolchainEntryV1::Symlink {
                    path: relative_text,
                    target: target.into(),
                });
                continue;
            }
            if !metadata.file_type().is_file() {
                return Err(Error::Inventory(format!(
                    "policy-toolchain contains a special file: {}",
                    path.display()
                )));
            }
            if metadata.len() > MAX_FILE_BYTES {
                return Err(Error::Inventory(format!(
                    "policy-toolchain member exceeds {MAX_FILE_BYTES} bytes: {}",
                    path.display()
                )));
            }
            *total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| Error::Inventory("policy-toolchain size overflow".into()))?;
            if *total_bytes > MAX_TOTAL_BYTES {
                return Err(Error::Inventory(format!(
                    "policy-toolchain exceeds {MAX_TOTAL_BYTES} total regular bytes"
                )));
            }
            let bytes = read_regular(&path, "policy-toolchain member")?;
            entries.push(PolicyToolchainEntryV1::File {
                path: relative_text,
                digest: digest_bytes(&bytes),
                length: metadata.len(),
                executable: is_executable(&metadata),
            });
        }
        Ok(())
    }

    let metadata = std::fs::symlink_metadata(root).map_err(|error| {
        Error::Filesystem(format!(
            "cannot inspect policy-toolchain root {}: {error}",
            root.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(Error::Filesystem(format!(
            "policy-toolchain root is not a directory: {}",
            root.display()
        )));
    }
    let mut entries = Vec::new();
    let mut total_bytes = 0;
    visit(root, root, &mut entries, &mut total_bytes)?;
    entries.sort_by(|left, right| left.path().cmp(right.path()));
    validate_manifest_rows(&entries)?;
    Ok(entries)
}

fn validate_manifest_rows(entries: &[PolicyToolchainEntryV1]) -> Result<()> {
    if entries.is_empty() {
        return Err(Error::Manifest(
            "policy-toolchain inventory must not be empty".into(),
        ));
    }
    if entries.len() > MAX_ENTRIES {
        return Err(Error::Manifest(format!(
            "policy-toolchain exceeds {MAX_ENTRIES} entries"
        )));
    }
    let mut previous: Option<&str> = None;
    let mut total_bytes = 0u64;
    for entry in entries {
        let path = entry.path();
        validate_relative_path(path, "toolchain member")?;
        if path == POLICY_TOOLCHAIN_MANIFEST {
            return Err(Error::Manifest(
                "manifest.json is self-excluded and cannot be an inventory member".into(),
            ));
        }
        if previous.is_some_and(|value| value >= path) {
            return Err(Error::Manifest(
                "policy-toolchain entries must be unique and sorted".into(),
            ));
        }
        previous = Some(path);
        match entry {
            PolicyToolchainEntryV1::File { digest, length, .. } => {
                if !valid_digest(digest) || *length > MAX_FILE_BYTES {
                    return Err(Error::Manifest(format!(
                        "invalid policy-toolchain file row for {path}"
                    )));
                }
                total_bytes = total_bytes
                    .checked_add(*length)
                    .ok_or_else(|| Error::Manifest("policy-toolchain size overflow".into()))?;
            }
            PolicyToolchainEntryV1::Symlink { target, .. } => {
                if Path::new(target).is_absolute() || target.is_empty() || target.contains('\\') {
                    return Err(Error::Manifest(format!(
                        "invalid policy-toolchain symlink row for {path}"
                    )));
                }
            }
        }
    }
    if total_bytes > MAX_TOTAL_BYTES {
        return Err(Error::Manifest(format!(
            "policy-toolchain exceeds {MAX_TOTAL_BYTES} total regular bytes"
        )));
    }
    Ok(())
}

fn validate_entry_inventory(root: &Path, entries: &[PolicyToolchainEntryV1]) -> Result<()> {
    let canonical_root = std::fs::canonicalize(root).map_err(|error| {
        Error::Filesystem(format!(
            "cannot canonicalize policy-toolchain root {}: {error}",
            root.display()
        ))
    })?;
    let paths = entries
        .iter()
        .map(|entry| entry.path())
        .collect::<BTreeSet<_>>();
    for entry in entries {
        if let PolicyToolchainEntryV1::Symlink { path, target } = entry {
            let link_path = root.join(path);
            let resolved = std::fs::canonicalize(&link_path).map_err(|error| {
                Error::Inventory(format!(
                    "policy-toolchain symlink is broken or cyclic: {path} -> {target:?}: {error}"
                ))
            })?;
            if !resolved.starts_with(&canonical_root) {
                return Err(Error::Inventory(format!(
                    "policy-toolchain symlink escapes its root: {path} -> {target:?}"
                )));
            }
        }
    }
    if paths.len() != entries.len() {
        return Err(Error::Inventory(
            "policy-toolchain inventory contains duplicate paths".into(),
        ));
    }
    Ok(())
}

fn require_regular_member(
    entries: &[PolicyToolchainEntryV1],
    path: &str,
    label: &str,
) -> Result<()> {
    if !entries
        .iter()
        .any(|entry| entry.path() == path && entry.is_regular_file())
    {
        return Err(Error::Manifest(format!(
            "policy-toolchain {label} is not an inventoried regular file: {path}"
        )));
    }
    Ok(())
}

fn confined_member(root: &Path, relative: &str, label: &str) -> Result<PathBuf> {
    validate_relative_path(relative, label)?;
    let root = std::fs::canonicalize(root).map_err(|error| {
        Error::Filesystem(format!("cannot canonicalize toolchain root: {error}"))
    })?;
    let candidate = root.join(relative);
    let metadata = std::fs::symlink_metadata(&candidate).map_err(|error| {
        Error::Filesystem(format!(
            "cannot inspect policy-toolchain {label} {}: {error}",
            candidate.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(Error::Inventory(format!(
            "policy-toolchain {label} is not a regular file: {}",
            candidate.display()
        )));
    }
    let canonical = std::fs::canonicalize(&candidate).map_err(|error| {
        Error::Filesystem(format!(
            "cannot canonicalize policy-toolchain {label}: {error}"
        ))
    })?;
    if !canonical.starts_with(&root) {
        return Err(Error::Inventory(format!(
            "policy-toolchain {label} escapes its root: {}",
            candidate.display()
        )));
    }
    Ok(canonical)
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        Error::Filesystem(format!(
            "cannot inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(Error::Filesystem(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    std::fs::read(path).map_err(|error| Error::Filesystem(format!("cannot read {label}: {error}")))
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

fn valid_digest(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("sha256-") else {
        return false;
    };
    if encoded.len() != 43
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return false;
    }
    URL_SAFE_NO_PAD
        .decode(encoded)
        .is_ok_and(|bytes| bytes.len() == 32)
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("policy-toolchain trust root refused: {0}")]
    TrustRoot(String),
    #[error("invalid policy-toolchain manifest: {0}")]
    Manifest(String),
    #[error("invalid policy-toolchain inventory: {0}")]
    Inventory(String),
    #[error("policy-toolchain filesystem error: {0}")]
    Filesystem(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn fixture(root: &Path) -> PolicyToolchainManifestV1 {
        write(&root.join("bin/bun"), b"runner");
        write(&root.join("scripts/generate-policy.mjs"), b"policy");
        let manifest = PolicyToolchainManifestV1::assemble(
            root,
            "aarch64-apple-darwin",
            Path::new("bin/bun"),
            Path::new("scripts/generate-policy.mjs"),
        )
        .unwrap();
        std::fs::write(
            root.join(POLICY_TOOLCHAIN_MANIFEST),
            manifest.canonical_bytes().unwrap(),
        )
        .unwrap();
        manifest
    }

    #[test]
    fn admits_a_closed_digest_addressed_toolchain() {
        let root = tempfile::tempdir().unwrap();
        let manifest = fixture(root.path());
        let admitted = admit_policy_toolchain_directory(
            root.path(),
            &manifest.toolchain_digest,
            "aarch64-apple-darwin",
        )
        .unwrap();
        assert_eq!(admitted.digest, manifest.toolchain_digest);
        assert_eq!(admitted.entry_count, 2);
    }

    #[test]
    fn refuses_mutation_and_unlisted_files() {
        let root = tempfile::tempdir().unwrap();
        let manifest = fixture(root.path());
        write(&root.path().join("scripts/generate-policy.mjs"), b"changed");
        assert!(admit_policy_toolchain_directory(
            root.path(),
            &manifest.toolchain_digest,
            "aarch64-apple-darwin"
        )
        .is_err());

        let root = tempfile::tempdir().unwrap();
        let manifest = fixture(root.path());
        write(&root.path().join("extra"), b"not listed");
        assert!(admit_policy_toolchain_directory(
            root.path(),
            &manifest.toolchain_digest,
            "aarch64-apple-darwin"
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        write(&root.path().join("bin/bun"), b"runner");
        write(&root.path().join("scripts/generate-policy.mjs"), b"policy");
        symlink("/etc/passwd", root.path().join("escape")).unwrap();
        let error = PolicyToolchainManifestV1::assemble(
            root.path(),
            "aarch64-apple-darwin",
            Path::new("bin/bun"),
            Path::new("scripts/generate-policy.mjs"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("not relative"));
    }
}
