//! Validation of the ephemeral capability minted by the production portable
//! Cargo runner after fresh offline store verification.
//!
//! This check runs before `build.rs` opens an artifact, host tool, framework,
//! manifest, or retained transport. The claim socket makes the receipt
//! process-bound and one-use; copying old JSON cannot recreate that authority.
//!
//! @ref LLP 0035#build-consumption-and-post-link-contracts — authoritative
//! consumption begins only after fresh checkout/store provenance verification.

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::fs::{self, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

pub const SOURCE_REVISION_ENV: &str = "IBEX_PORTABLE_HERMES_SOURCE_REVISION";
pub const CURRENT_REVISION_ENV: &str = "IBEX_PORTABLE_HERMES_CURRENT_REVISION";
pub const PREFLIGHT_RECEIPT_ENV: &str = "IBEX_PORTABLE_HERMES_PREFLIGHT_RECEIPT";
pub const PREFLIGHT_NONCE_ENV: &str = "IBEX_PORTABLE_HERMES_PREFLIGHT_NONCE";
pub const CHECKOUT_ROOT_ENV: &str = "IBEX_PORTABLE_HERMES_CHECKOUT_ROOT";
pub const CARGO_TARGET_MAP_ENV: &str = "IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP";
pub const CARGO_TARGET_MAP_DIGEST_ENV: &str = "IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP_DIGEST";
pub const PROMOTION_ADMISSION_ENV: &str = "IBEX_PORTABLE_HERMES_PROMOTION_ADMISSION";
pub const PROMOTION_ADMISSION_DIGEST_ENV: &str = "IBEX_PORTABLE_HERMES_PROMOTION_ADMISSION_DIGEST";

const RECEIPT_SCHEMA: &str = "ibex/portable-engine-build-preflight/1";
const CLAIM_SCHEMA: &str = "ibex/portable-engine-build-preflight-claim/1";
const PROMOTION_ADMISSION_SCHEMA: &str = "ibex/portable-engine-checked-promotion-admission/1";
const PROMOTION_ADMISSION_DOMAIN: &str = "ibex.portable-engine-checked-promotion-admission.v1";
const CAPABILITY_PREFIX: &str = ".portable-engine-build-capability-";
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_WRAPPER_BYTES: u64 = 1024 * 1024;

// Darwin's pathname-socket ABI cannot represent the full checkout-local
// capability path. Connecting through a relative name is safe only while cwd
// mutation is serialized across this process.
static CLAIM_CWD_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl NodeIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode() & 0o7777,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortableBuildAuthorization {
    pub receipt_path: PathBuf,
    pub rustc_wrapper_path: PathBuf,
    pub cargo_target_map_path: PathBuf,
    pub promotion_admission_path: PathBuf,
    promotion_admission_bytes: Vec<u8>,
    manifest_digest: String,
    installation_receipt_digest: String,
    verification_policy_digest: String,
    attestation_verification_digest: String,
    provenance_bundle_digest: String,
    #[cfg(test)]
    test_unbound: bool,
}

impl PortableBuildAuthorization {
    pub fn promotion_admission_bytes(&self) -> &[u8] {
        &self.promotion_admission_bytes
    }

    pub fn bind_consumed_authority(
        &self,
        manifest_digest: &str,
        installation_receipt_digest: &str,
        verification_policy_digest: &str,
        attestation_verification_digest: &str,
        provenance_bundle_digest: &str,
    ) -> Result<(), String> {
        #[cfg(test)]
        if self.test_unbound {
            return Ok(());
        }
        for (label, observed, expected) in [
            ("manifest", manifest_digest, self.manifest_digest.as_str()),
            (
                "installation receipt",
                installation_receipt_digest,
                self.installation_receipt_digest.as_str(),
            ),
            (
                "verification policy",
                verification_policy_digest,
                self.verification_policy_digest.as_str(),
            ),
            (
                "fresh attestation verification",
                attestation_verification_digest,
                self.attestation_verification_digest.as_str(),
            ),
            (
                "provenance bundle",
                provenance_bundle_digest,
                self.provenance_bundle_digest.as_str(),
            ),
        ] {
            if observed != expected {
                return Err(format!(
                    "portable build capability {label} binding differs from the consumed store"
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn unbound_test_only() -> Self {
        let mut promotion_admission_bytes =
            crate::portable_engine_build_consumption::canonical_json(&serde_json::json!({
                "schema": PROMOTION_ADMISSION_SCHEMA,
                "authorized": false,
                "currentRevision": "b".repeat(40),
                "sourceRevision": "b".repeat(40),
                "promotionTopicRevision": null,
                "sourceTreeObjectId": null,
                "targetTriple": "aarch64-apple-darwin",
                "portableArtifactId": format!("sha256-{}", "A".repeat(43)),
                "admissionDigest": null,
                "verificationDigest": format!("sha256-{}", "B".repeat(43)),
            }))
            .expect("canonical test promotion admission");
        promotion_admission_bytes.push(b'\n');
        Self {
            receipt_path: PathBuf::from("/test-only/unbound-preflight-receipt"),
            rustc_wrapper_path: PathBuf::from("/test-only/unbound-rustc-wrapper"),
            cargo_target_map_path: PathBuf::from("/test-only/unbound-cargo-target-map"),
            promotion_admission_path: PathBuf::from("/test-only/unbound-promotion-admission"),
            promotion_admission_bytes,
            manifest_digest: String::new(),
            installation_receipt_digest: String::new(),
            verification_policy_digest: String::new(),
            attestation_verification_digest: String::new(),
            provenance_bundle_digest: String::new(),
            test_unbound: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortableBuildPreflightRequest {
    pub repo_root: PathBuf,
    pub artifact_id: String,
    pub archive_digest: String,
    pub source_revision: String,
    pub current_revision: String,
    pub target_triple: String,
    pub receipt_path: PathBuf,
    pub nonce: String,
    pub selected_rustc_wrapper: PathBuf,
    pub cargo_target_map_path: PathBuf,
    pub cargo_target_map_digest: String,
    pub promotion_admission_path: PathBuf,
    pub promotion_admission_digest: String,
}

fn text<'a>(object: &'a serde_json::Map<String, Value>, field: &str) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("portable build preflight receipt.{field} is not a string"))
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
    label: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} is not an object"))?;
    let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = fields.to_vec();
    expected.sort_unstable();
    if actual != expected {
        return Err(format!("{label} has malformed exact fields"));
    }
    Ok(object)
}

fn parse_decimal(value: &str, label: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{label} is not canonical decimal"));
    }
    value
        .parse::<u64>()
        .map_err(|error| format!("parse {label}: {error}"))
}

fn parse_octal(value: &str, label: &str) -> Result<u32, String> {
    if value.len() != 4 || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(format!("{label} is not four-digit octal"));
    }
    u32::from_str_radix(value, 8).map_err(|error| format!("parse {label}: {error}"))
}

fn receipt_identity(value: &Value, label: &str) -> Result<NodeIdentity, String> {
    let object = exact_object(value, &["device", "inode", "mode", "uid"], label)?;
    Ok(NodeIdentity {
        device: parse_decimal(text(object, "device")?, &format!("{label}.device"))?,
        inode: parse_decimal(text(object, "inode")?, &format!("{label}.inode"))?,
        uid: parse_decimal(text(object, "uid")?, &format!("{label}.uid"))?
            .try_into()
            .map_err(|_| format!("{label}.uid exceeds u32"))?,
        mode: parse_octal(text(object, "mode")?, &format!("{label}.mode"))?,
    })
}

fn acl_listing(path: &Path) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/bin/ls")
            .args(["-lde", "--"])
            .arg(path)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("inspect ACL for {}: {error}", path.display()))?;
        if !output.status.success() || output.stdout.len() > 1024 * 1024 {
            return Err(format!("cannot inspect ACL for {}", path.display()));
        }
        return String::from_utf8(output.stdout)
            .map_err(|error| format!("ACL listing for {} is not UTF-8: {error}", path.display()));
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Ok(String::new())
    }
}

fn has_any_acl(path: &Path) -> Result<bool, String> {
    let listing = acl_listing(path)?;
    let first = listing.split_whitespace().next().unwrap_or_default();
    Ok(first.ends_with('+')
        || listing.lines().any(|line| {
            line.trim_start()
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_digit())
        }))
}

fn has_write_acl(path: &Path) -> Result<bool, String> {
    const MUTATIONS: &[&str] = &[
        "write",
        "append",
        "add_file",
        "add_subdirectory",
        "delete",
        "delete_child",
        "writeattr",
        "writeextattr",
        "writesecurity",
        "chown",
    ];
    Ok(acl_listing(path)?.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
            && trimmed.split_whitespace().any(|word| word == "allow")
            && MUTATIONS.iter().any(|permission| {
                trimmed
                    .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                    .any(|word| word == *permission)
            })
    }))
}

fn require_node(
    path: &Path,
    label: &str,
    kind: &str,
    exact_mode: Option<u32>,
    identity: Option<&NodeIdentity>,
    reject_any_acl: bool,
    nlink_one: bool,
) -> Result<Metadata, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} at {}: {error}", path.display()))?;
    let right_kind = match kind {
        "directory" => before.is_dir(),
        "regular" => before.is_file(),
        "socket" => before.file_type().is_socket(),
        _ => false,
    };
    if !right_kind || before.file_type().is_symlink() {
        return Err(format!("{label} is redirected or has the wrong type"));
    }
    if before.uid() != unsafe { libc::geteuid() } {
        return Err(format!("{label} is not effective-UID-owned"));
    }
    let mode = before.mode() & 0o7777;
    if mode & 0o7000 != 0 || mode & 0o022 != 0 {
        return Err(format!("{label} has unsafe mode {mode:04o}"));
    }
    if exact_mode.is_some_and(|expected| mode != expected) {
        return Err(format!(
            "{label} has mode {mode:04o}, expected {:04o}",
            exact_mode.expect("checked")
        ));
    }
    if before.nlink() == 0 || (nlink_one && before.nlink() != 1) {
        return Err(format!("{label} has an inadmissible link count"));
    }
    if reject_any_acl {
        if has_any_acl(path)? {
            return Err(format!("{label} has a macOS extended ACL"));
        }
    } else if has_write_acl(path)? {
        return Err(format!("{label} has a write-enabling macOS extended ACL"));
    }
    let observed = NodeIdentity::from_metadata(&before);
    if identity.is_some_and(|expected| observed != *expected) {
        return Err(format!(
            "{label} identity differs from the preflight receipt"
        ));
    }
    let after =
        fs::symlink_metadata(path).map_err(|error| format!("reinspect {label}: {error}"))?;
    if NodeIdentity::from_metadata(&after) != observed
        || after.len() != before.len()
        || after.nlink() != before.nlink()
    {
        return Err(format!("{label} changed during validation"));
    }
    Ok(before)
}

fn absolute_components(path: &Path) -> Result<Vec<PathBuf>, String> {
    if !path.is_absolute() {
        return Err(format!("trusted path must be absolute: {}", path.display()));
    }
    let mut current = PathBuf::new();
    let mut output = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                current.push(component.as_os_str());
                output.push(current.clone());
            }
            Component::CurDir | Component::ParentDir => {
                return Err(format!(
                    "trusted path is not normalized: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(output)
}

fn validate_ancestry(repo_root: &Path) -> Result<(), String> {
    let components = absolute_components(repo_root)?;
    for (index, path) in components.iter().enumerate() {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("inspect checkout ancestry {}: {error}", path.display()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.nlink() == 0 {
            return Err(format!(
                "checkout ancestry {} is redirected or not a directory",
                path.display()
            ));
        }
        let uid = metadata.uid();
        if uid != 0 && uid != unsafe { libc::geteuid() } {
            return Err(format!(
                "checkout ancestry {} is not root/effective-UID-owned",
                path.display()
            ));
        }
        let mode = metadata.mode() & 0o7777;
        if mode & 0o7022 != 0 {
            return Err(format!(
                "checkout ancestry {} has unsafe mode {mode:04o}",
                path.display()
            ));
        }
        if index + 1 == components.len() {
            if uid != unsafe { libc::geteuid() } || has_any_acl(path)? {
                return Err("checkout root violates effective-UID/ACL premise".to_owned());
            }
        } else if has_write_acl(path)? {
            return Err(format!(
                "checkout ancestry {} has a write-enabling ACL",
                path.display()
            ));
        }
    }
    Ok(())
}

fn read_pinned(
    path: &Path,
    label: &str,
    maximum: u64,
    mode: u32,
) -> Result<(Vec<u8>, Metadata), String> {
    let before = require_node(path, label, "regular", Some(mode), None, true, true)?;
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| format!("open {label} without following: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("inspect open {label}: {error}"))?;
    if NodeIdentity::from_metadata(&before) != NodeIdentity::from_metadata(&opened) {
        return Err(format!("{label} changed while opened"));
    }
    if before.len() == 0 || before.len() > maximum {
        return Err(format!("{label} has an invalid byte size"));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read {label}: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("reinspect open {label}: {error}"))?;
    if bytes.len() as u64 != before.len()
        || NodeIdentity::from_metadata(&opened) != NodeIdentity::from_metadata(&after)
        || opened.len() != after.len()
    {
        return Err(format!("{label} changed while read"));
    }
    Ok((bytes, before))
}

fn raw_digest(bytes: &[u8]) -> String {
    format!("sha256-{:x}", Sha256::digest(bytes))
}

fn assert_nonce(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("portable build preflight nonce is not 32-byte lowercase hex".to_owned());
    }
    Ok(())
}

fn assert_revision(value: &str) -> Result<(), String> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("portable build source revision is not lowercase SHA-1".to_owned());
    }
    Ok(())
}

fn assert_raw_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 71
        || !value.starts_with("sha256-")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{label} is not a raw SHA-256 digest"));
    }
    Ok(())
}

fn assert_semantic_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 50
        || !value.starts_with("sha256-")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(format!("{label} is not a semantic SHA-256 digest"));
    }
    Ok(())
}

fn validate_promotion_admission(
    bytes: &[u8],
    request: &PortableBuildPreflightRequest,
) -> Result<String, String> {
    let canonical_bytes = bytes
        .strip_suffix(b"\n")
        .ok_or("checked promotion admission must end in exactly one LF after its canonical JSON")?;
    if canonical_bytes.ends_with(b"\n") {
        return Err("checked promotion admission has more than one trailing line feed".to_owned());
    }
    let admission = crate::portable_engine_build_consumption::parse_canonical(
        canonical_bytes,
        "checked promotion admission",
    )?;
    let object = exact_object(
        &admission,
        &[
            "schema",
            "authorized",
            "currentRevision",
            "sourceRevision",
            "promotionTopicRevision",
            "sourceTreeObjectId",
            "targetTriple",
            "portableArtifactId",
            "admissionDigest",
            "verificationDigest",
        ],
        "checked promotion admission",
    )?;
    if text(object, "schema")? != PROMOTION_ADMISSION_SCHEMA
        || text(object, "currentRevision")? != request.current_revision
        || text(object, "sourceRevision")? != request.source_revision
        || text(object, "targetTriple")? != request.target_triple
        || text(object, "portableArtifactId")? != request.artifact_id
    {
        return Err(
            "checked promotion admission differs from its external build selectors".to_owned(),
        );
    }
    assert_revision(text(object, "currentRevision")?)?;
    assert_revision(text(object, "sourceRevision")?)?;
    let verification_digest = text(object, "verificationDigest")?;
    assert_semantic_digest(
        verification_digest,
        "checked promotion admission verification digest",
    )?;
    let expected = crate::portable_engine_build_consumption::semantic_digest_without(
        PROMOTION_ADMISSION_DOMAIN,
        &admission,
        "verificationDigest",
    )?;
    if verification_digest != expected {
        return Err(
            "checked promotion admission verification digest does not bind its exact fields"
                .to_owned(),
        );
    }
    let authorized = object
        .get("authorized")
        .and_then(Value::as_bool)
        .ok_or("checked promotion admission authorization is not boolean")?;
    if authorized {
        let topic = text(object, "promotionTopicRevision")?;
        let source_tree = text(object, "sourceTreeObjectId")?;
        let admission_digest = text(object, "admissionDigest")?;
        if request.current_revision == request.source_revision
            || assert_revision(topic).is_err()
            || topic == request.current_revision
            || topic == request.source_revision
            || assert_revision(source_tree).is_err()
        {
            return Err("authorized promotion admission lineage is malformed".to_owned());
        }
        assert_semantic_digest(admission_digest, "checked lineage admission digest")?;
    } else if request.current_revision != request.source_revision
        || !object
            .get("promotionTopicRevision")
            .is_some_and(Value::is_null)
        || !object.get("sourceTreeObjectId").is_some_and(Value::is_null)
        || !object.get("admissionDigest").is_some_and(Value::is_null)
    {
        return Err(
            "diagnostic promotion admission carries unauthorized lineage authority".to_owned(),
        );
    }
    Ok(verification_digest.to_owned())
}

fn process_alive(pid: libc::pid_t) -> Result<(), String> {
    if pid <= 1 {
        return Err("portable build preflight runner PID is invalid".to_owned());
    }
    if unsafe { libc::kill(pid, 0) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    Err(format!(
        "portable build preflight runner is not live: {error}"
    ))
}

fn require_peer_uid(stream: &UnixStream) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    unsafe {
        unsafe extern "C" {
            fn getpeereid(
                socket: libc::c_int,
                uid: *mut libc::uid_t,
                gid: *mut libc::gid_t,
            ) -> libc::c_int;
        }
        let mut uid = 0;
        let mut gid = 0;
        if getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) != 0 {
            return Err(format!(
                "inspect portable build claim peer: {}",
                std::io::Error::last_os_error()
            ));
        }
        if uid != libc::geteuid() {
            return Err("portable build claim peer is not effective-UID-owned".to_owned());
        }
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let mut credentials: libc::ucred = std::mem::zeroed();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut length,
        ) != 0
        {
            return Err(format!(
                "inspect portable build claim peer: {}",
                std::io::Error::last_os_error()
            ));
        }
        if credentials.uid != libc::geteuid() {
            return Err("portable build claim peer is not effective-UID-owned".to_owned());
        }
    }
    Ok(())
}

fn connect_claim_socket(capability_directory: &Path) -> Result<UnixStream, String> {
    let _claim_cwd_guard = CLAIM_CWD_LOCK
        .lock()
        .map_err(|_| "portable build claim cwd lock is poisoned".to_owned())?;
    let original = std::env::current_dir()
        .map_err(|error| format!("capture cwd before portable build claim: {error}"))?;
    std::env::set_current_dir(capability_directory).map_err(|error| {
        format!(
            "enter portable build capability directory {}: {error}",
            capability_directory.display()
        )
    })?;
    let connected = UnixStream::connect("claim.sock")
        .map_err(|error| format!("connect to live portable build preflight runner: {error}"));
    let restored = std::env::set_current_dir(&original)
        .map_err(|error| format!("restore cwd after portable build claim: {error}"));
    match (connected, restored) {
        (Ok(stream), Ok(())) => Ok(stream),
        (Err(error), Ok(())) | (_, Err(error)) => Err(error),
    }
}

pub fn validate_portable_build_preflight(
    request: &PortableBuildPreflightRequest,
) -> Result<PortableBuildAuthorization, String> {
    assert_nonce(&request.nonce)?;
    assert_revision(&request.source_revision)?;
    assert_revision(&request.current_revision)?;
    assert_raw_digest(
        &request.promotion_admission_digest,
        "externally selected promotion admission digest",
    )?;
    if !request.repo_root.is_absolute()
        || !request.receipt_path.is_absolute()
        || !request.selected_rustc_wrapper.is_absolute()
        || !request.cargo_target_map_path.is_absolute()
        || !request.promotion_admission_path.is_absolute()
    {
        return Err("portable build preflight paths must be absolute".to_owned());
    }
    validate_ancestry(&request.repo_root)?;
    let repo_root = fs::canonicalize(&request.repo_root)
        .map_err(|error| format!("canonicalize portable checkout root: {error}"))?;
    if repo_root != request.repo_root {
        return Err("portable checkout root is redirected or non-canonical".to_owned());
    }
    let target_root = repo_root.join("target");
    let store_root = target_root.join("hermes-artifacts");
    let capability_directory = target_root.join(format!("{CAPABILITY_PREFIX}{}", request.nonce));
    let expected_receipt = capability_directory.join("receipt.json");
    let expected_socket = capability_directory.join("claim.sock");
    let expected_wrapper = capability_directory.join("rustc-wrapper");
    let expected_target_map = capability_directory.join("cargo-target-map.json");
    let expected_promotion_admission = capability_directory.join("promotion-admission.json");
    if request.receipt_path != expected_receipt {
        return Err(
            "portable build preflight receipt is outside its nonce-bound directory".to_owned(),
        );
    }
    if request.selected_rustc_wrapper != expected_wrapper {
        return Err("RUSTC_WRAPPER is not the nonce-bound portable wrapper".to_owned());
    }
    if request.cargo_target_map_path != expected_target_map {
        return Err("portable Cargo target map is outside its nonce-bound directory".to_owned());
    }
    if request.promotion_admission_path != expected_promotion_admission {
        return Err("checked promotion admission is outside its nonce-bound directory".to_owned());
    }

    let (receipt_bytes, receipt_metadata) = read_pinned(
        &expected_receipt,
        "portable build preflight receipt",
        MAX_RECEIPT_BYTES,
        0o400,
    )?;
    let receipt = crate::portable_engine_build_consumption::parse_canonical(
        &receipt_bytes,
        "portable build preflight receipt",
    )?;
    let object = exact_object(
        &receipt,
        &[
            "schema",
            "nonce",
            "runnerPid",
            "checkoutRoot",
            "sourceRevision",
            "currentRevision",
            "artifactId",
            "archiveDigest",
            "manifestDigest",
            "installationReceiptDigest",
            "verificationPolicyDigest",
            "attestationVerificationDigest",
            "provenanceBundleDigest",
            "checkoutIdentity",
            "targetIdentity",
            "storeIdentity",
            "capabilityDirectoryIdentity",
            "claimSocketIdentity",
            "rustcWrapperPath",
            "rustcWrapperDigest",
            "rustcWrapperSourceDigest",
            "rustcWrapperIdentity",
            "cargoTargetMapPath",
            "cargoTargetMapDigest",
            "cargoTargetMapIdentity",
            "promotionAdmissionPath",
            "promotionAdmissionDigest",
            "promotionAdmissionVerificationDigest",
            "promotionAdmissionIdentity",
        ],
        "portable build preflight receipt",
    )?;
    for (field, expected) in [
        ("schema", RECEIPT_SCHEMA),
        ("nonce", request.nonce.as_str()),
        (
            "checkoutRoot",
            repo_root.to_str().ok_or("checkout root is not UTF-8")?,
        ),
        ("sourceRevision", request.source_revision.as_str()),
        ("currentRevision", request.current_revision.as_str()),
        ("artifactId", request.artifact_id.as_str()),
        ("archiveDigest", request.archive_digest.as_str()),
        (
            "rustcWrapperPath",
            expected_wrapper
                .to_str()
                .ok_or("rustc wrapper path is not UTF-8")?,
        ),
        (
            "cargoTargetMapPath",
            expected_target_map
                .to_str()
                .ok_or("Cargo target-map path is not UTF-8")?,
        ),
        (
            "promotionAdmissionPath",
            expected_promotion_admission
                .to_str()
                .ok_or("checked promotion admission path is not UTF-8")?,
        ),
    ] {
        if text(object, field)? != expected {
            return Err(format!(
                "portable build preflight receipt.{field} differs from its external selector"
            ));
        }
    }

    let checkout_identity = receipt_identity(&object["checkoutIdentity"], "checkoutIdentity")?;
    let target_identity = receipt_identity(&object["targetIdentity"], "targetIdentity")?;
    let store_identity = receipt_identity(&object["storeIdentity"], "storeIdentity")?;
    let capability_identity = receipt_identity(
        &object["capabilityDirectoryIdentity"],
        "capabilityDirectoryIdentity",
    )?;
    let socket_identity = receipt_identity(&object["claimSocketIdentity"], "claimSocketIdentity")?;
    let wrapper_identity =
        receipt_identity(&object["rustcWrapperIdentity"], "rustcWrapperIdentity")?;
    let target_map_identity =
        receipt_identity(&object["cargoTargetMapIdentity"], "cargoTargetMapIdentity")?;
    let promotion_admission_identity = receipt_identity(
        &object["promotionAdmissionIdentity"],
        "promotionAdmissionIdentity",
    )?;
    require_node(
        &repo_root,
        "portable checkout root",
        "directory",
        None,
        Some(&checkout_identity),
        true,
        false,
    )?;
    require_node(
        &target_root,
        "portable checkout target",
        "directory",
        None,
        Some(&target_identity),
        true,
        false,
    )?;
    require_node(
        &store_root,
        "portable engine store",
        "directory",
        Some(0o700),
        Some(&store_identity),
        true,
        false,
    )?;
    require_node(
        &capability_directory,
        "portable build capability directory",
        "directory",
        Some(0o700),
        Some(&capability_identity),
        true,
        false,
    )?;
    require_node(
        &expected_socket,
        "portable build claim socket",
        "socket",
        Some(0o600),
        Some(&socket_identity),
        true,
        true,
    )?;
    let (wrapper_bytes, wrapper_metadata) = read_pinned(
        &expected_wrapper,
        "portable rustc-wrapper launcher",
        MAX_WRAPPER_BYTES,
        0o500,
    )?;
    if NodeIdentity::from_metadata(&wrapper_metadata) != wrapper_identity {
        return Err(
            "portable rustc-wrapper identity differs from its preflight receipt".to_owned(),
        );
    }
    if raw_digest(&wrapper_bytes) != text(object, "rustcWrapperDigest")? {
        return Err("portable rustc-wrapper bytes differ from the preflight receipt".to_owned());
    }
    let wrapper_newline = wrapper_bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| "portable rustc-wrapper launcher has no shebang boundary".to_owned())?;
    let wrapper_body = &wrapper_bytes[wrapper_newline + 1..];
    if !wrapper_bytes.starts_with(b"#!")
        || raw_digest(wrapper_body) != text(object, "rustcWrapperSourceDigest")?
    {
        return Err(
            "portable rustc-wrapper checked source differs from the preflight receipt".to_owned(),
        );
    }
    let (target_map_bytes, target_map_metadata) = read_pinned(
        &expected_target_map,
        "portable Cargo target map",
        MAX_WRAPPER_BYTES,
        0o400,
    )?;
    if NodeIdentity::from_metadata(&target_map_metadata) != target_map_identity {
        return Err(
            "portable Cargo target-map identity differs from its preflight receipt".to_owned(),
        );
    }
    let target_map_digest = raw_digest(&target_map_bytes);
    if target_map_digest != text(object, "cargoTargetMapDigest")?
        || target_map_digest != request.cargo_target_map_digest
    {
        return Err(
            "portable Cargo target-map bytes differ from their external/receipt binding".to_owned(),
        );
    }
    let target_map = crate::portable_engine_build_consumption::parse_canonical(
        &target_map_bytes,
        "portable Cargo target map",
    )?;
    let target_map_object = target_map
        .as_object()
        .ok_or_else(|| "portable Cargo target map is not an object".to_owned())?;
    if target_map_object.get("schema")
        != Some(&Value::String(
            "ibex/portable-engine-cargo-target-map/1".to_owned(),
        ))
        || !target_map_object
            .get("targets")
            .is_some_and(Value::is_array)
    {
        return Err("portable Cargo target map has the wrong schema or target set".to_owned());
    }
    let (promotion_admission_bytes, promotion_admission_metadata) = read_pinned(
        &expected_promotion_admission,
        "checked promotion admission",
        MAX_RECEIPT_BYTES,
        0o400,
    )?;
    if NodeIdentity::from_metadata(&promotion_admission_metadata) != promotion_admission_identity {
        return Err(
            "checked promotion admission identity differs from its preflight receipt".to_owned(),
        );
    }
    let promotion_admission_digest = raw_digest(&promotion_admission_bytes);
    if promotion_admission_digest != text(object, "promotionAdmissionDigest")?
        || promotion_admission_digest != request.promotion_admission_digest
    {
        return Err(
            "checked promotion admission bytes differ from their external/receipt binding"
                .to_owned(),
        );
    }
    let promotion_verification_digest =
        validate_promotion_admission(&promotion_admission_bytes, request)?;
    if promotion_verification_digest != text(object, "promotionAdmissionVerificationDigest")? {
        return Err(
            "checked promotion admission verification differs from its preflight receipt"
                .to_owned(),
        );
    }
    if receipt_metadata.uid() != unsafe { libc::geteuid() } || receipt_metadata.nlink() != 1 {
        return Err("portable build preflight receipt ownership/link premise changed".to_owned());
    }

    let runner_pid_u64 = parse_decimal(text(object, "runnerPid")?, "runnerPid")?;
    let runner_pid: libc::pid_t = runner_pid_u64
        .try_into()
        .map_err(|_| "portable build preflight runner PID is out of range".to_owned())?;
    process_alive(runner_pid)?;
    let mut stream = connect_claim_socket(&capability_directory)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("bound portable build claim read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("bound portable build claim write timeout: {error}"))?;
    require_peer_uid(&stream)?;
    let claim = serde_json::json!({
        "schema": CLAIM_SCHEMA,
        "nonce": request.nonce,
        "runnerPid": runner_pid.to_string(),
    });
    let mut claim_bytes = crate::portable_engine_build_consumption::canonical_json(&claim)?;
    claim_bytes.push(b'\n');
    stream
        .write_all(&claim_bytes)
        .map_err(|error| format!("write portable build preflight claim: {error}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| format!("finish portable build preflight claim: {error}"))?;
    let mut response = Vec::new();
    stream
        .take(256)
        .read_to_end(&mut response)
        .map_err(|error| format!("read portable build preflight authorization: {error}"))?;
    if response != format!("authorized:{}\n", request.nonce).as_bytes() {
        return Err("portable build preflight claim was not authorized exactly once".to_owned());
    }

    process_alive(runner_pid)?;
    for (path, label, identity, kind, mode, nlink_one) in [
        (
            repo_root.as_path(),
            "portable checkout root",
            &checkout_identity,
            "directory",
            None,
            false,
        ),
        (
            target_root.as_path(),
            "portable checkout target",
            &target_identity,
            "directory",
            None,
            false,
        ),
        (
            store_root.as_path(),
            "portable engine store",
            &store_identity,
            "directory",
            Some(0o700),
            false,
        ),
        (
            capability_directory.as_path(),
            "portable build capability directory",
            &capability_identity,
            "directory",
            Some(0o700),
            false,
        ),
        (
            expected_socket.as_path(),
            "portable build claim socket",
            &socket_identity,
            "socket",
            Some(0o600),
            true,
        ),
        (
            expected_wrapper.as_path(),
            "portable rustc-wrapper launcher",
            &wrapper_identity,
            "regular",
            Some(0o500),
            true,
        ),
        (
            expected_target_map.as_path(),
            "portable Cargo target map",
            &target_map_identity,
            "regular",
            Some(0o400),
            true,
        ),
        (
            expected_promotion_admission.as_path(),
            "checked promotion admission",
            &promotion_admission_identity,
            "regular",
            Some(0o400),
            true,
        ),
    ] {
        require_node(path, label, kind, mode, Some(identity), true, nlink_one)?;
    }
    for (path, label, maximum, mode, expected_bytes) in [
        (
            expected_receipt.as_path(),
            "portable build preflight receipt",
            MAX_RECEIPT_BYTES,
            0o400,
            receipt_bytes.as_slice(),
        ),
        (
            expected_wrapper.as_path(),
            "portable rustc-wrapper launcher",
            MAX_WRAPPER_BYTES,
            0o500,
            wrapper_bytes.as_slice(),
        ),
        (
            expected_target_map.as_path(),
            "portable Cargo target map",
            MAX_WRAPPER_BYTES,
            0o400,
            target_map_bytes.as_slice(),
        ),
        (
            expected_promotion_admission.as_path(),
            "checked promotion admission",
            MAX_RECEIPT_BYTES,
            0o400,
            promotion_admission_bytes.as_slice(),
        ),
    ] {
        let (final_bytes, _) = read_pinned(path, label, maximum, mode)?;
        if final_bytes != expected_bytes {
            return Err(format!("{label} changed after the live capability claim"));
        }
    }

    Ok(PortableBuildAuthorization {
        receipt_path: expected_receipt,
        rustc_wrapper_path: expected_wrapper,
        cargo_target_map_path: expected_target_map,
        promotion_admission_path: expected_promotion_admission,
        promotion_admission_bytes,
        manifest_digest: text(object, "manifestDigest")?.to_owned(),
        installation_receipt_digest: text(object, "installationReceiptDigest")?.to_owned(),
        verification_policy_digest: text(object, "verificationPolicyDigest")?.to_owned(),
        attestation_verification_digest: text(object, "attestationVerificationDigest")?.to_owned(),
        provenance_bundle_digest: text(object, "provenanceBundleDigest")?.to_owned(),
        #[cfg(test)]
        test_unbound: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::thread;
    use tempfile::TempDir;

    struct Fixture {
        _temporary: TempDir,
        request: PortableBuildPreflightRequest,
        listener: Option<thread::JoinHandle<()>>,
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn json_identity(path: &Path) -> Value {
        let metadata = fs::symlink_metadata(path).unwrap();
        serde_json::json!({
            "device": metadata.dev().to_string(),
            "inode": metadata.ino().to_string(),
            "uid": metadata.uid().to_string(),
            "mode": format!("{:04o}", metadata.mode() & 0o7777),
        })
    }

    fn fixture() -> Fixture {
        fixture_with_authorization(false)
    }

    fn fixture_with_authorization(authorized: bool) -> Fixture {
        let temporary = TempDir::new().unwrap();
        let repo_root = fs::canonicalize(temporary.path()).unwrap().join("checkout");
        fs::create_dir(&repo_root).unwrap();
        set_mode(&repo_root, 0o700);
        let target = repo_root.join("target");
        fs::create_dir(&target).unwrap();
        set_mode(&target, 0o700);
        let store = target.join("hermes-artifacts");
        fs::create_dir(&store).unwrap();
        set_mode(&store, 0o700);
        let nonce = "1".repeat(64);
        let artifact_id = format!("sha256-{}", "A".repeat(43));
        let archive_digest = format!("sha256-{}", "a".repeat(64));
        let source_revision = "b".repeat(40);
        let current_revision = if authorized {
            "c".repeat(40)
        } else {
            source_revision.clone()
        };
        let capability = target.join(format!("{CAPABILITY_PREFIX}{nonce}"));
        fs::create_dir(&capability).unwrap();
        set_mode(&capability, 0o700);
        let wrapper = capability.join("rustc-wrapper");
        fs::write(&wrapper, b"#!/bin/sh\nexit 0\n").unwrap();
        set_mode(&wrapper, 0o500);
        let target_map = capability.join("cargo-target-map.json");
        let target_map_bytes =
            crate::portable_engine_build_consumption::canonical_json(&serde_json::json!({
                "schema": "ibex/portable-engine-cargo-target-map/1",
                "packageName": "fixture",
                "manifestDigest": format!("sha256-{}", "f".repeat(64)),
                "targets": [{
                    "crateName": "fixture",
                    "kind": "bin",
                    "name": "fixture",
                    "source": "src/main.rs",
                }],
            }))
            .unwrap();
        fs::write(&target_map, &target_map_bytes).unwrap();
        set_mode(&target_map, 0o400);
        let promotion_admission = capability.join("promotion-admission.json");
        let mut promotion_admission_value = serde_json::json!({
            "schema": PROMOTION_ADMISSION_SCHEMA,
            "authorized": authorized,
            "currentRevision": current_revision,
            "sourceRevision": source_revision,
            "promotionTopicRevision": authorized.then(|| "d".repeat(40)),
            "sourceTreeObjectId": authorized.then(|| "e".repeat(40)),
            "targetTriple": "aarch64-apple-darwin",
            "portableArtifactId": artifact_id,
            "admissionDigest": authorized.then(|| format!("sha256-{}", "E".repeat(43))),
            "verificationDigest": "",
        });
        promotion_admission_value["verificationDigest"] = Value::String(
            crate::portable_engine_build_consumption::semantic_digest_without(
                PROMOTION_ADMISSION_DOMAIN,
                &promotion_admission_value,
                "verificationDigest",
            )
            .unwrap(),
        );
        let mut promotion_admission_bytes =
            crate::portable_engine_build_consumption::canonical_json(&promotion_admission_value)
                .unwrap();
        promotion_admission_bytes.push(b'\n');
        fs::write(&promotion_admission, &promotion_admission_bytes).unwrap();
        set_mode(&promotion_admission, 0o400);
        let socket = capability.join("claim.sock");
        let _claim_cwd_guard = CLAIM_CWD_LOCK.lock().unwrap();
        let original_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&capability).unwrap();
        let listener = UnixListener::bind("claim.sock").unwrap();
        std::env::set_current_dir(original_cwd).unwrap();
        set_mode(&socket, 0o600);
        let listener_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut claim = Vec::new();
            stream.read_to_end(&mut claim).unwrap();
            let expected = serde_json::json!({
                "schema": CLAIM_SCHEMA,
                "nonce": "1".repeat(64),
                "runnerPid": std::process::id().to_string(),
            });
            let mut expected =
                crate::portable_engine_build_consumption::canonical_json(&expected).unwrap();
            expected.push(b'\n');
            if claim == expected {
                stream
                    .write_all(format!("authorized:{}\n", "1".repeat(64)).as_bytes())
                    .unwrap();
            }
        });
        let receipt = serde_json::json!({
            "schema": RECEIPT_SCHEMA,
            "nonce": nonce,
            "runnerPid": std::process::id().to_string(),
            "checkoutRoot": repo_root.to_str().unwrap(),
            "sourceRevision": source_revision,
            "currentRevision": current_revision,
            "artifactId": artifact_id,
            "archiveDigest": archive_digest,
            "manifestDigest": format!("sha256-{}", "B".repeat(43)),
            "installationReceiptDigest": format!("sha256-{}", "C".repeat(43)),
            "verificationPolicyDigest": format!("sha256-{}", "D".repeat(43)),
            "attestationVerificationDigest": format!("sha256-{}", "c".repeat(64)),
            "provenanceBundleDigest": format!("sha256-{}", "d".repeat(64)),
            "checkoutIdentity": json_identity(&repo_root),
            "targetIdentity": json_identity(&target),
            "storeIdentity": json_identity(&store),
            "capabilityDirectoryIdentity": json_identity(&capability),
            "claimSocketIdentity": json_identity(&socket),
            "rustcWrapperPath": wrapper.to_str().unwrap(),
            "rustcWrapperDigest": raw_digest(b"#!/bin/sh\nexit 0\n"),
            "rustcWrapperSourceDigest": raw_digest(b"exit 0\n"),
            "rustcWrapperIdentity": json_identity(&wrapper),
            "cargoTargetMapPath": target_map.to_str().unwrap(),
            "cargoTargetMapDigest": raw_digest(&target_map_bytes),
            "cargoTargetMapIdentity": json_identity(&target_map),
            "promotionAdmissionPath": promotion_admission.to_str().unwrap(),
            "promotionAdmissionDigest": raw_digest(&promotion_admission_bytes),
            "promotionAdmissionVerificationDigest": promotion_admission_value["verificationDigest"],
            "promotionAdmissionIdentity": json_identity(&promotion_admission),
        });
        let receipt_path = capability.join("receipt.json");
        fs::write(
            &receipt_path,
            crate::portable_engine_build_consumption::canonical_json(&receipt).unwrap(),
        )
        .unwrap();
        set_mode(&receipt_path, 0o400);
        Fixture {
            _temporary: temporary,
            request: PortableBuildPreflightRequest {
                repo_root,
                artifact_id,
                archive_digest,
                source_revision,
                current_revision,
                target_triple: "aarch64-apple-darwin".to_owned(),
                receipt_path,
                nonce,
                selected_rustc_wrapper: wrapper,
                cargo_target_map_path: target_map,
                cargo_target_map_digest: raw_digest(&target_map_bytes),
                promotion_admission_path: promotion_admission,
                promotion_admission_digest: raw_digest(&promotion_admission_bytes),
            },
            listener: Some(listener_thread),
        }
    }

    #[test]
    fn accepts_one_live_claim_and_binds_every_consumed_authority() {
        let mut fixture = fixture();
        let authorization = validate_portable_build_preflight(&fixture.request).unwrap();
        fixture.listener.take().unwrap().join().unwrap();
        authorization
            .bind_consumed_authority(
                &format!("sha256-{}", "B".repeat(43)),
                &format!("sha256-{}", "C".repeat(43)),
                &format!("sha256-{}", "D".repeat(43)),
                &format!("sha256-{}", "c".repeat(64)),
                &format!("sha256-{}", "d".repeat(64)),
            )
            .unwrap();
        let error = validate_portable_build_preflight(&fixture.request).unwrap_err();
        assert!(
            error.contains("connect to live") || error.contains("not authorized"),
            "copied/stale capability was not refused at its one-use live seam: {error}"
        );
    }

    #[test]
    fn diagnostic_a_marker_cannot_authorize_host_and_carries_distinct_authorized_a_p_c() {
        let mut diagnostic = fixture();
        let diagnostic_authorization =
            validate_portable_build_preflight(&diagnostic.request).unwrap();
        diagnostic.listener.take().unwrap().join().unwrap();
        let diagnostic_value: Value = serde_json::from_slice(
            diagnostic_authorization
                .promotion_admission_bytes()
                .strip_suffix(b"\n")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(diagnostic_value["authorized"].as_bool(), Some(false));
        assert_eq!(
            diagnostic_value["currentRevision"],
            diagnostic_value["sourceRevision"]
        );

        let mut promoted = fixture_with_authorization(true);
        let promoted_authorization = validate_portable_build_preflight(&promoted.request).unwrap();
        promoted.listener.take().unwrap().join().unwrap();
        let promoted_value: Value = serde_json::from_slice(
            promoted_authorization
                .promotion_admission_bytes()
                .strip_suffix(b"\n")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(promoted_value["authorized"].as_bool(), Some(true));
        let revisions = [
            promoted_value["sourceRevision"].as_str().unwrap(),
            promoted_value["promotionTopicRevision"].as_str().unwrap(),
            promoted_value["currentRevision"].as_str().unwrap(),
        ];
        assert_eq!(
            revisions
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
    }

    #[test]
    fn refuses_final_store_join_mutation() {
        let mut fixture = fixture();
        let authorization = validate_portable_build_preflight(&fixture.request).unwrap();
        fixture.listener.take().unwrap().join().unwrap();
        let error = authorization
            .bind_consumed_authority(
                &format!("sha256-{}", "Z".repeat(43)),
                &format!("sha256-{}", "C".repeat(43)),
                &format!("sha256-{}", "D".repeat(43)),
                &format!("sha256-{}", "c".repeat(64)),
                &format!("sha256-{}", "d".repeat(64)),
            )
            .unwrap_err();
        assert!(error.contains("manifest binding differs"));
    }

    #[test]
    fn refuses_hardlinked_or_relocated_receipt_before_claim() {
        let mut fixture = fixture();
        let hardlink = fixture.request.receipt_path.with_file_name("hardlink.json");
        fs::hard_link(&fixture.request.receipt_path, &hardlink).unwrap();
        let error = validate_portable_build_preflight(&fixture.request).unwrap_err();
        assert!(error.contains("link count"));
        // Let the fixture listener exit without leaving a blocked test thread.
        let _ = connect_claim_socket(fixture.request.receipt_path.parent().unwrap());
        fixture.listener.take().unwrap().join().unwrap();
    }
}
