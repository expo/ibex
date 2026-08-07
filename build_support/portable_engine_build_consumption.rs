//! Authoritative, checkout-local portable Hermes selection for `build.rs`.
//!
//! This module intentionally has no installer or network behavior. The caller
//! selects one already-installed artifact and one retained transport, and this
//! module closes that selection over the exact bytes used by the native build.
//!
//! @ref LLP 0035#content-addressed-installation — authoritative consumers use
//! one complete checkout-local store and one explicit retained transport.
//! @ref LLP 0035#build-consumption-and-post-link-contracts — the build record
//! binds the complete selected header, link, runtime, tool, and dependency set.

use crate::portable_engine_build_preflight::PortableBuildAuthorization;
use crate::portable_host_tool_runner::PortableHostToolContract;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

pub const ARTIFACT_ID_ENV: &str = "IBEX_PORTABLE_HERMES_ARTIFACT_ID";
pub const STORE_ROOT_ENV: &str = "IBEX_PORTABLE_HERMES_STORE_ROOT";
pub const ARCHIVE_DIGEST_ENV: &str = "IBEX_PORTABLE_HERMES_ARCHIVE_DIGEST";

pub const LEGACY_ENGINE_OVERRIDE_ENVS: &[&str] = &[
    "HERMESC",
    "HERMES_ANDROID_DIR",
    "HERMES_ANDROID_ROOT",
    "HERMES_BINARY",
    "HERMES_BIN_DIR",
    "HERMES_CLI",
    "HERMES_COMPILER",
    "HERMES_ENABLE_DEBUGGER",
    "HERMES_INCLUDE_DIR",
    "HERMES_LIB_DIR",
    "HERMES_LIB_NAME",
    "HERMES_LINK_STATIC",
    "HERMES_PROFILE_PROVENANCE_RECEIPT",
    "IBEX_LEGACY_HERMES_BLOCK_SCOPING",
    "IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE",
    "JSI_INCLUDE_DIR",
    "JSI_LIB_DIR",
];

const MANIFEST_SCHEMA: &str = "ibex/portable-engine-manifest/1";
const INSTALLATION_RECEIPT_SCHEMA: &str = "ibex/portable-engine-installation-receipt/1";
const PROFILE_RECEIPT_SCHEMA: &str = "ibex/hermes-profile-provenance-receipt/2";
const HEADER_SET_SCHEMA: &str = "ibex/portable-engine-header-set/1";
const BUILD_CONSUMPTION_SCHEMA: &str = "ibex/portable-engine-build-consumption/1";
const PORTABLE_IDENTITY_SCHEMA: &str = "ibex/portable-engine-artifact-identity/1";
const STORE_COMPLETION_SCHEMA: &str = "ibex/portable-engine-local-completion/1";
const TRANSPORT_COMPLETION_SCHEMA: &str = "ibex/portable-engine-local-transport-completion/1";
const TARGET_TRIPLE: &str = "aarch64-apple-darwin";
const RUNTIME_COMPONENT: &str = "lib/hermesvm.framework/Versions/1/hermesvm";
const FRAMEWORK_SEARCH_ROOT: &str = "lib";
const INCLUDE_ROOT: &str = "include";
const HERMESC_COMPONENT: &str = "bin/hermesc";
const REVIEWED_PROFILE_DOCUMENT: &str = "META-INF/authority/reviewed-profile-identity.json";
const HEADER_SET_DOCUMENT: &str = "META-INF/authority/header-set.json";
const MAX_JSON_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SELECTED_INPUT_BYTES: u64 = 1024 * 1024 * 1024;
const IJSON_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone)]
pub struct PortableEngineRequest {
    pub repo_root: PathBuf,
    pub cargo_out_dir: PathBuf,
    pub store_root: Option<PathBuf>,
    pub artifact_id: String,
    pub archive_digest: String,
    pub target_os: String,
    pub target_arch: String,
    pub target_triple: String,
    pub ibex_features: Vec<String>,
    /// Names, not values: even a seemingly-benign legacy override is an
    /// ambiguous second selector and therefore forbidden in portable mode.
    pub present_legacy_overrides: Vec<String>,
    /// One process-bound capability consumed before this module is entered.
    /// Its final joins are rechecked after the selected store bytes are read.
    pub build_authorization: PortableBuildAuthorization,
}

#[derive(Debug, Clone)]
pub struct PortableEngineSelection {
    pub include_dir: PathBuf,
    pub framework_search_dir: PathBuf,
    pub framework_name: String,
    /// Every checkout authority, retained transport, and selected payload path
    /// whose mutation must cause Cargo to rerun this consumer.
    pub rerun_if_changed: Vec<PathBuf>,
    pub runtime_path: PathBuf,
    pub hermesc_path: PathBuf,
    pub host_tool_contract: PortableHostToolContract,
    pub profile_receipt_path: PathBuf,
    pub hermes_bytecode_version: u32,
    pub manifest_bytes: Vec<u8>,
    pub installation_receipt_bytes: Vec<u8>,
    pub profile_receipt_bytes: Vec<u8>,
    pub build_consumption_bytes: Vec<u8>,
    /// Separate from frozen build-consumption v1: A and C consume identical
    /// engine bytes but carry different checked promotion authorization.
    pub promotion_admission_bytes: Vec<u8>,
}

#[cfg(test)]
fn portable_linker_rpaths(artifact_id: &str) -> (String, String) {
    let suffix = format!("hermes-artifacts/{artifact_id}/payload/lib");
    (
        format!("@loader_path/../{suffix}"),
        format!("@loader_path/../../{suffix}"),
    )
}

impl PortableEngineSelection {
    pub fn write_embedded_outputs(&self, out_dir: &Path) -> Result<(), String> {
        fs::write(
            out_dir.join("portable_engine_manifest.json"),
            &self.manifest_bytes,
        )
        .map_err(|error| format!("write embedded portable engine manifest: {error}"))?;
        fs::write(
            out_dir.join("portable_engine_installation_receipt.json"),
            &self.installation_receipt_bytes,
        )
        .map_err(|error| format!("write embedded portable installation receipt: {error}"))?;
        fs::write(
            out_dir.join("portable_engine_build_consumption.json"),
            &self.build_consumption_bytes,
        )
        .map_err(|error| format!("write embedded portable build consumption: {error}"))?;
        fs::write(
            out_dir.join("portable_engine_promotion_admission.json"),
            &self.promotion_admission_bytes,
        )
        .map_err(|error| format!("write embedded portable promotion admission: {error}"))?;
        fs::write(
            out_dir.join("hermes_profile_provenance.json"),
            &self.profile_receipt_bytes,
        )
        .map_err(|error| format!("write embedded Hermes profile receipt: {error}"))?;
        Ok(())
    }
}

pub fn write_absent_embedded_outputs(out_dir: &Path) -> Result<(), String> {
    for name in [
        "portable_engine_manifest.json",
        "portable_engine_installation_receipt.json",
        "portable_engine_build_consumption.json",
        "portable_engine_promotion_admission.json",
        "portable_engine_promotion_report.json",
        "portable_engine_promotion_scope.json",
    ] {
        fs::write(out_dir.join(name), b"null\n")
            .map_err(|error| format!("write absent portable engine marker {name}: {error}"))?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct RegularEntry {
    role: String,
    path: String,
    digest: String,
    size: u64,
    executable: bool,
}

#[derive(Debug)]
struct ManifestFacts {
    regular: BTreeMap<String, RegularEntry>,
    directories: BTreeSet<String>,
    symlinks: BTreeMap<String, String>,
    profile: Value,
    target: Value,
    interface: Value,
    build: Value,
}

#[derive(Debug)]
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an I-JSON value with no duplicate object names")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value < 0 || value as u64 > IJSON_MAX_SAFE_INTEGER {
                    return Err(E::custom(
                        "integer is outside the non-negative I-JSON range",
                    ));
                }
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value > IJSON_MAX_SAFE_INTEGER {
                    return Err(E::custom("integer is outside the I-JSON safe range"));
                }
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Err(E::custom("floating-point authority values are forbidden"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                let mut names = HashSet::new();
                while let Some(name) = map.next_key::<String>()? {
                    if !names.insert(name.clone()) {
                        return Err(de::Error::custom(format!(
                            "duplicate JSON object name {name:?}"
                        )));
                    }
                    let value = map.next_value::<StrictValue>()?;
                    values.insert(name, value.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

pub(crate) fn parse_strict(bytes: &[u8], label: &str) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| format!("{label} is not strict I-JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("{label} has trailing JSON input: {error}"))?;
    Ok(value.0)
}

fn compare_utf16(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn write_jcs(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if !number.is_u64() && !number.is_i64() {
                return Err("JCS authority value contains a floating-point number".to_owned());
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(text) => output.extend_from_slice(
            serde_json::to_string(text)
                .map_err(|error| format!("serialize JCS string: {error}"))?
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_jcs(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut names = object.keys().collect::<Vec<_>>();
            names.sort_by(|left, right| compare_utf16(left, right));
            for (index, name) in names.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(name)
                        .map_err(|error| format!("serialize JCS member name: {error}"))?
                        .as_bytes(),
                );
                output.push(b':');
                write_jcs(&object[name], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub(crate) fn canonical_json(value: &Value) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    write_jcs(value, &mut output)?;
    Ok(output)
}

pub(crate) fn parse_canonical(bytes: &[u8], label: &str) -> Result<Value, String> {
    let value = parse_strict(bytes, label)?;
    if canonical_json(&value)? != bytes {
        return Err(format!("{label} is not the exact RFC 8785 representation"));
    }
    Ok(value)
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

fn semantic_digest(domain: &str, value: &Value) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(canonical_json(value)?);
    Ok(format!("sha256-{}", base64url(&hasher.finalize())))
}

pub(crate) fn semantic_digest_without(
    domain: &str,
    value: &Value,
    field: &str,
) -> Result<String, String> {
    let mut projected = value.clone();
    projected
        .as_object_mut()
        .ok_or_else(|| format!("{domain} projection is not an object"))?
        .remove(field);
    semantic_digest(domain, &projected)
}

#[cfg(test)]
fn raw_digest(bytes: &[u8]) -> String {
    format!("sha256-{:x}", Sha256::digest(bytes))
}

fn raw_digest_reader(mut reader: impl Read) -> Result<(String, u64), String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut size = 0u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("read selected file: {error}"))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| "selected file size overflow".to_owned())?;
        hasher.update(&buffer[..read]);
    }
    Ok((format!("sha256-{:x}", hasher.finalize()), size))
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} is not an object"))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = fields.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!("{label} has malformed exact fields"));
    }
    Ok(object)
}

fn text<'a>(value: &'a Value, label: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{label} is not a non-empty string"))
}

fn safe_integer(value: &Value, label: &str) -> Result<u64, String> {
    value
        .as_u64()
        .filter(|value| *value <= IJSON_MAX_SAFE_INTEGER)
        .ok_or_else(|| format!("{label} is not a non-negative I-JSON safe integer"))
}

fn boolean(value: &Value, label: &str) -> Result<bool, String> {
    value
        .as_bool()
        .ok_or_else(|| format!("{label} is not a boolean"))
}

fn is_hex(text: &str, width: usize) -> bool {
    text.len() == width
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn assert_raw_digest(value: &str, label: &str) -> Result<(), String> {
    if value
        .strip_prefix("sha256-")
        .is_some_and(|digest| is_hex(digest, 64))
    {
        Ok(())
    } else {
        Err(format!("{label} is not a lowercase raw SHA-256 digest"))
    }
}

fn assert_semantic_digest(value: &str, label: &str) -> Result<(), String> {
    let Some(digest) = value.strip_prefix("sha256-") else {
        return Err(format!("{label} is not a semantic SHA-256 digest"));
    };
    if digest.len() == 43
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        && matches!(
            digest.as_bytes()[42],
            b'A' | b'E'
                | b'I'
                | b'M'
                | b'Q'
                | b'U'
                | b'Y'
                | b'c'
                | b'g'
                | b'k'
                | b'o'
                | b's'
                | b'w'
                | b'0'
                | b'4'
                | b'8'
        )
    {
        Ok(())
    } else {
        Err(format!("{label} is not unpadded base64url SHA-256"))
    }
}

fn assert_stable_id(value: &str, label: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
    {
        return Err(format!("{label} is not a stable ID"));
    }
    Ok(())
}

fn assert_payload_path(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.is_ascii()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(format!(
            "{label} is not a supported normalized payload path"
        ));
    }
    Ok(())
}

fn assert_sorted_unique_text(values: &[Value], label: &str) -> Result<Vec<String>, String> {
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        output.push(text(value, label)?.to_owned());
    }
    if output
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(format!(
            "{label} is not strictly UTF-8-byte sorted and unique"
        ));
    }
    Ok(output)
}

#[cfg(unix)]
fn same_file_object(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_object(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len()
}

#[cfg(unix)]
fn assert_read_only(metadata: &Metadata, label: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o222 != 0 {
        Err(format!("{label} is writable"))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn assert_read_only(metadata: &Metadata, label: &str) -> Result<(), String> {
    if !metadata.permissions().readonly() {
        Err(format!("{label} is writable"))
    } else {
        Ok(())
    }
}

fn require_directory(path: &Path, label: &str, read_only: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} at {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is redirected or not a directory"));
    }
    if read_only {
        assert_read_only(&metadata, label)?;
    }
    Ok(())
}

fn exact_directory_members(path: &Path, expected: &[&str], label: &str) -> Result<(), String> {
    let mut actual = fs::read_dir(path)
        .map_err(|error| format!("read {label} at {}: {error}", path.display()))?
        .map(|entry| {
            entry
                .map_err(|error| format!("read {label} member: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| format!("{label} has a non-UTF-8 member"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let mut expected = expected
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    expected.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if actual != expected {
        return Err(format!("{label} does not have exact expected membership"));
    }
    Ok(())
}

fn require_parent_chain(payload_root: &Path, relative: &str) -> Result<(), String> {
    let mut current = payload_root.to_path_buf();
    let mut components = relative.split('/').peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        current.push(component);
        require_directory(&current, "selected payload ancestor", true)?;
    }
    Ok(())
}

fn read_regular(path: &Path, label: &str, maximum: u64) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} at {}: {error}", path.display()))?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(format!("{label} is redirected or not a regular file"));
    }
    assert_read_only(&before, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.nlink() != 1 {
            return Err(format!("{label} is hard-linked"));
        }
    }
    if before.len() > maximum {
        return Err(format!("{label} exceeds its byte limit"));
    }
    let mut file =
        File::open(path).map_err(|error| format!("open {label} at {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("inspect open {label}: {error}"))?;
    if !same_file_object(&before, &opened) {
        return Err(format!("{label} changed while it was opened"));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read {label}: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("reinspect open {label}: {error}"))?;
    if !same_file_object(&opened, &after) || bytes.len() as u64 != before.len() {
        return Err(format!("{label} changed while it was read"));
    }
    Ok(bytes)
}

fn digest_regular(path: &Path, label: &str, maximum: u64) -> Result<(String, u64), String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} at {}: {error}", path.display()))?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(format!("{label} is redirected or not a regular file"));
    }
    assert_read_only(&before, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.nlink() != 1 {
            return Err(format!("{label} is hard-linked"));
        }
    }
    if before.len() > maximum {
        return Err(format!("{label} exceeds its byte limit"));
    }
    let file =
        File::open(path).map_err(|error| format!("open {label} at {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("inspect open {label}: {error}"))?;
    if !same_file_object(&before, &opened) {
        return Err(format!("{label} changed while it was opened"));
    }
    let result = raw_digest_reader(BufReader::new(&file))?;
    let after = file
        .metadata()
        .map_err(|error| format!("reinspect open {label}: {error}"))?;
    if !same_file_object(&opened, &after) || result.1 != before.len() {
        return Err(format!("{label} changed while it was hashed"));
    }
    Ok(result)
}

fn selected_payload_file(
    payload_root: &Path,
    entry: &RegularEntry,
    label: &str,
) -> Result<PathBuf, String> {
    assert_payload_path(&entry.path, label)?;
    require_parent_chain(payload_root, &entry.path)?;
    let path = entry
        .path
        .split('/')
        .fold(payload_root.to_path_buf(), |path, component| {
            path.join(component)
        });
    let (digest, size) = digest_regular(&path, label, MAX_SELECTED_INPUT_BYTES)?;
    if digest != entry.digest || size != entry.size {
        return Err(format!("{label} bytes differ from the portable manifest"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let executable = fs::metadata(&path)
            .map_err(|error| format!("inspect selected {label} mode: {error}"))?
            .permissions()
            .mode()
            & 0o111
            != 0;
        if executable != entry.executable {
            return Err(format!(
                "{label} executable mode differs from the portable manifest"
            ));
        }
    }
    Ok(path)
}

fn validate_target(value: &Value, label: &str) -> Result<(), String> {
    let object = exact_object(value, &["structuralFeatures", "triple"], label)?;
    let triple = text(&object["triple"], &format!("{label}.triple"))?;
    if triple.split('-').count() < 3
        || !triple
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(format!("{label}.triple is malformed"));
    }
    let features = object["structuralFeatures"]
        .as_array()
        .ok_or_else(|| format!("{label}.structuralFeatures is not an array"))?;
    let features = assert_sorted_unique_text(features, &format!("{label}.structuralFeatures"))?;
    for feature in features {
        assert_stable_id(&feature, &format!("{label}.structuralFeatures"))?;
    }
    Ok(())
}

fn validate_profile(value: &Value, label: &str) -> Result<u64, String> {
    let object = exact_object(
        value,
        &[
            "configuration",
            "debugger",
            "hermesBytecodeVersion",
            "id",
            "reviewedProfileIdentityDigest",
            "targetVariant",
        ],
        label,
    )?;
    assert_stable_id(
        text(&object["id"], &format!("{label}.id"))?,
        &format!("{label}.id"),
    )?;
    assert_stable_id(
        text(&object["targetVariant"], &format!("{label}.targetVariant"))?,
        &format!("{label}.targetVariant"),
    )?;
    if !matches!(
        text(&object["configuration"], &format!("{label}.configuration"))?,
        "Debug" | "Release" | "RelWithDebInfo"
    ) {
        return Err(format!("{label}.configuration is not admitted"));
    }
    boolean(&object["debugger"], &format!("{label}.debugger"))?;
    assert_semantic_digest(
        text(
            &object["reviewedProfileIdentityDigest"],
            &format!("{label}.reviewedProfileIdentityDigest"),
        )?,
        &format!("{label}.reviewedProfileIdentityDigest"),
    )?;
    safe_integer(
        &object["hermesBytecodeVersion"],
        &format!("{label}.hermesBytecodeVersion"),
    )
}

fn validate_manifest(manifest: &Value, selected_artifact: &str) -> Result<ManifestFacts, String> {
    let object = exact_object(
        manifest,
        &[
            "artifactId",
            "artifactKind",
            "build",
            "entries",
            "interface",
            "profile",
            "runtimeComponent",
            "schema",
            "source",
            "target",
        ],
        "portable manifest",
    )?;
    if object["schema"] != MANIFEST_SCHEMA || object["artifactKind"] != "hermes" {
        return Err("portable manifest has the wrong schema or artifact kind".to_owned());
    }
    let artifact_id = text(&object["artifactId"], "portable manifest artifactId")?;
    assert_semantic_digest(artifact_id, "portable manifest artifactId")?;
    if artifact_id != selected_artifact
        || semantic_digest_without("ibex.portable-engine-manifest.v1", manifest, "artifactId")?
            != artifact_id
    {
        return Err(
            "portable manifest artifact ID does not match its canonical projection or selector"
                .to_owned(),
        );
    }
    validate_target(&object["target"], "portable manifest target")?;
    if object["target"]["triple"] != TARGET_TRIPLE {
        return Err("portable manifest names a different target triple".to_owned());
    }
    validate_profile(&object["profile"], "portable manifest profile")?;

    let source = exact_object(
        &object["source"],
        &[
            "artifact",
            "patchStackDigest",
            "sourceCommit",
            "sourceRef",
            "sourceVersion",
        ],
        "portable manifest source",
    )?;
    text(&source["artifact"], "portable manifest source artifact")?;
    text(&source["sourceRef"], "portable manifest source ref")?;
    text(&source["sourceVersion"], "portable manifest source version")?;
    if !is_hex(
        text(&source["sourceCommit"], "portable manifest source commit")?,
        40,
    ) {
        return Err("portable manifest source commit is not 40 lowercase hex".to_owned());
    }
    assert_raw_digest(
        text(
            &source["patchStackDigest"],
            "portable manifest patch digest",
        )?,
        "portable manifest patch digest",
    )?;

    let build = exact_object(
        &object["build"],
        &[
            "authorityDigests",
            "publisherWorkflow",
            "repository",
            "sourceRef",
            "sourceRevision",
            "sourceTreeDigest",
        ],
        "portable manifest build",
    )?;
    for field in ["repository", "publisherWorkflow", "sourceRef"] {
        text(&build[field], &format!("portable manifest build {field}"))?;
    }
    if !is_hex(
        text(&build["sourceRevision"], "portable manifest build revision")?,
        40,
    ) {
        return Err("portable manifest build revision is not 40 lowercase hex".to_owned());
    }
    assert_semantic_digest(
        text(
            &build["sourceTreeDigest"],
            "portable manifest source tree digest",
        )?,
        "portable manifest source tree digest",
    )?;
    let authorities = build["authorityDigests"]
        .as_array()
        .filter(|rows| !rows.is_empty())
        .ok_or_else(|| {
            "portable manifest build authorities are empty or not an array".to_owned()
        })?;
    let mut prior = None::<String>;
    for row in authorities {
        let row = exact_object(row, &["digest", "path"], "build authority row")?;
        let path = text(&row["path"], "build authority path")?.to_owned();
        assert_payload_path(&path, "build authority path")?;
        assert_raw_digest(
            text(&row["digest"], "build authority digest")?,
            "build authority digest",
        )?;
        if prior
            .as_ref()
            .is_some_and(|prior| prior.as_bytes() >= path.as_bytes())
        {
            return Err("portable manifest build authorities are not strictly sorted".to_owned());
        }
        prior = Some(path);
    }

    let interface = exact_object(
        &object["interface"],
        &[
            "abiContractDigest",
            "forbiddenExportsDigest",
            "headerSetDigest",
            "hostTools",
            "loadableComponents",
            "requiredExportsDigest",
        ],
        "portable manifest interface",
    )?;
    for field in [
        "abiContractDigest",
        "forbiddenExportsDigest",
        "headerSetDigest",
        "requiredExportsDigest",
    ] {
        assert_semantic_digest(
            text(
                &interface[field],
                &format!("portable manifest interface {field}"),
            )?,
            &format!("portable manifest interface {field}"),
        )?;
    }

    let entries = object["entries"]
        .as_array()
        .filter(|entries| !entries.is_empty())
        .ok_or_else(|| "portable manifest entries are empty or not an array".to_owned())?;
    let mut regular = BTreeMap::new();
    let mut directories = BTreeSet::new();
    let mut symlinks = BTreeMap::new();
    let mut prior_path = None::<String>;
    let mut apple_path_equivalence = HashSet::new();
    for entry in entries {
        let kind = text(
            entry
                .get("kind")
                .ok_or_else(|| "manifest entry has no kind".to_owned())?,
            "manifest entry kind",
        )?;
        let fields = match kind {
            "regular" => &["digest", "executable", "kind", "path", "role", "size"][..],
            "directory" => &["kind", "path", "role"][..],
            "symlink" => &["kind", "path", "role", "target"][..],
            _ => return Err(format!("manifest entry has unknown kind {kind}")),
        };
        let entry_object = exact_object(entry, fields, "portable manifest entry")?;
        let path = text(&entry_object["path"], "manifest entry path")?.to_owned();
        assert_payload_path(&path, "manifest entry path")?;
        if !apple_path_equivalence.insert(path.to_ascii_lowercase()) {
            return Err(
                "portable manifest contains an Apple filesystem-equivalent path collision"
                    .to_owned(),
            );
        }
        if prior_path
            .as_ref()
            .is_some_and(|prior| prior.as_bytes() >= path.as_bytes())
        {
            return Err(
                "portable manifest entries are not strictly path-sorted and unique".to_owned(),
            );
        }
        prior_path = Some(path.clone());
        let role = text(&entry_object["role"], "manifest entry role")?.to_owned();
        if !matches!(
            role.as_str(),
            "runtime"
                | "runtime-dependency"
                | "link-input"
                | "header"
                | "host-tool"
                | "compatibility-fixture"
                | "profile-receipt"
                | "metadata"
                | "framework-resource"
        ) {
            return Err(format!("manifest entry {path} has unknown role {role}"));
        }
        match kind {
            "regular" => {
                let digest = text(&entry_object["digest"], "manifest entry digest")?.to_owned();
                assert_raw_digest(&digest, "manifest entry digest")?;
                let size = safe_integer(&entry_object["size"], "manifest entry size")?;
                let executable = boolean(&entry_object["executable"], "manifest entry executable")?;
                regular.insert(
                    path.clone(),
                    RegularEntry {
                        role,
                        path,
                        digest,
                        size,
                        executable,
                    },
                );
            }
            "directory" => {
                directories.insert(path);
            }
            "symlink" => {
                let target = text(&entry_object["target"], "manifest symlink target")?;
                if target.starts_with('/')
                    || !target.is_ascii()
                    || target.contains('\\')
                    || target.contains(':')
                    || target.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
                    || target
                        .split('/')
                        .any(|segment| segment.is_empty() || segment == ".")
                {
                    return Err("portable manifest contains an unsafe symlink target".to_owned());
                }
                symlinks.insert(path, target.to_owned());
            }
            _ => unreachable!(),
        }
    }

    if text(&object["runtimeComponent"], "portable runtime component")? != RUNTIME_COMPONENT {
        return Err(
            "portable manifest does not name the admitted macOS framework runtime".to_owned(),
        );
    }
    let runtime = regular
        .get(RUNTIME_COMPONENT)
        .ok_or_else(|| "portable runtime component is absent or not regular".to_owned())?;
    if runtime.role != "runtime" || !runtime.executable {
        return Err("portable runtime component has the wrong role or executable mode".to_owned());
    }

    let host_tools = interface["hostTools"]
        .as_array()
        .ok_or_else(|| "portable manifest hostTools is not an array".to_owned())?;
    let mut prior_tool = None::<(String, String)>;
    for tool in host_tools {
        let tool = exact_object(
            tool,
            &["compatibilityDigest", "digest", "path", "role"],
            "portable host tool",
        )?;
        if tool["role"] != "host-tool" {
            return Err("portable host tool has the wrong role".to_owned());
        }
        let path = text(&tool["path"], "portable host tool path")?.to_owned();
        assert_payload_path(&path, "portable host tool path")?;
        let digest = text(&tool["digest"], "portable host tool digest")?;
        assert_raw_digest(digest, "portable host tool digest")?;
        let compatibility = text(
            &tool["compatibilityDigest"],
            "portable host tool compatibility",
        )?;
        assert_semantic_digest(compatibility, "portable host tool compatibility")?;
        let entry = regular
            .get(&path)
            .ok_or_else(|| format!("portable host tool {path} is not a regular manifest entry"))?;
        if entry.role != "host-tool" || entry.digest != digest || !entry.executable {
            return Err(format!(
                "portable host tool {path} does not join its manifest entry"
            ));
        }
        let key = ("host-tool".to_owned(), path);
        if prior_tool.as_ref().is_some_and(|prior| prior >= &key) {
            return Err("portable host tools are not strictly role/path sorted".to_owned());
        }
        prior_tool = Some(key);
    }

    let components = interface["loadableComponents"]
        .as_array()
        .filter(|components| !components.is_empty())
        .ok_or_else(|| {
            "portable manifest loadableComponents is empty or not an array".to_owned()
        })?;
    let mut runtime_count = 0usize;
    let mut prior_component = None::<(bool, String, String)>;
    for component in components {
        let system = component
            .get("system")
            .and_then(Value::as_bool)
            .ok_or_else(|| "portable loadable component has no boolean system field".to_owned())?;
        if system {
            let component =
                exact_object(component, &["name", "role", "system"], "system component")?;
            if component["role"] != "runtime-dependency" {
                return Err("system component has the wrong role".to_owned());
            }
            let name = text(&component["name"], "system dependency name")?.to_owned();
            let key = (true, "runtime-dependency".to_owned(), name);
            if prior_component.as_ref().is_some_and(|prior| prior >= &key) {
                return Err("portable loadable components are not strictly sorted".to_owned());
            }
            prior_component = Some(key);
        } else {
            let component = exact_object(
                component,
                &["digest", "path", "role", "system"],
                "payload component",
            )?;
            let role = text(&component["role"], "payload component role")?.to_owned();
            if !matches!(role.as_str(), "runtime" | "runtime-dependency") {
                return Err("payload component has the wrong role".to_owned());
            }
            let path = text(&component["path"], "payload component path")?.to_owned();
            assert_payload_path(&path, "payload component path")?;
            let digest = text(&component["digest"], "payload component digest")?;
            assert_raw_digest(digest, "payload component digest")?;
            let entry = regular.get(&path).ok_or_else(|| {
                format!("payload component {path} is not a regular manifest entry")
            })?;
            if entry.role != role || entry.digest != digest {
                return Err(format!(
                    "payload component {path} does not join its manifest entry"
                ));
            }
            if role == "runtime" {
                runtime_count += 1;
                if path != RUNTIME_COMPONENT {
                    return Err("portable interface names a different runtime component".to_owned());
                }
            }
            let key = (false, role, path);
            if prior_component.as_ref().is_some_and(|prior| prior >= &key) {
                return Err("portable loadable components are not strictly sorted".to_owned());
            }
            prior_component = Some(key);
        }
    }
    if runtime_count != 1 {
        return Err("portable interface must name exactly one non-system runtime".to_owned());
    }

    Ok(ManifestFacts {
        regular,
        directories,
        symlinks,
        profile: object["profile"].clone(),
        target: object["target"].clone(),
        interface: object["interface"].clone(),
        build: object["build"].clone(),
    })
}

fn validate_installed_symlinks(payload_root: &Path, facts: &ManifestFacts) -> Result<(), String> {
    for (relative, expected_target) in &facts.symlinks {
        require_parent_chain(payload_root, relative)?;
        let path = relative
            .split('/')
            .fold(payload_root.to_path_buf(), |path, component| {
                path.join(component)
            });
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "inspect portable payload symlink {}: {error}",
                path.display()
            )
        })?;
        if !metadata.file_type().is_symlink() {
            return Err(format!(
                "portable payload symlink {relative} is absent or has another kind"
            ));
        }
        let actual_target = fs::read_link(&path)
            .map_err(|error| format!("read portable payload symlink {relative}: {error}"))?;
        if actual_target != Path::new(expected_target) {
            return Err(format!(
                "portable payload symlink {relative} differs from the manifest"
            ));
        }
        let resolved = fs::canonicalize(&path)
            .map_err(|error| format!("resolve portable payload symlink {relative}: {error}"))?;
        if !resolved.starts_with(payload_root) {
            return Err(format!(
                "portable payload symlink {relative} resolves outside the payload"
            ));
        }
    }
    Ok(())
}

fn validate_framework_resolution(
    payload_root: &Path,
    facts: &ManifestFacts,
    runtime_path: &Path,
) -> Result<(), String> {
    for (path, target) in [
        ("lib/hermesvm.framework/Versions/Current", "1"),
        (
            "lib/hermesvm.framework/hermesvm",
            "Versions/Current/hermesvm",
        ),
    ] {
        if facts.symlinks.get(path).map(String::as_str) != Some(target) {
            return Err(format!(
                "portable framework linker path {path} is not the admitted compatibility symlink"
            ));
        }
    }
    let linker_path = payload_root.join("lib/hermesvm.framework/hermesvm");
    if fs::canonicalize(&linker_path)
        .map_err(|error| format!("resolve portable framework linker path: {error}"))?
        != runtime_path
    {
        return Err(
            "portable framework linker path does not resolve to the rehashed runtime component"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_policy(policy: &Value, facts: &ManifestFacts, receipt: &Value) -> Result<(), String> {
    let policy_object = policy
        .as_object()
        .ok_or_else(|| "checked portable trust policy is not an object".to_owned())?;
    if policy_object.get("schema")
        != Some(&Value::String(
            "ibex/portable-engine-provenance-trust-policy/1".to_owned(),
        ))
    {
        return Err("checked portable trust policy has the wrong schema".to_owned());
    }
    let publisher_value = policy_object
        .get("enginePublisher")
        .ok_or_else(|| "checked policy has no enginePublisher".to_owned())?;
    let publisher = if publisher_value.get("offlineVerifier").is_some() {
        let publisher = exact_object(
            publisher_value,
            &[
                "allowedTriggers",
                "buildType",
                "certificateIssuer",
                "enabled",
                "offlineVerifier",
                "provenanceRoot",
                "repository",
                "repositoryId",
                "repositoryOwnerId",
                "repositoryVisibility",
                "runnerClass",
                "sourceRef",
                "trustedRoot",
                "workflowName",
                "workflowPath",
            ],
            "checked finalized engine publisher",
        )?;
        let verifier = exact_object(
            &publisher["offlineVerifier"],
            &["binaryDigest", "binarySize", "goVersion", "targetTriple"],
            "checked offline verifier",
        )?;
        assert_raw_digest(
            text(&verifier["binaryDigest"], "offline verifier digest")?,
            "offline verifier digest",
        )?;
        safe_integer(&verifier["binarySize"], "offline verifier size")?;
        text(&verifier["goVersion"], "offline verifier Go version")?;
        if verifier["targetTriple"] != TARGET_TRIPLE {
            return Err("checked offline verifier has the wrong target".to_owned());
        }
        let trusted_root = exact_object(
            &publisher["trustedRoot"],
            &["profile", "sha256", "size"],
            "checked trusted root",
        )?;
        text(&trusted_root["profile"], "trusted-root profile")?;
        if !is_hex(text(&trusted_root["sha256"], "trusted-root digest")?, 64) {
            return Err("checked trusted-root digest is not lowercase SHA-256".to_owned());
        }
        safe_integer(&trusted_root["size"], "trusted-root size")?;
        publisher
    } else {
        exact_object(
            publisher_value,
            &[
                "enabled",
                "provenanceRoot",
                "repository",
                "runnerClass",
                "sourceRef",
                "workflowPath",
            ],
            "checked pre-verifier engine publisher",
        )?
    };
    if publisher["enabled"] != true {
        return Err("checked engine publisher is disabled".to_owned());
    }
    let build = facts.build.as_object().expect("validated build object");
    let receipt = receipt.as_object().expect("validated installation receipt");
    for (policy_field, build_field, receipt_field) in [
        ("repository", "repository", "repository"),
        ("workflowPath", "publisherWorkflow", "publisherWorkflow"),
        ("sourceRef", "sourceRef", "sourceRef"),
    ] {
        if publisher[policy_field] != build[build_field]
            || publisher[policy_field] != receipt[receipt_field]
        {
            return Err(format!(
                "portable publisher {policy_field} does not join manifest and receipt"
            ));
        }
    }
    if publisher["runnerClass"] != receipt["runnerClass"] {
        return Err(
            "portable publisher runner class does not join installation receipt".to_owned(),
        );
    }

    let admitted = policy_object
        .get("admittedTargets")
        .and_then(Value::as_array)
        .ok_or_else(|| "checked policy admittedTargets is not an array".to_owned())?;
    let matching = admitted
        .iter()
        .filter(|target| target.get("triple") == Some(&Value::String(TARGET_TRIPLE.to_owned())))
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err("checked policy does not contain one exact macOS arm64 target".to_owned());
    }
    let row = matching[0]
        .as_object()
        .ok_or_else(|| "checked admitted target is not an object".to_owned())?;
    let target = facts.target.as_object().expect("validated target object");
    if row.get("structuralFeatures") != target.get("structuralFeatures") {
        return Err(
            "portable manifest structural features differ from checked target policy".to_owned(),
        );
    }
    let profile = facts.profile.as_object().expect("validated profile object");
    let policy_profile = row
        .get("profile")
        .and_then(Value::as_object)
        .ok_or_else(|| "checked admitted target has no profile object".to_owned())?;
    for field in [
        "id",
        "targetVariant",
        "configuration",
        "debugger",
        "hermesBytecodeVersion",
    ] {
        if policy_profile.get(field) != profile.get(field) {
            return Err(format!(
                "portable manifest profile {field} differs from checked policy"
            ));
        }
    }
    Ok(())
}

fn validate_host_tool_contract(
    document: &Value,
    compatibility_digest: &str,
    tool: &Value,
    tool_entry: &RegularEntry,
    facts: &ManifestFacts,
    policy: &Value,
) -> Result<PortableHostToolContract, String> {
    let object = exact_object(
        document,
        &[
            "actualHostTriple",
            "argv0",
            "binaryMachine",
            "dependencyClosure",
            "environment",
            "environmentMode",
            "inputFixtures",
            "invocations",
            "maxOutputBytes",
            "maxStderrBytes",
            "maxStdoutBytes",
            "schema",
            "stdin",
            "timeoutMs",
            "toolDigest",
            "toolPath",
            "toolRole",
            "workingDirectoryLifetime",
        ],
        "portable host-tool compatibility authority",
    )?;
    if object["schema"] != "ibex/portable-engine-host-tool-compatibility/1"
        || object["toolRole"] != "bytecode-compiler"
        || object["toolPath"] != HERMESC_COMPONENT
        || object["toolPath"] != tool["path"]
        || object["toolDigest"] != tool["digest"]
        || object["toolDigest"] != tool_entry.digest
        || object["actualHostTriple"] != TARGET_TRIPLE
        || object["environmentMode"] != "replace-exactly"
        || object["stdin"] != "empty"
        || object["workingDirectoryLifetime"] != "fresh-private-per-invocation"
        || object["argv0"] != "exact-tool-path"
    {
        return Err(
            "portable host-tool compatibility authority does not bind the exact selected compiler and execution mode"
                .to_owned(),
        );
    }
    let machine = exact_object(
        &object["binaryMachine"],
        &["architecture", "format"],
        "portable host-tool binary machine",
    )?;
    if machine["format"] != "mach-o" || machine["architecture"] != "arm64" {
        return Err("portable host tool has the wrong binary machine".to_owned());
    }

    let policy_target = policy["admittedTargets"]
        .as_array()
        .ok_or_else(|| "checked policy admittedTargets is not an array".to_owned())?
        .iter()
        .find(|target| target["triple"] == TARGET_TRIPLE)
        .ok_or_else(|| "checked policy omits the portable host-tool target".to_owned())?;
    let policy_host = exact_object(
        &policy_target["hostTool"],
        &[
            "actualHostTriple",
            "binaryMachine",
            "dependencyExtractorFormat",
            "executionContract",
            "systemDependencyPolicyKey",
        ],
        "checked portable host-tool policy",
    )?;
    if policy_host["actualHostTriple"] != object["actualHostTriple"]
        || policy_host["binaryMachine"] != object["binaryMachine"]
    {
        return Err("portable host tool differs from the checked host policy".to_owned());
    }
    let execution = serde_json::json!({
        "environmentMode": object["environmentMode"].clone(),
        "environment": object["environment"].clone(),
        "stdin": object["stdin"].clone(),
        "workingDirectoryLifetime": object["workingDirectoryLifetime"].clone(),
        "argv0": object["argv0"].clone(),
        "timeoutMs": object["timeoutMs"].clone(),
        "maxStdoutBytes": object["maxStdoutBytes"].clone(),
        "maxStderrBytes": object["maxStderrBytes"].clone(),
        "maxOutputBytes": object["maxOutputBytes"].clone(),
    });
    if policy_host["executionContract"] != execution {
        return Err("portable host-tool execution contract differs from checked policy".to_owned());
    }
    let required_tools = policy_target["requiredHostTools"]
        .as_array()
        .ok_or_else(|| "checked policy requiredHostTools is not an array".to_owned())?;
    if required_tools.len() != 1
        || required_tools[0]["toolRole"] != "bytecode-compiler"
        || required_tools[0]["toolPath"] != HERMESC_COMPONENT
    {
        return Err("checked policy does not require the exact selected hermesc".to_owned());
    }

    let environment = object["environment"]
        .as_array()
        .ok_or_else(|| "portable host-tool environment is not an array".to_owned())?;
    let mut environment_rows = Vec::with_capacity(environment.len());
    let mut prior_name = None::<String>;
    for row in environment {
        let row = exact_object(row, &["name", "value"], "host-tool environment row")?;
        let name = text(&row["name"], "host-tool environment name")?.to_owned();
        if !name.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_uppercase()
            } else {
                byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
            }
        }) || prior_name
            .as_ref()
            .is_some_and(|prior| prior.as_bytes() >= name.as_bytes())
        {
            return Err(
                "portable host-tool environment is malformed, unsorted, or duplicated".to_owned(),
            );
        }
        let value = row["value"]
            .as_str()
            .ok_or_else(|| "host-tool environment value is not a string".to_owned())?;
        if value.chars().any(|character| character.is_control()) {
            return Err("portable host-tool environment contains a control character".to_owned());
        }
        prior_name = Some(name.clone());
        environment_rows.push((name, value.to_owned()));
    }
    let timeout_ms = safe_integer(&object["timeoutMs"], "host-tool timeout")?;
    if timeout_ms == 0 {
        return Err("portable host-tool timeout is not positive".to_owned());
    }
    let contract = PortableHostToolContract {
        compatibility_digest: compatibility_digest.to_owned(),
        environment: environment_rows,
        timeout_ms,
        max_stdout_bytes: safe_integer(&object["maxStdoutBytes"], "host-tool stdout bound")?,
        max_stderr_bytes: safe_integer(&object["maxStderrBytes"], "host-tool stderr bound")?,
        max_output_bytes: safe_integer(&object["maxOutputBytes"], "host-tool output bound")?,
    };
    if semantic_digest("ibex.portable-engine-host-tool-compatibility.v1", document)?
        != contract.compatibility_digest
        || facts.interface["hostTools"][0]["compatibilityDigest"] != contract.compatibility_digest
    {
        return Err(
            "portable host-tool compatibility digest does not bind the replayed execution contract"
                .to_owned(),
        );
    }
    Ok(contract)
}

fn validate_installation_receipt(
    receipt: &Value,
    artifact_id: &str,
    archive_digest: &str,
    manifest: &Value,
    policy_digest: &str,
    archive_actual: &(String, u64),
    bundle_actual: &(String, u64),
) -> Result<(), String> {
    let object = exact_object(
        receipt,
        &[
            "archiveDigest",
            "artifactId",
            "manifestDigest",
            "provenanceBundleDigest",
            "publisherWorkflow",
            "repository",
            "runnerClass",
            "schema",
            "sourceRef",
            "sourceRevision",
            "verificationPolicyDigest",
        ],
        "portable installation receipt",
    )?;
    if object["schema"] != INSTALLATION_RECEIPT_SCHEMA
        || object["artifactId"] != artifact_id
        || object["archiveDigest"] != archive_digest
        || object["archiveDigest"] != archive_actual.0
        || object["provenanceBundleDigest"] != bundle_actual.0
        || object["verificationPolicyDigest"] != policy_digest
        || object["manifestDigest"]
            != semantic_digest("ibex.portable-engine-manifest-digest.v1", manifest)?
        || object["runnerClass"] != "github-hosted"
    {
        return Err("portable installation receipt does not bind the selected manifest, policy, archive, bundle, and runner".to_owned());
    }
    assert_raw_digest(
        text(&object["archiveDigest"], "installation archive digest")?,
        "installation archive digest",
    )?;
    assert_raw_digest(
        text(
            &object["provenanceBundleDigest"],
            "installation bundle digest",
        )?,
        "installation bundle digest",
    )?;
    for field in ["manifestDigest", "verificationPolicyDigest"] {
        assert_semantic_digest(
            text(&object[field], &format!("installation receipt {field}"))?,
            &format!("installation receipt {field}"),
        )?;
    }
    if !is_hex(
        text(&object["sourceRevision"], "installation source revision")?,
        40,
    ) {
        return Err("installation receipt source revision is not 40 lowercase hex".to_owned());
    }
    let build = manifest["build"].as_object().expect("validated build");
    if object["sourceRevision"] != build["sourceRevision"] {
        return Err("installation receipt source revision differs from the manifest".to_owned());
    }
    Ok(())
}

fn validate_completion(
    bytes: &[u8],
    expected_schema: &str,
    expected: &[(&str, &str)],
    label: &str,
) -> Result<(), String> {
    let value = parse_canonical(bytes, label)?;
    let mut fields = vec!["schema"];
    fields.extend(expected.iter().map(|(field, _)| *field));
    let object = exact_object(&value, &fields, label)?;
    if object["schema"] != expected_schema {
        return Err(format!("{label} has the wrong schema"));
    }
    for (field, expected) in expected {
        if object[*field] != *expected {
            return Err(format!("{label} does not bind {field}"));
        }
    }
    Ok(())
}

fn validate_header_set(
    document: &Value,
    facts: &ManifestFacts,
    payload_root: &Path,
) -> Result<(Value, Vec<PathBuf>), String> {
    let object = exact_object(
        document,
        &["headers", "includeRoots", "schema", "targetTriple"],
        "portable header set",
    )?;
    if object["schema"] != HEADER_SET_SCHEMA || object["targetTriple"] != TARGET_TRIPLE {
        return Err("portable header set has the wrong schema or target".to_owned());
    }
    let roots = object["includeRoots"]
        .as_array()
        .ok_or_else(|| "portable header include roots are not an array".to_owned())?;
    let roots = assert_sorted_unique_text(roots, "portable header include roots")?;
    if roots != [INCLUDE_ROOT] {
        return Err("portable macOS build requires the exact include root `include`".to_owned());
    }
    if !facts.directories.contains(INCLUDE_ROOT) {
        return Err("portable header include root is not a declared directory".to_owned());
    }
    require_directory(
        &payload_root.join(INCLUDE_ROOT),
        "portable header include root",
        true,
    )?;

    let rows = object["headers"]
        .as_array()
        .filter(|rows| !rows.is_empty())
        .ok_or_else(|| "portable header set is empty or not an array".to_owned())?;
    let expected = facts
        .regular
        .values()
        .filter(|entry| entry.role == "header")
        .map(|entry| (entry.path.clone(), entry.digest.clone(), entry.size))
        .collect::<Vec<_>>();
    let mut actual = Vec::new();
    let mut paths = Vec::new();
    let mut prior = None::<String>;
    for row in rows {
        let row = exact_object(row, &["digest", "path", "size"], "portable header row")?;
        let path = text(&row["path"], "portable header path")?.to_owned();
        let digest = text(&row["digest"], "portable header digest")?.to_owned();
        let size = safe_integer(&row["size"], "portable header size")?;
        if prior
            .as_ref()
            .is_some_and(|prior| prior.as_bytes() >= path.as_bytes())
        {
            return Err("portable header rows are not strictly path-sorted and unique".to_owned());
        }
        prior = Some(path.clone());
        let entry = facts
            .regular
            .get(&path)
            .ok_or_else(|| format!("portable header {path} is not a regular manifest entry"))?;
        if entry.role != "header" || entry.digest != digest || entry.size != size {
            return Err(format!(
                "portable header {path} does not join its manifest entry"
            ));
        }
        paths.push(selected_payload_file(
            payload_root,
            entry,
            "portable header",
        )?);
        actual.push((path, digest, size));
    }
    if actual != expected {
        return Err("portable header set is not the complete regular header membership".to_owned());
    }
    Ok((document.clone(), paths))
}

fn validate_profile_receipt(
    bytes: &[u8],
    facts: &ManifestFacts,
    reviewed_profile: &Value,
    runtime: &RegularEntry,
    profile_entry: &RegularEntry,
) -> Result<(Value, u32), String> {
    let receipt = parse_canonical(bytes, "Hermes profile receipt")?;
    let object = exact_object(
        &receipt,
        &["artifact", "origin", "profileId", "schema", "targetVariant"],
        "Hermes profile receipt",
    )?;
    if object["schema"] != PROFILE_RECEIPT_SCHEMA {
        return Err("Hermes profile receipt has the wrong schema".to_owned());
    }
    let profile = facts.profile.as_object().expect("validated profile");
    if object["profileId"] != profile["id"] || object["targetVariant"] != profile["targetVariant"] {
        return Err("Hermes profile receipt names a different selected profile".to_owned());
    }
    let artifact = exact_object(
        &object["artifact"],
        &["binaryDigest", "fileName", "targetArchitecture"],
        "Hermes profile artifact",
    )?;
    if artifact["binaryDigest"] != runtime.digest
        || artifact["fileName"] != "hermesvm"
        || !matches!(
            text(
                &artifact["targetArchitecture"],
                "Hermes receipt architecture"
            )?,
            "aarch64" | "universal"
        )
    {
        return Err(
            "Hermes profile receipt does not bind the selected runtime bytes and architecture"
                .to_owned(),
        );
    }
    let origin = exact_object(
        &object["origin"],
        &["cacheKey", "kind", "reviewedProfileIdentity"],
        "Hermes profile origin",
    )?;
    let reviewed = exact_object(
        reviewed_profile,
        &[
            "originKind",
            "profileId",
            "receiptDigest",
            "receiptPath",
            "reviewedProfileIdentity",
            "schema",
            "targetTriple",
            "targetVariant",
        ],
        "portable reviewed-profile authority",
    )?;
    if reviewed["schema"] != "ibex/portable-engine-reviewed-profile-identity/1"
        || reviewed["profileId"] != object["profileId"]
        || reviewed["targetVariant"] != object["targetVariant"]
        || reviewed["targetTriple"] != TARGET_TRIPLE
        || reviewed["originKind"] != origin["kind"]
        || reviewed["receiptPath"] != profile_entry.path
        || reviewed["receiptDigest"] != profile_entry.digest
    {
        return Err(
            "portable reviewed-profile authority does not join the exact profile receipt"
                .to_owned(),
        );
    }
    if origin["kind"] != "source-patched-cache"
        || origin["reviewedProfileIdentity"] != reviewed["reviewedProfileIdentity"]
    {
        return Err(
            "Hermes profile receipt does not bind the reviewed profile authority".to_owned(),
        );
    }
    text(&origin["cacheKey"], "Hermes profile cache key")?;
    let reviewed_digest = semantic_digest(
        "ibex.portable-engine-reviewed-profile-identity.v1",
        reviewed_profile,
    )?;
    if profile["reviewedProfileIdentityDigest"] != reviewed_digest {
        return Err("Hermes reviewed profile identity digest differs from manifest".to_owned());
    }
    let version = safe_integer(&profile["hermesBytecodeVersion"], "Hermes bytecode version")?;
    let version =
        u32::try_from(version).map_err(|_| "Hermes bytecode version exceeds u32".to_owned())?;
    Ok((receipt, version))
}

fn build_consumption(
    manifest: &Value,
    receipt: &Value,
    policy_digest: &str,
    facts: &ManifestFacts,
    header_set: &Value,
    features: &[String],
) -> Result<Value, String> {
    let runtime = facts
        .regular
        .get(RUNTIME_COMPONENT)
        .expect("validated runtime");
    let profile = facts.profile.as_object().expect("validated profile");
    let interface = facts.interface.as_object().expect("validated interface");
    let identity_profile = serde_json::json!({
        "id": profile["id"].clone(),
        "targetVariant": profile["targetVariant"].clone(),
        "configuration": profile["configuration"].clone(),
        "debugger": profile["debugger"].clone(),
        "hermesBytecodeVersion": profile["hermesBytecodeVersion"].clone(),
    });
    let portable = serde_json::json!({
        "schema": PORTABLE_IDENTITY_SCHEMA,
        "artifactId": manifest["artifactId"].clone(),
        "artifactKind": "hermes",
        "target": facts.target.clone(),
        "profile": identity_profile,
        "runtimeComponentDigest": runtime.digest,
        "reviewedProfileIdentityDigest": profile["reviewedProfileIdentityDigest"].clone(),
        "interfaceContractDigest": semantic_digest("ibex.portable-engine-interface.v1", &facts.interface)?,
    });

    let header_rows = header_set["headers"].clone();
    let headers = serde_json::json!({
        "headerSetDigest": interface["headerSetDigest"].clone(),
        "includeRoots": header_set["includeRoots"].clone(),
        "files": header_rows,
    });
    let mut link_inputs = facts
        .regular
        .values()
        .filter(|entry| matches!(entry.role.as_str(), "runtime" | "link-input"))
        .map(|entry| {
            serde_json::json!({
                "role": entry.role,
                "path": entry.path,
                "digest": entry.digest,
                "size": entry.size,
            })
        })
        .collect::<Vec<_>>();
    link_inputs.sort_by(|left, right| {
        (left["role"].as_str(), left["path"].as_str())
            .cmp(&(right["role"].as_str(), right["path"].as_str()))
    });

    let mut host_tools = Vec::new();
    for tool in interface["hostTools"]
        .as_array()
        .expect("validated host tools")
    {
        let path = tool["path"].as_str().expect("validated host tool path");
        let entry = facts.regular.get(path).expect("validated host tool entry");
        host_tools.push(serde_json::json!({
            "role": "host-tool",
            "path": path,
            "digest": entry.digest,
            "size": entry.size,
            "compatibilityDigest": tool["compatibilityDigest"].clone(),
        }));
    }
    host_tools.sort_by(|left, right| {
        (left["role"].as_str(), left["path"].as_str())
            .cmp(&(right["role"].as_str(), right["path"].as_str()))
    });

    let mut dependencies = Vec::new();
    for component in interface["loadableComponents"]
        .as_array()
        .expect("validated components")
    {
        if component["system"] == false && component["role"] == "runtime-dependency" {
            let path = component["path"]
                .as_str()
                .expect("validated dependency path");
            let entry = facts.regular.get(path).expect("validated dependency entry");
            dependencies.push(serde_json::json!({
                "role": "runtime-dependency",
                "path": path,
                "digest": entry.digest,
                "size": entry.size,
            }));
        }
    }
    dependencies.sort_by(|left, right| {
        (left["role"].as_str(), left["path"].as_str())
            .cmp(&(right["role"].as_str(), right["path"].as_str()))
    });

    let mut record = serde_json::json!({
        "schema": BUILD_CONSUMPTION_SCHEMA,
        "portable": portable,
        "manifestDigest": semantic_digest("ibex.portable-engine-manifest-digest.v1", manifest)?,
        "installationReceiptDigest": semantic_digest("ibex.portable-engine-installation-receipt.v1", receipt)?,
        "verificationPolicyDigest": policy_digest,
        "target": facts.target.clone(),
        "ibexFeatures": features,
        "headers": headers,
        "runtimeComponent": {
            "path": runtime.path,
            "digest": runtime.digest,
            "size": runtime.size,
        },
        "linkInputs": link_inputs,
        "hostTools": host_tools,
        "nonSystemLoadableDependencies": dependencies,
        "consumptionDigest": "",
    });
    record["consumptionDigest"] = Value::String(semantic_digest_without(
        "ibex.portable-engine-build-consumption.v1",
        &record,
        "consumptionDigest",
    )?);
    Ok(record)
}

pub fn consume_portable_engine(
    request: &PortableEngineRequest,
) -> Result<PortableEngineSelection, String> {
    if request.target_os != "macos"
        || request.target_arch != "aarch64"
        || request.target_triple != TARGET_TRIPLE
    {
        return Err(format!(
            "portable Hermes v1 build consumption supports only macOS arm64/{TARGET_TRIPLE}; selected {}/{}/{}",
            request.target_os, request.target_arch, request.target_triple
        ));
    }
    assert_semantic_digest(&request.artifact_id, "selected portable artifact ID")?;
    assert_raw_digest(&request.archive_digest, "selected retained archive digest")?;
    if !request.present_legacy_overrides.is_empty() {
        let mut names = request.present_legacy_overrides.clone();
        names.sort();
        names.dedup();
        return Err(format!(
            "portable Hermes selection conflicts with legacy engine overrides: {}",
            names.join(", ")
        ));
    }
    let mut features = request.ibex_features.clone();
    for feature in &features {
        assert_stable_id(feature, "active Cargo feature")?;
    }
    let original = features.clone();
    features.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    features.dedup();
    if features != original {
        return Err(
            "active Cargo features are not strictly UTF-8-byte sorted and unique".to_owned(),
        );
    }

    require_directory(&request.repo_root, "checkout root", false)?;
    let repo_root = fs::canonicalize(&request.repo_root).map_err(|error| {
        format!(
            "canonicalize checkout root {}: {error}",
            request.repo_root.display()
        )
    })?;
    if repo_root != request.repo_root {
        return Err("checkout root is redirected".to_owned());
    }
    let target_root = repo_root.join("target");
    require_directory(&target_root, "checkout target directory", false)?;
    let expected_store = target_root.join("hermes-artifacts");
    // Check both lexical checkout-local components before canonicalization.
    // Otherwise `canonicalize` would erase a target/store symlink and make an
    // external store compare equal to its redirected spelling.
    // @ref LLP 0035#content-addressed-installation
    require_directory(&expected_store, "checkout-local portable store", false)?;
    let selected_store = request
        .store_root
        .as_ref()
        .map(|path| {
            if path.is_absolute() {
                path.clone()
            } else {
                repo_root.join(path)
            }
        })
        .unwrap_or_else(|| expected_store.clone());
    let selected_store = fs::canonicalize(&selected_store).map_err(|error| {
        format!(
            "canonicalize selected portable store {}: {error}",
            selected_store.display()
        )
    })?;
    let expected_store = fs::canonicalize(&expected_store).map_err(|error| {
        format!(
            "canonicalize checkout-local portable store {}: {error}",
            expected_store.display()
        )
    })?;
    if selected_store != expected_store {
        return Err(format!(
            "portable Hermes store must be checkout-local at {}; selected {}",
            expected_store.display(),
            selected_store.display()
        ));
    }
    require_directory(&selected_store, "checkout-local portable store", false)?;

    let cargo_out_dir = fs::canonicalize(&request.cargo_out_dir).map_err(|error| {
        format!(
            "canonicalize Cargo OUT_DIR {}: {error}",
            request.cargo_out_dir.display()
        )
    })?;
    require_directory(&cargo_out_dir, "Cargo OUT_DIR", false)?;
    let cargo_profile_dir = cargo_out_dir
        .ancestors()
        .nth(3)
        .ok_or_else(|| "Cargo OUT_DIR has no profile output ancestor".to_owned())?;
    let checkout_target_root = expected_store
        .parent()
        .expect("checkout-local store has a target parent");
    if cargo_out_dir.file_name().and_then(|name| name.to_str()) != Some("out")
        || cargo_out_dir
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some("build")
        || cargo_profile_dir.parent() != Some(checkout_target_root)
    {
        return Err(format!(
            "authoritative portable Cargo output must be directly under {}/<profile>; OUT_DIR resolved to {}",
            checkout_target_root.display(),
            cargo_out_dir.display()
        ));
    }

    let artifact_root = selected_store.join(&request.artifact_id);
    require_directory(&artifact_root, "selected portable artifact root", true)?;
    if fs::canonicalize(&artifact_root)
        .map_err(|error| format!("canonicalize selected artifact root: {error}"))?
        != artifact_root
    {
        return Err("selected portable artifact root is redirected".to_owned());
    }
    exact_directory_members(
        &artifact_root,
        &["LOCAL", "META-INF", "payload"],
        "selected portable artifact root",
    )?;
    let local_root = artifact_root.join("LOCAL");
    let metadata_root = artifact_root.join("META-INF");
    let payload_root = artifact_root.join("payload");
    for (path, label) in [
        (&local_root, "portable LOCAL directory"),
        (&metadata_root, "portable META-INF directory"),
        (&payload_root, "portable payload directory"),
    ] {
        require_directory(path, label, true)?;
    }
    exact_directory_members(
        &metadata_root,
        &["portable-engine-manifest.json"],
        "portable META-INF",
    )?;
    exact_directory_members(&local_root, &["COMPLETE", "transport"], "portable LOCAL")?;

    let manifest_path = metadata_root.join("portable-engine-manifest.json");
    let manifest_bytes = read_regular(&manifest_path, "portable manifest", MAX_JSON_BYTES)?;
    let manifest = parse_canonical(&manifest_bytes, "portable manifest")?;
    let facts = validate_manifest(&manifest, &request.artifact_id)?;
    validate_installed_symlinks(&payload_root, &facts)?;
    let manifest_digest = semantic_digest("ibex.portable-engine-manifest-digest.v1", &manifest)?;

    let store_completion_bytes = read_regular(
        &local_root.join("COMPLETE"),
        "portable store completion marker",
        64 * 1024,
    )?;
    validate_completion(
        &store_completion_bytes,
        STORE_COMPLETION_SCHEMA,
        &[
            ("artifactId", &request.artifact_id),
            ("manifestDigest", &manifest_digest),
        ],
        "portable store completion marker",
    )?;

    let transport_parent = local_root.join("transport");
    require_directory(&transport_parent, "portable transport directory", true)?;
    let transport_root = transport_parent.join(&request.archive_digest);
    require_directory(&transport_root, "selected portable transport", true)?;
    exact_directory_members(
        &transport_root,
        &[
            "COMPLETE",
            "archive.tar.gz",
            "attestation-verification.json",
            "installation-receipt.json",
            "provenance.sigstore.json",
        ],
        "selected portable transport",
    )?;
    // Require the retained verifier result to remain an immutable regular
    // store member, without claiming fresh post-link provenance verification.
    let verification_bytes = read_regular(
        &transport_root.join("attestation-verification.json"),
        "retained attestation verification result",
        MAX_JSON_BYTES,
    )?;
    let archive_actual = digest_regular(
        &transport_root.join("archive.tar.gz"),
        "retained portable archive",
        MAX_ARCHIVE_BYTES,
    )?;
    if archive_actual.0 != request.archive_digest {
        return Err("selected retained archive directory differs from its exact bytes".to_owned());
    }
    let bundle_actual = digest_regular(
        &transport_root.join("provenance.sigstore.json"),
        "retained provenance bundle",
        MAX_BUNDLE_BYTES,
    )?;
    let installation_receipt_bytes = read_regular(
        &transport_root.join("installation-receipt.json"),
        "portable installation receipt",
        MAX_JSON_BYTES,
    )?;
    let installation_receipt =
        parse_canonical(&installation_receipt_bytes, "portable installation receipt")?;

    let policy_bytes =
        fs::read(repo_root.join("schemas/portable-engine-provenance-trust-policy-v1.json"))
            .map_err(|error| format!("read checked portable trust policy: {error}"))?;
    let policy = parse_strict(&policy_bytes, "checked portable trust policy")?;
    let policy_digest =
        semantic_digest("ibex.portable-engine-provenance-trust-policy.v1", &policy)?;
    validate_installation_receipt(
        &installation_receipt,
        &request.artifact_id,
        &request.archive_digest,
        &manifest,
        &policy_digest,
        &archive_actual,
        &bundle_actual,
    )?;
    validate_policy(&policy, &facts, &installation_receipt)?;

    let receipt = installation_receipt.as_object().expect("validated receipt");
    let transport_completion_bytes = read_regular(
        &transport_root.join("COMPLETE"),
        "portable transport completion marker",
        64 * 1024,
    )?;
    validate_completion(
        &transport_completion_bytes,
        TRANSPORT_COMPLETION_SCHEMA,
        &[
            ("artifactId", &request.artifact_id),
            ("archiveDigest", &request.archive_digest),
            (
                "provenanceBundleDigest",
                receipt["provenanceBundleDigest"]
                    .as_str()
                    .expect("validated bundle digest"),
            ),
            ("verificationPolicyDigest", &policy_digest),
        ],
        "portable transport completion marker",
    )?;

    let header_document_entry = facts
        .regular
        .get(HEADER_SET_DOCUMENT)
        .ok_or_else(|| "portable manifest omits its header-set authority document".to_owned())?;
    if header_document_entry.role != "metadata" {
        return Err("portable header-set authority has the wrong role".to_owned());
    }
    let header_document_path = selected_payload_file(
        &payload_root,
        header_document_entry,
        "portable header-set authority",
    )?;
    let header_document_bytes = read_regular(
        &header_document_path,
        "portable header-set authority",
        MAX_JSON_BYTES,
    )?;
    let header_document = parse_canonical(&header_document_bytes, "portable header set")?;
    if semantic_digest("ibex.portable-engine-header-set.v1", &header_document)?
        != facts.interface["headerSetDigest"]
    {
        return Err("portable header-set authority digest differs from the manifest".to_owned());
    }
    let (header_set, _header_paths) = validate_header_set(&header_document, &facts, &payload_root)?;

    let runtime = facts
        .regular
        .get(RUNTIME_COMPONENT)
        .expect("validated runtime")
        .clone();
    let runtime_path =
        selected_payload_file(&payload_root, &runtime, "portable runtime component")?;
    validate_framework_resolution(&payload_root, &facts, &runtime_path)?;

    let link_entries = facts
        .regular
        .values()
        .filter(|entry| matches!(entry.role.as_str(), "runtime" | "link-input"))
        .cloned()
        .collect::<Vec<_>>();
    if link_entries.is_empty() {
        return Err("portable manifest has no link inputs".to_owned());
    }
    if link_entries.len() != 1 || link_entries[0].path != RUNTIME_COMPONENT {
        return Err(
            "portable macOS v1 supports exactly the framework runtime as its sole link input"
                .to_owned(),
        );
    }
    for entry in &link_entries {
        selected_payload_file(&payload_root, entry, "portable link input")?;
    }

    let host_tools = facts.interface["hostTools"]
        .as_array()
        .expect("validated host tools");
    if host_tools.len() != 1 || host_tools[0]["path"] != HERMESC_COMPONENT {
        return Err(
            "portable macOS v1 build requires exactly the declared bin/hermesc host tool"
                .to_owned(),
        );
    }
    let hermesc_entry = facts
        .regular
        .get(HERMESC_COMPONENT)
        .ok_or_else(|| "portable manifest omits bin/hermesc".to_owned())?;
    let hermesc_path = selected_payload_file(&payload_root, hermesc_entry, "portable hermesc")?;
    let mut selected_host_tool_contract = None;
    for tool in host_tools {
        let compatibility = text(
            &tool["compatibilityDigest"],
            "host-tool compatibility digest",
        )?;
        let document_path = format!("META-INF/authority/host-tools/{compatibility}.json");
        let document_entry = facts.regular.get(&document_path).ok_or_else(|| {
            format!("portable manifest omits host-tool compatibility authority {document_path}")
        })?;
        if document_entry.role != "metadata" {
            return Err("portable host-tool compatibility authority has the wrong role".to_owned());
        }
        let path = selected_payload_file(
            &payload_root,
            document_entry,
            "portable host-tool compatibility authority",
        )?;
        let bytes = read_regular(
            &path,
            "portable host-tool compatibility authority",
            MAX_JSON_BYTES,
        )?;
        let document = parse_canonical(&bytes, "portable host-tool compatibility authority")?;
        if semantic_digest("ibex.portable-engine-host-tool-compatibility.v1", &document)?
            != compatibility
        {
            return Err(
                "portable host-tool compatibility authority digest differs from manifest"
                    .to_owned(),
            );
        }
        selected_host_tool_contract = Some(validate_host_tool_contract(
            &document,
            compatibility,
            tool,
            hermesc_entry,
            &facts,
            &policy,
        )?);
    }
    let host_tool_contract = selected_host_tool_contract
        .ok_or_else(|| "portable build selected no host-tool execution contract".to_owned())?;

    for component in facts.interface["loadableComponents"]
        .as_array()
        .expect("validated components")
    {
        if component["system"] == false && component["role"] == "runtime-dependency" {
            let path = component["path"]
                .as_str()
                .expect("validated component path");
            selected_payload_file(
                &payload_root,
                facts.regular.get(path).expect("validated component entry"),
                "portable non-system loadable dependency",
            )?;
        }
    }

    let reviewed_entry = facts
        .regular
        .get(REVIEWED_PROFILE_DOCUMENT)
        .ok_or_else(|| "portable manifest omits reviewed-profile authority".to_owned())?;
    if reviewed_entry.role != "metadata" {
        return Err("portable reviewed-profile authority has the wrong role".to_owned());
    }
    let reviewed_path = selected_payload_file(
        &payload_root,
        reviewed_entry,
        "portable reviewed-profile authority",
    )?;
    let reviewed_bytes = read_regular(
        &reviewed_path,
        "portable reviewed-profile authority",
        MAX_JSON_BYTES,
    )?;
    let reviewed_profile = parse_canonical(&reviewed_bytes, "portable reviewed-profile authority")?;

    let profile_entries = facts
        .regular
        .values()
        .filter(|entry| entry.role == "profile-receipt")
        .collect::<Vec<_>>();
    if profile_entries.len() != 1 {
        return Err(
            "portable manifest must contain exactly one regular profile receipt".to_owned(),
        );
    }
    let profile_entry = profile_entries[0];
    let profile_receipt_path = selected_payload_file(
        &payload_root,
        profile_entry,
        "portable Hermes profile receipt",
    )?;
    let profile_receipt_bytes = read_regular(
        &profile_receipt_path,
        "portable Hermes profile receipt",
        MAX_JSON_BYTES,
    )?;
    let (_profile_receipt, hermes_bytecode_version) = validate_profile_receipt(
        &profile_receipt_bytes,
        &facts,
        &reviewed_profile,
        &runtime,
        profile_entry,
    )?;

    let build_consumption = build_consumption(
        &manifest,
        &installation_receipt,
        &policy_digest,
        &facts,
        &header_set,
        &features,
    )?;
    let build_consumption_bytes = canonical_json(&build_consumption)?;
    let installation_receipt_digest = semantic_digest(
        "ibex.portable-engine-installation-receipt.v1",
        &installation_receipt,
    )?;
    request.build_authorization.bind_consumed_authority(
        &manifest_digest,
        &installation_receipt_digest,
        &policy_digest,
        &format!("sha256-{:x}", Sha256::digest(&verification_bytes)),
        &bundle_actual.0,
    )?;

    let mut rerun_if_changed = vec![
        repo_root.join("schemas/portable-engine-provenance-trust-policy-v1.json"),
        manifest_path,
        local_root.join("COMPLETE"),
        transport_root.join("COMPLETE"),
        transport_root.join("archive.tar.gz"),
        transport_root.join("attestation-verification.json"),
        transport_root.join("installation-receipt.json"),
        transport_root.join("provenance.sigstore.json"),
        request.build_authorization.receipt_path.clone(),
        request.build_authorization.rustc_wrapper_path.clone(),
        request.build_authorization.cargo_target_map_path.clone(),
        request.build_authorization.promotion_admission_path.clone(),
    ];
    rerun_if_changed.extend(
        facts
            .regular
            .keys()
            .chain(facts.symlinks.keys())
            .map(|relative| payload_root.join(relative)),
    );
    rerun_if_changed.sort();
    rerun_if_changed.dedup();

    Ok(PortableEngineSelection {
        include_dir: payload_root.join(INCLUDE_ROOT),
        framework_search_dir: payload_root.join(FRAMEWORK_SEARCH_ROOT),
        framework_name: "hermesvm".to_owned(),
        rerun_if_changed,
        runtime_path,
        hermesc_path,
        host_tool_contract,
        profile_receipt_path,
        hermes_bytecode_version,
        manifest_bytes,
        installation_receipt_bytes,
        profile_receipt_bytes,
        build_consumption_bytes,
        promotion_admission_bytes: request
            .build_authorization
            .promotion_admission_bytes()
            .to_vec(),
    })
}

pub fn active_cargo_features(manifest_path: &Path) -> Result<Vec<String>, String> {
    let manifest = fs::read_to_string(manifest_path).map_err(|error| {
        format!(
            "read Cargo manifest for exact feature names at {}: {error}",
            manifest_path.display()
        )
    })?;
    let mut in_features = false;
    let mut declared_by_environment = BTreeMap::<String, String>::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_features = line == "[features]";
            continue;
        }
        if !in_features || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, _definition)) = line.split_once('=') else {
            return Err(format!("malformed Cargo feature declaration {line:?}"));
        };
        let name = name.trim();
        let name = if name.starts_with('"') {
            serde_json::from_str::<String>(name)
                .map_err(|error| format!("malformed quoted Cargo feature name {name:?}: {error}"))?
        } else if name.starts_with('\'') && name.ends_with('\'') && name.len() >= 2 {
            name[1..name.len() - 1].to_owned()
        } else {
            name.to_owned()
        };
        assert_stable_id(&name, "declared Cargo feature")?;
        let environment = format!(
            "CARGO_FEATURE_{}",
            name.to_ascii_uppercase().replace(['-', '.'], "_")
        );
        if let Some(other) = declared_by_environment.insert(environment.clone(), name.clone()) {
            return Err(format!(
                "Cargo features {other:?} and {name:?} collide at {environment}; exact build identity is ambiguous"
            ));
        }
    }
    if declared_by_environment.is_empty() {
        return Err("Cargo manifest has no [features] declarations".to_owned());
    }
    let mut features = Vec::new();
    for (environment, feature) in &declared_by_environment {
        match std::env::var(environment) {
            Ok(value) if value == "1" => features.push(feature.clone()),
            Ok(value) => {
                return Err(format!(
                    "Cargo feature environment {environment} has unexpected value {value:?}"
                ))
            }
            Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!(
                    "Cargo feature environment {environment} is not Unicode"
                ))
            }
        }
    }
    for (name, _) in std::env::vars_os() {
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with("CARGO_FEATURE_") && !declared_by_environment.contains_key(name) {
            return Err(format!(
                "active Cargo feature environment {name} has no exact declaration in {}",
                manifest_path.display()
            ));
        }
    }
    features.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(features)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    const ZERO_RAW: &str =
        "sha256-0000000000000000000000000000000000000000000000000000000000000000";
    const SOURCE_REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct Fixture {
        _temporary: TempDir,
        repo_root: PathBuf,
        request: PortableEngineRequest,
        header_path: PathBuf,
        runtime_path: PathBuf,
        tool_path: PathBuf,
        dependency_path: PathBuf,
        profile_path: PathBuf,
        archive_path: PathBuf,
        receipt_path: PathBuf,
        manifest_path: PathBuf,
        framework_link_path: PathBuf,
    }

    fn bytes(value: &Value) -> Vec<u8> {
        canonical_json(value).expect("canonical test JSON")
    }

    fn regular_entry(path: &str, role: &str, contents: &[u8], executable: bool) -> Value {
        json!({
            "kind": "regular",
            "role": role,
            "path": path,
            "digest": raw_digest(contents),
            "size": contents.len(),
            "executable": executable,
        })
    }

    fn directory_entry(path: &str, role: &str) -> Value {
        json!({ "kind": "directory", "role": role, "path": path })
    }

    fn write_payload(root: &Path, path: &str, contents: &[u8]) {
        let destination = path
            .split('/')
            .fold(root.to_path_buf(), |path, component| path.join(component));
        fs::create_dir_all(destination.parent().expect("payload parent")).unwrap();
        fs::write(destination, contents).unwrap();
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_mode(path: &Path, mode: u32) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(mode & 0o222 == 0);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn make_tree_read_only(path: &Path) {
        let metadata = fs::symlink_metadata(path).unwrap();
        if metadata.file_type().is_symlink() {
            return;
        }
        if metadata.is_dir() {
            let entries = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            for entry in entries {
                make_tree_read_only(&entry);
            }
            set_mode(path, 0o555);
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let executable = metadata.permissions().mode() & 0o111 != 0;
                set_mode(path, if executable { 0o555 } else { 0o444 });
            }
            #[cfg(not(unix))]
            set_mode(path, 0o444);
        }
    }

    fn replace_file(path: &Path, contents: &[u8]) {
        set_mode(path, 0o644);
        fs::write(path, contents).unwrap();
        set_mode(path, 0o444);
    }

    fn make_fixture() -> Fixture {
        let temporary = TempDir::new().unwrap();
        let repo_input = temporary.path().join("checkout");
        fs::create_dir_all(&repo_input).unwrap();
        // macOS spells the temporary root through `/var` while its physical
        // path is under `/private/var`. Production deliberately admits only a
        // canonical checkout selector, so the fixture must model that premise.
        let repo_root = fs::canonicalize(repo_input).unwrap();
        let schema_root = repo_root.join("schemas");
        let store_root = repo_root.join("target/hermes-artifacts");
        fs::create_dir_all(&schema_root).unwrap();
        fs::create_dir_all(&store_root).unwrap();
        fs::create_dir_all(repo_root.join("target/debug/build/ibex-fixture/out")).unwrap();
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/portable-engine-provenance-trust-policy-v1.json"),
            schema_root.join("portable-engine-provenance-trust-policy-v1.json"),
        )
        .unwrap();
        let policy_bytes =
            fs::read(schema_root.join("portable-engine-provenance-trust-policy-v1.json")).unwrap();
        let policy = parse_strict(&policy_bytes, "fixture policy").unwrap();
        let policy_digest =
            semantic_digest("ibex.portable-engine-provenance-trust-policy.v1", &policy).unwrap();
        let execution_contract = policy["admittedTargets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|target| target["triple"] == TARGET_TRIPLE)
            .unwrap()["hostTool"]["executionContract"]
            .clone();

        let header = b"#pragma once\nnamespace facebook { namespace jsi {} }\n".to_vec();
        let runtime = b"fixture-macho-hermes-runtime".to_vec();
        let tool = b"fixture-macho-hermesc".to_vec();
        let dependency = b"fixture-macho-runtime-dependency".to_vec();
        let reviewed_inner = json!({
            "artifact": "facebook/hermes",
            "patchApplicationAuthorityDigest": ZERO_RAW,
            "patchIdentityAuthorityDigest": ZERO_RAW,
            "patchStackDigest": ZERO_RAW,
            "sourceBuildAuthorityDigests": {
                "scripts/build-hermes-linux.sh": ZERO_RAW,
                "scripts/build-hermes.sh": ZERO_RAW,
            },
            "sourceCommit": SOURCE_REVISION,
            "sourceRef": "0.13.0-stable",
            "sourceVersion": "0.13.0",
        });
        let profile_receipt = json!({
            "schema": PROFILE_RECEIPT_SCHEMA,
            "profileId": "source-patched",
            "targetVariant": "default",
            "artifact": {
                "binaryDigest": raw_digest(&runtime),
                "fileName": "hermesvm",
                "targetArchitecture": "aarch64",
            },
            "origin": {
                "kind": "source-patched-cache",
                "cacheKey": "fixture-cache-key",
                "reviewedProfileIdentity": reviewed_inner,
            },
        });
        let profile_bytes = bytes(&profile_receipt);
        let reviewed_profile = json!({
            "schema": "ibex/portable-engine-reviewed-profile-identity/1",
            "profileId": "source-patched",
            "targetVariant": "default",
            "targetTriple": TARGET_TRIPLE,
            "originKind": "source-patched-cache",
            "receiptPath": "share/hermes/profile-provenance.json",
            "receiptDigest": raw_digest(&profile_bytes),
            "reviewedProfileIdentity": profile_receipt["origin"]["reviewedProfileIdentity"].clone(),
        });
        let reviewed_bytes = bytes(&reviewed_profile);
        let reviewed_digest = semantic_digest(
            "ibex.portable-engine-reviewed-profile-identity.v1",
            &reviewed_profile,
        )
        .unwrap();

        let header_set = json!({
            "schema": HEADER_SET_SCHEMA,
            "targetTriple": TARGET_TRIPLE,
            "includeRoots": [INCLUDE_ROOT],
            "headers": [{
                "path": "include/jsi/jsi.h",
                "digest": raw_digest(&header),
                "size": header.len(),
            }],
        });
        let header_set_bytes = bytes(&header_set);
        let header_set_digest =
            semantic_digest("ibex.portable-engine-header-set.v1", &header_set).unwrap();
        let compatibility = json!({
            "schema": "ibex/portable-engine-host-tool-compatibility/1",
            "toolRole": "bytecode-compiler",
            "toolPath": HERMESC_COMPONENT,
            "toolDigest": raw_digest(&tool),
            "actualHostTriple": TARGET_TRIPLE,
            "binaryMachine": { "format": "mach-o", "architecture": "arm64" },
            "environmentMode": execution_contract["environmentMode"].clone(),
            "environment": execution_contract["environment"].clone(),
            "stdin": execution_contract["stdin"].clone(),
            "workingDirectoryLifetime": execution_contract["workingDirectoryLifetime"].clone(),
            "argv0": execution_contract["argv0"].clone(),
            "timeoutMs": execution_contract["timeoutMs"].clone(),
            "maxStdoutBytes": execution_contract["maxStdoutBytes"].clone(),
            "maxStderrBytes": execution_contract["maxStderrBytes"].clone(),
            "maxOutputBytes": execution_contract["maxOutputBytes"].clone(),
            "dependencyClosure": {
                "extractor": { "format": "mach-o" },
                "systemDependencies": [],
            },
            "inputFixtures": [],
            "invocations": [],
        });
        let compatibility_bytes = bytes(&compatibility);
        let compatibility_digest = semantic_digest(
            "ibex.portable-engine-host-tool-compatibility.v1",
            &compatibility,
        )
        .unwrap();
        let compatibility_path =
            format!("META-INF/authority/host-tools/{compatibility_digest}.json");

        let mut entries = vec![
            directory_entry("META-INF", "metadata"),
            directory_entry("META-INF/authority", "metadata"),
            regular_entry(HEADER_SET_DOCUMENT, "metadata", &header_set_bytes, false),
            directory_entry("META-INF/authority/host-tools", "metadata"),
            regular_entry(&compatibility_path, "metadata", &compatibility_bytes, false),
            regular_entry(
                REVIEWED_PROFILE_DOCUMENT,
                "metadata",
                &reviewed_bytes,
                false,
            ),
            directory_entry("bin", "host-tool"),
            regular_entry(HERMESC_COMPONENT, "host-tool", &tool, true),
            directory_entry("include", "header"),
            directory_entry("include/jsi", "header"),
            regular_entry("include/jsi/jsi.h", "header", &header, false),
            directory_entry("lib", "runtime"),
            directory_entry("lib/hermesvm.framework", "framework-resource"),
            directory_entry("lib/hermesvm.framework/Versions", "framework-resource"),
            directory_entry("lib/hermesvm.framework/Versions/1", "framework-resource"),
            json!({
                "kind": "symlink",
                "role": "framework-resource",
                "path": "lib/hermesvm.framework/Versions/Current",
                "target": "1",
            }),
            regular_entry(RUNTIME_COMPONENT, "runtime", &runtime, true),
            json!({
                "kind": "symlink",
                "role": "framework-resource",
                "path": "lib/hermesvm.framework/hermesvm",
                "target": "Versions/Current/hermesvm",
            }),
            regular_entry(
                "lib/libfixture-dependency.dylib",
                "runtime-dependency",
                &dependency,
                true,
            ),
            directory_entry("share", "profile-receipt"),
            directory_entry("share/hermes", "profile-receipt"),
            regular_entry(
                "share/hermes/profile-provenance.json",
                "profile-receipt",
                &profile_bytes,
                false,
            ),
        ];
        entries.sort_by(|left, right| {
            left["path"]
                .as_str()
                .unwrap()
                .as_bytes()
                .cmp(right["path"].as_str().unwrap().as_bytes())
        });
        let target = json!({
            "triple": TARGET_TRIPLE,
            "structuralFeatures": ["dynamic-library", "framework"],
        });
        let profile = json!({
            "id": "source-patched",
            "targetVariant": "default",
            "configuration": "Release",
            "debugger": false,
            "hermesBytecodeVersion": 99,
            "reviewedProfileIdentityDigest": reviewed_digest,
        });
        let interface = json!({
            "abiContractDigest": semantic_digest("fixture.abi", &json!({"v": 1})).unwrap(),
            "requiredExportsDigest": semantic_digest("fixture.required", &json!({"v": 1})).unwrap(),
            "forbiddenExportsDigest": semantic_digest("fixture.forbidden", &json!({"v": 1})).unwrap(),
            "headerSetDigest": header_set_digest,
            "hostTools": [{
                "role": "host-tool",
                "path": HERMESC_COMPONENT,
                "digest": raw_digest(&tool),
                "compatibilityDigest": compatibility_digest,
            }],
            "loadableComponents": [
                {
                    "role": "runtime",
                    "path": RUNTIME_COMPONENT,
                    "digest": raw_digest(&runtime),
                    "system": false,
                },
                {
                    "role": "runtime-dependency",
                    "path": "lib/libfixture-dependency.dylib",
                    "digest": raw_digest(&dependency),
                    "system": false,
                },
                {
                    "role": "runtime-dependency",
                    "name": "/usr/lib/libSystem.B.dylib",
                    "system": true,
                },
            ],
        });
        let mut manifest = json!({
            "schema": MANIFEST_SCHEMA,
            "artifactId": "",
            "artifactKind": "hermes",
            "target": target,
            "profile": profile,
            "source": {
                "artifact": "facebook/hermes",
                "sourceCommit": SOURCE_REVISION,
                "sourceRef": "0.13.0-stable",
                "sourceVersion": "0.13.0",
                "patchStackDigest": ZERO_RAW,
            },
            "build": {
                "repository": "expo/ibex",
                "sourceRevision": SOURCE_REVISION,
                "sourceTreeDigest": semantic_digest("fixture.tree", &json!({"v": 1})).unwrap(),
                "sourceRef": "refs/heads/main",
                "publisherWorkflow": ".github/workflows/hermes-artifacts.yml",
                "authorityDigests": [{ "path": "fixture-authority", "digest": ZERO_RAW }],
            },
            "interface": interface,
            "entries": entries,
            "runtimeComponent": RUNTIME_COMPONENT,
        });
        manifest["artifactId"] = Value::String(
            semantic_digest_without("ibex.portable-engine-manifest.v1", &manifest, "artifactId")
                .unwrap(),
        );
        let artifact_id = manifest["artifactId"].as_str().unwrap().to_owned();
        let manifest_bytes = bytes(&manifest);
        let manifest_digest =
            semantic_digest("ibex.portable-engine-manifest-digest.v1", &manifest).unwrap();
        let archive = b"fixture-retained-archive".to_vec();
        let bundle = b"{\"fixture\":true}".to_vec();
        let archive_digest = raw_digest(&archive);
        let bundle_digest = raw_digest(&bundle);
        let receipt = json!({
            "schema": INSTALLATION_RECEIPT_SCHEMA,
            "artifactId": artifact_id,
            "manifestDigest": manifest_digest,
            "archiveDigest": archive_digest,
            "provenanceBundleDigest": bundle_digest,
            "verificationPolicyDigest": policy_digest,
            "repository": "expo/ibex",
            "publisherWorkflow": ".github/workflows/hermes-artifacts.yml",
            "sourceRef": "refs/heads/main",
            "sourceRevision": SOURCE_REVISION,
            "runnerClass": "github-hosted",
        });
        let receipt_bytes = bytes(&receipt);

        let artifact_root = store_root.join(&artifact_id);
        let payload_root = artifact_root.join("payload");
        fs::create_dir_all(artifact_root.join("META-INF")).unwrap();
        fs::create_dir_all(artifact_root.join("LOCAL/transport").join(&archive_digest)).unwrap();
        fs::create_dir_all(&payload_root).unwrap();
        fs::write(
            artifact_root.join("META-INF/portable-engine-manifest.json"),
            &manifest_bytes,
        )
        .unwrap();
        for (path, contents) in [
            (HEADER_SET_DOCUMENT, header_set_bytes.as_slice()),
            (&compatibility_path, compatibility_bytes.as_slice()),
            (REVIEWED_PROFILE_DOCUMENT, reviewed_bytes.as_slice()),
            (HERMESC_COMPONENT, tool.as_slice()),
            ("include/jsi/jsi.h", header.as_slice()),
            (RUNTIME_COMPONENT, runtime.as_slice()),
            ("lib/libfixture-dependency.dylib", dependency.as_slice()),
            (
                "share/hermes/profile-provenance.json",
                profile_bytes.as_slice(),
            ),
        ] {
            write_payload(&payload_root, path, contents);
        }
        for entry in manifest["entries"].as_array().unwrap() {
            if entry["kind"] == "regular" && entry["executable"] == true {
                let relative = entry["path"].as_str().unwrap();
                let path = relative
                    .split('/')
                    .fold(payload_root.clone(), |path, component| path.join(component));
                set_mode(&path, 0o755);
            }
        }
        for entry in manifest["entries"].as_array().unwrap() {
            if entry["kind"] == "directory" {
                let path = entry["path"].as_str().unwrap();
                fs::create_dir_all(
                    path.split('/')
                        .fold(payload_root.clone(), |path, component| path.join(component)),
                )
                .unwrap();
            }
        }
        {
            use std::os::unix::fs::symlink;
            symlink(
                "1",
                payload_root.join("lib/hermesvm.framework/Versions/Current"),
            )
            .unwrap();
            symlink(
                "Versions/Current/hermesvm",
                payload_root.join("lib/hermesvm.framework/hermesvm"),
            )
            .unwrap();
        }
        let store_completion = json!({
            "schema": STORE_COMPLETION_SCHEMA,
            "artifactId": artifact_id,
            "manifestDigest": manifest_digest,
        });
        fs::write(
            artifact_root.join("LOCAL/COMPLETE"),
            bytes(&store_completion),
        )
        .unwrap();
        let transport_root = artifact_root.join("LOCAL/transport").join(&archive_digest);
        fs::write(transport_root.join("archive.tar.gz"), &archive).unwrap();
        fs::write(transport_root.join("provenance.sigstore.json"), &bundle).unwrap();
        fs::write(transport_root.join("attestation-verification.json"), b"{}").unwrap();
        fs::write(
            transport_root.join("installation-receipt.json"),
            &receipt_bytes,
        )
        .unwrap();
        let transport_completion = json!({
            "schema": TRANSPORT_COMPLETION_SCHEMA,
            "artifactId": artifact_id,
            "archiveDigest": archive_digest,
            "provenanceBundleDigest": bundle_digest,
            "verificationPolicyDigest": policy_digest,
        });
        fs::write(
            transport_root.join("COMPLETE"),
            bytes(&transport_completion),
        )
        .unwrap();
        make_tree_read_only(&artifact_root);

        let request = PortableEngineRequest {
            repo_root: repo_root.clone(),
            cargo_out_dir: repo_root.join("target/debug/build/ibex-fixture/out"),
            store_root: None,
            artifact_id,
            archive_digest,
            target_os: "macos".to_owned(),
            target_arch: "aarch64".to_owned(),
            target_triple: TARGET_TRIPLE.to_owned(),
            ibex_features: vec!["cli-notify".to_owned(), "host-http-server".to_owned()],
            present_legacy_overrides: Vec::new(),
            build_authorization: PortableBuildAuthorization::unbound_test_only(),
        };
        Fixture {
            _temporary: temporary,
            repo_root,
            header_path: payload_root.join("include/jsi/jsi.h"),
            runtime_path: payload_root.join(RUNTIME_COMPONENT),
            tool_path: payload_root.join(HERMESC_COMPONENT),
            dependency_path: payload_root.join("lib/libfixture-dependency.dylib"),
            profile_path: payload_root.join("share/hermes/profile-provenance.json"),
            archive_path: transport_root.join("archive.tar.gz"),
            receipt_path: transport_root.join("installation-receipt.json"),
            manifest_path: artifact_root.join("META-INF/portable-engine-manifest.json"),
            framework_link_path: payload_root.join("lib/hermesvm.framework/hermesvm"),
            request,
        }
    }

    fn assert_refused(fixture: &Fixture, needle: &str) {
        let error = consume_portable_engine(&fixture.request).unwrap_err();
        assert!(
            error.contains(needle),
            "expected refusal containing {needle:?}, got {error:?}"
        );
    }

    fn coherently_rebind_manifest(fixture: &mut Fixture, mutate: impl FnOnce(&mut Value)) {
        let mut manifest = parse_canonical(
            &fs::read(&fixture.manifest_path).unwrap(),
            "fixture manifest",
        )
        .unwrap();
        mutate(&mut manifest);
        manifest["artifactId"] = Value::String(String::new());
        let artifact_id =
            semantic_digest_without("ibex.portable-engine-manifest.v1", &manifest, "artifactId")
                .unwrap();
        manifest["artifactId"] = Value::String(artifact_id.clone());
        let manifest_digest =
            semantic_digest("ibex.portable-engine-manifest-digest.v1", &manifest).unwrap();
        replace_file(&fixture.manifest_path, &bytes(&manifest));

        let mut receipt =
            parse_canonical(&fs::read(&fixture.receipt_path).unwrap(), "fixture receipt").unwrap();
        receipt["artifactId"] = Value::String(artifact_id.clone());
        receipt["manifestDigest"] = Value::String(manifest_digest.clone());
        replace_file(&fixture.receipt_path, &bytes(&receipt));

        let artifact_root = fixture
            .manifest_path
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let store_complete_path = artifact_root.join("LOCAL/COMPLETE");
        let mut store_complete = parse_canonical(
            &fs::read(&store_complete_path).unwrap(),
            "fixture store completion",
        )
        .unwrap();
        store_complete["artifactId"] = Value::String(artifact_id.clone());
        store_complete["manifestDigest"] = Value::String(manifest_digest);
        replace_file(&store_complete_path, &bytes(&store_complete));

        let transport_complete_path = fixture.receipt_path.parent().unwrap().join("COMPLETE");
        let mut transport_complete = parse_canonical(
            &fs::read(&transport_complete_path).unwrap(),
            "fixture transport completion",
        )
        .unwrap();
        transport_complete["artifactId"] = Value::String(artifact_id.clone());
        replace_file(&transport_complete_path, &bytes(&transport_complete));

        let rebound_root = artifact_root.parent().unwrap().join(&artifact_id);
        // The fixture models a finalized read-only store. macOS requires the
        // source directory itself to be writable while renaming it, so grant
        // only that temporary mutation and immediately restore finalization.
        set_mode(&artifact_root, 0o755);
        fs::rename(&artifact_root, &rebound_root).unwrap();
        make_tree_read_only(&rebound_root);
        fixture.request.artifact_id = artifact_id;
    }

    #[test]
    fn emits_canonical_complete_build_consumption_and_exact_paths() {
        let fixture = make_fixture();
        let selection = consume_portable_engine(&fixture.request).unwrap();
        assert_eq!(
            selection.include_dir,
            fs::canonicalize(&fixture.repo_root)
                .unwrap()
                .join("target/hermes-artifacts")
                .join(&fixture.request.artifact_id)
                .join("payload/include")
        );
        assert_eq!(
            selection.runtime_path,
            fs::canonicalize(&fixture.runtime_path).unwrap()
        );
        assert_eq!(
            selection.hermesc_path,
            fs::canonicalize(&fixture.tool_path).unwrap()
        );
        assert_eq!(
            selection.profile_receipt_path,
            fs::canonicalize(&fixture.profile_path).unwrap()
        );
        let (binary_linker_rpath, nested_linker_rpath) =
            portable_linker_rpaths(&fixture.request.artifact_id);
        assert_eq!(
            binary_linker_rpath,
            format!(
                "@loader_path/../hermes-artifacts/{}/payload/lib",
                fixture.request.artifact_id
            )
        );
        assert_eq!(
            nested_linker_rpath,
            format!(
                "@loader_path/../../hermes-artifacts/{}/payload/lib",
                fixture.request.artifact_id
            )
        );
        let checkout = fs::canonicalize(&fixture.repo_root)
            .unwrap()
            .display()
            .to_string();
        let store = fs::canonicalize(fixture.repo_root.join("target/hermes-artifacts"))
            .unwrap()
            .display()
            .to_string();
        for rpath in [&binary_linker_rpath, &nested_linker_rpath] {
            let linker_arg = format!("-Wl,-rpath,{rpath}");
            assert!(rpath.starts_with("@loader_path/"));
            assert!(!linker_arg.contains(&checkout));
            assert!(!linker_arg.contains(&store));
        }
        let build_evidence = std::str::from_utf8(&selection.build_consumption_bytes).unwrap();
        assert!(!build_evidence.contains(&checkout));
        assert!(!build_evidence.contains(&store));
        assert!(selection
            .rerun_if_changed
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        for path in [
            &fixture.header_path,
            &fixture.runtime_path,
            &fixture.tool_path,
            &fixture.dependency_path,
            &fixture.profile_path,
            &fixture.archive_path,
            &fixture.receipt_path,
            &fixture.manifest_path,
            &fixture.framework_link_path,
        ] {
            let watched_path = fs::canonicalize(&fixture.repo_root)
                .unwrap()
                .join(path.strip_prefix(&fixture.repo_root).unwrap());
            assert!(
                selection.rerun_if_changed.contains(&watched_path),
                "selected path is not watched by Cargo: {}",
                watched_path.display()
            );
        }
        let record = parse_canonical(
            &selection.build_consumption_bytes,
            "emitted build consumption",
        )
        .unwrap();
        exact_object(
            &record,
            &[
                "consumptionDigest",
                "headers",
                "hostTools",
                "ibexFeatures",
                "installationReceiptDigest",
                "linkInputs",
                "manifestDigest",
                "nonSystemLoadableDependencies",
                "portable",
                "runtimeComponent",
                "schema",
                "target",
                "verificationPolicyDigest",
            ],
            "emitted build consumption",
        )
        .unwrap();
        assert_eq!(record["schema"], BUILD_CONSUMPTION_SCHEMA);
        assert_eq!(
            record["ibexFeatures"],
            json!(["cli-notify", "host-http-server"])
        );
        assert_eq!(record["headers"]["files"].as_array().unwrap().len(), 1);
        assert_eq!(record["linkInputs"].as_array().unwrap().len(), 1);
        assert_eq!(record["hostTools"].as_array().unwrap().len(), 1);
        assert_eq!(
            record["hostTools"][0]["compatibilityDigest"],
            selection.host_tool_contract.compatibility_digest
        );
        assert_eq!(
            selection.host_tool_contract.environment,
            vec![
                ("LC_ALL".to_owned(), "C".to_owned()),
                ("TZ".to_owned(), "UTC".to_owned()),
            ]
        );
        assert_eq!(
            record["nonSystemLoadableDependencies"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            record["consumptionDigest"],
            semantic_digest_without(
                "ibex.portable-engine-build-consumption.v1",
                &record,
                "consumptionDigest",
            )
            .unwrap()
        );
        let out = fixture.repo_root.join("out");
        fs::create_dir(&out).unwrap();
        selection.write_embedded_outputs(&out).unwrap();
        assert_eq!(
            fs::read(out.join("portable_engine_build_consumption.json")).unwrap(),
            selection.build_consumption_bytes
        );
        assert_eq!(
            fs::read(out.join("portable_engine_promotion_admission.json")).unwrap(),
            selection.promotion_admission_bytes
        );
        assert!(selection.promotion_admission_bytes.ends_with(b"\n"));
        assert_ne!(selection.promotion_admission_bytes, b"null\n");
    }

    #[test]
    fn legacy_embedded_promotion_admission_is_exact_null_line() {
        let temporary = TempDir::new().unwrap();
        write_absent_embedded_outputs(temporary.path()).unwrap();
        assert_eq!(
            fs::read(
                temporary
                    .path()
                    .join("portable_engine_promotion_admission.json")
            )
            .unwrap(),
            b"null\n"
        );
    }

    #[test]
    fn refuses_target_feature_and_legacy_selector_confusion() {
        let mut fixture = make_fixture();
        fixture.request.target_triple = "x86_64-apple-darwin".to_owned();
        assert_refused(&fixture, "supports only macOS arm64");

        let mut fixture = make_fixture();
        coherently_rebind_manifest(&mut fixture, |manifest| {
            manifest["target"]["triple"] = Value::String("x86_64-apple-darwin".to_owned());
        });
        assert_refused(&fixture, "manifest names a different target triple");

        let mut fixture = make_fixture();
        fixture.request.ibex_features.reverse();
        assert_refused(&fixture, "features are not strictly");

        let mut fixture = make_fixture();
        fixture.request.present_legacy_overrides = vec!["HERMES_LIB_DIR".to_owned()];
        assert_refused(&fixture, "conflicts with legacy engine overrides");
    }

    #[test]
    fn accepts_only_the_closed_finalized_engine_publisher_shape() {
        let fixture = make_fixture();
        let manifest = parse_canonical(
            &fs::read(&fixture.manifest_path).unwrap(),
            "fixture manifest",
        )
        .unwrap();
        let facts = validate_manifest(&manifest, &fixture.request.artifact_id).unwrap();
        let receipt = parse_canonical(
            &fs::read(&fixture.receipt_path).unwrap(),
            "fixture installation receipt",
        )
        .unwrap();
        let policy_path = fixture
            .repo_root
            .join("schemas/portable-engine-provenance-trust-policy-v1.json");
        let mut policy = parse_strict(&fs::read(policy_path).unwrap(), "fixture policy").unwrap();
        policy["enginePublisher"] = json!({
            "allowedTriggers": ["push", "workflow_dispatch"],
            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            "certificateIssuer": "https://token.actions.githubusercontent.com",
            "enabled": true,
            "offlineVerifier": {
                "binaryDigest": ZERO_RAW,
                "binarySize": 1,
                "goVersion": "go1.26.5",
                "targetTriple": TARGET_TRIPLE,
            },
            "repository": "expo/ibex",
            "repositoryId": "1268046138",
            "repositoryOwnerId": "12504344",
            "repositoryVisibility": "public",
            "workflowPath": ".github/workflows/hermes-artifacts.yml",
            "workflowName": "Hermes artifact cache",
            "sourceRef": "refs/heads/main",
            "runnerClass": "github-hosted",
            "provenanceRoot": "github-oidc-artifact-attestations",
            "trustedRoot": {
                "profile": "sigstore-public-good-rekor-v1",
                "sha256": "0".repeat(64),
                "size": 1,
            },
        });
        validate_policy(&policy, &facts, &receipt).unwrap();

        policy["enginePublisher"]["unexpectedAuthority"] = Value::Bool(true);
        let error = validate_policy(&policy, &facts, &receipt).unwrap_err();
        assert!(error.contains("malformed exact fields"));
    }

    #[test]
    fn refuses_external_or_redirected_store_paths() {
        let mut fixture = make_fixture();
        let external = fixture.repo_root.join("external-store");
        fs::create_dir(&external).unwrap();
        fixture.request.store_root = Some(external);
        assert_refused(&fixture, "must be checkout-local");

        let mut fixture = make_fixture();
        let external_out = fixture
            .repo_root
            .join("external-target/debug/build/ibex-fixture/out");
        fs::create_dir_all(&external_out).unwrap();
        fixture.request.cargo_out_dir = external_out;
        assert_refused(&fixture, "Cargo output must be directly under");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let fixture = make_fixture();
            let target = fixture.repo_root.join("target");
            let external_target = fixture.repo_root.join("external-target-root");
            fs::rename(&target, &external_target).unwrap();
            symlink(&external_target, &target).unwrap();
            assert_refused(&fixture, "checkout target directory is redirected");

            let fixture = make_fixture();
            let store = fixture.repo_root.join("target/hermes-artifacts");
            let external_store = fixture.repo_root.join("external-store-root");
            fs::rename(&store, &external_store).unwrap();
            symlink(&external_store, &store).unwrap();
            assert_refused(&fixture, "checkout-local portable store is redirected");

            let fixture = make_fixture();
            let parent = fixture.header_path.parent().unwrap();
            set_mode(parent, 0o755);
            set_mode(&fixture.header_path, 0o644);
            fs::remove_file(&fixture.header_path).unwrap();
            let decoy = fixture.repo_root.join("decoy-header");
            fs::write(&decoy, b"fixture-jsi-header").unwrap();
            symlink(&decoy, &fixture.header_path).unwrap();
            set_mode(parent, 0o555);
            assert_refused(&fixture, "redirected or not a regular file");

            let fixture = make_fixture();
            let parent = fixture.framework_link_path.parent().unwrap();
            set_mode(parent, 0o755);
            fs::remove_file(&fixture.framework_link_path).unwrap();
            symlink("Versions/1/not-hermesvm", &fixture.framework_link_path).unwrap();
            set_mode(parent, 0o555);
            assert_refused(&fixture, "differs from the manifest");
        }
    }

    #[test]
    fn refuses_header_runtime_tool_dependency_and_profile_substitution() {
        let cases: &[(fn(&Fixture) -> PathBuf, &str)] = &[
            (
                |fixture: &Fixture| fixture.header_path.clone(),
                "portable header",
            ),
            (
                |fixture: &Fixture| fixture.runtime_path.clone(),
                "portable runtime component",
            ),
            (
                |fixture: &Fixture| fixture.tool_path.clone(),
                "portable hermesc",
            ),
            (
                |fixture: &Fixture| fixture.dependency_path.clone(),
                "portable non-system loadable dependency",
            ),
            (
                |fixture: &Fixture| fixture.profile_path.clone(),
                "portable Hermes profile receipt",
            ),
        ];
        for (select_path, label) in cases {
            let fixture = make_fixture();
            replace_file(&select_path(&fixture), b"same-name-substituted-bytes");
            assert_refused(&fixture, label);
        }
    }

    #[test]
    fn refuses_archive_manifest_and_installation_receipt_substitution() {
        let fixture = make_fixture();
        replace_file(&fixture.archive_path, b"different-retained-archive");
        assert_refused(&fixture, "selected retained archive directory differs");

        let fixture = make_fixture();
        let mut manifest = fs::read(&fixture.manifest_path).unwrap();
        manifest.push(b'\n');
        replace_file(&fixture.manifest_path, &manifest);
        assert_refused(&fixture, "not the exact RFC 8785 representation");

        let fixture = make_fixture();
        let receipt_bytes = fs::read(&fixture.receipt_path).unwrap();
        let mut receipt = parse_canonical(&receipt_bytes, "fixture receipt").unwrap();
        receipt["sourceRevision"] = Value::String("b".repeat(40));
        replace_file(&fixture.receipt_path, &bytes(&receipt));
        assert_refused(&fixture, "source revision differs");
    }
}
