//! Portable package identity and process-local mapped Hermes evidence.
//!
//! The portable half is reconstructed only from the canonical manifest,
//! installation receipt, and build-consumption bytes authenticated and emitted
//! by `build.rs`. The mapped half independently rejoins those bytes to the
//! kernel object containing `makeHermesRuntime` and to fresh no-follow file
//! observations.
//!
//! @ref LLP 0035#runtime-identity-split — portable equality excludes every
//! host-local value, while mapped identity is one process-local observation.
//! @ref LLP 0035#macos — the macOS proof joins PROC_PIDREGIONPATHINFO for the
//! Hermes factory address to the pinned manifest-selected runtime component.

#[cfg(target_os = "macos")]
use capsec_semantics::model::NonEmptyString;
use capsec_semantics::model::{Digest, ObjectIdentity, ObjectPlatform};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
#[cfg(target_os = "macos")]
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
#[cfg(target_os = "macos")]
use std::io::{Read as _, Seek as _};
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::sync::OnceLock;

const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;
const PORTABLE_MANIFEST_SCHEMA: &str = "ibex/portable-engine-manifest/1";
const PORTABLE_BUILD_SCHEMA: &str = "ibex/portable-engine-build-consumption/1";
const PORTABLE_RECEIPT_SCHEMA: &str = "ibex/portable-engine-installation-receipt/1";
const MANIFEST_ARTIFACT_ID_DOMAIN: &str = "ibex.portable-engine-manifest.v1";
const MANIFEST_DIGEST_DOMAIN: &str = "ibex.portable-engine-manifest-digest.v1";
const INTERFACE_DIGEST_DOMAIN: &str = "ibex.portable-engine-interface.v1";
const RECEIPT_DIGEST_DOMAIN: &str = "ibex.portable-engine-installation-receipt.v1";
const BUILD_CONSUMPTION_DIGEST_DOMAIN: &str = "ibex.portable-engine-build-consumption.v1";
const MAPPED_OBSERVATION_DIGEST_DOMAIN: &str = "ibex.mapped-engine-instance-identity.v1";

const MANIFEST_KEYS: &[&str] = &[
    "schema",
    "artifactId",
    "artifactKind",
    "target",
    "profile",
    "source",
    "build",
    "interface",
    "entries",
    "runtimeComponent",
];
const RECEIPT_KEYS: &[&str] = &[
    "schema",
    "artifactId",
    "manifestDigest",
    "archiveDigest",
    "provenanceBundleDigest",
    "verificationPolicyDigest",
    "repository",
    "publisherWorkflow",
    "sourceRef",
    "sourceRevision",
    "runnerClass",
];
const BUILD_KEYS: &[&str] = &[
    "schema",
    "portable",
    "manifestDigest",
    "installationReceiptDigest",
    "verificationPolicyDigest",
    "target",
    "ibexFeatures",
    "headers",
    "runtimeComponent",
    "linkInputs",
    "hostTools",
    "nonSystemLoadableDependencies",
    "consumptionDigest",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PortableEngineArtifactIdentitySchema {
    #[serde(rename = "ibex/portable-engine-artifact-identity/1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortableEngineArtifactKind {
    Hermes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableEngineTarget {
    pub triple: String,
    pub structural_features: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PortableEngineConfiguration {
    Debug,
    Release,
    RelWithDebInfo,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableEngineProfile {
    pub id: String,
    pub target_variant: String,
    pub configuration: PortableEngineConfiguration,
    pub debugger: bool,
    pub hermes_bytecode_version: u64,
}

/// Exact Rust wire type for
/// `schemas/portable-engine-artifact-identity-v1.schema.json`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortableEngineArtifactIdentity {
    pub schema: PortableEngineArtifactIdentitySchema,
    pub artifact_id: Digest,
    pub artifact_kind: PortableEngineArtifactKind,
    pub target: PortableEngineTarget,
    pub profile: PortableEngineProfile,
    pub runtime_component_digest: RawSha256Digest,
    pub reviewed_profile_identity_digest: Digest,
    pub interface_contract_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct RawSha256Digest(String);

impl RawSha256Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let encoded = value
            .strip_prefix("sha256-")
            .ok_or_else(|| format!("invalid raw SHA-256 digest {value:?}"))?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(format!("invalid raw SHA-256 digest {value:?}"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RawSha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct HexAddress(String);

impl HexAddress {
    pub fn from_u64(value: u64) -> Self {
        Self(format!("0x{value:x}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn value(&self) -> Result<u64, String> {
        let digits = self
            .0
            .strip_prefix("0x")
            .ok_or_else(|| format!("invalid hexadecimal address {:?}", self.0))?;
        u64::from_str_radix(digits, 16)
            .map_err(|_| format!("invalid hexadecimal address {:?}", self.0))
    }
}

impl<'de> Deserialize<'de> for HexAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let digits = value.strip_prefix("0x").ok_or_else(|| {
            serde::de::Error::custom(format!("invalid hexadecimal address {value:?}"))
        })?;
        if digits.is_empty()
            || !digits
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(serde::de::Error::custom(format!(
                "invalid hexadecimal address {value:?}"
            )));
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MappedEngineInstanceIdentitySchema {
    #[serde(rename = "ibex/mapped-engine-instance-identity/1")]
    V1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum MacOsMappingProofClass {
    #[serde(rename = "macos-proc-pid-region-path-info")]
    ProcPidRegionPathInfo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LinuxMappingProofClass {
    #[serde(rename = "linux-proc-self-maps")]
    ProcSelfMaps,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WindowsMappingProofClass {
    #[serde(rename = "windows-locked-module-closure")]
    LockedModuleClosure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MacOsPlatform {
    Macos,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinuxPlatform {
    Linux,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowsPlatform {
    Windows,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacOsPlatformMappingObservation {
    pub platform: MacOsPlatform,
    pub region_start: HexAddress,
    pub region_end: HexAddress,
    pub mapped_object: ObjectIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MacOsMappingProof {
    pub class: MacOsMappingProofClass,
    pub platform_observation: MacOsPlatformMappingObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxPlatformMappingObservation {
    pub platform: LinuxPlatform,
    pub mapping_start: HexAddress,
    pub mapping_end: HexAddress,
    pub permissions: String,
    pub file_offset: HexAddress,
    pub mapped_object: ObjectIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinuxMappingProof {
    pub class: LinuxMappingProofClass,
    pub platform_observation: LinuxPlatformMappingObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MappedModuleObservation {
    pub path: String,
    pub object: ObjectIdentity,
    pub digest: RawSha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsPlatformMappingObservation {
    pub platform: WindowsPlatform,
    pub runtime_module: MappedModuleObservation,
    pub dependencies: Vec<MappedModuleObservation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsMappingProof {
    pub class: WindowsMappingProofClass,
    pub platform_observation: WindowsPlatformMappingObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MappedEngineMappingProof {
    MacOs(MacOsMappingProof),
    Linux(LinuxMappingProof),
    Windows(WindowsMappingProof),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MappedEngineFileObservation {
    pub size: u64,
    pub digest: RawSha256Digest,
    pub object: ObjectIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProcessArchitecture {
    #[serde(rename = "aarch64")]
    Aarch64,
    #[serde(rename = "x86_64")]
    X86_64,
}

/// Exact Rust wire type for
/// `schemas/mapped-engine-instance-identity-v1.schema.json`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MappedEngineInstanceIdentity {
    pub schema: MappedEngineInstanceIdentitySchema,
    pub portable: PortableEngineArtifactIdentity,
    pub canonical_local_runtime_path: String,
    pub local_object: ObjectIdentity,
    pub mapping_proof: MappedEngineMappingProof,
    pub before: MappedEngineFileObservation,
    pub after: MappedEngineFileObservation,
    pub process_architecture: ProcessArchitecture,
    pub observation_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MappedEngineObservationPayload<'a> {
    schema: MappedEngineInstanceIdentitySchema,
    portable: &'a PortableEngineArtifactIdentity,
    canonical_local_runtime_path: &'a str,
    local_object: &'a ObjectIdentity,
    mapping_proof: &'a MappedEngineMappingProof,
    before: &'a MappedEngineFileObservation,
    after: &'a MappedEngineFileObservation,
    process_architecture: ProcessArchitecture,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmbeddedManifestProfile {
    id: String,
    target_variant: String,
    configuration: PortableEngineConfiguration,
    debugger: bool,
    hermes_bytecode_version: u64,
    reviewed_profile_identity_digest: Digest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuildRuntimeComponent {
    path: String,
    digest: RawSha256Digest,
    size: u64,
}

fn exact_object<'a>(
    value: &'a Value,
    expected: &[&str],
    label: &str,
) -> Result<&'a Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} is not an object"))?;
    let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
    actual.sort_unstable();
    let mut wanted = expected.to_vec();
    wanted.sort_unstable();
    if actual != wanted {
        return Err(format!(
            "{label} has fields {:?}, expected {:?}",
            actual, wanted
        ));
    }
    Ok(object)
}

fn object_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    label: &str,
) -> Result<&'a Value, String> {
    object
        .get(field)
        .ok_or_else(|| format!("{label} has no {field}"))
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    label: &str,
) -> Result<&'a str, String> {
    object_field(object, field, label)?
        .as_str()
        .ok_or_else(|| format!("{label}.{field} is not a string"))
}

fn parse_exact_canonical_object(bytes: &str, label: &str) -> Result<Value, String> {
    if bytes == "null\n" {
        return Err(format!("{label} is absent from this non-portable build"));
    }
    let value: Value = serde_json::from_str(bytes)
        .map_err(|error| format!("{label} is not strict JSON: {error}"))?;
    if !value.is_object() {
        return Err(format!("{label} is not a canonical object"));
    }
    let canonical = capsec_semantics::canonical::to_jcs(&value)
        .map_err(|error| format!("{label} is not I-JSON: {error}"))?;
    if canonical.as_bytes() != bytes.as_bytes() {
        return Err(format!("{label} bytes are not exact RFC 8785 JCS"));
    }
    Ok(value)
}

fn semantic_digest(domain: &str, value: &Value, omit: &[&str]) -> Result<Digest, String> {
    let omit = omit
        .iter()
        .map(|field| (*field).to_owned())
        .collect::<Vec<_>>();
    let digest = capsec_semantics::digest::compute_domain_digest(domain, value, &omit)
        .map_err(|error| format!("failed to compute {domain} digest: {error}"))?;
    Digest::new(digest)
}

fn valid_wire_string(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(|character| {
            character <= '\u{001f}' || ('\u{007f}'..='\u{009f}').contains(&character)
        })
}

fn valid_stable_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'))
        && bytes.all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'.'
                    | b'_'
                    | b'/'
                    | b'-'
            )
        })
}

fn valid_target_triple(value: &str) -> bool {
    let components = value.split('-').collect::<Vec<_>>();
    (3..=4).contains(&components.len())
        && components.iter().all(|component| {
            !component.is_empty()
                && component
                    .bytes()
                    .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
        })
}

fn validate_string_set(values: &[String], label: &str) -> Result<(), String> {
    for (index, value) in values.iter().enumerate() {
        if !valid_wire_string(value) {
            return Err(format!("{label}[{index}] is not a schema-valid string"));
        }
        if index > 0 && values[index - 1].as_bytes() >= value.as_bytes() {
            return Err(format!("{label} is not strictly UTF-8 sorted and unique"));
        }
    }
    Ok(())
}

impl PortableEngineArtifactIdentity {
    pub fn validate(&self) -> Result<(), String> {
        if !valid_target_triple(&self.target.triple) {
            return Err("portable engine target triple is malformed".into());
        }
        validate_string_set(
            &self.target.structural_features,
            "portable engine structuralFeatures",
        )?;
        if !valid_stable_id(&self.profile.id) || !valid_stable_id(&self.profile.target_variant) {
            return Err("portable engine profile identity is malformed".into());
        }
        if self.profile.hermes_bytecode_version > MAX_IJSON_INTEGER {
            return Err("portable engine bytecode version exceeds the I-JSON safe range".into());
        }
        Ok(())
    }
}

fn project_manifest_portable(manifest: &Value) -> Result<PortableEngineArtifactIdentity, String> {
    let root = exact_object(manifest, MANIFEST_KEYS, "embedded portable manifest")?;
    if string_field(root, "schema", "embedded portable manifest")? != PORTABLE_MANIFEST_SCHEMA {
        return Err("embedded portable manifest has the wrong schema".into());
    }
    let artifact_id = Digest::new(string_field(
        root,
        "artifactId",
        "embedded portable manifest",
    )?)?;
    let computed_artifact_id =
        semantic_digest(MANIFEST_ARTIFACT_ID_DOMAIN, manifest, &["artifactId"])?;
    if artifact_id != computed_artifact_id {
        return Err("embedded portable manifest artifactId is stale or substituted".into());
    }
    let artifact_kind: PortableEngineArtifactKind = serde_json::from_value(
        object_field(root, "artifactKind", "embedded portable manifest")?.clone(),
    )
    .map_err(|error| format!("embedded portable manifest artifactKind is invalid: {error}"))?;
    let target: PortableEngineTarget =
        serde_json::from_value(object_field(root, "target", "embedded portable manifest")?.clone())
            .map_err(|error| format!("embedded portable manifest target is invalid: {error}"))?;
    let manifest_profile: EmbeddedManifestProfile = serde_json::from_value(
        object_field(root, "profile", "embedded portable manifest")?.clone(),
    )
    .map_err(|error| format!("embedded portable manifest profile is invalid: {error}"))?;
    let interface = object_field(root, "interface", "embedded portable manifest")?;
    let interface_object = interface
        .as_object()
        .ok_or_else(|| "embedded portable manifest interface is not an object".to_owned())?;
    let loadable = interface_object
        .get("loadableComponents")
        .and_then(Value::as_array)
        .ok_or_else(|| "embedded portable manifest has no loadableComponents".to_owned())?;
    let mut runtime = None;
    for component in loadable {
        let Some(component_object) = component.as_object() else {
            return Err("embedded portable manifest loadable component is not an object".into());
        };
        if component_object.get("system").and_then(Value::as_bool) == Some(false)
            && component_object.get("role").and_then(Value::as_str) == Some("runtime")
        {
            if runtime.is_some() {
                return Err("embedded portable manifest repeats the runtime component".into());
            }
            exact_object(
                component,
                &["role", "path", "digest", "system"],
                "embedded portable runtime component",
            )?;
            let path = string_field(
                component_object,
                "path",
                "embedded portable runtime component",
            )?;
            let digest = RawSha256Digest::new(string_field(
                component_object,
                "digest",
                "embedded portable runtime component",
            )?)?;
            runtime = Some((path.to_owned(), digest));
        }
    }
    let (runtime_path, runtime_component_digest) = runtime
        .ok_or_else(|| "embedded portable manifest has no unique non-system runtime".to_owned())?;
    if string_field(root, "runtimeComponent", "embedded portable manifest")? != runtime_path {
        return Err("embedded portable manifest runtime component projection disagrees".into());
    }
    let identity = PortableEngineArtifactIdentity {
        schema: PortableEngineArtifactIdentitySchema::V1,
        artifact_id,
        artifact_kind,
        target,
        profile: PortableEngineProfile {
            id: manifest_profile.id,
            target_variant: manifest_profile.target_variant,
            configuration: manifest_profile.configuration,
            debugger: manifest_profile.debugger,
            hermes_bytecode_version: manifest_profile.hermes_bytecode_version,
        },
        runtime_component_digest,
        reviewed_profile_identity_digest: manifest_profile.reviewed_profile_identity_digest,
        interface_contract_digest: semantic_digest(INTERFACE_DIGEST_DOMAIN, interface, &[])?,
    };
    identity.validate()?;
    Ok(identity)
}

fn reconstruct_portable_identity_from_embedded(
    manifest_bytes: &str,
    receipt_bytes: &str,
    build_bytes: &str,
) -> Result<PortableEngineArtifactIdentity, String> {
    let manifest = parse_exact_canonical_object(manifest_bytes, "embedded portable manifest")?;
    let receipt =
        parse_exact_canonical_object(receipt_bytes, "embedded portable installation receipt")?;
    let build = parse_exact_canonical_object(build_bytes, "embedded portable build consumption")?;
    let manifest_root = exact_object(&manifest, MANIFEST_KEYS, "embedded portable manifest")?;
    let receipt_root = exact_object(
        &receipt,
        RECEIPT_KEYS,
        "embedded portable installation receipt",
    )?;
    let build_root = exact_object(&build, BUILD_KEYS, "embedded portable build consumption")?;
    if string_field(
        receipt_root,
        "schema",
        "embedded portable installation receipt",
    )? != PORTABLE_RECEIPT_SCHEMA
    {
        return Err("embedded portable installation receipt has the wrong schema".into());
    }
    if string_field(build_root, "schema", "embedded portable build consumption")?
        != PORTABLE_BUILD_SCHEMA
    {
        return Err("embedded portable build consumption has the wrong schema".into());
    }

    let projected = project_manifest_portable(&manifest)?;
    let carried: PortableEngineArtifactIdentity = serde_json::from_value(
        object_field(
            build_root,
            "portable",
            "embedded portable build consumption",
        )?
        .clone(),
    )
    .map_err(|error| format!("embedded build portable identity is malformed: {error}"))?;
    carried.validate()?;
    if carried != projected {
        return Err("embedded build portable identity is not the manifest projection".into());
    }

    let manifest_digest = semantic_digest(MANIFEST_DIGEST_DOMAIN, &manifest, &[])?;
    let receipt_manifest_digest = Digest::new(string_field(
        receipt_root,
        "manifestDigest",
        "embedded portable installation receipt",
    )?)?;
    let build_manifest_digest = Digest::new(string_field(
        build_root,
        "manifestDigest",
        "embedded portable build consumption",
    )?)?;
    if receipt_manifest_digest != manifest_digest || build_manifest_digest != manifest_digest {
        return Err("embedded portable manifest digest joins disagree".into());
    }
    if Digest::new(string_field(
        receipt_root,
        "artifactId",
        "embedded portable installation receipt",
    )?)? != projected.artifact_id
    {
        return Err("embedded portable receipt names another artifact".into());
    }

    let receipt_digest = semantic_digest(RECEIPT_DIGEST_DOMAIN, &receipt, &[])?;
    if Digest::new(string_field(
        build_root,
        "installationReceiptDigest",
        "embedded portable build consumption",
    )?)? != receipt_digest
    {
        return Err(
            "embedded portable installation receipt digest disagrees with build consumption".into(),
        );
    }
    let receipt_policy = Digest::new(string_field(
        receipt_root,
        "verificationPolicyDigest",
        "embedded portable installation receipt",
    )?)?;
    let build_policy = Digest::new(string_field(
        build_root,
        "verificationPolicyDigest",
        "embedded portable build consumption",
    )?)?;
    if receipt_policy != build_policy {
        return Err("embedded portable verification policy digests disagree".into());
    }
    let build_target: PortableEngineTarget = serde_json::from_value(
        object_field(build_root, "target", "embedded portable build consumption")?.clone(),
    )
    .map_err(|error| format!("embedded portable build target is malformed: {error}"))?;
    if build_target != projected.target {
        return Err("embedded portable build target differs from the manifest".into());
    }
    let build_runtime: BuildRuntimeComponent = serde_json::from_value(
        object_field(
            build_root,
            "runtimeComponent",
            "embedded portable build consumption",
        )?
        .clone(),
    )
    .map_err(|error| format!("embedded portable build runtime component is malformed: {error}"))?;
    if build_runtime.size > MAX_IJSON_INTEGER {
        return Err("embedded portable runtime size exceeds the I-JSON safe range".into());
    }
    if build_runtime.path
        != string_field(
            manifest_root,
            "runtimeComponent",
            "embedded portable manifest",
        )?
        || build_runtime.digest != projected.runtime_component_digest
    {
        return Err("embedded portable build runtime component differs from the manifest".into());
    }
    if semantic_digest(
        BUILD_CONSUMPTION_DIGEST_DOMAIN,
        &build,
        &["consumptionDigest"],
    )? != Digest::new(string_field(
        build_root,
        "consumptionDigest",
        "embedded portable build consumption",
    )?)? {
        return Err("embedded portable build consumption digest is stale".into());
    }
    Ok(projected)
}

fn embedded_portable_identity_result() -> &'static Result<PortableEngineArtifactIdentity, String> {
    static IDENTITY: OnceLock<Result<PortableEngineArtifactIdentity, String>> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        reconstruct_portable_identity_from_embedded(
            super::EMBEDDED_PORTABLE_ENGINE_MANIFEST,
            super::EMBEDDED_PORTABLE_ENGINE_INSTALLATION_RECEIPT,
            super::EMBEDDED_PORTABLE_ENGINE_BUILD_CONSUMPTION,
        )
    })
}

/// Reconstruct the portable engine identity from build-authenticated embedded
/// records. Ordinary/legacy builds return an error rather than manufacturing a
/// path- or environment-derived identity.
pub fn loaded_engine_portable_identity() -> Result<PortableEngineArtifactIdentity, String> {
    embedded_portable_identity_result()
        .as_ref()
        .cloned()
        .map_err(Clone::clone)
}

fn portable_marker_presence(markers: [&str; 3]) -> Result<bool, String> {
    let absent = markers.map(|marker| marker == "null\n");
    if absent.iter().all(|value| *value) {
        return Ok(false);
    }
    if absent.iter().any(|value| *value) {
        return Err(
            "portable engine build markers are mixed between absent and authenticated values"
                .into(),
        );
    }
    Ok(true)
}

/// Return the authenticated portable identity when this is a portable build.
///
/// The only compatibility case is the exact legacy marker triplet written by
/// `build.rs`. A mixed triplet is corruption, not a legacy build, and fails
/// closed. The strict [`loaded_engine_portable_identity`] API remains the
/// authority-bearing entry point for callers that require portable mode.
pub fn loaded_engine_portable_identity_if_present(
) -> Result<Option<PortableEngineArtifactIdentity>, String> {
    if !portable_marker_presence([
        super::EMBEDDED_PORTABLE_ENGINE_MANIFEST,
        super::EMBEDDED_PORTABLE_ENGINE_INSTALLATION_RECEIPT,
        super::EMBEDDED_PORTABLE_ENGINE_BUILD_CONSUMPTION,
    ])? {
        return Ok(None);
    }
    loaded_engine_portable_identity().map(Some)
}

impl MappedEngineInstanceIdentity {
    fn payload(&self) -> MappedEngineObservationPayload<'_> {
        MappedEngineObservationPayload {
            schema: self.schema,
            portable: &self.portable,
            canonical_local_runtime_path: &self.canonical_local_runtime_path,
            local_object: &self.local_object,
            mapping_proof: &self.mapping_proof,
            before: &self.before,
            after: &self.after,
            process_architecture: self.process_architecture,
        }
    }

    fn computed_observation_digest(&self) -> Result<Digest, String> {
        let payload = serde_json::to_value(self.payload())
            .map_err(|error| format!("failed to serialize mapped engine observation: {error}"))?;
        semantic_digest(MAPPED_OBSERVATION_DIGEST_DOMAIN, &payload, &[])
    }

    pub fn validate(&self) -> Result<(), String> {
        self.portable.validate()?;
        if !valid_wire_string(&self.canonical_local_runtime_path)
            || !Path::new(&self.canonical_local_runtime_path).is_absolute()
        {
            return Err("mapped engine runtime path is not one absolute canonical path".into());
        }
        validate_object_identity(&self.local_object, "mapped engine localObject")?;
        validate_file_observation(&self.before, "mapped engine before")?;
        validate_file_observation(&self.after, "mapped engine after")?;
        if self.before.object != self.local_object || self.after.object != self.local_object {
            return Err("mapped engine file observations name another local object".into());
        }
        if self.before.digest != self.portable.runtime_component_digest
            || self.after.digest != self.portable.runtime_component_digest
        {
            return Err("mapped engine file observations name other runtime bytes".into());
        }
        if self.before.size != self.after.size {
            return Err("mapped engine runtime size changed".into());
        }
        match &self.mapping_proof {
            MappedEngineMappingProof::MacOs(proof) => {
                if proof.platform_observation.mapped_object != self.local_object {
                    return Err("macOS mapping proof names another local object".into());
                }
                if proof.platform_observation.region_start.value()?
                    >= proof.platform_observation.region_end.value()?
                {
                    return Err("macOS mapping proof has an empty or reversed region".into());
                }
                if self.local_object.platform != ObjectPlatform::Apple {
                    return Err("macOS mapping proof does not use an Apple object identity".into());
                }
            }
            MappedEngineMappingProof::Linux(proof) => {
                if proof.platform_observation.mapped_object != self.local_object {
                    return Err("Linux mapping proof names another local object".into());
                }
                if proof.platform_observation.mapping_start.value()?
                    >= proof.platform_observation.mapping_end.value()?
                    || !valid_linux_permissions(&proof.platform_observation.permissions)
                {
                    return Err("Linux mapping proof has malformed region fields".into());
                }
            }
            MappedEngineMappingProof::Windows(proof) => {
                if proof.platform_observation.runtime_module.object != self.local_object
                    || proof.platform_observation.runtime_module.digest
                        != self.portable.runtime_component_digest
                {
                    return Err("Windows mapping proof names another runtime module".into());
                }
                let unique = proof
                    .platform_observation
                    .dependencies
                    .iter()
                    .map(|dependency| {
                        serde_json::to_value(dependency)
                            .ok()
                            .and_then(|value| capsec_semantics::canonical::to_jcs(&value).ok())
                    })
                    .collect::<Option<BTreeSet<_>>>()
                    .ok_or_else(|| "Windows dependency observation is not I-JSON".to_owned())?;
                if unique.len() != proof.platform_observation.dependencies.len() {
                    return Err("Windows mapping proof repeats a dependency".into());
                }
            }
        }
        let target_architecture = self
            .portable
            .target
            .triple
            .split('-')
            .next()
            .ok_or_else(|| "portable target has no architecture".to_owned())?;
        let process_architecture = match self.process_architecture {
            ProcessArchitecture::Aarch64 => "aarch64",
            ProcessArchitecture::X86_64 => "x86_64",
        };
        if process_architecture != target_architecture {
            return Err("mapped process architecture differs from the portable target".into());
        }
        if self.observation_digest != self.computed_observation_digest()? {
            return Err("mapped engine observationDigest is stale or substituted".into());
        }
        Ok(())
    }
}

fn validate_object_identity(object: &ObjectIdentity, label: &str) -> Result<(), String> {
    if !valid_wire_string(object.volume.as_str()) || !valid_wire_string(object.file.as_str()) {
        return Err(format!("{label} contains an invalid object coordinate"));
    }
    Ok(())
}

fn validate_file_observation(
    observation: &MappedEngineFileObservation,
    label: &str,
) -> Result<(), String> {
    if observation.size > MAX_IJSON_INTEGER {
        return Err(format!("{label}.size exceeds the I-JSON safe range"));
    }
    validate_object_identity(&observation.object, &format!("{label}.object"))
}

fn valid_linux_permissions(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 4
        && matches!(bytes[0], b'r' | b'-')
        && matches!(bytes[1], b'w' | b'-')
        && matches!(bytes[2], b'x' | b'-')
        && matches!(bytes[3], b'p' | b's')
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NativeMacOsFactoryMappingObservationV1 {
    struct_size: u32,
    observation_class: u32,
    region_start: u64,
    region_end: u64,
    device: u64,
    inode: u64,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn ibex_private_hermes_macos_mapping_observation_v1(
        output: *mut NativeMacOsFactoryMappingObservationV1,
    ) -> i32;
}

#[cfg(target_os = "macos")]
const NATIVE_MACOS_MAPPING_OBSERVATION_CLASS: u32 = 1;

#[cfg(target_os = "macos")]
fn object_identity_from_unix_coordinates(
    device: u64,
    inode: u64,
) -> Result<ObjectIdentity, String> {
    if inode == 0 {
        return Err("macOS mapping observation has a zero inode".into());
    }
    Ok(ObjectIdentity {
        platform: ObjectPlatform::Apple,
        volume: NonEmptyString::new(format!("dev:{device}"))?,
        file: NonEmptyString::new(format!("ino:{inode}"))?,
    })
}

#[cfg(target_os = "macos")]
fn capture_native_macos_mapping() -> Result<MacOsMappingProof, String> {
    let mut native = NativeMacOsFactoryMappingObservationV1 {
        struct_size: std::mem::size_of::<NativeMacOsFactoryMappingObservationV1>() as u32,
        ..NativeMacOsFactoryMappingObservationV1::default()
    };
    let status = unsafe { ibex_private_hermes_macos_mapping_observation_v1(&mut native) };
    if status != 1
        || native.struct_size as usize
            != std::mem::size_of::<NativeMacOsFactoryMappingObservationV1>()
        || native.observation_class != NATIVE_MACOS_MAPPING_OBSERVATION_CLASS
        || native.region_start >= native.region_end
    {
        return Err("failed to obtain the complete macOS Hermes factory mapping".into());
    }
    Ok(MacOsMappingProof {
        class: MacOsMappingProofClass::ProcPidRegionPathInfo,
        platform_observation: MacOsPlatformMappingObservation {
            platform: MacOsPlatform::Macos,
            region_start: HexAddress::from_u64(native.region_start),
            region_end: HexAddress::from_u64(native.region_end),
            mapped_object: object_identity_from_unix_coordinates(native.device, native.inode)?,
        },
    })
}

#[cfg(target_os = "macos")]
fn object_and_change_coordinates(
    file: &std::fs::File,
    metadata: &std::fs::Metadata,
) -> Result<(ObjectIdentity, MacOsChangeCoordinates), String> {
    use std::os::unix::fs::MetadataExt;
    let object = super::engine_object_identity(file, metadata)?;
    Ok((
        object,
        (
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ),
    ))
}

#[cfg(target_os = "macos")]
type MacOsChangeCoordinates = (i64, i64, i64, i64);

#[cfg(target_os = "macos")]
fn observe_pinned_file(
    file: &std::fs::File,
    expected_mapping_object: &ObjectIdentity,
    expected_change: Option<MacOsChangeCoordinates>,
) -> Result<(MappedEngineFileObservation, MacOsChangeCoordinates), String> {
    let before_metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect mapped Hermes runtime: {error}"))?;
    if !before_metadata.is_file() {
        return Err("mapped Hermes runtime is not a regular file".into());
    }
    if before_metadata.len() > MAX_IJSON_INTEGER {
        return Err("mapped Hermes runtime exceeds the I-JSON size range".into());
    }
    let (before_object, before_change) = object_and_change_coordinates(&file, &before_metadata)?;
    if &before_object != expected_mapping_object {
        return Err("loaded Hermes path names a different object than the factory mapping".into());
    }
    if expected_change.is_some_and(|expected| expected != before_change) {
        return Err(
            "pinned Hermes runtime change coordinates differ from the initial observation".into(),
        );
    }
    let mut reader = file;
    reader
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|error| format!("failed to rewind pinned Hermes runtime: {error}"))?;
    let mut hasher = Sha256::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|error| format!("failed to hash mapped Hermes runtime: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    let after_metadata = file
        .metadata()
        .map_err(|error| format!("failed to revalidate mapped Hermes runtime: {error}"))?;
    let (after_object, after_change) = object_and_change_coordinates(&file, &after_metadata)?;
    if after_object != before_object
        || after_metadata.len() != before_metadata.len()
        || after_change != before_change
    {
        return Err("mapped Hermes runtime changed while it was authenticated".into());
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(71);
    hex.push_str("sha256-");
    use std::fmt::Write as _;
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing SHA-256 hex to a String cannot fail");
    }
    Ok((
        MappedEngineFileObservation {
            size: before_metadata.len(),
            digest: RawSha256Digest::new(hex)?,
            object: before_object,
        },
        before_change,
    ))
}

#[cfg(target_os = "macos")]
fn open_pinned_file_observation(
    canonical_path: &Path,
    expected_mapping_object: &ObjectIdentity,
) -> Result<
    (
        std::fs::File,
        MappedEngineFileObservation,
        MacOsChangeCoordinates,
    ),
    String,
> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(canonical_path).map_err(|error| {
        format!(
            "failed to pin mapped Hermes runtime {}: {error}",
            canonical_path.display()
        )
    })?;
    let (observation, change) = observe_pinned_file(&file, expected_mapping_object, None)?;
    Ok((file, observation, change))
}

#[cfg(target_os = "macos")]
fn capture_file_observation(
    canonical_path: &Path,
    expected_mapping_object: &ObjectIdentity,
) -> Result<MappedEngineFileObservation, String> {
    let (_file, observation, _change) =
        open_pinned_file_observation(canonical_path, expected_mapping_object)?;
    Ok(observation)
}

#[cfg(target_os = "macos")]
struct MacOsMappedEngineExpectation {
    portable: PortableEngineArtifactIdentity,
    canonical_path: PathBuf,
    local_object: ObjectIdentity,
    mapping_proof: MacOsMappingProof,
    before: MappedEngineFileObservation,
    pinned_file: std::sync::Mutex<std::fs::File>,
    pinned_change: MacOsChangeCoordinates,
    process_architecture: ProcessArchitecture,
}

/// A non-serializable, process-local bracket around one engine-using phase.
///
/// Beginning the bracket pins the mapped object and its bytes. Finishing
/// consumes the bracket and obtains the fresh after-observation. Keeping the
/// owner coordinates private prevents conformance code from importing a
/// mapped observation produced in another process or thread as if it covered
/// the current engine work.
#[must_use = "mapped-engine observations must be finalized after engine work"]
pub struct LoadedEngineMappedObservation {
    owner_process_id: u32,
    owner_thread_id: std::thread::ThreadId,
    _thread_affinity: std::marker::PhantomData<std::rc::Rc<()>>,
    #[cfg(target_os = "macos")]
    expected: MacOsMappedEngineExpectation,
}

fn verify_observation_owner(
    owner_process_id: u32,
    owner_thread_id: std::thread::ThreadId,
) -> Result<(), String> {
    if owner_process_id != std::process::id() {
        return Err("mapped-engine observation belongs to another process".into());
    }
    if owner_thread_id != std::thread::current().id() {
        return Err("mapped-engine observation belongs to another thread".into());
    }
    Ok(())
}

impl LoadedEngineMappedObservation {
    /// Finalize the mapped identity after the bracketed engine work.
    #[cfg(target_os = "macos")]
    pub fn finish(self) -> Result<MappedEngineInstanceIdentity, String> {
        verify_observation_owner(self.owner_process_id, self.owner_thread_id)?;
        complete_macos_mapped_identity(&self.expected)
    }

    /// Portable mapped-engine production is deliberately macOS-only in this
    /// implementation slice.
    #[cfg(not(target_os = "macos"))]
    pub fn finish(self) -> Result<MappedEngineInstanceIdentity, String> {
        verify_observation_owner(self.owner_process_id, self.owner_thread_id)?;
        Err("portable mapped-engine identity is not implemented for this platform".into())
    }
}

#[cfg(target_os = "macos")]
fn current_process_architecture() -> Result<ProcessArchitecture, String> {
    match std::env::consts::ARCH {
        "aarch64" => Ok(ProcessArchitecture::Aarch64),
        "x86_64" => Ok(ProcessArchitecture::X86_64),
        other => Err(format!("unsupported macOS process architecture {other}")),
    }
}

#[cfg(target_os = "macos")]
fn capture_macos_expectation() -> Result<MacOsMappedEngineExpectation, String> {
    let portable = loaded_engine_portable_identity()?;
    let canonical_path = super::loaded_engine_binary_path()?;
    if std::fs::canonicalize(&canonical_path)
        .map_err(|error| format!("failed to canonicalize mapped Hermes runtime: {error}"))?
        != canonical_path
    {
        return Err("loaded Hermes runtime path is not canonical".into());
    }
    let mapping_before = capture_native_macos_mapping()?;
    let local_object = mapping_before.platform_observation.mapped_object.clone();
    let (pinned_file, before, pinned_change) =
        open_pinned_file_observation(&canonical_path, &local_object)?;
    let mapping_after = capture_native_macos_mapping()?;
    if mapping_after != mapping_before {
        return Err("Hermes factory mapping changed during the initial observation".into());
    }
    if before.digest != portable.runtime_component_digest {
        return Err("mapped Hermes runtime bytes differ from the portable artifact".into());
    }
    Ok(MacOsMappedEngineExpectation {
        portable,
        canonical_path,
        local_object,
        mapping_proof: mapping_before,
        before,
        pinned_file: std::sync::Mutex::new(pinned_file),
        pinned_change,
        process_architecture: current_process_architecture()?,
    })
}

/// Start one fresh mapped-engine observation interval in the current process
/// and thread. Unlike the compatibility accessor below, this does not reuse a
/// process-global before-observation.
#[cfg(target_os = "macos")]
pub fn begin_loaded_engine_mapped_observation() -> Result<LoadedEngineMappedObservation, String> {
    Ok(LoadedEngineMappedObservation {
        owner_process_id: std::process::id(),
        owner_thread_id: std::thread::current().id(),
        _thread_affinity: std::marker::PhantomData,
        expected: capture_macos_expectation()?,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn begin_loaded_engine_mapped_observation() -> Result<LoadedEngineMappedObservation, String> {
    Err("portable mapped-engine identity is not implemented for this platform".into())
}

#[cfg(target_os = "macos")]
fn expected_macos_mapped_engine() -> &'static Result<MacOsMappedEngineExpectation, String> {
    static EXPECTED: OnceLock<Result<MacOsMappedEngineExpectation, String>> = OnceLock::new();
    EXPECTED.get_or_init(capture_macos_expectation)
}

#[cfg(target_os = "macos")]
fn verify_unchanged_runtime_observation(
    before: &MappedEngineFileObservation,
    after: &MappedEngineFileObservation,
    portable: &PortableEngineArtifactIdentity,
) -> Result<(), String> {
    if before != after
        || before.digest != portable.runtime_component_digest
        || after.digest != portable.runtime_component_digest
    {
        return Err("mapped Hermes runtime differs from its initial file observation".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn complete_macos_mapped_identity(
    expected: &MacOsMappedEngineExpectation,
) -> Result<MappedEngineInstanceIdentity, String> {
    let mapping_before = capture_native_macos_mapping()?;
    let (after, after_change) = {
        let pinned_file = expected
            .pinned_file
            .lock()
            .map_err(|_| "pinned Hermes runtime lock is poisoned".to_owned())?;
        observe_pinned_file(
            &pinned_file,
            &expected.local_object,
            Some(expected.pinned_change),
        )?
    };
    if after_change != expected.pinned_change {
        return Err("pinned Hermes runtime changed across the mapped observation interval".into());
    }
    let path_after = capture_file_observation(&expected.canonical_path, &expected.local_object)?;
    if path_after != after {
        return Err("loaded Hermes path no longer names the retained mapped runtime object".into());
    }
    let mapping_after = capture_native_macos_mapping()?;
    if mapping_before != expected.mapping_proof || mapping_after != expected.mapping_proof {
        return Err("Hermes factory mapping differs from the initial observation".into());
    }
    verify_unchanged_runtime_observation(&expected.before, &after, &expected.portable)?;
    let path = expected
        .canonical_path
        .to_str()
        .ok_or_else(|| "mapped Hermes runtime path is not UTF-8".to_owned())?
        .to_owned();
    let mapping_proof = MappedEngineMappingProof::MacOs(expected.mapping_proof.clone());
    let mut identity = MappedEngineInstanceIdentity {
        schema: MappedEngineInstanceIdentitySchema::V1,
        portable: expected.portable.clone(),
        canonical_local_runtime_path: path,
        local_object: expected.local_object.clone(),
        mapping_proof,
        before: expected.before.clone(),
        after,
        process_architecture: expected.process_architecture,
        observation_digest: Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")?,
    };
    identity.observation_digest = identity.computed_observation_digest()?;
    identity.validate()?;
    Ok(identity)
}

/// Return one schema-exact macOS mapped-engine identity. The first call fixes
/// the pre-phase expectation; every call obtains fresh mapping and file
/// observations and refuses any drift before returning evidence.
#[cfg(target_os = "macos")]
pub fn loaded_engine_mapped_instance_identity() -> Result<MappedEngineInstanceIdentity, String> {
    expected_macos_mapped_engine()
        .as_ref()
        .map_err(Clone::clone)
        .and_then(complete_macos_mapped_identity)
}

/// The portable/mapped runtime producer is intentionally macOS-only in this
/// implementation slice. Other targets retain their existing legacy APIs.
#[cfg(not(target_os = "macos"))]
pub fn loaded_engine_mapped_instance_identity() -> Result<MappedEngineInstanceIdentity, String> {
    Err("portable mapped-engine identity is not implemented for this platform".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../schemas/vectors/portable-engine-provenance-v1.valid.json"
        ))
        .expect("portable provenance vectors are JSON")
    }

    fn canonical(value: &Value) -> String {
        capsec_semantics::canonical::to_jcs(value).expect("test value is I-JSON")
    }

    fn embedded_fixture() -> (Value, Value, Value) {
        let vectors = vectors();
        let documents = vectors["documents"].as_object().unwrap();
        (
            documents["manifest"].clone(),
            documents["installationReceipt"].clone(),
            documents["buildConsumption"].clone(),
        )
    }

    #[test]
    fn portable_identity_is_reconstructed_from_all_embedded_authorities() {
        let (manifest, receipt, build) = embedded_fixture();
        let identity = reconstruct_portable_identity_from_embedded(
            &canonical(&manifest),
            &canonical(&receipt),
            &canonical(&build),
        )
        .unwrap();
        let expected: PortableEngineArtifactIdentity =
            serde_json::from_value(build["portable"].clone()).unwrap();
        assert_eq!(identity, expected);
        identity.validate().unwrap();
        let serialized = serde_json::to_value(&identity).unwrap();
        assert_eq!(serialized, build["portable"]);
    }

    #[test]
    fn portable_substitution_fails_even_after_build_digest_recomputation() {
        let (manifest, receipt, mut build) = embedded_fixture();
        build["portable"]["profile"]["debugger"] = Value::Bool(true);
        let replacement = semantic_digest(
            BUILD_CONSUMPTION_DIGEST_DOMAIN,
            &build,
            &["consumptionDigest"],
        )
        .unwrap();
        build["consumptionDigest"] = Value::String(replacement.to_string());
        let error = reconstruct_portable_identity_from_embedded(
            &canonical(&manifest),
            &canonical(&receipt),
            &canonical(&build),
        )
        .unwrap_err();
        assert!(error.contains("not the manifest projection"), "{error}");
    }

    #[test]
    fn malformed_or_absent_embedded_identity_fails_closed() {
        let (manifest, receipt, mut build) = embedded_fixture();
        build["portable"]["unexpected"] = Value::Bool(true);
        let error = reconstruct_portable_identity_from_embedded(
            &canonical(&manifest),
            &canonical(&receipt),
            &canonical(&build),
        )
        .unwrap_err();
        assert!(error.contains("portable identity is malformed"), "{error}");

        let noncanonical = format!("{}\n", canonical(&manifest));
        let error = reconstruct_portable_identity_from_embedded(
            &noncanonical,
            &canonical(&receipt),
            &canonical(&embedded_fixture().2),
        )
        .unwrap_err();
        assert!(error.contains("not exact RFC 8785 JCS"), "{error}");

        let error =
            reconstruct_portable_identity_from_embedded("null\n", "null\n", "null\n").unwrap_err();
        assert!(
            error.contains("absent from this non-portable build"),
            "{error}"
        );
    }

    #[test]
    fn legacy_portable_markers_are_all_or_nothing() {
        assert!(!portable_marker_presence(["null\n", "null\n", "null\n"]).unwrap());
        assert!(portable_marker_presence(["{}", "{}", "{}"]).unwrap());
        for markers in [
            ["null\n", "{}", "{}"],
            ["{}", "null\n", "{}"],
            ["{}", "{}", "null\n"],
        ] {
            let error = portable_marker_presence(markers).unwrap_err();
            assert!(error.contains("mixed"), "{error}");
        }
    }

    #[test]
    fn mapped_observation_owner_rejects_wrong_process_or_thread() {
        let current_process = std::process::id();
        let current_thread = std::thread::current().id();
        assert!(verify_observation_owner(current_process, current_thread).is_ok());
        let other_process = current_process.checked_add(1).unwrap_or(1);
        let error = verify_observation_owner(other_process, current_thread).unwrap_err();
        assert!(error.contains("another process"), "{error}");

        let other_thread = std::thread::spawn(|| std::thread::current().id())
            .join()
            .unwrap();
        let error = verify_observation_owner(current_process, other_thread).unwrap_err();
        assert!(error.contains("another thread"), "{error}");
    }

    #[test]
    fn mapped_identity_type_and_domain_digest_match_the_frozen_vector() {
        let vectors = vectors();
        let value = vectors["documents"]["mappedInstance"].clone();
        let identity: MappedEngineInstanceIdentity = serde_json::from_value(value.clone()).unwrap();
        identity.validate().unwrap();
        assert_eq!(serde_json::to_value(&identity).unwrap(), value);
        assert_eq!(
            identity.observation_digest.as_str(),
            "sha256-ozMLTYAK44JvGybxPiO_Rfc-QnGYIB550-tsAh8-Sb0"
        );
        assert_eq!(
            identity.computed_observation_digest().unwrap(),
            identity.observation_digest
        );
    }

    #[test]
    fn aslr_local_mapping_changes_do_not_change_portable_identity() {
        let value = vectors()["documents"]["mappedInstance"].clone();
        let first: MappedEngineInstanceIdentity = serde_json::from_value(value.clone()).unwrap();
        let mut second_value = value;
        second_value["mappingProof"]["platformObservation"]["regionStart"] =
            Value::String("0x700000000".into());
        second_value["mappingProof"]["platformObservation"]["regionEnd"] =
            Value::String("0x700100000".into());
        let mut second: MappedEngineInstanceIdentity =
            serde_json::from_value(second_value).unwrap();
        second.observation_digest = second.computed_observation_digest().unwrap();

        first.validate().unwrap();
        second.validate().unwrap();
        assert_eq!(first.portable, second.portable);
        assert_ne!(first.mapping_proof, second.mapping_proof);
        assert_ne!(first.observation_digest, second.observation_digest);
    }

    #[cfg(target_os = "macos")]
    fn object_for_file(path: &Path) -> ObjectIdentity {
        let file = std::fs::File::open(path).unwrap();
        let metadata = file.metadata().unwrap();
        object_and_change_coordinates(&file, &metadata).unwrap().0
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn mapped_path_must_name_the_factory_mapping_object() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = directory.path().join("hermesvm");
        std::fs::write(&runtime, b"mapped-runtime").unwrap();
        let runtime = std::fs::canonicalize(runtime).unwrap();
        let actual = object_for_file(&runtime);
        let substituted = ObjectIdentity {
            platform: ObjectPlatform::Apple,
            volume: actual.volume.clone(),
            file: NonEmptyString::new("ino:substituted").unwrap(),
        };
        let error = capture_file_observation(&runtime, &substituted).unwrap_err();
        assert!(
            error.contains("different object than the factory mapping"),
            "{error}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn file_mutation_invalidates_the_initial_mapped_observation() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = directory.path().join("hermesvm");
        std::fs::write(&runtime, b"before-runtime").unwrap();
        let runtime = std::fs::canonicalize(runtime).unwrap();
        let object = object_for_file(&runtime);
        let before = capture_file_observation(&runtime, &object).unwrap();
        std::fs::write(&runtime, b"after--runtime").unwrap();
        let after = capture_file_observation(&runtime, &object).unwrap();
        assert_eq!(before.object, after.object);
        assert_eq!(before.size, after.size);
        assert_ne!(before.digest, after.digest);

        let (manifest, receipt, build) = embedded_fixture();
        let mut portable = reconstruct_portable_identity_from_embedded(
            &canonical(&manifest),
            &canonical(&receipt),
            &canonical(&build),
        )
        .unwrap();
        portable.runtime_component_digest = before.digest.clone();
        assert!(verify_unchanged_runtime_observation(&before, &after, &portable).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn retained_descriptor_rejects_ancestor_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let original_parent = directory.path().join("original");
        let moved_parent = directory.path().join("moved");
        std::fs::create_dir(&original_parent).unwrap();
        let runtime = original_parent.join("hermesvm");
        std::fs::write(&runtime, b"mapped-runtime").unwrap();
        let runtime = std::fs::canonicalize(runtime).unwrap();
        let object = object_for_file(&runtime);
        let (pinned, before, change) = open_pinned_file_observation(&runtime, &object).unwrap();

        std::fs::rename(&original_parent, &moved_parent).unwrap();
        std::fs::create_dir(&original_parent).unwrap();
        std::fs::write(&runtime, b"mapped-runtime").unwrap();

        let (retained_after, retained_change) =
            observe_pinned_file(&pinned, &object, Some(change)).unwrap();
        assert_eq!(retained_after, before);
        assert_eq!(retained_change, change);
        let error = capture_file_observation(&runtime, &object).unwrap_err();
        assert!(
            error.contains("different object than the factory mapping"),
            "{error}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_factory_observation_has_exact_class_region_and_object() {
        let proof = capture_native_macos_mapping().unwrap();
        assert_eq!(proof.class, MacOsMappingProofClass::ProcPidRegionPathInfo);
        assert!(
            proof.platform_observation.region_start.value().unwrap()
                < proof.platform_observation.region_end.value().unwrap()
        );
        assert_eq!(
            proof.platform_observation.mapped_object,
            super::super::loaded_engine_binary_identity()
                .unwrap()
                .object
        );
    }

    #[test]
    fn live_portable_api_never_falls_back_to_legacy_paths_or_environment() {
        if super::super::EMBEDDED_PORTABLE_ENGINE_MANIFEST == "null\n" {
            let error = loaded_engine_portable_identity().unwrap_err();
            assert!(
                error.contains("absent from this non-portable build"),
                "{error}"
            );
            assert!(loaded_engine_mapped_instance_identity().is_err());
        } else {
            loaded_engine_portable_identity()
                .unwrap()
                .validate()
                .unwrap();
        }
    }
}
