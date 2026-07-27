//! Authenticated native runtime-extension authority capsules.
//!
//! Extension manifests contribute only namespaced data. They cannot provide
//! matchers, normalizers, precedence, or executable authorization logic. The
//! semantic core owns one exact resource shape and uses these records only to
//! authenticate which extension operation names exist.
//! @ref LLP 0021#ownership-and-profile-identity

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::digest::compute_domain_digest;
use crate::model::{Digest, NonEmptyString, ObjectIdentity, SafeUint, StableId, Stage};
use crate::strict_json::parse_strict;
use crate::{Error, Result};

pub const RUNTIME_EXTENSION_AUTHORITY_CAPSULE_SCHEMA: &str =
    "ibex/runtime-extension-authority-capsule/1";
pub const RUNTIME_EXTENSION_AUTHORITY_TEMPLATE_SCHEMA: &str =
    "ibex/runtime-extension-authority-template/1";
pub const RUNTIME_EXTENSION_AUTHORITY_FRAGMENT_SCHEMA: &str =
    "ibex/runtime-extension-authority-fragment/1";
pub const RUNTIME_EXTENSION_REGISTRY_PROJECTION_SCHEMA: &str =
    "ibex/runtime-extension-registry-projection/1";
pub const RUNTIME_EXTENSION_MAPPED_EXECUTABLE_SCHEMA: &str =
    "ibex/runtime-extension-mapped-executable/1";
pub const RUNTIME_EXTENSION_DECLARED_EXECUTABLE_SELECTION_SCHEMA: &str =
    "exact.runtime-extension-executable-selection/v1";
pub const RUNTIME_EXTENSION_SET_DOMAIN: &str = "ibex:runtime-extension-set:1";
pub const RUNTIME_EXTENSION_DECLARED_EXECUTABLE_SELECTION_DOMAIN: &str =
    "exact:runtime-extension-executable-selection:1";
pub const RUNTIME_EXTENSION_AUTHORITY_CAPSULE_DOMAIN: &str =
    "ibex:runtime-extension-authority-capsule:1";
pub const RUNTIME_EXTENSION_EXECUTABLE_SELECTION_DOMAIN: &str =
    "ibex:runtime-extension-executable-selection:1";
pub const RUNTIME_EXTENSION_INVOKE_SEMANTICS: &str = "runtime-extension.invoke.authenticated-v1";
pub const RUNTIME_EXTENSION_RESOURCE_KIND: &str = "runtime-extension";

const MAX_EXTENSION_ROWS: usize = 256;
const MAX_DESCRIPTOR_ITEMS: usize = 4096;
const MAX_WIRE_STRING_BYTES: usize = 1024;

/// One closed authenticated projection of all native extensions selected for
/// a runtime construction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionAuthorityCapsule {
    pub schema: String,
    pub authority_capsule_digest: Digest,
    pub target: RuntimeExtensionTarget,
    pub profile: RuntimeExtensionBuildProfile,
    pub sdk_version: SafeUint,
    pub runtime_features: Vec<RuntimeExtensionSdkFeature>,
    pub extension_set_digest: Digest,
    pub declared_executable_selection_identity: Digest,
    pub executable_selection_identity: Digest,
    pub descriptors: Vec<RuntimeExtensionDescriptor>,
    pub linked_artifacts: Vec<RuntimeExtensionLinkedArtifactIdentity>,
    pub mapped_executable: RuntimeExtensionMappedExecutableIdentity,
}

/// Pre-link declaration projection. It deliberately cannot be armed: the
/// final executable selection and authority digests do not exist until the
/// launcher has observed the loaded image containing the generated registry
/// and every callable extension anchor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionAuthorityTemplate {
    pub schema: String,
    pub target: RuntimeExtensionTarget,
    pub profile: RuntimeExtensionBuildProfile,
    pub sdk_version: SafeUint,
    pub runtime_features: Vec<RuntimeExtensionSdkFeature>,
    pub extension_set_digest: Digest,
    pub declared_executable_selection_identity: Digest,
    pub descriptors: Vec<RuntimeExtensionDescriptor>,
    pub linked_artifacts: Vec<RuntimeExtensionLinkedArtifactIdentity>,
}

/// One ASLR-independent pointer into the loaded executable image. The label
/// is generator-owned and the offset is relative to the OS-reported image
/// base, never an absolute process address.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionMappedExecutableAnchor {
    pub label: NonEmptyString,
    pub image_offset: SafeUint,
}

/// Independently observed loaded-executable file identity. The historical
/// schema name says "mapped", but v1 authenticates the pinned on-disk file,
/// not relocated executable pages. The complete file and the generated anchor
/// inventory bind the trusted build's registry and source-linked code.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionMappedExecutableIdentity {
    pub schema: String,
    pub executable_object: ObjectIdentity,
    pub range: RuntimeExtensionLinkedArtifactRange,
    pub content_digest: Digest,
    pub anchors: Vec<RuntimeExtensionMappedExecutableAnchor>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeExtensionTarget {
    Ios,
    Macos,
    Windows,
    Android,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeExtensionBuildProfile {
    Development,
    Production,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeExtensionSdkFeature {
    CopiedBuffers,
    Introspection,
    KeyedExternalBuffers,
    NativeModules,
    OperationMembrane,
    OwnerExecutor,
}

/// Selection facts and all trusted-bootstrap surfaces for one extension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionDescriptor {
    pub id: StableId,
    pub version: NonEmptyString,
    pub sdk_version: NonEmptyString,
    pub manifest_digest: Digest,
    pub trusted_bootstrap: RuntimeExtensionTrustedBootstrap,
    pub bootstrap: Vec<RuntimeExtensionBootstrapArtifact>,
    pub required_feature_bits: SafeUint,
    pub globals: Vec<RuntimeExtensionGlobal>,
    pub modules: Vec<RuntimeExtensionModule>,
    pub callbacks: Vec<RuntimeExtensionCallback>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_abi: Option<RuntimeExtensionProviderAbi>,
    pub linked_artifact_ids: Vec<StableId>,
    pub authority_fragment: RuntimeExtensionAuthorityFragment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeExtensionBootstrapRealm {
    App,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeExtensionInstallPhase {
    PreUserCode,
}

/// The only bootstrap realm/phase admitted by the v1 SDK.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionTrustedBootstrap {
    pub realm: RuntimeExtensionBootstrapRealm,
    pub install_phase: RuntimeExtensionInstallPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeExtensionBootstrapFormat {
    Source,
    HermesBytecode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeExtensionBootstrapEvaluationMode {
    ScriptGlobal,
}

/// Optional trusted JS/HBC bootstrap payload. The bytes remain build-owned;
/// the capsule binds their exact content, length, source identity, and one
/// closed evaluation mode.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionBootstrapArtifact {
    pub id: StableId,
    pub format: RuntimeExtensionBootstrapFormat,
    pub evaluation_mode: RuntimeExtensionBootstrapEvaluationMode,
    pub content_digest: Digest,
    pub source_url: NonEmptyString,
    pub byte_length: SafeUint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeExtensionGlobalKind {
    Function,
    Object,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionGlobal {
    pub name: NonEmptyString,
    pub kind: RuntimeExtensionGlobalKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionModule {
    pub specifier: NonEmptyString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeExtensionCallbackDelivery {
    RuntimeThread,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeExtensionCallbackProducerAffinity {
    RuntimeOwner,
    BackgroundProducer,
    ProviderThread,
}

/// One callback entrypoint produced by an authenticated extension operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionCallback {
    pub id: StableId,
    pub operation_id: StableId,
    pub producer_affinity: RuntimeExtensionCallbackProducerAffinity,
    pub delivery: RuntimeExtensionCallbackDelivery,
    pub max_pending: SafeUint,
}

/// Optional provider-facing ABI identity. It is bound to one authenticated
/// linked artifact, never to a pathname or a dynamically discovered symbol.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionProviderAbi {
    pub id: StableId,
    pub min_version: SafeUint,
    pub selected_version: SafeUint,
    pub struct_size: SafeUint,
    pub identity_digest: Digest,
    pub linked_artifact_id: StableId,
}

/// Namespaced data-only merge fragment. Operation and authority-class strings
/// are interpreted by the fixed runtime-extension adapter; no manifest field
/// can install code into the semantic core.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionAuthorityFragment {
    pub schema: String,
    pub namespace: StableId,
    pub operations: Vec<RuntimeExtensionOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionOperation {
    pub operation_id: StableId,
    pub authority_class: StableId,
    pub semantics: StableId,
    pub stage: Stage,
    pub atomicity_group: StableId,
    pub resource_kinds: Vec<NonEmptyString>,
    pub js_entry_path: NonEmptyString,
    pub flags: SafeUint,
}

/// Data-only construction projection emitted from the structurally validated
/// C registry. Comparing this value to the armed capsule closes the gap where
/// a table could present the right capsule digest alongside different runtime
/// surfaces.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionRegistryProjection {
    pub schema: String,
    pub extension_set_digest: Digest,
    pub authority_capsule_digest: Digest,
    pub executable_selection_identity: Digest,
    pub descriptors: Vec<RuntimeExtensionRegistryDescriptorProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionRegistryDescriptorProjection {
    pub id: StableId,
    pub version: NonEmptyString,
    pub sdk_version: NonEmptyString,
    pub manifest_digest: Digest,
    pub authority_capsule_digest: Digest,
    pub trusted_bootstrap: RuntimeExtensionTrustedBootstrap,
    pub bootstrap: Vec<RuntimeExtensionBootstrapArtifact>,
    pub required_feature_bits: SafeUint,
    pub globals: Vec<RuntimeExtensionGlobal>,
    pub modules: Vec<RuntimeExtensionModule>,
    pub callbacks: Vec<RuntimeExtensionCallback>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_abi: Option<RuntimeExtensionRegistryProviderAbiProjection>,
    pub authority_fragment: RuntimeExtensionAuthorityFragment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionRegistryProviderAbiProjection {
    pub id: StableId,
    pub min_version: SafeUint,
    pub selected_version: SafeUint,
    pub struct_size: SafeUint,
    pub identity_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionLinkedArtifactIdentity {
    pub artifact_id: StableId,
    pub extension_id: StableId,
    pub executable_object: ObjectIdentity,
    pub range: RuntimeExtensionLinkedArtifactRange,
    pub content_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionLinkedArtifactRange {
    pub offset: SafeUint,
    pub length: SafeUint,
}

impl RuntimeExtensionAuthorityCapsule {
    /// Strict I-JSON parse plus complete digest and cross-reference validation.
    pub fn parse_json(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|error| Error::InvalidIJson {
            path: "$".into(),
            message: format!("runtime-extension capsule is not UTF-8: {error}"),
        })?;
        Self::from_value(parse_strict(text)?)
    }

    /// Decode a value that has already passed duplicate-key/I-JSON parsing.
    pub fn from_value(value: Value) -> Result<Self> {
        let capsule: Self = serde_json::from_value(value).map_err(|error| {
            Error::InvalidModel(format!("invalid runtime-extension capsule: {error}"))
        })?;
        capsule.validate()?;
        Ok(capsule)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != RUNTIME_EXTENSION_AUTHORITY_CAPSULE_SCHEMA {
            return refused("runtime-extension authority capsule schema is unsupported");
        }
        validate_authority_contents(&self.descriptors, &self.linked_artifacts)?;
        validate_selection_facts(self.sdk_version, &self.runtime_features, &self.descriptors)?;
        self.mapped_executable.validate()?;
        validate_executable_anchor_inventory(&self.descriptors, &self.mapped_executable)?;

        let expected_set = self.compute_extension_set_digest()?;
        if self.extension_set_digest != expected_set {
            return refused("runtime-extension set digest is stale or tampered");
        }
        let expected_declared_selection = compute_declared_executable_selection_identity(
            self.target,
            self.profile,
            self.sdk_version,
            &self.runtime_features,
            &self.extension_set_digest,
            &self.descriptors,
            &self.linked_artifacts,
        )?;
        if self.declared_executable_selection_identity != expected_declared_selection {
            return refused(
                "runtime-extension declared executable-selection identity is stale or tampered",
            );
        }
        let expected_executable_selection = compute_executable_selection_identity(
            &self.declared_executable_selection_identity,
            &self.mapped_executable,
        )?;
        if self.executable_selection_identity != expected_executable_selection {
            return refused(
                "runtime-extension final executable-selection identity is stale or tampered",
            );
        }
        let expected_capsule = self.compute_authority_capsule_digest()?;
        if self.authority_capsule_digest != expected_capsule {
            return refused("runtime-extension authority capsule digest is stale or tampered");
        }
        Ok(())
    }

    pub fn compute_extension_set_digest(&self) -> Result<Digest> {
        compute_extension_set_digest(&self.descriptors)
    }

    pub fn compute_declared_executable_selection_identity(&self) -> Result<Digest> {
        compute_declared_executable_selection_identity(
            self.target,
            self.profile,
            self.sdk_version,
            &self.runtime_features,
            &self.extension_set_digest,
            &self.descriptors,
            &self.linked_artifacts,
        )
    }

    pub fn compute_executable_selection_identity(&self) -> Result<Digest> {
        compute_executable_selection_identity(
            &self.declared_executable_selection_identity,
            &self.mapped_executable,
        )
    }

    pub fn compute_authority_capsule_digest(&self) -> Result<Digest> {
        let value = serde_json::to_value(self).map_err(|error| {
            Error::InvalidModel(format!(
                "cannot serialize runtime-extension authority capsule: {error}"
            ))
        })?;
        digest_from_domain(
            RUNTIME_EXTENSION_AUTHORITY_CAPSULE_DOMAIN,
            &value,
            &["authorityCapsuleDigest".to_owned()],
        )
    }

    /// Exact namespaced lookup used by the host adapter. An operation from one
    /// extension can never collide with or borrow another extension's row.
    pub fn operation(
        &self,
        extension_id: &str,
        operation_id: &str,
    ) -> Option<&RuntimeExtensionOperation> {
        self.descriptors
            .iter()
            .find(|descriptor| descriptor.id.as_str() == extension_id)?
            .authority_fragment
            .operations
            .iter()
            .find(|operation| operation.operation_id.as_str() == operation_id)
    }

    pub fn authority_class(&self, extension_id: &str, operation_id: &str) -> Option<&StableId> {
        self.operation(extension_id, operation_id)
            .map(|operation| &operation.authority_class)
    }

    /// The exact data a structurally validated native registry must project
    /// before Hermes allocation. Linked-object facts stay launcher-owned in
    /// the capsule; every registry-visible identity and surface is copied here.
    pub fn registry_projection(&self) -> RuntimeExtensionRegistryProjection {
        RuntimeExtensionRegistryProjection {
            schema: RUNTIME_EXTENSION_REGISTRY_PROJECTION_SCHEMA.into(),
            extension_set_digest: self.extension_set_digest.clone(),
            authority_capsule_digest: self.authority_capsule_digest.clone(),
            executable_selection_identity: self.executable_selection_identity.clone(),
            descriptors: self
                .descriptors
                .iter()
                .map(|descriptor| {
                    RuntimeExtensionRegistryDescriptorProjection::from_descriptor(
                        descriptor,
                        &self.authority_capsule_digest,
                    )
                })
                .collect(),
        }
    }

    /// Strictly parse and exactly compare a native registry projection. No
    /// matcher, normalization hook, or caller-defined omission participates.
    pub fn matches_registry_projection_json(&self, bytes: &[u8]) -> Result<bool> {
        let projection = RuntimeExtensionRegistryProjection::parse_json(bytes)?;
        Ok(projection == self.registry_projection())
    }

    /// Refuse unless the launcher-observed loaded-executable file identity
    /// exactly equals the capsule's sorted protected artifact inventory.
    pub fn validate_launcher_mapped_executable(
        &self,
        observed: &RuntimeExtensionMappedExecutableIdentity,
    ) -> Result<()> {
        if observed != &self.mapped_executable {
            return refused(
                "runtime-extension mapped executable differs from launcher observation",
            );
        }
        Ok(())
    }
}

impl RuntimeExtensionAuthorityTemplate {
    /// Strictly parse a non-armable pre-link authority template.
    pub fn parse_json(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|error| Error::InvalidIJson {
            path: "$".into(),
            message: format!("runtime-extension authority template is not UTF-8: {error}"),
        })?;
        let template: Self = serde_json::from_value(parse_strict(text)?).map_err(|error| {
            Error::InvalidModel(format!(
                "invalid runtime-extension authority template: {error}"
            ))
        })?;
        template.validate()?;
        Ok(template)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != RUNTIME_EXTENSION_AUTHORITY_TEMPLATE_SCHEMA {
            return refused("runtime-extension authority template schema is unsupported");
        }
        validate_authority_contents(&self.descriptors, &self.linked_artifacts)?;
        validate_selection_facts(self.sdk_version, &self.runtime_features, &self.descriptors)?;
        let expected_set = compute_extension_set_digest(&self.descriptors)?;
        if self.extension_set_digest != expected_set {
            return refused("runtime-extension template set digest is stale or tampered");
        }
        let expected_declared_selection = compute_declared_executable_selection_identity(
            self.target,
            self.profile,
            self.sdk_version,
            &self.runtime_features,
            &self.extension_set_digest,
            &self.descriptors,
            &self.linked_artifacts,
        )?;
        if self.declared_executable_selection_identity != expected_declared_selection {
            return refused(
                "runtime-extension template executable-selection identity is stale or tampered",
            );
        }
        Ok(())
    }

    /// Finalize the only armable capsule by composing the generator-owned
    /// selection with a launcher-observed final executable identity.
    pub fn finalize(
        self,
        mapped_executable: RuntimeExtensionMappedExecutableIdentity,
    ) -> Result<RuntimeExtensionAuthorityCapsule> {
        self.validate()?;
        mapped_executable.validate()?;
        validate_executable_anchor_inventory(&self.descriptors, &mapped_executable)?;
        let executable_selection_identity = compute_executable_selection_identity(
            &self.declared_executable_selection_identity,
            &mapped_executable,
        )?;
        let mut capsule = RuntimeExtensionAuthorityCapsule {
            schema: RUNTIME_EXTENSION_AUTHORITY_CAPSULE_SCHEMA.into(),
            authority_capsule_digest: executable_selection_identity.clone(),
            target: self.target,
            profile: self.profile,
            sdk_version: self.sdk_version,
            runtime_features: self.runtime_features,
            extension_set_digest: self.extension_set_digest,
            declared_executable_selection_identity: self.declared_executable_selection_identity,
            executable_selection_identity,
            descriptors: self.descriptors,
            linked_artifacts: self.linked_artifacts,
            mapped_executable,
        };
        capsule.authority_capsule_digest = capsule.compute_authority_capsule_digest()?;
        capsule.validate()?;
        Ok(capsule)
    }
}

impl RuntimeExtensionMappedExecutableIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.schema != RUNTIME_EXTENSION_MAPPED_EXECUTABLE_SCHEMA {
            return refused("runtime-extension mapped executable schema is unsupported");
        }
        if self.range.offset != SafeUint::ZERO || self.range.length == SafeUint::ZERO {
            return refused(
                "runtime-extension mapped executable must cover the complete executable file",
            );
        }
        if self.anchors.is_empty() || self.anchors.len() > MAX_DESCRIPTOR_ITEMS {
            return refused("runtime-extension mapped executable anchors exceed closed bounds");
        }
        require_sorted_unique_by(
            &self.anchors,
            |anchor| anchor.label.as_str(),
            "runtime-extension mapped executable anchors",
        )?;
        Ok(())
    }
}

fn validate_selection_facts(
    sdk_version: SafeUint,
    runtime_features: &[RuntimeExtensionSdkFeature],
    descriptors: &[RuntimeExtensionDescriptor],
) -> Result<()> {
    if sdk_version == SafeUint::ZERO || sdk_version.get() > u32::MAX.into() {
        return refused("runtime-extension selected SDK version is outside v1 bounds");
    }
    if runtime_features.is_empty() || runtime_features.len() > 64 {
        return refused("runtime-extension selected feature inventory is empty or unbounded");
    }
    if runtime_features.windows(2).any(|pair| pair[0] >= pair[1]) {
        return refused("runtime-extension selected features must be sorted and unique");
    }
    let sdk_text = sdk_version.get().to_string();
    let selected_feature_bits = runtime_features.iter().fold(0_u64, |bits, feature| {
        bits | match feature {
            RuntimeExtensionSdkFeature::OwnerExecutor => 1 << 0,
            RuntimeExtensionSdkFeature::OperationMembrane => 1 << 1,
            RuntimeExtensionSdkFeature::CopiedBuffers => 1 << 2,
            RuntimeExtensionSdkFeature::KeyedExternalBuffers => 1 << 3,
            RuntimeExtensionSdkFeature::NativeModules => 1 << 4,
            RuntimeExtensionSdkFeature::Introspection => 1 << 5,
        }
    });
    for descriptor in descriptors {
        if descriptor.sdk_version.as_str() != sdk_text {
            return refused("runtime-extension descriptor SDK version differs from selection");
        }
        if descriptor.required_feature_bits.get() & !selected_feature_bits != 0 {
            return refused(
                "runtime-extension descriptor requires a feature absent from the selection",
            );
        }
    }
    Ok(())
}

fn compute_declared_executable_selection_identity(
    target: RuntimeExtensionTarget,
    profile: RuntimeExtensionBuildProfile,
    sdk_version: SafeUint,
    runtime_features: &[RuntimeExtensionSdkFeature],
    extension_set_digest: &Digest,
    descriptors: &[RuntimeExtensionDescriptor],
    linked_artifacts: &[RuntimeExtensionLinkedArtifactIdentity],
) -> Result<Digest> {
    digest_from_domain(
        RUNTIME_EXTENSION_DECLARED_EXECUTABLE_SELECTION_DOMAIN,
        &json!({
            "schema": RUNTIME_EXTENSION_DECLARED_EXECUTABLE_SELECTION_SCHEMA,
            "target": target,
            "profile": profile,
            "sdkVersion": sdk_version,
            "runtimeFeatures": runtime_features,
            "extensionSetDigest": extension_set_digest,
            "descriptors": descriptors,
            "linkedArtifacts": linked_artifacts,
        }),
        &[],
    )
}

fn compute_executable_selection_identity(
    declared_executable_selection_identity: &Digest,
    mapped_executable: &RuntimeExtensionMappedExecutableIdentity,
) -> Result<Digest> {
    digest_from_domain(
        RUNTIME_EXTENSION_EXECUTABLE_SELECTION_DOMAIN,
        &json!({
            "declaredExecutableSelectionIdentity":
                declared_executable_selection_identity,
            "mappedExecutable": mapped_executable,
        }),
        &[],
    )
}

fn validate_executable_anchor_inventory(
    descriptors: &[RuntimeExtensionDescriptor],
    mapped_executable: &RuntimeExtensionMappedExecutableIdentity,
) -> Result<()> {
    let mut expected = BTreeSet::from([
        "registry.build".to_owned(),
        "registry.descriptors".to_owned(),
        "registry.table".to_owned(),
    ]);
    for descriptor in descriptors {
        let prefix = descriptor.id.as_str();
        for suffix in [
            "lifecycle.checkpoint",
            "lifecycle.close",
            "lifecycle.install",
            "lifecycle.quiesce",
            "lifecycle.table",
        ] {
            expected.insert(format!("{prefix}.{suffix}"));
        }
        if descriptor.provider_abi.is_some() {
            expected.insert(format!("{prefix}.provider.factory"));
        }
        for bootstrap in &descriptor.bootstrap {
            expected.insert(format!("{prefix}.bootstrap.{}", bootstrap.id.as_str()));
        }
    }
    let observed = mapped_executable
        .anchors
        .iter()
        .map(|anchor| anchor.label.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if observed != expected {
        return refused(
            "runtime-extension executable anchor inventory differs from the declared registry",
        );
    }
    Ok(())
}

fn compute_extension_set_digest(descriptors: &[RuntimeExtensionDescriptor]) -> Result<Digest> {
    let selection = descriptors
        .iter()
        .map(|descriptor| {
            json!({
                "id": descriptor.id,
                "version": descriptor.version,
                "sdkVersion": descriptor.sdk_version,
                "manifestDigest": descriptor.manifest_digest,
            })
        })
        .collect::<Vec<_>>();
    digest_from_domain(RUNTIME_EXTENSION_SET_DOMAIN, &json!(selection), &[])
}

fn validate_authority_contents(
    descriptor_rows: &[RuntimeExtensionDescriptor],
    linked_artifact_rows: &[RuntimeExtensionLinkedArtifactIdentity],
) -> Result<()> {
    if descriptor_rows.is_empty() || descriptor_rows.len() > MAX_EXTENSION_ROWS {
        return refused("runtime-extension descriptor set is empty or exceeds its bound");
    }
    if linked_artifact_rows.is_empty() || linked_artifact_rows.len() > MAX_DESCRIPTOR_ITEMS {
        return refused("runtime-extension linked artifact set is empty or exceeds its bound");
    }

    require_sorted_unique_by(
        descriptor_rows,
        |descriptor| descriptor.id.as_str(),
        "runtime-extension descriptors",
    )?;
    require_sorted_unique_by(
        linked_artifact_rows,
        |artifact| artifact.artifact_id.as_str(),
        "runtime-extension linked artifacts",
    )?;

    let descriptors = descriptor_rows
        .iter()
        .map(|descriptor| (descriptor.id.as_str(), descriptor))
        .collect::<BTreeMap<_, _>>();
    let artifacts = linked_artifact_rows
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let mut global_names = BTreeSet::new();
    let mut module_specifiers = BTreeSet::new();
    let mut object_ranges = BTreeMap::<&ObjectIdentity, Vec<(u64, u64)>>::new();

    for artifact in linked_artifact_rows {
        if !descriptors.contains_key(artifact.extension_id.as_str()) {
            return refused("runtime-extension linked artifact names an unknown extension");
        }
        if artifact.range.length == SafeUint::ZERO {
            return refused("runtime-extension linked artifact range is empty");
        }
        let end = artifact
            .range
            .offset
            .get()
            .checked_add(artifact.range.length.get())
            .ok_or_else(|| {
                Error::ArmRefused("runtime-extension linked artifact range overflows".into())
            })?;
        if SafeUint::new(end).is_err() {
            return refused("runtime-extension linked artifact range exceeds I-JSON");
        }
        object_ranges
            .entry(&artifact.executable_object)
            .or_default()
            .push((artifact.range.offset.get(), end));
    }
    for ranges in object_ranges.values_mut() {
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return refused("runtime-extension linked artifact ranges overlap");
        }
    }

    for descriptor in descriptor_rows {
        validate_descriptor(
            descriptor,
            &artifacts,
            &mut global_names,
            &mut module_specifiers,
        )?;
    }
    Ok(())
}

impl RuntimeExtensionRegistryProjection {
    pub fn parse_json(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|error| Error::InvalidIJson {
            path: "$".into(),
            message: format!("runtime-extension registry projection is not UTF-8: {error}"),
        })?;
        let projection: Self = serde_json::from_value(parse_strict(text)?).map_err(|error| {
            Error::InvalidModel(format!(
                "invalid runtime-extension registry projection: {error}"
            ))
        })?;
        if projection.schema != RUNTIME_EXTENSION_REGISTRY_PROJECTION_SCHEMA {
            return refused("runtime-extension registry projection schema is unsupported");
        }
        if projection.descriptors.is_empty() || projection.descriptors.len() > MAX_EXTENSION_ROWS {
            return refused("runtime-extension registry projection exceeds its closed bounds");
        }
        require_sorted_unique_by(
            &projection.descriptors,
            |descriptor| descriptor.id.as_str(),
            "runtime-extension registry projection descriptors",
        )?;
        if projection.descriptors.iter().any(|descriptor| {
            descriptor.authority_capsule_digest != projection.authority_capsule_digest
        }) {
            return refused(
                "runtime-extension descriptor authority capsule digest differs from registry",
            );
        }
        Ok(projection)
    }
}

impl RuntimeExtensionRegistryDescriptorProjection {
    fn from_descriptor(
        descriptor: &RuntimeExtensionDescriptor,
        authority_capsule_digest: &Digest,
    ) -> Self {
        Self {
            id: descriptor.id.clone(),
            version: descriptor.version.clone(),
            sdk_version: descriptor.sdk_version.clone(),
            manifest_digest: descriptor.manifest_digest.clone(),
            authority_capsule_digest: authority_capsule_digest.clone(),
            trusted_bootstrap: descriptor.trusted_bootstrap.clone(),
            bootstrap: descriptor.bootstrap.clone(),
            required_feature_bits: descriptor.required_feature_bits,
            globals: descriptor.globals.clone(),
            modules: descriptor.modules.clone(),
            callbacks: descriptor.callbacks.clone(),
            provider_abi: descriptor.provider_abi.as_ref().map(|provider| {
                RuntimeExtensionRegistryProviderAbiProjection {
                    id: provider.id.clone(),
                    min_version: provider.min_version,
                    selected_version: provider.selected_version,
                    struct_size: provider.struct_size,
                    identity_digest: provider.identity_digest.clone(),
                }
            }),
            authority_fragment: descriptor.authority_fragment.clone(),
        }
    }
}

fn validate_descriptor<'a>(
    descriptor: &'a RuntimeExtensionDescriptor,
    artifacts: &BTreeMap<&str, &'a RuntimeExtensionLinkedArtifactIdentity>,
    global_names: &mut BTreeSet<String>,
    module_specifiers: &mut BTreeSet<String>,
) -> Result<()> {
    validate_wire_string(descriptor.version.as_str(), "extension version")?;
    validate_wire_string(descriptor.sdk_version.as_str(), "extension SDK version")?;
    if descriptor.bootstrap.len() > MAX_DESCRIPTOR_ITEMS
        || descriptor.globals.len() > MAX_DESCRIPTOR_ITEMS
        || descriptor.modules.len() > MAX_DESCRIPTOR_ITEMS
        || descriptor.callbacks.len() > MAX_DESCRIPTOR_ITEMS
        || descriptor.linked_artifact_ids.is_empty()
        || descriptor.linked_artifact_ids.len() > MAX_DESCRIPTOR_ITEMS
        || descriptor.authority_fragment.operations.is_empty()
        || descriptor.authority_fragment.operations.len() > MAX_DESCRIPTOR_ITEMS
    {
        return refused("runtime-extension descriptor collection exceeds its closed bounds");
    }
    require_sorted_unique_by(
        &descriptor.bootstrap,
        |artifact| artifact.id.as_str(),
        "runtime-extension bootstrap artifacts",
    )?;
    require_sorted_unique_by(
        &descriptor.globals,
        |global| global.name.as_str(),
        "runtime-extension globals",
    )?;
    require_sorted_unique_by(
        &descriptor.modules,
        |module| module.specifier.as_str(),
        "runtime-extension modules",
    )?;
    require_sorted_unique_by(
        &descriptor.callbacks,
        |callback| callback.id.as_str(),
        "runtime-extension callbacks",
    )?;
    require_sorted_unique_by(
        &descriptor.linked_artifact_ids,
        StableId::as_str,
        "runtime-extension descriptor artifact IDs",
    )?;
    require_sorted_unique_by(
        &descriptor.authority_fragment.operations,
        |operation| operation.operation_id.as_str(),
        "runtime-extension operations",
    )?;

    if descriptor.authority_fragment.schema != RUNTIME_EXTENSION_AUTHORITY_FRAGMENT_SCHEMA
        || descriptor.authority_fragment.namespace != descriptor.id
    {
        return refused("runtime-extension authority fragment namespace or schema is invalid");
    }

    for artifact in &descriptor.bootstrap {
        validate_wire_string(
            artifact.source_url.as_str(),
            "runtime-extension bootstrap source URL",
        )?;
        if artifact.byte_length == SafeUint::ZERO {
            return refused("runtime-extension bootstrap artifact is empty");
        }
    }
    for global in &descriptor.globals {
        validate_wire_string(global.name.as_str(), "runtime-extension global name")?;
        if !is_dotted_identifier_path(global.name.as_str()) {
            return refused("runtime-extension global name is not a dotted identifier path");
        }
        if global_names
            .iter()
            .any(|existing| global_paths_overlap(existing.as_str(), global.name.as_str()))
        {
            return refused("runtime-extension global paths overlap");
        }
        global_names.insert(global.name.as_str().to_owned());
    }
    for module in &descriptor.modules {
        validate_wire_string(
            module.specifier.as_str(),
            "runtime-extension module specifier",
        )?;
        if !module_specifiers.insert(module.specifier.as_str().to_owned()) {
            return refused("runtime-extension module specifiers collide");
        }
    }

    let operation_ids = descriptor
        .authority_fragment
        .operations
        .iter()
        .map(|operation| operation.operation_id.as_str())
        .collect::<BTreeSet<_>>();
    for operation in &descriptor.authority_fragment.operations {
        validate_wire_string(
            operation.js_entry_path.as_str(),
            "runtime-extension operation JS entry path",
        )?;
        if !is_owned_operation_entry_path(
            operation.js_entry_path.as_str(),
            &descriptor.globals,
            &descriptor.modules,
        ) {
            return refused("runtime-extension operation JS entry path is malformed or unowned");
        }
        if operation.semantics.as_str() != RUNTIME_EXTENSION_INVOKE_SEMANTICS {
            return refused("runtime-extension operation names unsupported effect semantics");
        }
        require_sorted_unique_by(
            &operation.resource_kinds,
            NonEmptyString::as_str,
            "runtime-extension operation resource kinds",
        )?;
        if operation.resource_kinds.len() != 1
            || operation.resource_kinds[0].as_str() != RUNTIME_EXTENSION_RESOURCE_KIND
        {
            return refused("runtime-extension operation resource kind is not Ibex-owned v1");
        }
        if operation.flags.get() > u32::MAX.into() {
            return refused("runtime-extension operation flags exceed the SDK v1 field");
        }
    }
    for callback in &descriptor.callbacks {
        if !operation_ids.contains(callback.operation_id.as_str()) {
            return refused("runtime-extension callback names an unknown operation");
        }
        if callback.max_pending == SafeUint::ZERO || callback.max_pending.get() > 65_536 {
            return refused("runtime-extension callback pending bound is outside SDK v1");
        }
    }

    for artifact_id in &descriptor.linked_artifact_ids {
        let Some(artifact) = artifacts.get(artifact_id.as_str()) else {
            return refused("runtime-extension descriptor names an unknown linked artifact");
        };
        if artifact.extension_id != descriptor.id {
            return refused("runtime-extension descriptor borrows another extension's artifact");
        }
    }
    let actual_ids = artifacts
        .values()
        .filter(|artifact| artifact.extension_id == descriptor.id)
        .map(|artifact| artifact.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    let declared_ids = descriptor
        .linked_artifact_ids
        .iter()
        .map(StableId::as_str)
        .collect::<BTreeSet<_>>();
    if actual_ids != declared_ids {
        return refused("runtime-extension descriptor artifact set is incomplete");
    }
    if let Some(provider) = &descriptor.provider_abi {
        if provider.min_version == SafeUint::ZERO
            || provider.selected_version < provider.min_version
            || provider.struct_size == SafeUint::ZERO
            || provider.min_version.get() > u32::MAX.into()
            || provider.selected_version.get() > u32::MAX.into()
            || provider.struct_size.get() > u32::MAX.into()
        {
            return refused("runtime-extension provider ABI facts are inconsistent");
        }
        if !declared_ids.contains(provider.linked_artifact_id.as_str()) {
            return refused("runtime-extension provider ABI names an unowned linked artifact");
        }
    }
    Ok(())
}

fn global_paths_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('.'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn is_dotted_identifier_path(path: &str) -> bool {
    path.split('.').all(|segment| {
        let Some((&first, rest)) = segment.as_bytes().split_first() else {
            return false;
        };
        (first.is_ascii_alphabetic() || first == b'_' || first == b'$')
            && rest
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'$')
    })
}

fn is_owned_operation_entry_path(
    path: &str,
    globals: &[RuntimeExtensionGlobal],
    modules: &[RuntimeExtensionModule],
) -> bool {
    if let Some((owner, export_path)) = path.split_once('#') {
        if owner.is_empty() || export_path.is_empty() || export_path.contains('#') {
            return false;
        }
        return is_dotted_identifier_path(export_path)
            && (globals.iter().any(|global| global.name.as_str() == owner)
                || modules
                    .iter()
                    .any(|module| module.specifier.as_str() == owner));
    }

    if modules
        .iter()
        .any(|module| module.specifier.as_str() == path)
    {
        return true;
    }
    is_dotted_identifier_path(path)
        && globals.iter().any(|global| {
            path == global.name.as_str()
                || path
                    .strip_prefix(global.name.as_str())
                    .is_some_and(|suffix| suffix.starts_with('.'))
        })
}

fn validate_wire_string(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_WIRE_STRING_BYTES
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return refused(format!("{label} is not a bounded canonical wire string"));
    }
    Ok(())
}

fn require_sorted_unique_by<T>(values: &[T], key: impl Fn(&T) -> &str, label: &str) -> Result<()> {
    if values.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return refused(format!("{label} must be sorted and unique"));
    }
    Ok(())
}

fn digest_from_domain(domain: &str, value: &Value, omissions: &[String]) -> Result<Digest> {
    Digest::new(compute_domain_digest(domain, value, omissions)?).map_err(Error::InvalidModel)
}

fn refused<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::ArmRefused(message.into()))
}

#[cfg(test)]
pub(crate) fn test_authority_capsule() -> RuntimeExtensionAuthorityCapsule {
    let test_digest = |label: &str| {
        digest_from_domain("ibex:runtime-extension-test:1", &json!(label), &[]).unwrap()
    };
    let mut capsule = RuntimeExtensionAuthorityCapsule {
        schema: RUNTIME_EXTENSION_AUTHORITY_CAPSULE_SCHEMA.into(),
        authority_capsule_digest: test_digest("placeholder-authority"),
        target: RuntimeExtensionTarget::Macos,
        profile: RuntimeExtensionBuildProfile::Production,
        sdk_version: SafeUint::new(1).unwrap(),
        runtime_features: vec![
            RuntimeExtensionSdkFeature::CopiedBuffers,
            RuntimeExtensionSdkFeature::OperationMembrane,
            RuntimeExtensionSdkFeature::OwnerExecutor,
        ],
        extension_set_digest: test_digest("placeholder-set"),
        declared_executable_selection_identity: test_digest("declared-selection"),
        executable_selection_identity: test_digest("selection"),
        descriptors: vec![RuntimeExtensionDescriptor {
            id: StableId::new("acme.echo").unwrap(),
            version: NonEmptyString::new("1.2.3").unwrap(),
            sdk_version: NonEmptyString::new("1").unwrap(),
            manifest_digest: test_digest("manifest"),
            trusted_bootstrap: RuntimeExtensionTrustedBootstrap {
                realm: RuntimeExtensionBootstrapRealm::App,
                install_phase: RuntimeExtensionInstallPhase::PreUserCode,
            },
            bootstrap: Vec::new(),
            required_feature_bits: SafeUint::new(7).unwrap(),
            globals: vec![RuntimeExtensionGlobal {
                name: NonEmptyString::new("AcmeEcho").unwrap(),
                kind: RuntimeExtensionGlobalKind::Object,
            }],
            modules: vec![RuntimeExtensionModule {
                specifier: NonEmptyString::new("acme:echo").unwrap(),
            }],
            callbacks: vec![RuntimeExtensionCallback {
                id: StableId::new("completion").unwrap(),
                operation_id: StableId::new("echo").unwrap(),
                producer_affinity: RuntimeExtensionCallbackProducerAffinity::BackgroundProducer,
                delivery: RuntimeExtensionCallbackDelivery::RuntimeThread,
                max_pending: SafeUint::new(8).unwrap(),
            }],
            provider_abi: Some(RuntimeExtensionProviderAbi {
                id: StableId::new("acme.echo.provider").unwrap(),
                min_version: SafeUint::new(1).unwrap(),
                selected_version: SafeUint::new(2).unwrap(),
                struct_size: SafeUint::new(64).unwrap(),
                identity_digest: test_digest("provider"),
                linked_artifact_id: StableId::new("acme.echo.image").unwrap(),
            }),
            linked_artifact_ids: vec![StableId::new("acme.echo.image").unwrap()],
            authority_fragment: RuntimeExtensionAuthorityFragment {
                schema: RUNTIME_EXTENSION_AUTHORITY_FRAGMENT_SCHEMA.into(),
                namespace: StableId::new("acme.echo").unwrap(),
                operations: vec![RuntimeExtensionOperation {
                    operation_id: StableId::new("echo").unwrap(),
                    authority_class: StableId::new("local.transform").unwrap(),
                    semantics: StableId::new(RUNTIME_EXTENSION_INVOKE_SEMANTICS).unwrap(),
                    stage: Stage::Requested,
                    atomicity_group: StableId::new("acme.echo.decision").unwrap(),
                    resource_kinds: vec![
                        NonEmptyString::new(RUNTIME_EXTENSION_RESOURCE_KIND).unwrap()
                    ],
                    js_entry_path: NonEmptyString::new("AcmeEcho.echo").unwrap(),
                    flags: SafeUint::ZERO,
                }],
            },
        }],
        linked_artifacts: vec![RuntimeExtensionLinkedArtifactIdentity {
            artifact_id: StableId::new("acme.echo.image").unwrap(),
            extension_id: StableId::new("acme.echo").unwrap(),
            executable_object: ObjectIdentity {
                platform: crate::model::ObjectPlatform::Unix,
                volume: NonEmptyString::new("dev:1").unwrap(),
                file: NonEmptyString::new("ino:2").unwrap(),
            },
            range: RuntimeExtensionLinkedArtifactRange {
                offset: SafeUint::new(4096).unwrap(),
                length: SafeUint::new(512).unwrap(),
            },
            content_digest: test_digest("linked-image"),
        }],
        mapped_executable: RuntimeExtensionMappedExecutableIdentity {
            schema: RUNTIME_EXTENSION_MAPPED_EXECUTABLE_SCHEMA.into(),
            executable_object: ObjectIdentity {
                platform: crate::model::ObjectPlatform::Unix,
                volume: NonEmptyString::new("dev:1").unwrap(),
                file: NonEmptyString::new("ino:3").unwrap(),
            },
            range: RuntimeExtensionLinkedArtifactRange {
                offset: SafeUint::ZERO,
                length: SafeUint::new(16_384).unwrap(),
            },
            content_digest: test_digest("mapped-executable"),
            anchors: [
                "acme.echo.lifecycle.checkpoint",
                "acme.echo.lifecycle.close",
                "acme.echo.lifecycle.install",
                "acme.echo.lifecycle.quiesce",
                "acme.echo.lifecycle.table",
                "acme.echo.provider.factory",
                "registry.build",
                "registry.descriptors",
                "registry.table",
            ]
            .into_iter()
            .enumerate()
            .map(|(index, label)| RuntimeExtensionMappedExecutableAnchor {
                label: NonEmptyString::new(label).unwrap(),
                image_offset: SafeUint::new(1024 + index as u64).unwrap(),
            })
            .collect(),
        },
    };
    capsule.extension_set_digest = capsule.compute_extension_set_digest().unwrap();
    capsule.declared_executable_selection_identity =
        compute_declared_executable_selection_identity(
            capsule.target,
            capsule.profile,
            capsule.sdk_version,
            &capsule.runtime_features,
            &capsule.extension_set_digest,
            &capsule.descriptors,
            &capsule.linked_artifacts,
        )
        .unwrap();
    capsule.executable_selection_identity = compute_executable_selection_identity(
        &capsule.declared_executable_selection_identity,
        &capsule.mapped_executable,
    )
    .unwrap();
    capsule.authority_capsule_digest = capsule.compute_authority_capsule_digest().unwrap();
    capsule
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Digest {
        digest_from_domain("ibex:runtime-extension-test:1", &json!(label), &[]).unwrap()
    }

    fn unsigned_capsule() -> RuntimeExtensionAuthorityCapsule {
        RuntimeExtensionAuthorityCapsule {
            schema: RUNTIME_EXTENSION_AUTHORITY_CAPSULE_SCHEMA.into(),
            authority_capsule_digest: digest("placeholder-authority"),
            target: RuntimeExtensionTarget::Macos,
            profile: RuntimeExtensionBuildProfile::Production,
            sdk_version: SafeUint::new(1).unwrap(),
            runtime_features: vec![
                RuntimeExtensionSdkFeature::CopiedBuffers,
                RuntimeExtensionSdkFeature::OperationMembrane,
                RuntimeExtensionSdkFeature::OwnerExecutor,
            ],
            extension_set_digest: digest("placeholder-set"),
            declared_executable_selection_identity: digest("declared-selection"),
            executable_selection_identity: digest("selection"),
            descriptors: vec![RuntimeExtensionDescriptor {
                id: StableId::new("acme.echo").unwrap(),
                version: NonEmptyString::new("1.2.3").unwrap(),
                sdk_version: NonEmptyString::new("1").unwrap(),
                manifest_digest: digest("manifest"),
                trusted_bootstrap: RuntimeExtensionTrustedBootstrap {
                    realm: RuntimeExtensionBootstrapRealm::App,
                    install_phase: RuntimeExtensionInstallPhase::PreUserCode,
                },
                bootstrap: Vec::new(),
                required_feature_bits: SafeUint::new(7).unwrap(),
                globals: vec![RuntimeExtensionGlobal {
                    name: NonEmptyString::new("AcmeEcho").unwrap(),
                    kind: RuntimeExtensionGlobalKind::Object,
                }],
                modules: vec![RuntimeExtensionModule {
                    specifier: NonEmptyString::new("acme:echo").unwrap(),
                }],
                callbacks: vec![RuntimeExtensionCallback {
                    id: StableId::new("completion").unwrap(),
                    operation_id: StableId::new("echo").unwrap(),
                    producer_affinity: RuntimeExtensionCallbackProducerAffinity::BackgroundProducer,
                    delivery: RuntimeExtensionCallbackDelivery::RuntimeThread,
                    max_pending: SafeUint::new(8).unwrap(),
                }],
                provider_abi: Some(RuntimeExtensionProviderAbi {
                    id: StableId::new("acme.echo.provider").unwrap(),
                    min_version: SafeUint::new(1).unwrap(),
                    selected_version: SafeUint::new(2).unwrap(),
                    struct_size: SafeUint::new(64).unwrap(),
                    identity_digest: digest("provider"),
                    linked_artifact_id: StableId::new("acme.echo.image").unwrap(),
                }),
                linked_artifact_ids: vec![StableId::new("acme.echo.image").unwrap()],
                authority_fragment: RuntimeExtensionAuthorityFragment {
                    schema: RUNTIME_EXTENSION_AUTHORITY_FRAGMENT_SCHEMA.into(),
                    namespace: StableId::new("acme.echo").unwrap(),
                    operations: vec![RuntimeExtensionOperation {
                        operation_id: StableId::new("echo").unwrap(),
                        authority_class: StableId::new("local.transform").unwrap(),
                        semantics: StableId::new(RUNTIME_EXTENSION_INVOKE_SEMANTICS).unwrap(),
                        stage: Stage::Requested,
                        atomicity_group: StableId::new("acme.echo.decision").unwrap(),
                        resource_kinds: vec![
                            NonEmptyString::new(RUNTIME_EXTENSION_RESOURCE_KIND).unwrap()
                        ],
                        js_entry_path: NonEmptyString::new("AcmeEcho.echo").unwrap(),
                        flags: SafeUint::ZERO,
                    }],
                },
            }],
            linked_artifacts: vec![RuntimeExtensionLinkedArtifactIdentity {
                artifact_id: StableId::new("acme.echo.image").unwrap(),
                extension_id: StableId::new("acme.echo").unwrap(),
                executable_object: ObjectIdentity {
                    platform: crate::model::ObjectPlatform::Unix,
                    volume: NonEmptyString::new("dev:1").unwrap(),
                    file: NonEmptyString::new("ino:2").unwrap(),
                },
                range: RuntimeExtensionLinkedArtifactRange {
                    offset: SafeUint::new(4096).unwrap(),
                    length: SafeUint::new(512).unwrap(),
                },
                content_digest: digest("linked-image"),
            }],
            mapped_executable: RuntimeExtensionMappedExecutableIdentity {
                schema: RUNTIME_EXTENSION_MAPPED_EXECUTABLE_SCHEMA.into(),
                executable_object: ObjectIdentity {
                    platform: crate::model::ObjectPlatform::Unix,
                    volume: NonEmptyString::new("dev:1").unwrap(),
                    file: NonEmptyString::new("ino:3").unwrap(),
                },
                range: RuntimeExtensionLinkedArtifactRange {
                    offset: SafeUint::ZERO,
                    length: SafeUint::new(16_384).unwrap(),
                },
                content_digest: digest("mapped-executable"),
                anchors: [
                    "acme.echo.lifecycle.checkpoint",
                    "acme.echo.lifecycle.close",
                    "acme.echo.lifecycle.install",
                    "acme.echo.lifecycle.quiesce",
                    "acme.echo.lifecycle.table",
                    "acme.echo.provider.factory",
                    "registry.build",
                    "registry.descriptors",
                    "registry.table",
                ]
                .into_iter()
                .enumerate()
                .map(|(index, label)| RuntimeExtensionMappedExecutableAnchor {
                    label: NonEmptyString::new(label).unwrap(),
                    image_offset: SafeUint::new(1024 + index as u64).unwrap(),
                })
                .collect(),
            },
        }
    }

    fn signed_capsule() -> RuntimeExtensionAuthorityCapsule {
        let mut capsule = unsigned_capsule();
        capsule.extension_set_digest = capsule.compute_extension_set_digest().unwrap();
        capsule.declared_executable_selection_identity =
            compute_declared_executable_selection_identity(
                capsule.target,
                capsule.profile,
                capsule.sdk_version,
                &capsule.runtime_features,
                &capsule.extension_set_digest,
                &capsule.descriptors,
                &capsule.linked_artifacts,
            )
            .unwrap();
        capsule.executable_selection_identity = compute_executable_selection_identity(
            &capsule.declared_executable_selection_identity,
            &capsule.mapped_executable,
        )
        .unwrap();
        capsule.authority_capsule_digest = capsule.compute_authority_capsule_digest().unwrap();
        capsule
    }

    #[test]
    fn validates_closed_namespaced_capsule_and_exact_lookup() {
        let capsule = signed_capsule();
        capsule.validate().unwrap();
        assert_eq!(
            capsule
                .authority_class("acme.echo", "echo")
                .map(StableId::as_str),
            Some("local.transform")
        );
        assert!(capsule.authority_class("other.echo", "echo").is_none());
        assert!(capsule.authority_class("acme.echo", "other").is_none());
    }

    #[test]
    fn operation_entry_paths_are_closed_to_declared_globals_and_modules() {
        for js_entry_path in [
            "AcmeEcho",
            "AcmeEcho.echo",
            "AcmeEcho#echo",
            "AcmeEcho#$private.nested",
            "acme:echo",
            "acme:echo#echo",
            "acme:echo#echo.nested",
        ] {
            let mut capsule = unsigned_capsule();
            capsule.descriptors[0].authority_fragment.operations[0].js_entry_path =
                NonEmptyString::new(js_entry_path).unwrap();
            validate_authority_contents(&capsule.descriptors, &capsule.linked_artifacts)
                .unwrap_or_else(|error| panic!("valid entry path {js_entry_path}: {error}"));
        }

        for js_entry_path in [
            "AcmeEcho..echo",
            "AcmeEcho.",
            "AcmeEcho.foo/bar",
            "AcmeEcho.foo-bar",
            "AcmeEcho.1bad",
            "AcmeEcho.child#echo",
            "acme:echo#bad..export",
            "acme:echo#bad.",
            "acme:echo#",
            "acme:echo##echo",
            "undeclared:module#echo",
            "Undeclared.echo",
        ] {
            let mut capsule = unsigned_capsule();
            capsule.descriptors[0].authority_fragment.operations[0].js_entry_path =
                NonEmptyString::new(js_entry_path).unwrap();
            let error =
                validate_authority_contents(&capsule.descriptors, &capsule.linked_artifacts)
                    .unwrap_err()
                    .to_string();
            assert!(
                error.contains("operation JS entry path"),
                "invalid entry path {js_entry_path}: {error}"
            );
        }

        let mut malformed_global = unsigned_capsule();
        malformed_global.descriptors[0].globals[0].name =
            NonEmptyString::new("AcmeEcho..nested").unwrap();
        let error = validate_authority_contents(
            &malformed_global.descriptors,
            &malformed_global.linked_artifacts,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("dotted identifier path"), "{error}");

        let mut authenticated_malformed = signed_capsule();
        authenticated_malformed.descriptors[0]
            .authority_fragment
            .operations[0]
            .js_entry_path = NonEmptyString::new("acme:echo#bad..export").unwrap();
        let error = authenticated_malformed.validate().unwrap_err().to_string();
        assert!(error.contains("operation JS entry path"), "{error}");
    }

    #[test]
    fn strict_parser_rejects_executable_semantic_fields() {
        let capsule = signed_capsule();
        let mut value = serde_json::to_value(capsule).unwrap();
        value["descriptors"][0]["authorityFragment"]["matcher"] = json!("manifest-code");
        let error = RuntimeExtensionAuthorityCapsule::parse_json(
            serde_json::to_string(&value).unwrap().as_bytes(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unknown field `matcher`"), "{error}");

        let duplicate = r#"{"schema":"a","schema":"b"}"#;
        assert!(RuntimeExtensionAuthorityCapsule::parse_json(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn rejects_set_digest_drift_and_descriptor_swap() {
        let mut stale_set = signed_capsule();
        stale_set.descriptors[0].version = NonEmptyString::new("2.0.0").unwrap();
        assert!(stale_set.validate().is_err());

        let mut swapped = signed_capsule();
        swapped.descriptors[0].globals[0].name = NonEmptyString::new("Replacement").unwrap();
        swapped.extension_set_digest = swapped.compute_extension_set_digest().unwrap();
        assert!(swapped.validate().is_err());
    }

    #[test]
    fn recomputes_declared_and_final_selection_and_requires_every_anchor_role() {
        let mut opaque_declared = signed_capsule();
        opaque_declared.declared_executable_selection_identity = digest("opaque-declared");
        opaque_declared.executable_selection_identity = opaque_declared
            .compute_executable_selection_identity()
            .unwrap();
        opaque_declared.authority_capsule_digest =
            opaque_declared.compute_authority_capsule_digest().unwrap();
        let error = opaque_declared.validate().unwrap_err().to_string();
        assert!(error.contains("declared executable-selection"), "{error}");

        let mut opaque_final = signed_capsule();
        opaque_final.executable_selection_identity = digest("opaque-final");
        opaque_final.authority_capsule_digest =
            opaque_final.compute_authority_capsule_digest().unwrap();
        let error = opaque_final.validate().unwrap_err().to_string();
        assert!(error.contains("final executable-selection"), "{error}");

        let mut missing_anchor = signed_capsule();
        missing_anchor.mapped_executable.anchors.remove(0);
        missing_anchor.executable_selection_identity = missing_anchor
            .compute_executable_selection_identity()
            .unwrap();
        missing_anchor.authority_capsule_digest =
            missing_anchor.compute_authority_capsule_digest().unwrap();
        let error = missing_anchor.validate().unwrap_err().to_string();
        assert!(error.contains("anchor inventory"), "{error}");

        let mut extra_anchor = signed_capsule();
        extra_anchor
            .mapped_executable
            .anchors
            .push(RuntimeExtensionMappedExecutableAnchor {
                label: NonEmptyString::new("acme.echo.host-services.factory").unwrap(),
                image_offset: SafeUint::new(2048).unwrap(),
            });
        extra_anchor
            .mapped_executable
            .anchors
            .sort_by(|left, right| left.label.as_str().cmp(right.label.as_str()));
        extra_anchor.executable_selection_identity = extra_anchor
            .compute_executable_selection_identity()
            .unwrap();
        extra_anchor.authority_capsule_digest =
            extra_anchor.compute_authority_capsule_digest().unwrap();
        let error = extra_anchor.validate().unwrap_err().to_string();
        assert!(error.contains("anchor inventory"), "{error}");
    }

    #[test]
    fn registry_projection_requires_every_authenticated_surface_field() {
        let capsule = signed_capsule();
        let projection = capsule.registry_projection();
        assert!(capsule
            .matches_registry_projection_json(&serde_json::to_vec(&projection).unwrap())
            .unwrap());

        let mut changed_operation = serde_json::to_value(&projection).unwrap();
        changed_operation["descriptors"][0]["authorityFragment"]["operations"][0]["flags"] =
            json!(1);
        assert!(!capsule
            .matches_registry_projection_json(&serde_json::to_vec(&changed_operation).unwrap())
            .unwrap());

        for (field, replacement) in [
            ("semantics", json!("runtime-extension.other")),
            ("stage", json!("commit")),
            ("atomicityGroup", json!("replacement.decision")),
            ("resourceKinds", json!(["path-exact"])),
        ] {
            let mut changed_effect = serde_json::to_value(&projection).unwrap();
            changed_effect["descriptors"][0]["authorityFragment"]["operations"][0][field] =
                replacement;
            assert!(
                !capsule
                    .matches_registry_projection_json(&serde_json::to_vec(&changed_effect).unwrap())
                    .unwrap(),
                "registry operation field {field} must be authenticated"
            );
        }

        let mut changed_callback = serde_json::to_value(&projection).unwrap();
        changed_callback["descriptors"][0]["callbacks"][0]["maxPending"] = json!(9);
        assert!(!capsule
            .matches_registry_projection_json(&serde_json::to_vec(&changed_callback).unwrap())
            .unwrap());

        let mut changed_selection = serde_json::to_value(&projection).unwrap();
        changed_selection["executableSelectionIdentity"] =
            serde_json::to_value(digest("other-selection")).unwrap();
        assert!(!capsule
            .matches_registry_projection_json(&serde_json::to_vec(&changed_selection).unwrap())
            .unwrap());

        let different_capsule_digest =
            serde_json::to_value(digest("other-authority-capsule")).unwrap();
        let mut inconsistent_descriptor_digest = serde_json::to_value(&projection).unwrap();
        inconsistent_descriptor_digest["descriptors"][0]["authorityCapsuleDigest"] =
            different_capsule_digest.clone();
        assert!(capsule
            .matches_registry_projection_json(
                &serde_json::to_vec(&inconsistent_descriptor_digest).unwrap()
            )
            .is_err());

        let mut changed_capsule_digest = serde_json::to_value(&projection).unwrap();
        changed_capsule_digest["authorityCapsuleDigest"] = different_capsule_digest.clone();
        changed_capsule_digest["descriptors"][0]["authorityCapsuleDigest"] =
            different_capsule_digest;
        assert!(!capsule
            .matches_registry_projection_json(&serde_json::to_vec(&changed_capsule_digest).unwrap())
            .unwrap());

        let mut executable_field = serde_json::to_value(projection).unwrap();
        executable_field["descriptors"][0]["normalizer"] = json!("extension-code");
        assert!(capsule
            .matches_registry_projection_json(&serde_json::to_vec(&executable_field).unwrap())
            .is_err());
    }

    #[test]
    fn rejects_out_of_range_callback_operation_provider_and_bootstrap_facts() {
        let mut callback = signed_capsule();
        callback.descriptors[0].callbacks[0].max_pending = SafeUint::ZERO;
        assert!(callback.validate().is_err());

        let mut operation = signed_capsule();
        operation.descriptors[0].authority_fragment.operations[0].flags =
            SafeUint::new(u64::from(u32::MAX) + 1).unwrap();
        assert!(operation.validate().is_err());

        let mut provider = signed_capsule();
        provider.descriptors[0]
            .provider_abi
            .as_mut()
            .unwrap()
            .selected_version = SafeUint::ZERO;
        assert!(provider.validate().is_err());

        let mut bootstrap = signed_capsule();
        bootstrap.descriptors[0]
            .bootstrap
            .push(RuntimeExtensionBootstrapArtifact {
                id: StableId::new("setup").unwrap(),
                format: RuntimeExtensionBootstrapFormat::HermesBytecode,
                evaluation_mode: RuntimeExtensionBootstrapEvaluationMode::ScriptGlobal,
                content_digest: digest("bootstrap"),
                source_url: NonEmptyString::new("ibex:extension/setup.hbc").unwrap(),
                byte_length: SafeUint::ZERO,
            });
        assert!(bootstrap.validate().is_err());
    }

    #[test]
    fn generic_wire_projection_has_no_product_vocabulary() {
        let text = serde_json::to_string(&signed_capsule()).unwrap();
        let web_product_upper = ["Web", "GPU"].concat();
        let web_product_lower = ["web", "gpu"].concat();
        for forbidden in [
            "Exact",
            "exact",
            web_product_upper.as_str(),
            web_product_lower.as_str(),
        ] {
            assert!(!text.contains(forbidden), "{text}");
        }
        assert!(!text.contains("matcher"));
        assert!(!text.contains("normalizer"));
    }
}
