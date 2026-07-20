//! Versioned, carrier-independent module artifact contract.
//!
//! @ref LLP 0027#canonical-encoding-and-validation — artifacts use strict
//! canonical JSON and are verified before cache publication or compilation.
//! @ref LLP 0027#digest-domains — semantic identity is independent of the
//! inline/prepared carrier while the physical payload is authenticated too.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use capsec_semantics::model::{Digest, NonEmptyString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::io::Read;

use super::identity::{ImportAttributes, SourceId};

pub const MODULE_ARTIFACT_SCHEMA_V1: &str = "ibex/module-artifact/1";
pub const MODULE_ARTIFACT_SEMANTIC_DOMAIN_V1: &str = "ibex:module-artifact:semantic:1";
pub const MODULE_ARTIFACT_FACTORY_DOMAIN_V1: &str = "ibex:module-artifact:factory:1";
pub const MODULE_ARTIFACT_FINGERPRINT_DOMAIN_V1: &str =
    "ibex:module-artifact:transform-fingerprint:1";
pub const MODULE_ARTIFACT_CACHE_DOMAIN_V1: &str = "ibex:module-artifact:cache-key:1";

/// Typed SourceId whose wire representation is the canonical versioned string,
/// not a second ad-hoc JSON embedding of the algebra.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalSourceId(pub SourceId);

impl Serialize for CanonicalSourceId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.encode().map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for CanonicalSourceId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        SourceId::decode(&encoded)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceGoalV1 {
    Module,
    CommonJs,
    Json,
    Builtin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceDialectV1 {
    Js,
    Jsx,
    Ts,
    Tsx,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransformFingerprintV1 {
    pub producer: NonEmptyString,
    pub parser_version: NonEmptyString,
    pub transform_version: NonEmptyString,
    pub hermes_target: NonEmptyString,
    pub typescript_jsx_options_digest: Digest,
    pub module_runner_abi: NonEmptyString,
    pub hermes_compat_version: NonEmptyString,
    pub commonjs_detector: NonEmptyString,
    pub commonjs_detector_version: NonEmptyString,
    pub output_options_digest: Digest,
}

impl TransformFingerprintV1 {
    pub fn digest(&self) -> Result<Digest> {
        digest_value(
            MODULE_ARTIFACT_FINGERPRINT_DOMAIN_V1,
            &serde_json::to_value(self)?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StaticEdgeV1 {
    /// A statically detected CommonJS `require("specifier")` call. This is a
    /// distinct edge kind because package conditions, authorization coverage,
    /// and cache identity differ from ESM static imports.
    CommonJsRequire { specifier: NonEmptyString },
    SideEffect {
        specifier: NonEmptyString,
        attributes: ImportAttributes,
    },
    Default {
        specifier: NonEmptyString,
        local: NonEmptyString,
        attributes: ImportAttributes,
    },
    Namespace {
        specifier: NonEmptyString,
        local: NonEmptyString,
        attributes: ImportAttributes,
    },
    Named {
        specifier: NonEmptyString,
        imported: NonEmptyString,
        local: NonEmptyString,
        attributes: ImportAttributes,
    },
    ReExportNamed {
        specifier: NonEmptyString,
        imported: NonEmptyString,
        exported: NonEmptyString,
        attributes: ImportAttributes,
    },
    ReExportStar {
        specifier: NonEmptyString,
        attributes: ImportAttributes,
    },
    ReExportNamespace {
        specifier: NonEmptyString,
        exported: NonEmptyString,
        attributes: ImportAttributes,
    },
}

impl StaticEdgeV1 {
    fn attributes(&self) -> Option<&ImportAttributes> {
        match self {
            Self::CommonJsRequire { .. } => None,
            Self::SideEffect { attributes, .. }
            | Self::Default { attributes, .. }
            | Self::Namespace { attributes, .. }
            | Self::Named { attributes, .. }
            | Self::ReExportNamed { attributes, .. }
            | Self::ReExportStar { attributes, .. }
            | Self::ReExportNamespace { attributes, .. } => Some(attributes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DynamicEdgeV1 {
    Literal {
        specifier: NonEmptyString,
        attributes: ImportAttributes,
    },
    /// The expression must be resolved and authorized at call time. `site`
    /// is stable producer order, not a source offset or host path.
    Computed { site: u32 },
}

impl DynamicEdgeV1 {
    pub fn literal_specifier(&self) -> Option<&str> {
        match self {
            Self::Literal { specifier, .. } => Some(specifier.as_str()),
            Self::Computed { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExportDescriptorV1 {
    Local {
        exported: NonEmptyString,
        local: NonEmptyString,
    },
    Indirect {
        exported: NonEmptyString,
        specifier: NonEmptyString,
        imported: NonEmptyString,
    },
    Star {
        specifier: NonEmptyString,
    },
    Namespace {
        exported: NonEmptyString,
        specifier: NonEmptyString,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommonJsExportsV1 {
    pub detector: NonEmptyString,
    pub detector_version: NonEmptyString,
    pub names: Vec<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reexports: Vec<NonEmptyString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceMapV1 {
    pub version: u8,
    pub source_ids: Vec<CanonicalSourceId>,
    pub names: Vec<String>,
    pub mappings: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleSemanticsV1 {
    pub source_id: CanonicalSourceId,
    pub source_goal: SourceGoalV1,
    pub dialect: Option<SourceDialectV1>,
    pub source_integrity: Digest,
    pub transform_fingerprint: TransformFingerprintV1,
    pub static_edges: Vec<StaticEdgeV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_edges: Vec<DynamicEdgeV1>,
    pub export_descriptors: Vec<ExportDescriptorV1>,
    pub commonjs_exports: Option<CommonJsExportsV1>,
    pub has_top_level_await: bool,
    pub factory_digest: Digest,
    pub source_map: SourceMapV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ModulePayloadV1 {
    Inline {
        encoding: InlineEncodingV1,
        factory_source: String,
    },
    Carrier {
        carrier_digest: Digest,
        entry_id: NonEmptyString,
        entry_factory_digest: Digest,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InlineEncodingV1 {
    Utf8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProducerIdentityV1 {
    InProcess {
        producer_id: NonEmptyString,
        producer_binary_digest: Digest,
    },
    Prepared {
        producer_id: NonEmptyString,
        producer_binary_digest: Digest,
        deployment_graph_digest: Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleArtifactV1 {
    pub schema: String,
    pub semantics: ModuleSemanticsV1,
    pub semantic_digest: Digest,
    pub payload: ModulePayloadV1,
    pub producer: ProducerIdentityV1,
}

#[derive(Debug, Clone)]
pub enum ArtifactAdmissionV1 {
    TrustedInProcess {
        expected_source_id: SourceId,
        expected_source_integrity: Digest,
        expected_producer_id: NonEmptyString,
        producer_binary_digest: Digest,
        transform_fingerprint_digest: Digest,
    },
    DigestBoundPrepared {
        expected_source_id: SourceId,
        expected_source_integrity: Digest,
        expected_producer_id: NonEmptyString,
        producer_binary_digest: Digest,
        deployment_graph_digest: Digest,
        expected_carrier_digest: Digest,
        expected_entry_id: NonEmptyString,
        authorized_semantic_digests: BTreeSet<Digest>,
        transform_fingerprint_digest: Digest,
    },
}

/// Capability returned only after structural, digest, source, transform, and
/// producer/deployment admission checks succeed. Native factory compilation
/// and cache publication consume this type rather than a raw deserialization.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedModuleArtifactV1<'a> {
    artifact: &'a ModuleArtifactV1,
}

#[derive(Debug, Clone)]
pub struct AdmittedModuleArtifactV1 {
    artifact: ModuleArtifactV1,
}

impl AdmittedModuleArtifactV1 {
    pub fn decode(bytes: &[u8], admission: &ArtifactAdmissionV1) -> Result<Self> {
        let artifact = ModuleArtifactV1::decode_canonical(bytes)?;
        artifact.verify_for_admission(admission)?;
        Ok(Self { artifact })
    }

    pub fn verified(&self) -> VerifiedModuleArtifactV1<'_> {
        VerifiedModuleArtifactV1 {
            artifact: &self.artifact,
        }
    }

    pub fn artifact(&self) -> &ModuleArtifactV1 {
        &self.artifact
    }
}

impl<'a> VerifiedModuleArtifactV1<'a> {
    pub fn artifact(self) -> &'a ModuleArtifactV1 {
        self.artifact
    }

    pub fn inline_factory_source(self) -> Option<&'a str> {
        match &self.artifact.payload {
            ModulePayloadV1::Inline { factory_source, .. } => Some(factory_source),
            ModulePayloadV1::Carrier { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactCacheKeyV1 {
    schema: String,
    source_id: CanonicalSourceId,
    source_integrity: Digest,
    transform_fingerprint_digest: Digest,
    engine_binary_digest: Digest,
    producer_binary_digest: Digest,
    runtime_configuration_digest: Digest,
}

impl ArtifactCacheKeyV1 {
    pub fn for_verified(
        verified: VerifiedModuleArtifactV1<'_>,
        engine_binary_digest: Digest,
        runtime_configuration_digest: Digest,
    ) -> Result<Self> {
        let artifact = verified.artifact();
        let producer_binary_digest = match &artifact.producer {
            ProducerIdentityV1::InProcess {
                producer_binary_digest,
                ..
            }
            | ProducerIdentityV1::Prepared {
                producer_binary_digest,
                ..
            } => producer_binary_digest.clone(),
        };
        Ok(Self {
            schema: MODULE_ARTIFACT_SCHEMA_V1.into(),
            source_id: artifact.semantics.source_id.clone(),
            source_integrity: artifact.semantics.source_integrity.clone(),
            transform_fingerprint_digest: artifact.semantics.transform_fingerprint.digest()?,
            engine_binary_digest,
            producer_binary_digest,
            runtime_configuration_digest,
        })
    }

    pub fn digest(&self) -> Result<Digest> {
        digest_value(
            MODULE_ARTIFACT_CACHE_DOMAIN_V1,
            &serde_json::to_value(self)?,
        )
    }
}

impl ModuleArtifactV1 {
    pub fn new_inline(
        semantics: ModuleSemanticsV1,
        factory_source: String,
        producer: ProducerIdentityV1,
    ) -> Result<Self> {
        let observed = digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory_source.as_bytes())?;
        if observed != semantics.factory_digest {
            bail!("inline factory bytes disagree with the semantic factory digest");
        }
        let semantic_digest = semantics_digest(&semantics)?;
        let artifact = Self {
            schema: MODULE_ARTIFACT_SCHEMA_V1.to_owned(),
            semantics,
            semantic_digest,
            payload: ModulePayloadV1::Inline {
                encoding: InlineEncodingV1::Utf8,
                factory_source,
            },
            producer,
        };
        artifact.validate_structure()?;
        Ok(artifact)
    }

    pub fn new_carrier(
        semantics: ModuleSemanticsV1,
        carrier_digest: Digest,
        entry_id: NonEmptyString,
        producer: ProducerIdentityV1,
    ) -> Result<Self> {
        let semantic_digest = semantics_digest(&semantics)?;
        let entry_factory_digest = semantics.factory_digest.clone();
        let artifact = Self {
            schema: MODULE_ARTIFACT_SCHEMA_V1.to_owned(),
            semantics,
            semantic_digest,
            payload: ModulePayloadV1::Carrier {
                carrier_digest,
                entry_id,
                entry_factory_digest,
            },
            producer,
        };
        artifact.validate_structure()?;
        Ok(artifact)
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        let value = serde_json::to_value(self)?;
        capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| anyhow!("cannot canonicalize ModuleArtifact: {error}"))
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).context("ModuleArtifact is not UTF-8")?;
        let value = capsec_semantics::strict_json::parse_strict(text)
            .map_err(|error| anyhow!("ModuleArtifact is not strict JSON: {error}"))?;
        let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| anyhow!("cannot canonicalize ModuleArtifact: {error}"))?;
        if canonical != bytes {
            bail!("ModuleArtifact bytes are not canonical JCS");
        }
        let artifact: Self =
            serde_json::from_value(value).context("ModuleArtifact has an invalid shape")?;
        artifact.validate_structure()?;
        Ok(artifact)
    }

    pub fn verify_for_admission(
        &self,
        admission: &ArtifactAdmissionV1,
    ) -> Result<VerifiedModuleArtifactV1<'_>> {
        self.validate_structure()?;
        let (expected_source_id, expected_source_integrity, expected_fingerprint) = match admission
        {
            ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id,
                expected_source_integrity,
                expected_producer_id,
                producer_binary_digest,
                transform_fingerprint_digest,
            } => {
                match &self.producer {
                    ProducerIdentityV1::InProcess {
                        producer_id,
                        producer_binary_digest: observed,
                        ..
                    } if producer_id == expected_producer_id
                        && observed == producer_binary_digest => {}
                    _ => bail!("artifact is not from the trusted in-process producer"),
                }
                (
                    expected_source_id,
                    expected_source_integrity,
                    transform_fingerprint_digest,
                )
            }
            ArtifactAdmissionV1::DigestBoundPrepared {
                expected_source_id,
                expected_source_integrity,
                expected_producer_id,
                producer_binary_digest,
                deployment_graph_digest,
                expected_carrier_digest,
                expected_entry_id,
                authorized_semantic_digests,
                transform_fingerprint_digest,
            } => {
                match &self.producer {
                    ProducerIdentityV1::Prepared {
                        producer_id,
                        producer_binary_digest: observed_producer,
                        deployment_graph_digest: observed_graph,
                        ..
                    } if producer_id == expected_producer_id
                        && observed_producer == producer_binary_digest
                        && observed_graph == deployment_graph_digest => {}
                    _ => bail!("prepared artifact producer or deployment graph is stale"),
                }
                if !authorized_semantic_digests.contains(&self.semantic_digest) {
                    bail!("prepared artifact semantic digest is absent from the deployment graph");
                }
                match &self.payload {
                    ModulePayloadV1::Carrier {
                        carrier_digest,
                        entry_id,
                        ..
                    } if carrier_digest == expected_carrier_digest
                        && entry_id == expected_entry_id => {}
                    _ => bail!("prepared artifact carrier or entry is not deployment-bound"),
                }
                (
                    expected_source_id,
                    expected_source_integrity,
                    transform_fingerprint_digest,
                )
            }
        };

        if &self.semantics.source_id.0 != expected_source_id {
            bail!("artifact SourceId disagrees with authenticated resolution");
        }
        if &self.semantics.source_integrity != expected_source_integrity {
            bail!("artifact source integrity disagrees with authenticated source bytes");
        }
        if &self.semantics.transform_fingerprint.digest()? != expected_fingerprint {
            bail!("artifact transform fingerprint is stale");
        }
        Ok(VerifiedModuleArtifactV1 { artifact: self })
    }

    fn validate_structure(&self) -> Result<()> {
        if self.schema != MODULE_ARTIFACT_SCHEMA_V1 {
            bail!("unsupported ModuleArtifact schema {:?}", self.schema);
        }
        validate_semantics(&self.semantics)?;
        let expected_semantic_digest = semantics_digest(&self.semantics)?;
        if self.semantic_digest != expected_semantic_digest {
            bail!("ModuleArtifact semantic digest is stale or tampered");
        }
        match &self.payload {
            ModulePayloadV1::Inline { factory_source, .. } => {
                if factory_source.is_empty() {
                    bail!("inline factory source must not be empty");
                }
                let observed =
                    digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory_source.as_bytes())?;
                if observed != self.semantics.factory_digest {
                    bail!("inline factory payload does not match semantic factory digest");
                }
                if !matches!(self.producer, ProducerIdentityV1::InProcess { .. }) {
                    bail!("inline artifacts require an in-process producer identity");
                }
            }
            ModulePayloadV1::Carrier {
                entry_factory_digest,
                ..
            } => {
                if entry_factory_digest != &self.semantics.factory_digest {
                    bail!("carrier entry does not bind the semantic factory digest");
                }
                if !matches!(self.producer, ProducerIdentityV1::Prepared { .. }) {
                    bail!("carrier artifacts require a prepared producer identity");
                }
            }
        }
        Ok(())
    }
}

pub fn digest_bytes(domain: &str, bytes: &[u8]) -> Result<Digest> {
    digest_reader(domain, bytes)
}

/// Compute the same domain-separated digest as [`digest_bytes`] without
/// materializing the complete input. Large executable carriers use this path
/// so authentication does not require a second binary-sized allocation.
pub fn digest_reader(domain: &str, mut reader: impl Read) -> Result<Digest> {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut chunk)
            .context("read domain-separated digest input")?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    Digest::new(format!(
        "sha256-{}",
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    ))
    .map_err(anyhow::Error::msg)
}

pub fn source_integrity(bytes: &[u8]) -> Result<Digest> {
    Digest::new(format!(
        "sha256-{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
    ))
    .map_err(anyhow::Error::msg)
}

fn digest_value(domain: &str, value: &serde_json::Value) -> Result<Digest> {
    let canonical = capsec_semantics::canonical::to_jcs_bytes(value)
        .map_err(|error| anyhow!("cannot canonicalize digest input: {error}"))?;
    digest_bytes(domain, &canonical)
}

pub(crate) fn semantics_digest(semantics: &ModuleSemanticsV1) -> Result<Digest> {
    digest_value(
        MODULE_ARTIFACT_SEMANTIC_DOMAIN_V1,
        &serde_json::to_value(semantics)?,
    )
}

fn validate_semantics(semantics: &ModuleSemanticsV1) -> Result<()> {
    match (&semantics.source_id.0, semantics.source_goal) {
        (SourceId::Builtin { .. }, SourceGoalV1::Builtin) => {}
        (SourceId::Builtin { .. }, _) => bail!("builtin SourceId requires builtin source goal"),
        (_, SourceGoalV1::Builtin) => bail!("builtin source goal requires builtin SourceId"),
        _ => {}
    }
    let executable_source = matches!(
        semantics.source_goal,
        SourceGoalV1::Module | SourceGoalV1::CommonJs | SourceGoalV1::Builtin
    );
    if executable_source != semantics.dialect.is_some() {
        bail!("source dialect presence disagrees with source goal");
    }
    if semantics.has_top_level_await && semantics.source_goal != SourceGoalV1::Module {
        bail!("top-level await is only valid for Module source goal");
    }
    match semantics.source_goal {
        SourceGoalV1::Module => {
            if semantics
                .static_edges
                .iter()
                .any(|edge| matches!(edge, StaticEdgeV1::CommonJsRequire { .. }))
            {
                bail!("CommonJS require edges require CommonJs source goal");
            }
        }
        SourceGoalV1::CommonJs | SourceGoalV1::Builtin => {
            if semantics
                .static_edges
                .iter()
                .any(|edge| !matches!(edge, StaticEdgeV1::CommonJsRequire { .. }))
                || !semantics.export_descriptors.is_empty()
            {
                bail!("ESM static edges/exports require Module source goal");
            }
        }
        SourceGoalV1::Json => {
            if !semantics.static_edges.is_empty()
                || !semantics.dynamic_edges.is_empty()
                || !semantics.export_descriptors.is_empty()
            {
                bail!("module edges/exports require an executable source goal");
            }
        }
    }
    match (&semantics.commonjs_exports, semantics.source_goal) {
        (Some(exports), SourceGoalV1::CommonJs | SourceGoalV1::Builtin) => {
            if exports.detector != semantics.transform_fingerprint.commonjs_detector
                || exports.detector_version
                    != semantics.transform_fingerprint.commonjs_detector_version
            {
                bail!("CommonJS detector identity disagrees with transform fingerprint");
            }
            if exports.names.windows(2).any(|pair| pair[0] >= pair[1]) {
                bail!("CommonJS detected names must be sorted and unique");
            }
            if exports.reexports.windows(2).any(|pair| pair[0] >= pair[1]) {
                bail!("CommonJS reexports must be sorted and unique");
            }
            let require_specifiers = semantics
                .static_edges
                .iter()
                .filter_map(|edge| match edge {
                    StaticEdgeV1::CommonJsRequire { specifier } => Some(specifier),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            if exports
                .reexports
                .iter()
                .any(|specifier| !require_specifiers.contains(specifier))
            {
                bail!("CommonJS reexport lacks a matching require edge");
            }
        }
        (None, SourceGoalV1::CommonJs | SourceGoalV1::Builtin) => {
            bail!("CommonJS-shaped artifact lacks detector output")
        }
        (Some(_), _) => bail!("CommonJS detector output is invalid for this source goal"),
        (None, _) => {}
    }
    for edge in &semantics.static_edges {
        if let Some(attributes) = edge.attributes() {
            ImportAttributes::new(attributes.entries().clone())?;
        }
    }
    let mut computed_sites = BTreeSet::new();
    for edge in &semantics.dynamic_edges {
        match edge {
            DynamicEdgeV1::Literal { attributes, .. } => {
                ImportAttributes::new(attributes.entries().clone())?;
            }
            DynamicEdgeV1::Computed { site } if computed_sites.insert(*site) => {}
            DynamicEdgeV1::Computed { .. } => {
                bail!("computed dynamic-import sites must be unique")
            }
        }
    }
    if semantics.source_map.version != 3 {
        bail!("only source-map version 3 is supported");
    }
    if semantics.source_map.source_ids.is_empty()
        || semantics.source_map.source_ids[0] != semantics.source_id
    {
        bail!("source map must begin with the artifact SourceId");
    }
    if semantics
        .source_map
        .source_ids
        .iter()
        .collect::<BTreeSet<_>>()
        .len()
        != semantics.source_map.source_ids.len()
    {
        bail!("source map SourceIds must be unique");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsec_semantics::model::{PathComponent, Principal};

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct RejectionFixtureManifest {
        schema: String,
        cases: Vec<RejectionFixtureCase>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct RejectionFixtureCase {
        id: String,
        mutation: String,
        expected: String,
    }

    fn digest(label: &str) -> Digest {
        digest_bytes("test", label.as_bytes()).unwrap()
    }

    #[test]
    fn streaming_digest_matches_the_byte_slice_contract() {
        let bytes = vec![0x5au8; 192 * 1024 + 17];
        assert_eq!(
            digest_reader("streaming-test", std::io::Cursor::new(&bytes)).unwrap(),
            digest_bytes("streaming-test", &bytes).unwrap()
        );
    }

    fn source_id() -> SourceId {
        SourceId::file(
            Principal::Root {
                identity: NonEmptyString::new("project-fixture").unwrap(),
            },
            vec![
                PathComponent::utf8("src").unwrap(),
                PathComponent::utf8("main.mjs").unwrap(),
            ],
        )
        .unwrap()
    }

    fn fingerprint() -> TransformFingerprintV1 {
        TransformFingerprintV1 {
            producer: NonEmptyString::new("ibex-oxc").unwrap(),
            parser_version: NonEmptyString::new("oxc-1").unwrap(),
            transform_version: NonEmptyString::new("ibex-transform-1").unwrap(),
            hermes_target: NonEmptyString::new("hermes-0.13-bytecode-96").unwrap(),
            typescript_jsx_options_digest: digest("ts-jsx"),
            module_runner_abi: NonEmptyString::new("ibex-module-runner-1").unwrap(),
            hermes_compat_version: NonEmptyString::new("hermes-compat-1").unwrap(),
            commonjs_detector: NonEmptyString::new("cjs-module-lexer").unwrap(),
            commonjs_detector_version: NonEmptyString::new("2.1.0").unwrap(),
            output_options_digest: digest("options"),
        }
    }

    fn artifact() -> ModuleArtifactV1 {
        let source_id = source_id();
        let factory = "function ($export, context) { return { execute: function () {} }; }";
        let semantics = ModuleSemanticsV1 {
            source_id: CanonicalSourceId(source_id.clone()),
            source_goal: SourceGoalV1::Module,
            dialect: Some(SourceDialectV1::Js),
            source_integrity: digest("source"),
            transform_fingerprint: fingerprint(),
            static_edges: vec![StaticEdgeV1::Named {
                specifier: NonEmptyString::new("dep").unwrap(),
                imported: NonEmptyString::new("value").unwrap(),
                local: NonEmptyString::new("value").unwrap(),
                attributes: ImportAttributes::default(),
            }],
            dynamic_edges: Vec::new(),
            export_descriptors: vec![ExportDescriptorV1::Local {
                exported: NonEmptyString::new("value").unwrap(),
                local: NonEmptyString::new("value").unwrap(),
            }],
            commonjs_exports: None,
            has_top_level_await: false,
            factory_digest: digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory.as_bytes())
                .unwrap(),
            source_map: SourceMapV1 {
                version: 3,
                source_ids: vec![CanonicalSourceId(source_id)],
                names: vec!["value".into()],
                mappings: "AAAA".into(),
            },
        };
        ModuleArtifactV1::new_inline(
            semantics,
            factory.into(),
            ProducerIdentityV1::InProcess {
                producer_id: NonEmptyString::new("ibex-runtime").unwrap(),
                producer_binary_digest: digest("producer"),
            },
        )
        .unwrap()
    }

    #[test]
    fn canonical_round_trip_and_trusted_admission() {
        let artifact = artifact();
        let bytes = artifact.encode_canonical().unwrap();
        assert_eq!(
            ModuleArtifactV1::decode_canonical(&bytes).unwrap(),
            artifact
        );
        let admission = ArtifactAdmissionV1::TrustedInProcess {
            expected_source_id: source_id(),
            expected_source_integrity: digest("source"),
            expected_producer_id: NonEmptyString::new("ibex-runtime").unwrap(),
            producer_binary_digest: digest("producer"),
            transform_fingerprint_digest: fingerprint().digest().unwrap(),
        };
        let admitted = AdmittedModuleArtifactV1::decode(&bytes, &admission).unwrap();
        assert_eq!(admitted.artifact(), &artifact);
    }

    #[test]
    fn rejects_noncanonical_unknown_duplicate_and_field_substitution() {
        let artifact = artifact();
        let bytes = artifact.encode_canonical().unwrap();
        let mut spaced = b" ".to_vec();
        spaced.extend_from_slice(&bytes);
        assert!(ModuleArtifactV1::decode_canonical(&spaced).is_err());

        let text = String::from_utf8(bytes.clone()).unwrap();
        let duplicate = text.replacen(
            "{\"payload\"",
            "{\"schema\":\"ibex/module-artifact/1\",\"payload\"",
            1,
        );
        assert!(ModuleArtifactV1::decode_canonical(duplicate.as_bytes()).is_err());

        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["unexpected"] = serde_json::json!(true);
        let unknown = capsec_semantics::canonical::to_jcs_bytes(&value).unwrap();
        assert!(ModuleArtifactV1::decode_canonical(&unknown).is_err());

        value.as_object_mut().unwrap().remove("unexpected");
        value["semantics"]["hasTopLevelAwait"] = serde_json::json!(true);
        let substituted = capsec_semantics::canonical::to_jcs_bytes(&value).unwrap();
        assert!(ModuleArtifactV1::decode_canonical(&substituted).is_err());
    }

    #[test]
    fn inline_and_carrier_share_semantic_digest_but_not_payload_trust() {
        let inline = artifact();
        let carrier = ModuleArtifactV1::new_carrier(
            inline.semantics.clone(),
            digest("carrier"),
            NonEmptyString::new("entry-0").unwrap(),
            ProducerIdentityV1::Prepared {
                producer_id: NonEmptyString::new("ibex-builder").unwrap(),
                producer_binary_digest: digest("prepared-producer"),
                deployment_graph_digest: digest("graph"),
            },
        )
        .unwrap();
        assert_eq!(inline.semantic_digest, carrier.semantic_digest);
        assert!(carrier
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: source_id(),
                expected_source_integrity: digest("source"),
                expected_producer_id: NonEmptyString::new("ibex-runtime").unwrap(),
                producer_binary_digest: digest("producer"),
                transform_fingerprint_digest: fingerprint().digest().unwrap(),
            })
            .is_err());
        carrier
            .verify_for_admission(&ArtifactAdmissionV1::DigestBoundPrepared {
                expected_source_id: source_id(),
                expected_source_integrity: digest("source"),
                expected_producer_id: NonEmptyString::new("ibex-builder").unwrap(),
                producer_binary_digest: digest("prepared-producer"),
                deployment_graph_digest: digest("graph"),
                expected_carrier_digest: digest("carrier"),
                expected_entry_id: NonEmptyString::new("entry-0").unwrap(),
                authorized_semantic_digests: [carrier.semantic_digest.clone()]
                    .into_iter()
                    .collect(),
                transform_fingerprint_digest: fingerprint().digest().unwrap(),
            })
            .unwrap();
    }

    #[test]
    fn rejects_payload_tampering_stale_producer_and_source_map_substitution() {
        let artifact = artifact();
        let mut payload_tamper = artifact.clone();
        let ModulePayloadV1::Inline { factory_source, .. } = &mut payload_tamper.payload else {
            unreachable!()
        };
        factory_source.push_str(" tampered");
        assert!(payload_tamper.validate_structure().is_err());

        assert!(artifact
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: source_id(),
                expected_source_integrity: digest("source"),
                expected_producer_id: NonEmptyString::new("ibex-runtime").unwrap(),
                producer_binary_digest: digest("stale-producer"),
                transform_fingerprint_digest: fingerprint().digest().unwrap(),
            })
            .is_err());

        let mut map_tamper = artifact.clone();
        map_tamper.semantics.source_map.source_ids[0] =
            CanonicalSourceId(SourceId::synthetic("session", "other-source").unwrap());
        map_tamper.semantic_digest = semantics_digest(&map_tamper.semantics).unwrap();
        assert!(map_tamper.validate_structure().is_err());
    }

    #[test]
    fn cache_key_covers_engine_producer_and_runtime_configuration() {
        let artifact = artifact();
        let verified = artifact
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: source_id(),
                expected_source_integrity: digest("source"),
                expected_producer_id: NonEmptyString::new("ibex-runtime").unwrap(),
                producer_binary_digest: digest("producer"),
                transform_fingerprint_digest: fingerprint().digest().unwrap(),
            })
            .unwrap();
        let base =
            ArtifactCacheKeyV1::for_verified(verified, digest("engine"), digest("config")).unwrap();
        let stale_engine =
            ArtifactCacheKeyV1::for_verified(verified, digest("other-engine"), digest("config"))
                .unwrap();
        assert_ne!(base.digest().unwrap(), stale_engine.digest().unwrap());
    }

    #[test]
    fn checked_in_rejection_manifest_drives_every_tamper_fixture() {
        let fixtures: RejectionFixtureManifest = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/module-artifact-v1/rejections.json"
        ))
        .unwrap();
        assert_eq!(fixtures.schema, "ibex/module-artifact-rejection-fixtures/1");
        let expected_source_id = source_id();
        let expected_integrity = digest("source");
        let expected_fingerprint = fingerprint().digest().unwrap();

        for case in fixtures.cases {
            assert!(!case.id.is_empty());
            assert!(!case.expected.is_empty());
            let base = artifact();
            let rejected = match case.mutation.as_str() {
                "prefix-whitespace" => {
                    let mut bytes = b" ".to_vec();
                    bytes.extend(base.encode_canonical().unwrap());
                    ModuleArtifactV1::decode_canonical(&bytes).is_err()
                }
                "duplicate-schema" => {
                    let text = String::from_utf8(base.encode_canonical().unwrap()).unwrap();
                    let duplicate = text.replacen(
                        "{\"payload\"",
                        "{\"schema\":\"ibex/module-artifact/1\",\"payload\"",
                        1,
                    );
                    ModuleArtifactV1::decode_canonical(duplicate.as_bytes()).is_err()
                }
                "add-unknown-field" | "toggle-tla-without-redigest" => {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&base.encode_canonical().unwrap()).unwrap();
                    if case.mutation == "add-unknown-field" {
                        value["unknown"] = serde_json::json!(true);
                    } else {
                        value["semantics"]["hasTopLevelAwait"] = serde_json::json!(true);
                    }
                    let bytes = capsec_semantics::canonical::to_jcs_bytes(&value).unwrap();
                    ModuleArtifactV1::decode_canonical(&bytes).is_err()
                }
                "replace-inline-factory" => {
                    let mut changed = base;
                    let ModulePayloadV1::Inline { factory_source, .. } = &mut changed.payload
                    else {
                        unreachable!()
                    };
                    factory_source.push_str("tamper");
                    changed.validate_structure().is_err()
                }
                "replace-primary-source-id" => {
                    let mut changed = base;
                    changed.semantics.source_map.source_ids[0] =
                        CanonicalSourceId(SourceId::synthetic("session", "different").unwrap());
                    changed.semantic_digest = semantics_digest(&changed.semantics).unwrap();
                    changed.validate_structure().is_err()
                }
                "replace-carrier-entry-digest" => {
                    let mut changed = base;
                    changed.payload = ModulePayloadV1::Carrier {
                        carrier_digest: digest("carrier"),
                        entry_id: NonEmptyString::new("entry").unwrap(),
                        entry_factory_digest: digest("different-factory"),
                    };
                    changed.producer = ProducerIdentityV1::Prepared {
                        producer_id: NonEmptyString::new("builder").unwrap(),
                        producer_binary_digest: digest("prepared"),
                        deployment_graph_digest: digest("graph"),
                    };
                    changed.validate_structure().is_err()
                }
                "replace-producer-binary-digest" => base
                    .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                        expected_source_id: expected_source_id.clone(),
                        expected_source_integrity: expected_integrity.clone(),
                        expected_producer_id: NonEmptyString::new("ibex-runtime").unwrap(),
                        producer_binary_digest: digest("stale"),
                        transform_fingerprint_digest: expected_fingerprint.clone(),
                    })
                    .is_err(),
                "replace-transform-version" => {
                    let mut changed = base;
                    changed.semantics.transform_fingerprint.transform_version =
                        NonEmptyString::new("stale-transform").unwrap();
                    changed.semantic_digest = semantics_digest(&changed.semantics).unwrap();
                    changed
                        .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                            expected_source_id: expected_source_id.clone(),
                            expected_source_integrity: expected_integrity.clone(),
                            expected_producer_id: NonEmptyString::new("ibex-runtime").unwrap(),
                            producer_binary_digest: digest("producer"),
                            transform_fingerprint_digest: expected_fingerprint.clone(),
                        })
                        .is_err()
                }
                "replace-source-id" => {
                    let mut changed = base;
                    let replacement = SourceId::synthetic("session", "replacement").unwrap();
                    changed.semantics.source_id = CanonicalSourceId(replacement.clone());
                    changed.semantics.source_map.source_ids[0] = CanonicalSourceId(replacement);
                    changed.semantic_digest = semantics_digest(&changed.semantics).unwrap();
                    changed
                        .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                            expected_source_id: expected_source_id.clone(),
                            expected_source_integrity: expected_integrity.clone(),
                            expected_producer_id: NonEmptyString::new("ibex-runtime").unwrap(),
                            producer_binary_digest: digest("producer"),
                            transform_fingerprint_digest: expected_fingerprint.clone(),
                        })
                        .is_err()
                }
                other => panic!("unknown checked-in artifact mutation {other:?}"),
            };
            assert!(rejected, "fixture {} was unexpectedly admitted", case.id);
        }
    }

    #[test]
    fn checked_in_schema_names_the_exact_v1_envelope() {
        let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../schemas/module-artifact-v1.schema.json"
        ))
        .unwrap();
        assert_eq!(
            schema["properties"]["schema"]["const"],
            MODULE_ARTIFACT_SCHEMA_V1
        );
        assert_eq!(schema["additionalProperties"], false);
    }

    #[test]
    fn every_v1_edge_export_and_source_goal_round_trips() {
        let mut module = artifact();
        let attrs = ImportAttributes::default();
        module.semantics.static_edges = vec![
            StaticEdgeV1::SideEffect {
                specifier: NonEmptyString::new("side").unwrap(),
                attributes: attrs.clone(),
            },
            StaticEdgeV1::Default {
                specifier: NonEmptyString::new("default").unwrap(),
                local: NonEmptyString::new("defaultValue").unwrap(),
                attributes: attrs.clone(),
            },
            StaticEdgeV1::Namespace {
                specifier: NonEmptyString::new("namespace").unwrap(),
                local: NonEmptyString::new("namespaceValue").unwrap(),
                attributes: attrs.clone(),
            },
            StaticEdgeV1::Named {
                specifier: NonEmptyString::new("named").unwrap(),
                imported: NonEmptyString::new("before").unwrap(),
                local: NonEmptyString::new("after").unwrap(),
                attributes: attrs.clone(),
            },
            StaticEdgeV1::ReExportNamed {
                specifier: NonEmptyString::new("reexport").unwrap(),
                imported: NonEmptyString::new("before").unwrap(),
                exported: NonEmptyString::new("after").unwrap(),
                attributes: attrs.clone(),
            },
            StaticEdgeV1::ReExportStar {
                specifier: NonEmptyString::new("star").unwrap(),
                attributes: attrs.clone(),
            },
            StaticEdgeV1::ReExportNamespace {
                specifier: NonEmptyString::new("namespace-reexport").unwrap(),
                exported: NonEmptyString::new("ns").unwrap(),
                attributes: attrs,
            },
        ];
        module.semantics.export_descriptors = vec![
            ExportDescriptorV1::Local {
                exported: NonEmptyString::new("local").unwrap(),
                local: NonEmptyString::new("local").unwrap(),
            },
            ExportDescriptorV1::Indirect {
                exported: NonEmptyString::new("after").unwrap(),
                specifier: NonEmptyString::new("reexport").unwrap(),
                imported: NonEmptyString::new("before").unwrap(),
            },
            ExportDescriptorV1::Star {
                specifier: NonEmptyString::new("star").unwrap(),
            },
            ExportDescriptorV1::Namespace {
                exported: NonEmptyString::new("ns").unwrap(),
                specifier: NonEmptyString::new("namespace-reexport").unwrap(),
            },
        ];
        module.semantic_digest = semantics_digest(&module.semantics).unwrap();
        let bytes = module.encode_canonical().unwrap();
        assert_eq!(ModuleArtifactV1::decode_canonical(&bytes).unwrap(), module);

        let variants = [
            (
                SourceGoalV1::CommonJs,
                SourceId::file(
                    Principal::Root {
                        identity: NonEmptyString::new("project-fixture").unwrap(),
                    },
                    vec![PathComponent::utf8("main.cjs").unwrap()],
                )
                .unwrap(),
                Some(SourceDialectV1::Js),
            ),
            (
                SourceGoalV1::Json,
                SourceId::file(
                    Principal::Root {
                        identity: NonEmptyString::new("project-fixture").unwrap(),
                    },
                    vec![PathComponent::utf8("data.json").unwrap()],
                )
                .unwrap(),
                None,
            ),
            (
                SourceGoalV1::Builtin,
                SourceId::builtin("ibex-runtime", "node:path").unwrap(),
                Some(SourceDialectV1::Js),
            ),
            (
                SourceGoalV1::Module,
                SourceId::synthetic("session", "stdin").unwrap(),
                Some(SourceDialectV1::Js),
            ),
        ];
        for (goal, source_id, dialect) in variants {
            let factory = "function () { return { execute: function () {} }; }";
            let commonjs_exports = matches!(goal, SourceGoalV1::CommonJs | SourceGoalV1::Builtin)
                .then(|| CommonJsExportsV1 {
                    detector: fingerprint().commonjs_detector,
                    detector_version: fingerprint().commonjs_detector_version,
                    names: vec![NonEmptyString::new("answer").unwrap()],
                    reexports: Vec::new(),
                });
            let semantics = ModuleSemanticsV1 {
                source_id: CanonicalSourceId(source_id.clone()),
                source_goal: goal,
                dialect,
                source_integrity: digest("variant-source"),
                transform_fingerprint: fingerprint(),
                static_edges: Vec::new(),
                dynamic_edges: Vec::new(),
                export_descriptors: Vec::new(),
                commonjs_exports,
                has_top_level_await: false,
                factory_digest: digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory.as_bytes())
                    .unwrap(),
                source_map: SourceMapV1 {
                    version: 3,
                    source_ids: vec![CanonicalSourceId(source_id)],
                    names: Vec::new(),
                    mappings: String::new(),
                },
            };
            let variant = ModuleArtifactV1::new_inline(
                semantics,
                factory.into(),
                ProducerIdentityV1::InProcess {
                    producer_id: NonEmptyString::new("ibex-runtime").unwrap(),
                    producer_binary_digest: digest("producer"),
                },
            )
            .unwrap();
            assert_eq!(
                ModuleArtifactV1::decode_canonical(&variant.encode_canonical().unwrap()).unwrap(),
                variant
            );
        }
    }

    #[test]
    fn commonjs_require_edges_are_goal_typed_and_round_trip() {
        let base = artifact();
        let factory_source = match base.payload {
            ModulePayloadV1::Inline { factory_source, .. } => factory_source,
            ModulePayloadV1::Carrier { .. } => unreachable!(),
        };
        let mut semantics = base.semantics;
        semantics.source_goal = SourceGoalV1::CommonJs;
        semantics.static_edges = vec![StaticEdgeV1::CommonJsRequire {
            specifier: NonEmptyString::new("conditional-package").unwrap(),
        }];
        semantics.export_descriptors.clear();
        semantics.commonjs_exports = Some(CommonJsExportsV1 {
            detector: semantics.transform_fingerprint.commonjs_detector.clone(),
            detector_version: semantics
                .transform_fingerprint
                .commonjs_detector_version
                .clone(),
            names: vec![NonEmptyString::new("answer").unwrap()],
            reexports: Vec::new(),
        });
        let commonjs =
            ModuleArtifactV1::new_inline(semantics, factory_source, base.producer).unwrap();
        let bytes = commonjs.encode_canonical().unwrap();
        assert_eq!(
            ModuleArtifactV1::decode_canonical(&bytes).unwrap(),
            commonjs
        );

        let mut esm = artifact();
        esm.semantics.static_edges = vec![StaticEdgeV1::CommonJsRequire {
            specifier: NonEmptyString::new("conditional-package").unwrap(),
        }];
        esm.semantic_digest = semantics_digest(&esm.semantics).unwrap();
        assert!(esm.encode_canonical().is_err());
    }
}
