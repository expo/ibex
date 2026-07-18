//! Canonical prepared module carriers and per-original-module provenance.
//!
//! A carrier is physical storage, never module identity. Admission binds its
//! bytes to one authenticated principal and deployment graph, while every
//! entry retains the original module's semantic core and `SourceId`.
//! @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
//! @ref LLP 0026#9-production-artifacts-and-bytecode

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Context, Result};
use capsec_semantics::model::{Digest, NonEmptyString, Principal};
use serde::{Deserialize, Serialize};

use super::artifact::{
    digest_bytes, semantics_digest, ModuleArtifactV1, ModulePayloadV1, ModuleSemanticsV1,
    ProducerIdentityV1, VerifiedModuleArtifactV1,
};

pub const PREPARED_CARRIER_SCHEMA_V2: &str = "ibex/module-carrier/2";
pub const PREPARED_CARRIER_BYTES_DOMAIN_V1: &str = "ibex/module-carrier-bytes/1";
const HERMES_BYTECODE_MAGIC: u64 = 0x1F1903C103BC1FC6;
const HERMES_BYTECODE_HEADER_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PreparedCarrierEngineBindingV2 {
    LoadedFile {
        #[serde(rename = "binaryDigest")]
        binary_digest: Digest,
    },
    StaticCompatibility {
        #[serde(rename = "compatibilityIdentity")]
        compatibility_identity: Digest,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HermesBytecodeMetadataV1 {
    pub bytecode_version: u32,
    pub file_length: u32,
}

impl HermesBytecodeMetadataV1 {
    /// Inspect the authenticated HBC header instead of accepting producer
    /// assertions about the emitted bytecode.
    /// @ref LLP 0029#1-command-surface-and-producer-pipeline — HBC metadata is derived from emitted bytes and bound to the target engine
    pub fn inspect(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HERMES_BYTECODE_HEADER_LEN {
            bail!("Hermes carrier bytecode is shorter than its v1 header");
        }
        let magic = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        if magic != HERMES_BYTECODE_MAGIC {
            bail!("Hermes carrier bytecode has the wrong execution magic");
        }
        let bytecode_version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if bytecode_version == 0 {
            bail!("Hermes carrier bytecode version must be nonzero");
        }
        let file_length = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        if usize::try_from(file_length).ok() != Some(bytes.len()) {
            bail!("Hermes carrier bytecode header length disagrees with its bytes");
        }
        Ok(Self {
            bytecode_version,
            file_length,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PreparedCarrierEncodingV2 {
    JavascriptFactoryTable,
    HermesBytecode {
        #[serde(rename = "engineBinding")]
        engine_binding: PreparedCarrierEngineBindingV2,
        #[serde(rename = "bytecodeVersion")]
        bytecode_version: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedCarrierEntryV2 {
    pub entry_id: NonEmptyString,
    pub semantics: ModuleSemanticsV1,
    pub semantic_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedModuleCarrierV2 {
    pub schema: String,
    pub encoding: PreparedCarrierEncodingV2,
    pub carrier_digest: Digest,
    pub defining_principal: Principal,
    pub producer_id: NonEmptyString,
    pub producer_binary_digest: Digest,
    pub deployment_graph_digest: Digest,
    pub entries: Vec<PreparedCarrierEntryV2>,
}

#[derive(Debug, Clone)]
pub struct PreparedCarrierAdmissionV2 {
    pub expected_principal: Principal,
    pub expected_producer_id: NonEmptyString,
    pub producer_binary_digest: Digest,
    pub deployment_graph_digest: Digest,
    pub authorized_semantic_digests: BTreeSet<Digest>,
    pub expected_engine_binding: Option<PreparedCarrierEngineBindingV2>,
    pub expected_bytecode_version: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AdmittedPreparedCarrierV2 {
    manifest: PreparedModuleCarrierV2,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct VerifiedPreparedCarrierEntryV2<'a> {
    manifest: &'a PreparedModuleCarrierV2,
    entry: &'a PreparedCarrierEntryV2,
    bytes: &'a [u8],
}

impl PreparedModuleCarrierV2 {
    /// Build a deterministic per-principal source carrier from admitted inline
    /// artifacts. The table only creates factory functions; module bodies stay
    /// behind their record `execute` phase.
    pub fn from_inline_artifacts<'a>(
        defining_principal: Principal,
        producer_id: NonEmptyString,
        producer_binary_digest: Digest,
        deployment_graph_digest: Digest,
        artifacts: impl IntoIterator<Item = (NonEmptyString, VerifiedModuleArtifactV1<'a>)>,
    ) -> Result<(Self, Vec<u8>)> {
        let mut artifacts: Vec<_> = artifacts.into_iter().collect();
        artifacts.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
        if artifacts.is_empty() {
            bail!("prepared carrier requires at least one module entry");
        }
        let mut source = String::from("(function(){\"use strict\";var table=Object.create(null);");
        let mut entries = Vec::with_capacity(artifacts.len());
        let mut previous: Option<&str> = None;
        for (entry_id, verified) in &artifacts {
            if previous.is_some_and(|value| value == entry_id.as_str()) {
                bail!("prepared carrier entry ids must be unique");
            }
            previous = Some(entry_id.as_str());
            let artifact = verified.artifact();
            let principal = match artifact.semantics.source_id.0.defining_principal() {
                Some(principal) => principal,
                None if matches!(
                    &artifact.semantics.source_id.0,
                    super::identity::SourceId::Builtin { .. }
                ) && defining_principal.is_root() =>
                {
                    &defining_principal
                }
                None => bail!("v1 executable carrier SourceId has no authenticated owner"),
            };
            if principal != &defining_principal {
                bail!("prepared carrier cannot cross defining principals");
            }
            let ModulePayloadV1::Inline { factory_source, .. } = &artifact.payload else {
                bail!("prepared source carriers can only be built from inline artifacts");
            };
            source.push_str("Object.defineProperty(table,");
            source.push_str(&serde_json::to_string(entry_id.as_str())?);
            source.push_str(",{value:(");
            source.push_str(factory_source);
            source.push_str("),enumerable:true});");
            entries.push(PreparedCarrierEntryV2 {
                entry_id: entry_id.clone(),
                semantics: artifact.semantics.clone(),
                semantic_digest: artifact.semantic_digest.clone(),
            });
        }
        source.push_str("return Object.freeze(table);})()");
        let bytes = source.into_bytes();
        let manifest = Self {
            schema: PREPARED_CARRIER_SCHEMA_V2.into(),
            encoding: PreparedCarrierEncodingV2::JavascriptFactoryTable,
            carrier_digest: digest_bytes(PREPARED_CARRIER_BYTES_DOMAIN_V1, &bytes)?,
            defining_principal,
            producer_id,
            producer_binary_digest,
            deployment_graph_digest,
            entries,
        };
        manifest.validate(&bytes)?;
        Ok((manifest, bytes))
    }

    /// Bind the same logical entries to bytecode compiled from this carrier's
    /// source table. Semantic digests remain carrier-independent.
    pub fn bind_hermes_bytecode(
        &self,
        bytes: &[u8],
        engine_binding: PreparedCarrierEngineBindingV2,
    ) -> Result<Self> {
        let metadata = HermesBytecodeMetadataV1::inspect(bytes)?;
        let mut manifest = self.clone();
        manifest.encoding = PreparedCarrierEncodingV2::HermesBytecode {
            engine_binding,
            bytecode_version: metadata.bytecode_version,
        };
        manifest.carrier_digest = digest_bytes(PREPARED_CARRIER_BYTES_DOMAIN_V1, bytes)?;
        manifest.validate(bytes)?;
        Ok(manifest)
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| anyhow!("cannot canonicalize prepared carrier: {error}"))
    }

    pub fn prepared_artifact(&self, entry_id: &str) -> Result<ModuleArtifactV1> {
        let entry = self.entry(entry_id)?;
        ModuleArtifactV1::new_carrier(
            entry.semantics.clone(),
            self.carrier_digest.clone(),
            entry.entry_id.clone(),
            ProducerIdentityV1::Prepared {
                producer_id: self.producer_id.clone(),
                producer_binary_digest: self.producer_binary_digest.clone(),
                deployment_graph_digest: self.deployment_graph_digest.clone(),
            },
        )
    }

    fn entry(&self, entry_id: &str) -> Result<&PreparedCarrierEntryV2> {
        self.entries
            .binary_search_by(|entry| entry.entry_id.as_str().cmp(entry_id))
            .ok()
            .map(|index| &self.entries[index])
            .ok_or_else(|| anyhow!("prepared carrier has no entry {entry_id:?}"))
    }

    fn validate(&self, bytes: &[u8]) -> Result<()> {
        if self.schema != PREPARED_CARRIER_SCHEMA_V2 {
            bail!("unsupported prepared carrier schema {:?}", self.schema);
        }
        if self.entries.is_empty() {
            bail!("prepared carrier requires at least one entry");
        }
        if self.carrier_digest != digest_bytes(PREPARED_CARRIER_BYTES_DOMAIN_V1, bytes)? {
            bail!("prepared carrier bytes do not match the manifest digest");
        }
        let mut previous: Option<&str> = None;
        for entry in &self.entries {
            if previous.is_some_and(|value| value >= entry.entry_id.as_str()) {
                bail!("prepared carrier entries must be strictly ordered and unique");
            }
            previous = Some(entry.entry_id.as_str());
            if semantics_digest(&entry.semantics)? != entry.semantic_digest {
                bail!("prepared carrier entry semantic digest is stale");
            }
            let owner_agrees = entry.semantics.source_id.0.defining_principal()
                == Some(&self.defining_principal)
                || (matches!(
                    &entry.semantics.source_id.0,
                    super::identity::SourceId::Builtin { .. }
                ) && self.defining_principal.is_root());
            if !owner_agrees {
                bail!("prepared carrier entry crosses its defining principal");
            }
        }
        Ok(())
    }
}

impl AdmittedPreparedCarrierV2 {
    pub fn decode_and_admit(
        manifest_bytes: &[u8],
        carrier_bytes: &[u8],
        admission: &PreparedCarrierAdmissionV2,
    ) -> Result<Self> {
        let text = std::str::from_utf8(manifest_bytes)
            .context("prepared carrier manifest is not UTF-8")?;
        let value = capsec_semantics::strict_json::parse_strict(text)
            .map_err(|error| anyhow!("prepared carrier manifest is not strict JSON: {error}"))?;
        let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| anyhow!("cannot canonicalize prepared carrier: {error}"))?;
        if canonical != manifest_bytes {
            bail!("prepared carrier manifest bytes are not canonical JCS");
        }
        let manifest: PreparedModuleCarrierV2 =
            serde_json::from_value(value).context("prepared carrier manifest shape is invalid")?;
        manifest.validate(carrier_bytes)?;
        if manifest.defining_principal != admission.expected_principal {
            bail!("prepared carrier defining principal is not authorized");
        }
        if manifest.producer_id != admission.expected_producer_id
            || manifest.producer_binary_digest != admission.producer_binary_digest
            || manifest.deployment_graph_digest != admission.deployment_graph_digest
        {
            bail!("prepared carrier producer or deployment graph is stale");
        }
        if manifest.entries.iter().any(|entry| {
            !admission
                .authorized_semantic_digests
                .contains(&entry.semantic_digest)
        }) {
            bail!("prepared carrier contains a module absent from the deployment graph");
        }
        match &manifest.encoding {
            PreparedCarrierEncodingV2::JavascriptFactoryTable => {
                if admission.expected_engine_binding.is_some()
                    || admission.expected_bytecode_version.is_some()
                {
                    bail!("source carrier admission must not claim a bytecode engine");
                }
            }
            PreparedCarrierEncodingV2::HermesBytecode {
                engine_binding,
                bytecode_version,
            } => {
                let inspected = HermesBytecodeMetadataV1::inspect(carrier_bytes)?;
                if admission.expected_engine_binding.as_ref() != Some(engine_binding)
                    || admission.expected_bytecode_version != Some(*bytecode_version)
                    || inspected.bytecode_version != *bytecode_version
                {
                    bail!("prepared Hermes carrier targets a different engine");
                }
            }
        }
        Ok(Self {
            manifest,
            bytes: carrier_bytes.to_vec(),
        })
    }

    pub fn manifest(&self) -> &PreparedModuleCarrierV2 {
        &self.manifest
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn entry(&self, entry_id: &str) -> Result<VerifiedPreparedCarrierEntryV2<'_>> {
        Ok(VerifiedPreparedCarrierEntryV2 {
            manifest: &self.manifest,
            entry: self.manifest.entry(entry_id)?,
            bytes: &self.bytes,
        })
    }
}

impl VerifiedPreparedCarrierEntryV2<'_> {
    pub fn manifest(&self) -> &PreparedModuleCarrierV2 {
        self.manifest
    }

    pub fn entry(&self) -> &PreparedCarrierEntryV2 {
        self.entry
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Return the number of generated lines that precede this entry's factory
    /// in an authenticated JavaScript factory-table carrier.
    ///
    /// Artifact source maps are deliberately carrier-independent, so their
    /// generated positions begin at the factory's first line. A prepared
    /// factory table concatenates those factories and must add this offset
    /// when interpreting a carrier stack position. Ambiguous marker matches
    /// fail closed instead of guessing at an unauthenticated location.
    /// @ref LLP 0027#artifact-envelope — source maps are semantic, carrier-independent artifact fields
    pub fn javascript_factory_generated_line_offset(&self) -> Option<u32> {
        if self.manifest.encoding != PreparedCarrierEncodingV2::JavascriptFactoryTable {
            return None;
        }
        let marker = format!(
            "Object.defineProperty(table,{},{{value:(",
            serde_json::to_string(self.entry.entry_id.as_str()).ok()?
        );
        let mut matches = self
            .bytes
            .windows(marker.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == marker.as_bytes()).then_some(offset));
        let marker_offset = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        u32::try_from(
            self.bytes[..marker_offset + marker.len()]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count(),
        )
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_loader::artifact::{
        source_integrity, ArtifactAdmissionV1, CanonicalSourceId, ModuleSemanticsV1,
        SourceDialectV1, SourceGoalV1, SourceMapV1, TransformFingerprintV1,
        MODULE_ARTIFACT_FACTORY_DOMAIN_V1,
    };
    use crate::module_loader::identity::SourceId;
    use capsec_semantics::model::PathComponent;

    fn digest(label: &str) -> Digest {
        digest_bytes("carrier-test", label.as_bytes()).unwrap()
    }

    fn principal(name: &str) -> Principal {
        Principal::Root {
            identity: NonEmptyString::new(name).unwrap(),
        }
    }

    fn hbc(version: u32) -> Vec<u8> {
        let mut bytes = vec![0; HERMES_BYTECODE_HEADER_LEN];
        let file_length = bytes.len() as u32;
        bytes[0..8].copy_from_slice(&HERMES_BYTECODE_MAGIC.to_le_bytes());
        bytes[8..12].copy_from_slice(&version.to_le_bytes());
        bytes[32..36].copy_from_slice(&file_length.to_le_bytes());
        bytes
    }

    fn loaded_engine(label: &str) -> PreparedCarrierEngineBindingV2 {
        PreparedCarrierEngineBindingV2::LoadedFile {
            binary_digest: digest(label),
        }
    }

    fn artifact(owner: Principal, name: &str) -> ModuleArtifactV1 {
        artifact_with_factory(
            owner,
            name,
            "function(){return {declare:function(){},execute:function(){}}}",
        )
    }

    fn artifact_with_factory(owner: Principal, name: &str, factory: &str) -> ModuleArtifactV1 {
        let source_id = SourceId::file(owner, vec![PathComponent::utf8(name).unwrap()]).unwrap();
        let fingerprint = TransformFingerprintV1 {
            producer: NonEmptyString::new("carrier-test").unwrap(),
            parser_version: NonEmptyString::new("1").unwrap(),
            transform_version: NonEmptyString::new("1").unwrap(),
            hermes_target: NonEmptyString::new("test").unwrap(),
            typescript_jsx_options_digest: digest("options"),
            module_runner_abi: NonEmptyString::new("1").unwrap(),
            hermes_compat_version: NonEmptyString::new("1").unwrap(),
            commonjs_detector: NonEmptyString::new("detector").unwrap(),
            commonjs_detector_version: NonEmptyString::new("1").unwrap(),
            output_options_digest: digest("output"),
        };
        ModuleArtifactV1::new_inline(
            ModuleSemanticsV1 {
                source_id: CanonicalSourceId(source_id.clone()),
                source_goal: SourceGoalV1::Module,
                dialect: Some(SourceDialectV1::Js),
                source_integrity: source_integrity(name.as_bytes()).unwrap(),
                transform_fingerprint: fingerprint,
                static_edges: Vec::new(),
                dynamic_edges: Vec::new(),
                export_descriptors: Vec::new(),
                commonjs_exports: None,
                has_top_level_await: false,
                factory_digest: digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory.as_bytes())
                    .unwrap(),
                source_map: SourceMapV1 {
                    version: 3,
                    source_ids: vec![CanonicalSourceId(source_id)],
                    names: Vec::new(),
                    mappings: String::new(),
                },
            },
            factory.into(),
            ProducerIdentityV1::InProcess {
                producer_id: NonEmptyString::new("source-producer").unwrap(),
                producer_binary_digest: digest("source-producer"),
            },
        )
        .unwrap()
    }

    fn verified(artifact: &ModuleArtifactV1) -> VerifiedModuleArtifactV1<'_> {
        artifact
            .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                expected_source_id: artifact.semantics.source_id.0.clone(),
                expected_source_integrity: artifact.semantics.source_integrity.clone(),
                expected_producer_id: NonEmptyString::new("source-producer").unwrap(),
                producer_binary_digest: digest("source-producer"),
                transform_fingerprint_digest: artifact
                    .semantics
                    .transform_fingerprint
                    .digest()
                    .unwrap(),
            })
            .unwrap()
    }

    fn admission(
        owner: Principal,
        manifest: &PreparedModuleCarrierV2,
    ) -> PreparedCarrierAdmissionV2 {
        PreparedCarrierAdmissionV2 {
            expected_principal: owner,
            expected_producer_id: NonEmptyString::new("prepared-producer").unwrap(),
            producer_binary_digest: digest("prepared-producer"),
            deployment_graph_digest: digest("deployment-graph"),
            authorized_semantic_digests: manifest
                .entries
                .iter()
                .map(|entry| entry.semantic_digest.clone())
                .collect(),
            expected_engine_binding: None,
            expected_bytecode_version: None,
        }
    }

    #[test]
    fn source_and_hbc_carriers_preserve_semantics_and_original_identity() {
        let owner = principal("project");
        let first = artifact_with_factory(
            owner.clone(),
            "a.mjs",
            "function(){\nreturn {declare:function(){},execute:function(){}}\n}",
        );
        let second = artifact(owner.clone(), "b.mjs");
        let (manifest, bytes) = PreparedModuleCarrierV2::from_inline_artifacts(
            owner.clone(),
            NonEmptyString::new("prepared-producer").unwrap(),
            digest("prepared-producer"),
            digest("deployment-graph"),
            [
                (NonEmptyString::new("a").unwrap(), verified(&first)),
                (NonEmptyString::new("b").unwrap(), verified(&second)),
            ],
        )
        .unwrap();
        let admitted = AdmittedPreparedCarrierV2::decode_and_admit(
            &manifest.encode_canonical().unwrap(),
            &bytes,
            &admission(owner.clone(), &manifest),
        )
        .unwrap();
        let prepared = manifest.prepared_artifact("a").unwrap();
        assert_eq!(prepared.semantic_digest, first.semantic_digest);
        assert_eq!(
            admitted.entry("a").unwrap().entry().semantics.source_id,
            first.semantics.source_id
        );
        assert_eq!(
            admitted
                .entry("a")
                .unwrap()
                .javascript_factory_generated_line_offset(),
            Some(0)
        );
        assert_eq!(
            admitted
                .entry("b")
                .unwrap()
                .javascript_factory_generated_line_offset(),
            Some(2)
        );

        let bytes = hbc(96);
        let engine = loaded_engine("engine");
        let hbc = manifest
            .bind_hermes_bytecode(&bytes, engine.clone())
            .unwrap();
        let mut hbc_admission = admission(owner, &hbc);
        hbc_admission.expected_engine_binding = Some(engine);
        hbc_admission.expected_bytecode_version = Some(96);
        let admitted_hbc = AdmittedPreparedCarrierV2::decode_and_admit(
            &hbc.encode_canonical().unwrap(),
            &bytes,
            &hbc_admission,
        )
        .unwrap();
        assert_eq!(
            admitted_hbc
                .entry("b")
                .unwrap()
                .javascript_factory_generated_line_offset(),
            None
        );
    }

    #[test]
    fn tamper_cross_principal_and_stale_engine_fail_closed() {
        let owner = principal("project");
        let foreign = artifact(principal("foreign"), "foreign.mjs");
        assert!(PreparedModuleCarrierV2::from_inline_artifacts(
            owner.clone(),
            NonEmptyString::new("prepared-producer").unwrap(),
            digest("prepared-producer"),
            digest("deployment-graph"),
            [(NonEmptyString::new("foreign").unwrap(), verified(&foreign))],
        )
        .is_err());

        let local = artifact(owner.clone(), "local.mjs");
        let (manifest, mut bytes) = PreparedModuleCarrierV2::from_inline_artifacts(
            owner.clone(),
            NonEmptyString::new("prepared-producer").unwrap(),
            digest("prepared-producer"),
            digest("deployment-graph"),
            [(NonEmptyString::new("local").unwrap(), verified(&local))],
        )
        .unwrap();
        bytes.push(0);
        assert!(AdmittedPreparedCarrierV2::decode_and_admit(
            &manifest.encode_canonical().unwrap(),
            &bytes,
            &admission(owner.clone(), &manifest),
        )
        .is_err());

        let bytes = hbc(96);
        let hbc = manifest
            .bind_hermes_bytecode(&bytes, loaded_engine("engine-a"))
            .unwrap();
        let mut stale = admission(owner, &hbc);
        stale.expected_engine_binding = Some(loaded_engine("engine-b"));
        stale.expected_bytecode_version = Some(96);
        assert!(AdmittedPreparedCarrierV2::decode_and_admit(
            &hbc.encode_canonical().unwrap(),
            &bytes,
            &stale,
        )
        .is_err());

        let mut malformed = bytes;
        malformed[32..36].copy_from_slice(&129u32.to_le_bytes());
        assert!(HermesBytecodeMetadataV1::inspect(&malformed).is_err());
    }

    #[test]
    fn checked_in_schema_names_the_exact_carrier_envelope() {
        let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../schemas/module-carrier-v2.schema.json"
        ))
        .unwrap();
        assert_eq!(
            schema["properties"]["schema"]["const"],
            PREPARED_CARRIER_SCHEMA_V2
        );
        assert_eq!(schema["additionalProperties"], false);
    }
}
