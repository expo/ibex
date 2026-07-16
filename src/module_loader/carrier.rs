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

pub const PREPARED_CARRIER_SCHEMA_V1: &str = "ibex/module-carrier/1";
pub const PREPARED_CARRIER_BYTES_DOMAIN_V1: &str = "ibex/module-carrier-bytes/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PreparedCarrierEncodingV1 {
    JavascriptFactoryTable,
    HermesBytecode {
        engine_binary_digest: Digest,
        bytecode_version: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedCarrierEntryV1 {
    pub entry_id: NonEmptyString,
    pub semantics: ModuleSemanticsV1,
    pub semantic_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedModuleCarrierV1 {
    pub schema: String,
    pub encoding: PreparedCarrierEncodingV1,
    pub carrier_digest: Digest,
    pub defining_principal: Principal,
    pub producer_id: NonEmptyString,
    pub producer_binary_digest: Digest,
    pub deployment_graph_digest: Digest,
    pub entries: Vec<PreparedCarrierEntryV1>,
}

#[derive(Debug, Clone)]
pub struct PreparedCarrierAdmissionV1 {
    pub expected_principal: Principal,
    pub expected_producer_id: NonEmptyString,
    pub producer_binary_digest: Digest,
    pub deployment_graph_digest: Digest,
    pub authorized_semantic_digests: BTreeSet<Digest>,
    pub expected_engine_binary_digest: Option<Digest>,
    pub expected_bytecode_version: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AdmittedPreparedCarrierV1 {
    manifest: PreparedModuleCarrierV1,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct VerifiedPreparedCarrierEntryV1<'a> {
    manifest: &'a PreparedModuleCarrierV1,
    entry: &'a PreparedCarrierEntryV1,
    bytes: &'a [u8],
}

impl PreparedModuleCarrierV1 {
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
            entries.push(PreparedCarrierEntryV1 {
                entry_id: entry_id.clone(),
                semantics: artifact.semantics.clone(),
                semantic_digest: artifact.semantic_digest.clone(),
            });
        }
        source.push_str("return Object.freeze(table);})()");
        let bytes = source.into_bytes();
        let manifest = Self {
            schema: PREPARED_CARRIER_SCHEMA_V1.into(),
            encoding: PreparedCarrierEncodingV1::JavascriptFactoryTable,
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
        engine_binary_digest: Digest,
        bytecode_version: u32,
    ) -> Result<Self> {
        if bytecode_version == 0 {
            bail!("Hermes carrier bytecode version must be nonzero");
        }
        let mut manifest = self.clone();
        manifest.encoding = PreparedCarrierEncodingV1::HermesBytecode {
            engine_binary_digest,
            bytecode_version,
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

    fn entry(&self, entry_id: &str) -> Result<&PreparedCarrierEntryV1> {
        self.entries
            .binary_search_by(|entry| entry.entry_id.as_str().cmp(entry_id))
            .ok()
            .map(|index| &self.entries[index])
            .ok_or_else(|| anyhow!("prepared carrier has no entry {entry_id:?}"))
    }

    fn validate(&self, bytes: &[u8]) -> Result<()> {
        if self.schema != PREPARED_CARRIER_SCHEMA_V1 {
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

impl AdmittedPreparedCarrierV1 {
    pub fn decode_and_admit(
        manifest_bytes: &[u8],
        carrier_bytes: &[u8],
        admission: &PreparedCarrierAdmissionV1,
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
        let manifest: PreparedModuleCarrierV1 =
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
            PreparedCarrierEncodingV1::JavascriptFactoryTable => {
                if admission.expected_engine_binary_digest.is_some()
                    || admission.expected_bytecode_version.is_some()
                {
                    bail!("source carrier admission must not claim a bytecode engine");
                }
            }
            PreparedCarrierEncodingV1::HermesBytecode {
                engine_binary_digest,
                bytecode_version,
            } => {
                if admission.expected_engine_binary_digest.as_ref() != Some(engine_binary_digest)
                    || admission.expected_bytecode_version != Some(*bytecode_version)
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

    pub fn manifest(&self) -> &PreparedModuleCarrierV1 {
        &self.manifest
    }

    pub fn entry(&self, entry_id: &str) -> Result<VerifiedPreparedCarrierEntryV1<'_>> {
        Ok(VerifiedPreparedCarrierEntryV1 {
            manifest: &self.manifest,
            entry: self.manifest.entry(entry_id)?,
            bytes: &self.bytes,
        })
    }
}

impl VerifiedPreparedCarrierEntryV1<'_> {
    pub fn manifest(&self) -> &PreparedModuleCarrierV1 {
        self.manifest
    }

    pub fn entry(&self) -> &PreparedCarrierEntryV1 {
        self.entry
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes
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

    fn artifact(owner: Principal, name: &str) -> ModuleArtifactV1 {
        let source_id = SourceId::file(owner, vec![PathComponent::utf8(name).unwrap()]).unwrap();
        let factory = "function(){return {declare:function(){},execute:function(){}}}";
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
        manifest: &PreparedModuleCarrierV1,
    ) -> PreparedCarrierAdmissionV1 {
        PreparedCarrierAdmissionV1 {
            expected_principal: owner,
            expected_producer_id: NonEmptyString::new("prepared-producer").unwrap(),
            producer_binary_digest: digest("prepared-producer"),
            deployment_graph_digest: digest("deployment-graph"),
            authorized_semantic_digests: manifest
                .entries
                .iter()
                .map(|entry| entry.semantic_digest.clone())
                .collect(),
            expected_engine_binary_digest: None,
            expected_bytecode_version: None,
        }
    }

    #[test]
    fn source_and_hbc_carriers_preserve_semantics_and_original_identity() {
        let owner = principal("project");
        let first = artifact(owner.clone(), "a.mjs");
        let second = artifact(owner.clone(), "b.mjs");
        let (manifest, bytes) = PreparedModuleCarrierV1::from_inline_artifacts(
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
        let admitted = AdmittedPreparedCarrierV1::decode_and_admit(
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

        let engine = digest("engine");
        let hbc = manifest
            .bind_hermes_bytecode(b"hbc", engine.clone(), 96)
            .unwrap();
        let mut hbc_admission = admission(owner, &hbc);
        hbc_admission.expected_engine_binary_digest = Some(engine);
        hbc_admission.expected_bytecode_version = Some(96);
        AdmittedPreparedCarrierV1::decode_and_admit(
            &hbc.encode_canonical().unwrap(),
            b"hbc",
            &hbc_admission,
        )
        .unwrap();
    }

    #[test]
    fn tamper_cross_principal_and_stale_engine_fail_closed() {
        let owner = principal("project");
        let foreign = artifact(principal("foreign"), "foreign.mjs");
        assert!(PreparedModuleCarrierV1::from_inline_artifacts(
            owner.clone(),
            NonEmptyString::new("prepared-producer").unwrap(),
            digest("prepared-producer"),
            digest("deployment-graph"),
            [(NonEmptyString::new("foreign").unwrap(), verified(&foreign))],
        )
        .is_err());

        let local = artifact(owner.clone(), "local.mjs");
        let (manifest, mut bytes) = PreparedModuleCarrierV1::from_inline_artifacts(
            owner.clone(),
            NonEmptyString::new("prepared-producer").unwrap(),
            digest("prepared-producer"),
            digest("deployment-graph"),
            [(NonEmptyString::new("local").unwrap(), verified(&local))],
        )
        .unwrap();
        bytes.push(0);
        assert!(AdmittedPreparedCarrierV1::decode_and_admit(
            &manifest.encode_canonical().unwrap(),
            &bytes,
            &admission(owner.clone(), &manifest),
        )
        .is_err());

        let hbc = manifest
            .bind_hermes_bytecode(b"hbc", digest("engine-a"), 96)
            .unwrap();
        let mut stale = admission(owner, &hbc);
        stale.expected_engine_binary_digest = Some(digest("engine-b"));
        stale.expected_bytecode_version = Some(96);
        assert!(AdmittedPreparedCarrierV1::decode_and_admit(
            &hbc.encode_canonical().unwrap(),
            b"hbc",
            &stale,
        )
        .is_err());
    }

    #[test]
    fn checked_in_schema_names_the_exact_carrier_envelope() {
        let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../schemas/module-carrier-v1.schema.json"
        ))
        .unwrap();
        assert_eq!(
            schema["properties"]["schema"]["const"],
            PREPARED_CARRIER_SCHEMA_V1
        );
        assert_eq!(schema["additionalProperties"], false);
    }
}
