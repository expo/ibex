//! Release-pinned Catalog V2 admission for app-bound executables.
//! @ref LLP 0048#81-strict-schema-and-binary-definitions — a target may
//! advertise the restricted worker only with exact target-specific evidence.

use std::collections::BTreeSet;

use ibex_sfe_format::app_bound::{
    StubContractV4, TargetAdvertisementV1, RESTRICTED_WORKER_ABI_V1, TARGET_ADVERTISEMENT_SCHEMA_V1,
};
use serde::{Deserialize, Serialize};

use super::{
    digest_bytes, valid_digest, CatalogArtifactRoleV1, CatalogArtifactV1, CatalogEntryV1,
    CatalogManifestV1, Error, Result,
};

pub const CATALOG_SCHEMA_V2: &str = "ibex/sfe-catalog/2";
pub const CATALOG_DOMAIN_V2: &str = "ibex:sfe-catalog:2";
pub const ADVERTISEMENT_MEDIA_TYPE_V1: &str =
    "application/vnd.ibex.restricted-worker-target-advertisement+json;version=1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogManifestV2 {
    pub schema: String,
    pub release: String,
    pub sequence: u64,
    pub entries: Vec<CatalogEntryV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogEntryV2 {
    pub target: String,
    pub minimum_platform: String,
    pub contract_digest: String,
    pub engine_compatibility_identity: String,
    pub hermesc_identity: String,
    pub hbc_version: u32,
    pub contract: CatalogArtifactV1,
    pub stub_unsigned_core: CatalogArtifactV1,
    pub hermesc: CatalogArtifactV1,
    pub restricted_worker_target: Option<RestrictedWorkerTargetV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestrictedWorkerTargetV1 {
    pub advertisement_digest: String,
    pub artifact: RestrictedWorkerArtifactV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestrictedWorkerArtifactV1 {
    pub role: String,
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

impl RestrictedWorkerArtifactV1 {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            role: "restricted-worker-target-advertisement".into(),
            digest: digest_bytes(bytes),
            size: bytes.len() as u64,
            media_type: ADVERTISEMENT_MEDIA_TYPE_V1.into(),
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.role != "restricted-worker-target-advertisement"
            || !valid_digest(&self.digest)
            || self.size == 0
            || self.size > 64 * 1024
            || self.media_type != ADVERTISEMENT_MEDIA_TYPE_V1
        {
            return Err(Error::Manifest(
                "restricted-worker target artifact is invalid".into(),
            ));
        }
        Ok(())
    }
}

impl CatalogEntryV2 {
    fn project_v1(&self) -> CatalogEntryV1 {
        CatalogEntryV1 {
            target: self.target.clone(),
            minimum_platform: self.minimum_platform.clone(),
            contract_digest: self.contract_digest.clone(),
            engine_compatibility_identity: self.engine_compatibility_identity.clone(),
            hermesc_identity: self.hermesc_identity.clone(),
            hbc_version: self.hbc_version,
            contract: self.contract.clone(),
            stub_unsigned_core: self.stub_unsigned_core.clone(),
            hermesc: self.hermesc.clone(),
        }
    }
}

impl CatalogManifestV2 {
    pub fn from_target_artifacts(
        release: impl Into<String>,
        sequence: u64,
        contract_bytes: &[u8],
        stub: &[u8],
        hermesc: &[u8],
        advertisement_bytes: &[u8],
    ) -> Result<Self> {
        let value = strict_value(contract_bytes, "V4 stub contract")?;
        let contract: StubContractV4 =
            serde_json::from_value(value).map_err(|e| Error::Contract(e.to_string()))?;
        contract
            .validate()
            .map_err(|e| Error::Contract(e.to_string()))?;
        let advertisement_value = strict_value(
            advertisement_bytes,
            "restricted-worker target advertisement",
        )?;
        let advertisement: TargetAdvertisementV1 = serde_json::from_value(advertisement_value)
            .map_err(|e| Error::Contract(e.to_string()))?;
        advertisement
            .validate()
            .map_err(|e| Error::Contract(e.to_string()))?;
        let manifest = Self {
            schema: CATALOG_SCHEMA_V2.into(),
            release: release.into(),
            sequence,
            entries: vec![CatalogEntryV2 {
                target: contract.target.triple.clone(),
                minimum_platform: contract.target.minimum_platform.clone(),
                contract_digest: contract
                    .digest()
                    .map_err(|e| Error::Contract(e.to_string()))?,
                engine_compatibility_identity: contract.engine.identity().into(),
                hermesc_identity: contract.hermesc.identity().unwrap_or_default().into(),
                hbc_version: match contract.hermesc {
                    ibex_sfe_format::HermescCompatibilityV1::CatalogArtifact {
                        hbc_version,
                        ..
                    } => hbc_version,
                    _ => return Err(Error::Contract("V4 contract has no release hermesc".into())),
                },
                contract: CatalogArtifactV1::from_bytes(
                    CatalogArtifactRoleV1::StubContract,
                    "application/vnd.ibex.stub-contract+json;version=4",
                    contract_bytes,
                ),
                stub_unsigned_core: CatalogArtifactV1::from_bytes(
                    CatalogArtifactRoleV1::StubUnsignedCore,
                    "application/vnd.ibex.stub-core",
                    stub,
                ),
                hermesc: CatalogArtifactV1::from_bytes(
                    CatalogArtifactRoleV1::Hermesc,
                    "application/vnd.ibex.hermesc",
                    hermesc,
                ),
                restricted_worker_target: Some(RestrictedWorkerTargetV1 {
                    advertisement_digest: advertisement
                        .digest()
                        .map_err(|e| Error::Contract(e.to_string()))?,
                    artifact: RestrictedWorkerArtifactV1::from_bytes(advertisement_bytes),
                }),
            }],
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != CATALOG_SCHEMA_V2
            || self.release.is_empty()
            || self.sequence == 0
            || self.entries.is_empty()
        {
            return Err(Error::Manifest("V2 catalog header is invalid".into()));
        }
        let projected = CatalogManifestV1 {
            schema: super::CATALOG_SCHEMA_V1.into(),
            release: self.release.clone(),
            sequence: self.sequence,
            entries: self
                .entries
                .iter()
                .map(CatalogEntryV2::project_v1)
                .collect(),
        };
        projected.validate()?;
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            if !seen.insert(&entry.target) {
                return Err(Error::Manifest("duplicate V2 catalog target".into()));
            }
            if let Some(worker) = &entry.restricted_worker_target {
                if !valid_digest(&worker.advertisement_digest) {
                    return Err(Error::Manifest(
                        "target advertisement semantic digest is invalid".into(),
                    ));
                }
                worker.artifact.validate()?;
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let v = serde_json::to_value(self).map_err(|e| Error::Manifest(e.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&v).map_err(|e| Error::Manifest(e.to_string()))
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let v = serde_json::to_value(self).map_err(|e| Error::Manifest(e.to_string()))?;
        capsec_semantics::digest::compute_domain_digest(CATALOG_DOMAIN_V2, &v, &[])
            .map_err(|e| Error::Manifest(e.to_string()))
    }
}

pub struct PinnedCatalogV2 {
    manifest: CatalogManifestV2,
    digest: String,
}
impl PinnedCatalogV2 {
    pub fn load(bytes: &[u8], expected: &str) -> Result<Self> {
        if !valid_digest(expected) {
            return Err(Error::TrustRoot("V2 catalog digest is malformed".into()));
        }
        let text = std::str::from_utf8(bytes).map_err(|e| Error::Manifest(e.to_string()))?;
        let value = capsec_semantics::strict_json::parse_strict(text)
            .map_err(|e| Error::Manifest(e.to_string()))?;
        if capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|e| Error::Manifest(e.to_string()))?
            != bytes
        {
            return Err(Error::Manifest("V2 catalog is not canonical".into()));
        }
        let manifest: CatalogManifestV2 =
            serde_json::from_value(value).map_err(|e| Error::Manifest(e.to_string()))?;
        manifest.validate()?;
        if manifest.digest()? != expected {
            return Err(Error::TrustRoot(
                "V2 catalog disagrees with pinned digest".into(),
            ));
        }
        Ok(Self {
            manifest,
            digest: expected.into(),
        })
    }
    pub fn manifest(&self) -> &CatalogManifestV2 {
        &self.manifest
    }
    pub fn entry(&self, target: &str) -> Result<&CatalogEntryV2> {
        self.manifest
            .entries
            .iter()
            .find(|e| e.target == target)
            .ok_or_else(|| Error::Target(target.into()))
    }
    pub fn admit_target<'a>(
        &'a self,
        target: &str,
        contract_bytes: &'a [u8],
        stub: &'a [u8],
        hermesc: &'a [u8],
        advertisement_bytes: &'a [u8],
    ) -> Result<AdmittedCatalogTargetV2<'a>> {
        let entry = self.entry(target)?;
        let worker = entry
            .restricted_worker_target
            .as_ref()
            .ok_or_else(|| Error::Target("restricted worker is not advertised".into()))?;
        for (artifact, bytes) in [
            (&entry.contract, contract_bytes),
            (&entry.stub_unsigned_core, stub),
            (&entry.hermesc, hermesc),
        ] {
            if artifact.digest != digest_bytes(bytes) || artifact.size != bytes.len() as u64 {
                return Err(Error::Artifact("V2 catalog artifact bytes disagree".into()));
            }
        }
        if worker.artifact.digest != digest_bytes(advertisement_bytes)
            || worker.artifact.size != advertisement_bytes.len() as u64
        {
            return Err(Error::Artifact(
                "target advertisement bytes disagree".into(),
            ));
        }
        let contract_value = strict_value(contract_bytes, "V4 stub contract")?;
        let contract: StubContractV4 =
            serde_json::from_value(contract_value).map_err(|e| Error::Contract(e.to_string()))?;
        if contract
            .canonical_bytes()
            .map_err(|e| Error::Contract(e.to_string()))?
            != contract_bytes
            || contract
                .digest()
                .map_err(|e| Error::Contract(e.to_string()))?
                != entry.contract_digest
        {
            return Err(Error::Contract("V4 stub contract digest mismatch".into()));
        }
        let advertisement_value = strict_value(
            advertisement_bytes,
            "restricted-worker target advertisement",
        )?;
        let advertisement: TargetAdvertisementV1 = serde_json::from_value(advertisement_value)
            .map_err(|e| Error::Contract(e.to_string()))?;
        if advertisement.schema != TARGET_ADVERTISEMENT_SCHEMA_V1
            || advertisement
                .canonical_bytes()
                .map_err(|e| Error::Contract(e.to_string()))?
                != advertisement_bytes
            || advertisement
                .digest()
                .map_err(|e| Error::Contract(e.to_string()))?
                != worker.advertisement_digest
        {
            return Err(Error::Contract(
                "target advertisement digest mismatch".into(),
            ));
        }
        let external = &contract.external_worker;
        if !external.enabled
            || external.target_advertisement_digest.as_deref()
                != Some(worker.advertisement_digest.as_str())
            || contract.target.triple != entry.target
            || contract.target.minimum_platform != entry.minimum_platform
            || contract.engine.identity() != entry.engine_compatibility_identity
            || advertisement.target != contract.target
            || advertisement.engine_compatibility_digest != entry.engine_compatibility_identity
            || advertisement.native_abi != RESTRICTED_WORKER_ABI_V1
            || advertisement.language_profile != external.language_profile
            || advertisement.language_profile_digest != external.language_profile_digest
            || advertisement.worker_policy != external.worker_policy
            || advertisement.worker_policy_digest != external.worker_policy_digest
            || advertisement.broker_protocol != external.broker_protocol
            || advertisement.global_inventory_digest != external.global_inventory_digest
            || advertisement.defaults_digest
                != external
                    .defaults
                    .digest()
                    .map_err(|e| Error::Contract(e.to_string()))?
            || advertisement.maxima_digest
                != external
                    .maxima
                    .digest()
                    .map_err(|e| Error::Contract(e.to_string()))?
        {
            return Err(Error::Contract(
                "restricted-worker catalog identities disagree".into(),
            ));
        }
        Ok(AdmittedCatalogTargetV2 {
            catalog_digest: &self.digest,
            entry,
            contract,
            advertisement,
            stub_unsigned_core: stub,
            hermesc,
        })
    }
}

fn strict_value(bytes: &[u8], name: &str) -> Result<serde_json::Value> {
    let text = std::str::from_utf8(bytes).map_err(|e| Error::Manifest(format!("{name}: {e}")))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|e| Error::Manifest(e.to_string()))?;
    if capsec_semantics::canonical::to_jcs_bytes(&value)
        .map_err(|e| Error::Manifest(e.to_string()))?
        != bytes
    {
        return Err(Error::Manifest(format!("{name} is not canonical")));
    }
    Ok(value)
}

pub struct AdmittedCatalogTargetV2<'a> {
    pub catalog_digest: &'a str,
    pub entry: &'a CatalogEntryV2,
    pub contract: StubContractV4,
    pub advertisement: TargetAdvertisementV1,
    pub stub_unsigned_core: &'a [u8],
    pub hermesc: &'a [u8],
}
