//! Release-pinned content-addressed catalog admission for compiled stubs.
//!
//! A catalog digest is a release trust root, not a caller-selected checksum.
//! Loading therefore requires the exact digest compiled into the distributor,
//! and target admission rechecks every artifact and contract cross-binding.
//! @ref LLP 0029#2-executable-layout-stub-envelope-footer — a pinned manifest authenticates stub, contract, and hermesc as one target entry

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ibex_sfe_format::{
    EngineCompatibilityV1, HermescCompatibilityV1, HermescRecipeV1, StubContractV3,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub mod policy_toolchain;

pub const CATALOG_SCHEMA_V1: &str = "ibex/sfe-catalog/1";
pub const CATALOG_DOMAIN_V1: &str = "ibex:sfe-catalog:1";

/// Return the filesystem-safe address component for an authenticated catalog.
pub fn catalog_store_key(digest: &str) -> Result<&str> {
    if !valid_digest(digest) {
        return Err(Error::TrustRoot(
            "compiled catalog digest is malformed".into(),
        ));
    }
    Ok(&digest["sha256-".len()..])
}

/// Install one already-extracted release catalog under its immutable address.
///
/// The expected digest is supplied by the release binary, not by the user.
/// Every source file is reopened as a regular file, and every catalog entry is
/// fully admitted before an atomic directory rename makes the installation
/// visible.
/// @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog
pub fn install_pinned_catalog_directory(
    source_root: &Path,
    catalogs_dir: &Path,
    expected_digest: &str,
) -> Result<PathBuf> {
    let key = catalog_store_key(expected_digest)?;
    let (manifest_bytes, artifacts) = admit_catalog_directory(source_root, expected_digest)?;
    std::fs::create_dir_all(catalogs_dir).map_err(|error| {
        Error::Installation(format!(
            "cannot create catalog store {}: {error}",
            catalogs_dir.display()
        ))
    })?;
    let final_root = catalogs_dir.join(key);
    if final_root.exists() {
        admit_catalog_directory(&final_root, expected_digest)?;
        return Ok(final_root);
    }

    let staging = tempfile::Builder::new()
        .prefix(".ibex-sfe-catalog-install-")
        .tempdir_in(catalogs_dir)
        .map_err(|error| {
            Error::Installation(format!(
                "cannot create catalog staging directory in {}: {error}",
                catalogs_dir.display()
            ))
        })?;
    write_new(&staging.path().join("manifest.json"), &manifest_bytes)?;
    for (address, bytes) in artifacts {
        let path = staging.path().join(address);
        let parent = path
            .parent()
            .ok_or_else(|| Error::Installation("catalog artifact address has no parent".into()))?;
        std::fs::create_dir_all(parent).map_err(|error| {
            Error::Installation(format!(
                "cannot create catalog artifact directory {}: {error}",
                parent.display()
            ))
        })?;
        write_new(&path, &bytes)?;
    }
    admit_catalog_directory(staging.path(), expected_digest)?;
    match std::fs::rename(staging.path(), &final_root) {
        Ok(()) => Ok(final_root),
        Err(rename_error) if final_root.exists() => {
            admit_catalog_directory(&final_root, expected_digest).map_err(|admission_error| {
                Error::Installation(format!(
                    "catalog installation raced with an invalid destination after {rename_error}: {admission_error}"
                ))
            })?;
            Ok(final_root)
        }
        Err(error) => Err(Error::Installation(format!(
            "cannot publish catalog at {}: {error}",
            final_root.display()
        ))),
    }
}

fn admit_catalog_directory(
    root: &Path,
    expected_digest: &str,
) -> Result<(Vec<u8>, BTreeMap<String, Vec<u8>>)> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| {
        Error::Installation(format!(
            "cannot inspect catalog directory {}: {error}",
            root.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(Error::Installation(format!(
            "catalog root is not a directory: {}",
            root.display()
        )));
    }
    let manifest_bytes = read_regular(&root.join("manifest.json"), "catalog manifest")?;
    let catalog = PinnedCatalogV1::load(&manifest_bytes, expected_digest)?;
    let mut artifacts = BTreeMap::new();
    for entry in &catalog.manifest().entries {
        let contract = read_catalog_artifact(root, &entry.contract)?;
        let stub = read_catalog_artifact(root, &entry.stub_unsigned_core)?;
        let hermesc = read_catalog_artifact(root, &entry.hermesc)?;
        catalog.admit_target(
            &entry.target,
            CatalogTargetArtifacts {
                contract: &contract,
                stub_unsigned_core: &stub,
                hermesc: &hermesc,
            },
        )?;
        for (artifact, bytes) in [
            (&entry.contract, contract),
            (&entry.stub_unsigned_core, stub),
            (&entry.hermesc, hermesc),
        ] {
            let address = artifact.content_address()?;
            if let Some(existing) = artifacts.insert(address, bytes.clone()) {
                if existing != bytes {
                    return Err(Error::Artifact(
                        "one content address resolves to different artifact bytes".into(),
                    ));
                }
            }
        }
    }
    Ok((manifest_bytes, artifacts))
}

fn read_catalog_artifact(root: &Path, artifact: &CatalogArtifactV1) -> Result<Vec<u8>> {
    read_regular(&root.join(artifact.content_address()?), "catalog artifact")
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        Error::Installation(format!(
            "cannot inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(Error::Installation(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    std::fs::read(path).map_err(|error| {
        Error::Installation(format!("cannot read {label} {}: {error}", path.display()))
    })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            Error::Installation(format!("cannot create {}: {error}", path.display()))
        })?;
    output.write_all(bytes).map_err(|error| {
        Error::Installation(format!("cannot write {}: {error}", path.display()))
    })?;
    output
        .sync_all()
        .map_err(|error| Error::Installation(format!("cannot sync {}: {error}", path.display())))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogManifestV1 {
    pub schema: String,
    pub release: String,
    pub sequence: u64,
    pub entries: Vec<CatalogEntryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogEntryV1 {
    pub target: String,
    pub minimum_platform: String,
    pub contract_digest: String,
    pub engine_compatibility_identity: String,
    pub hermesc_identity: String,
    pub hbc_version: u32,
    pub contract: CatalogArtifactV1,
    pub stub_unsigned_core: CatalogArtifactV1,
    pub hermesc: CatalogArtifactV1,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatalogArtifactRoleV1 {
    StubContract,
    StubUnsignedCore,
    Hermesc,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogArtifactV1 {
    pub role: CatalogArtifactRoleV1,
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

impl CatalogArtifactV1 {
    pub fn from_bytes(
        role: CatalogArtifactRoleV1,
        media_type: impl Into<String>,
        bytes: &[u8],
    ) -> Self {
        Self {
            role,
            digest: digest_bytes(bytes),
            size: bytes.len() as u64,
            media_type: media_type.into(),
        }
    }

    pub fn content_address(&self) -> Result<String> {
        if !valid_digest(&self.digest) {
            return Err(Error::Manifest("artifact digest is malformed".into()));
        }
        Ok(format!("sha256/{}/blob", &self.digest["sha256-".len()..]))
    }

    fn validate(&self, role: CatalogArtifactRoleV1) -> Result<()> {
        if self.role != role
            || !valid_digest(&self.digest)
            || self.size == 0
            || self.media_type.is_empty()
        {
            return Err(Error::Manifest(format!(
                "catalog artifact {role:?} is invalid"
            )));
        }
        Ok(())
    }

    fn admit(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 != self.size || digest_bytes(bytes) != self.digest {
            return Err(Error::Artifact(format!(
                "catalog artifact {:?} digest or size mismatch",
                self.role
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PinnedCatalogV1 {
    manifest: CatalogManifestV1,
    digest: String,
}

impl PinnedCatalogV1 {
    pub fn load(bytes: &[u8], expected_digest: &str) -> Result<Self> {
        if !valid_digest(expected_digest) {
            return Err(Error::TrustRoot(
                "compiled catalog digest is malformed".into(),
            ));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|error| Error::Manifest(format!("catalog is not UTF-8: {error}")))?;
        let value = capsec_semantics::strict_json::parse_strict(text)
            .map_err(|error| Error::Manifest(error.to_string()))?;
        let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| Error::Manifest(error.to_string()))?;
        if canonical != bytes {
            return Err(Error::Manifest(
                "catalog bytes are not the exact canonical JCS representation".into(),
            ));
        }
        let digest =
            capsec_semantics::digest::compute_domain_digest(CATALOG_DOMAIN_V1, &value, &[])
                .map_err(|error| Error::Manifest(error.to_string()))?;
        if digest != expected_digest {
            return Err(Error::TrustRoot(
                "catalog digest differs from the release-pinned trust root".into(),
            ));
        }
        let manifest: CatalogManifestV1 =
            serde_json::from_value(value).map_err(|error| Error::Manifest(error.to_string()))?;
        manifest.validate()?;
        Ok(Self { manifest, digest })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn manifest(&self) -> &CatalogManifestV1 {
        &self.manifest
    }

    pub fn entry(&self, target: &str) -> Result<&CatalogEntryV1> {
        self.manifest
            .entries
            .binary_search_by(|entry| entry.target.as_str().cmp(target))
            .map(|index| &self.manifest.entries[index])
            .map_err(|_| {
                Error::Target(format!(
                "catalog has no entry for {target}; fetch the catalog artifacts for this release"
            ))
            })
    }

    pub fn admit_target<'a>(
        &'a self,
        target: &str,
        artifacts: CatalogTargetArtifacts<'a>,
    ) -> Result<AdmittedCatalogTargetV1<'a>> {
        let entry = self.entry(target)?;
        entry.contract.admit(artifacts.contract)?;
        entry
            .stub_unsigned_core
            .admit(artifacts.stub_unsigned_core)?;
        entry.hermesc.admit(artifacts.hermesc)?;
        let contract_text = std::str::from_utf8(artifacts.contract)
            .map_err(|error| Error::Contract(format!("contract is not UTF-8: {error}")))?;
        let contract_value = capsec_semantics::strict_json::parse_strict(contract_text)
            .map_err(|error| Error::Contract(error.to_string()))?;
        let contract: StubContractV3 = serde_json::from_value(contract_value)
            .map_err(|error| Error::Contract(error.to_string()))?;
        if contract
            .canonical_bytes()
            .map_err(|error| Error::Contract(error.to_string()))?
            != artifacts.contract
        {
            return Err(Error::Contract("stub contract is not canonical".into()));
        }
        let contract_digest = contract
            .digest()
            .map_err(|error| Error::Contract(error.to_string()))?;
        if !contract.release_eligible
            || contract_digest != entry.contract_digest
            || contract.target.triple != entry.target
            || contract.target.minimum_platform != entry.minimum_platform
            || contract.engine.identity() != entry.engine_compatibility_identity
            || contract.hermesc.identity() != Some(entry.hermesc_identity.as_str())
        {
            return Err(Error::Contract(
                "catalog entry and release stub contract disagree".into(),
            ));
        }
        let HermescCompatibilityV1::CatalogArtifact {
            binary_digest,
            hbc_version,
            recipe_digest,
            ..
        } = &contract.hermesc
        else {
            return Err(Error::Contract(
                "release contract does not carry a catalog hermesc".into(),
            ));
        };
        if binary_digest != &entry.hermesc.digest
            || *hbc_version != entry.hbc_version
            || recipe_digest
                != &HermescRecipeV1::production()
                    .digest()
                    .map_err(|error| Error::Contract(error.to_string()))?
            || entry.hermesc_identity != contract.hermesc.identity().unwrap_or_default()
        {
            return Err(Error::Contract(
                "catalog hermesc artifact and compatibility identity disagree".into(),
            ));
        }
        Ok(AdmittedCatalogTargetV1 {
            catalog_digest: &self.digest,
            entry,
            contract,
            stub_unsigned_core: artifacts.stub_unsigned_core,
            hermesc: artifacts.hermesc,
        })
    }
}

impl CatalogManifestV1 {
    /// Construct one catalog entry from the exact release artifacts, deriving
    /// every identity from authenticated bytes rather than build-script text.
    /// @ref LLP 0029#2-executable-layout-stub-envelope-footer
    pub fn from_target_artifacts(
        release: impl Into<String>,
        sequence: u64,
        contract_bytes: &[u8],
        stub_unsigned_core: &[u8],
        hermesc: &[u8],
    ) -> Result<Self> {
        let contract_text = std::str::from_utf8(contract_bytes)
            .map_err(|error| Error::Contract(format!("contract is not UTF-8: {error}")))?;
        let contract_value = capsec_semantics::strict_json::parse_strict(contract_text)
            .map_err(|error| Error::Contract(error.to_string()))?;
        let contract: StubContractV3 = serde_json::from_value(contract_value)
            .map_err(|error| Error::Contract(error.to_string()))?;
        if contract
            .canonical_bytes()
            .map_err(|error| Error::Contract(error.to_string()))?
            != contract_bytes
        {
            return Err(Error::Contract("stub contract is not canonical".into()));
        }
        if !contract.release_eligible {
            return Err(Error::Contract(
                "catalog construction requires a release-eligible stub contract".into(),
            ));
        }
        let EngineCompatibilityV1::StaticHermes {
            hbc_version: engine_hbc_version,
            ..
        } = &contract.engine
        else {
            return Err(Error::Contract(
                "catalog construction requires a static Hermes contract".into(),
            ));
        };
        let HermescCompatibilityV1::CatalogArtifact {
            binary_digest,
            hbc_version,
            recipe_digest,
            compiler_identity,
        } = &contract.hermesc
        else {
            return Err(Error::Contract(
                "catalog construction requires a catalog hermesc contract".into(),
            ));
        };
        let hermesc_artifact = CatalogArtifactV1::from_bytes(
            CatalogArtifactRoleV1::Hermesc,
            "application/vnd.ibex.hermesc",
            hermesc,
        );
        if binary_digest != &hermesc_artifact.digest {
            return Err(Error::Contract(
                "contract hermesc digest disagrees with the supplied compiler bytes".into(),
            ));
        }
        if hbc_version != engine_hbc_version {
            return Err(Error::Contract(
                "contract hermesc and engine HBC versions disagree".into(),
            ));
        }
        let production_recipe_digest = HermescRecipeV1::production()
            .digest()
            .map_err(|error| Error::Contract(error.to_string()))?;
        if recipe_digest != &production_recipe_digest {
            return Err(Error::Contract(format!(
                "contract hermesc recipe {recipe_digest} differs from fixed production recipe {production_recipe_digest}"
            )));
        }
        if compiler_identity != contract.hermesc.identity().unwrap_or_default() {
            return Err(Error::Contract(
                "contract hermesc compiler identity is internally inconsistent".into(),
            ));
        }
        let entry = CatalogEntryV1 {
            target: contract.target.triple.clone(),
            minimum_platform: contract.target.minimum_platform.clone(),
            contract_digest: contract
                .digest()
                .map_err(|error| Error::Contract(error.to_string()))?,
            engine_compatibility_identity: contract.engine.identity().into(),
            hermesc_identity: compiler_identity.clone(),
            hbc_version: *hbc_version,
            contract: CatalogArtifactV1::from_bytes(
                CatalogArtifactRoleV1::StubContract,
                "application/vnd.ibex.stub-contract+json",
                contract_bytes,
            ),
            stub_unsigned_core: CatalogArtifactV1::from_bytes(
                CatalogArtifactRoleV1::StubUnsignedCore,
                "application/vnd.ibex.stub-core",
                stub_unsigned_core,
            ),
            hermesc: hermesc_artifact,
        };
        let manifest = Self {
            schema: CATALOG_SCHEMA_V1.into(),
            release: release.into(),
            sequence,
            entries: vec![entry],
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|error| Error::Manifest(error.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| Error::Manifest(error.to_string()))
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|error| Error::Manifest(error.to_string()))?;
        capsec_semantics::digest::compute_domain_digest(CATALOG_DOMAIN_V1, &value, &[])
            .map_err(|error| Error::Manifest(error.to_string()))
    }

    fn validate(&self) -> Result<()> {
        if self.schema != CATALOG_SCHEMA_V1
            || self.release.is_empty()
            || self.sequence == 0
            || self.entries.is_empty()
        {
            return Err(Error::Manifest("catalog header is invalid".into()));
        }
        let mut targets = BTreeSet::new();
        let mut previous = None;
        for entry in &self.entries {
            if entry.target.is_empty()
                || !ibex_sfe_format::valid_release_target_baseline_v1(
                    &entry.target,
                    &entry.minimum_platform,
                )
                || entry.hbc_version == 0
                || !valid_digest(&entry.contract_digest)
                || !valid_digest(&entry.engine_compatibility_identity)
                || !valid_digest(&entry.hermesc_identity)
                || previous.is_some_and(|value: &str| value >= entry.target.as_str())
                || !targets.insert(&entry.target)
            {
                return Err(Error::Manifest("catalog target entry is invalid".into()));
            }
            entry
                .contract
                .validate(CatalogArtifactRoleV1::StubContract)?;
            entry
                .stub_unsigned_core
                .validate(CatalogArtifactRoleV1::StubUnsignedCore)?;
            entry.hermesc.validate(CatalogArtifactRoleV1::Hermesc)?;
            previous = Some(entry.target.as_str());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CatalogTargetArtifacts<'a> {
    pub contract: &'a [u8],
    pub stub_unsigned_core: &'a [u8],
    pub hermesc: &'a [u8],
}

#[derive(Debug)]
pub struct AdmittedCatalogTargetV1<'a> {
    pub catalog_digest: &'a str,
    pub entry: &'a CatalogEntryV1,
    pub contract: StubContractV3,
    pub stub_unsigned_core: &'a [u8],
    pub hermesc: &'a [u8],
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("SFC001 catalog trust root refused: {0}")]
    TrustRoot(String),
    #[error("SFC002 catalog manifest refused: {0}")]
    Manifest(String),
    #[error("SFC003 catalog target unavailable: {0}")]
    Target(String),
    #[error("SFC004 catalog artifact refused: {0}")]
    Artifact(String),
    #[error("SFC005 stub contract refused: {0}")]
    Contract(String),
    #[error("SFC006 catalog installation refused: {0}")]
    Installation(String),
}

pub type Result<T> = std::result::Result<T, Error>;

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

fn valid_digest(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("sha256-") else {
        return false;
    };
    URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .is_some_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibex_sfe_format::{
        EngineCompatibilityV1, StubAbisV1, StubAcceptedSchemasV1, StubBackendInventoryV1,
        StubBootContractV3, StubTargetV1, ENTRY_DESIGNATION_SCHEMA_V1, ENVELOPE_SCHEMA_V2,
        STUB_CONTRACT_SCHEMA_V3,
    };

    fn fixture() -> (CatalogManifestV1, Vec<u8>, Vec<u8>, Vec<u8>) {
        let stub = b"unsigned release stub".to_vec();
        let hermesc = b"catalog hermesc".to_vec();
        let hermesc_digest = digest_bytes(&hermesc);
        let engine = EngineCompatibilityV1::static_hermes(
            "hermes-full-static-release-v1",
            digest_bytes(b"static archive bundle"),
            99,
        )
        .unwrap();
        let compiler = HermescCompatibilityV1::catalog_artifact(
            &hermesc_digest,
            99,
            HermescRecipeV1::production().digest().unwrap(),
        )
        .unwrap();
        let contract = StubContractV3 {
            schema: STUB_CONTRACT_SCHEMA_V3.into(),
            profile: "release-v1".into(),
            release_eligible: true,
            target: StubTargetV1 {
                triple: "aarch64-apple-darwin".into(),
                minimum_platform: "macos-13.0-arm64".into(),
            },
            engine: engine.clone(),
            hermesc: compiler.clone(),
            accepted_schemas: StubAcceptedSchemasV1 {
                envelope: ENVELOPE_SCHEMA_V2.into(),
                entry_designation: ENTRY_DESIGNATION_SCHEMA_V1.into(),
                embedded_graph: "ibex/embedded-module-graph/1".into(),
                authenticated_graph_snapshot: "ibex/authenticated-graph-snapshot/1".into(),
                computed_candidates: "ibex/computed-candidates/1".into(),
                carrier: "ibex/module-carrier/2".into(),
                canonical_policy: "ibex/capsec-policy/2".into(),
                armed_snapshot: "ibex/capsec-armed/1".into(),
                runtime_capsec_projection: "ibex/capsec-runtime-projection/1".into(),
                runtime_identity: "ibex/runtime-identity/1".into(),
                environment_profile: "ibex/compiled-environment-profile/1".into(),
            },
            abis: StubAbisV1 {
                module_runner: "module-runner-test-v1".into(),
                arming: "arming-test-v1".into(),
            },
            transform_profile_digest: digest_bytes(b"transform"),
            runtime_capsec_projection_digest: digest_bytes(b"capsec"),
            runtime_identity_digest: digest_bytes(b"identity"),
            environment_profile_digest: digest_bytes(b"environment"),
            boot: StubBootContractV3::dual_mode(""),
            backends: StubBackendInventoryV1::release_for_target("aarch64-apple-darwin").unwrap(),
        };
        let contract_bytes = contract.canonical_bytes().unwrap();
        let entry = CatalogEntryV1 {
            target: contract.target.triple.clone(),
            minimum_platform: contract.target.minimum_platform.clone(),
            contract_digest: contract.digest().unwrap(),
            engine_compatibility_identity: engine.identity().into(),
            hermesc_identity: compiler.identity().unwrap().into(),
            hbc_version: 99,
            contract: CatalogArtifactV1::from_bytes(
                CatalogArtifactRoleV1::StubContract,
                "application/vnd.ibex.stub-contract+json",
                &contract_bytes,
            ),
            stub_unsigned_core: CatalogArtifactV1::from_bytes(
                CatalogArtifactRoleV1::StubUnsignedCore,
                "application/vnd.ibex.stub-core",
                &stub,
            ),
            hermesc: CatalogArtifactV1::from_bytes(
                CatalogArtifactRoleV1::Hermesc,
                "application/vnd.ibex.hermesc",
                &hermesc,
            ),
        };
        (
            CatalogManifestV1 {
                schema: CATALOG_SCHEMA_V1.into(),
                release: "ibex-test-1".into(),
                sequence: 1,
                entries: vec![entry],
            },
            contract_bytes,
            stub,
            hermesc,
        )
    }

    #[test]
    fn pinned_catalog_admits_only_the_cross_bound_target_artifacts() {
        let (manifest, contract, stub, hermesc) = fixture();
        let digest = manifest.digest().unwrap();
        let bytes = manifest.canonical_bytes().unwrap();
        let catalog = PinnedCatalogV1::load(&bytes, &digest).unwrap();
        let admitted = catalog
            .admit_target(
                "aarch64-apple-darwin",
                CatalogTargetArtifacts {
                    contract: &contract,
                    stub_unsigned_core: &stub,
                    hermesc: &hermesc,
                },
            )
            .unwrap();
        assert_eq!(admitted.catalog_digest, digest);
        assert_eq!(
            admitted.entry.stub_unsigned_core.content_address().unwrap(),
            format!(
                "sha256/{}/blob",
                &admitted.entry.stub_unsigned_core.digest["sha256-".len()..]
            )
        );
    }

    #[test]
    fn release_catalog_entry_is_derived_from_exact_artifact_bytes() {
        let (_fixture_manifest, contract, stub, hermesc) = fixture();
        let manifest = CatalogManifestV1::from_target_artifacts(
            "ibex-test-derived",
            7,
            &contract,
            &stub,
            &hermesc,
        )
        .unwrap();
        let digest = manifest.digest().unwrap();
        let bytes = manifest.canonical_bytes().unwrap();
        let pinned = PinnedCatalogV1::load(&bytes, &digest).unwrap();
        let admitted = pinned
            .admit_target(
                "aarch64-apple-darwin",
                CatalogTargetArtifacts {
                    contract: &contract,
                    stub_unsigned_core: &stub,
                    hermesc: &hermesc,
                },
            )
            .unwrap();
        assert_eq!(admitted.entry.contract.digest, digest_bytes(&contract));
        assert_eq!(
            admitted.entry.stub_unsigned_core.digest,
            digest_bytes(&stub)
        );
        assert_eq!(admitted.entry.hermesc.digest, digest_bytes(&hermesc));

        let mut changed_hermesc = hermesc;
        changed_hermesc.push(0);
        assert!(CatalogManifestV1::from_target_artifacts(
            "ibex-test-derived",
            7,
            &contract,
            &stub,
            &changed_hermesc,
        )
        .is_err());
    }

    #[test]
    fn artifact_substitution_and_contract_swap_refuse() {
        let (manifest, contract, stub, hermesc) = fixture();
        let catalog = PinnedCatalogV1::load(
            &manifest.canonical_bytes().unwrap(),
            &manifest.digest().unwrap(),
        )
        .unwrap();
        let mut changed_stub = stub.clone();
        changed_stub[0] ^= 1;
        assert!(matches!(
            catalog.admit_target(
                "aarch64-apple-darwin",
                CatalogTargetArtifacts {
                    contract: &contract,
                    stub_unsigned_core: &changed_stub,
                    hermesc: &hermesc,
                },
            ),
            Err(Error::Artifact(_))
        ));
        let mut changed_contract = contract.clone();
        changed_contract[0] ^= 1;
        assert!(matches!(
            catalog.admit_target(
                "aarch64-apple-darwin",
                CatalogTargetArtifacts {
                    contract: &changed_contract,
                    stub_unsigned_core: &stub,
                    hermesc: &hermesc,
                },
            ),
            Err(Error::Artifact(_))
        ));
        let mut changed_hermesc = hermesc.clone();
        changed_hermesc[0] ^= 1;
        assert!(matches!(
            catalog.admit_target(
                "aarch64-apple-darwin",
                CatalogTargetArtifacts {
                    contract: &contract,
                    stub_unsigned_core: &stub,
                    hermesc: &changed_hermesc,
                },
            ),
            Err(Error::Artifact(_))
        ));
    }

    #[test]
    fn prior_or_attacker_selected_manifest_fails_release_pin() {
        let (mut manifest, _, _, _) = fixture();
        let old_bytes = manifest.canonical_bytes().unwrap();
        let old_digest = manifest.digest().unwrap();
        manifest.sequence += 1;
        let current_digest = manifest.digest().unwrap();
        assert_ne!(old_digest, current_digest);
        assert!(matches!(
            PinnedCatalogV1::load(&old_bytes, &current_digest),
            Err(Error::TrustRoot(_))
        ));
    }

    #[test]
    fn noncanonical_manifest_and_missing_target_refuse() {
        let (manifest, _, _, _) = fixture();
        let digest = manifest.digest().unwrap();
        let mut bytes = manifest.canonical_bytes().unwrap();
        bytes.push(b'\n');
        assert!(matches!(
            PinnedCatalogV1::load(&bytes, &digest),
            Err(Error::Manifest(_))
        ));
        let catalog = PinnedCatalogV1::load(&manifest.canonical_bytes().unwrap(), &digest).unwrap();
        assert!(matches!(
            catalog.entry("x86_64-unknown-linux-gnu"),
            Err(Error::Target(_))
        ));
    }

    #[test]
    fn pinned_directory_install_is_atomic_verified_and_idempotent() {
        let (manifest, contract, stub, hermesc) = fixture();
        let digest = manifest.digest().unwrap();
        let source = tempfile::tempdir().unwrap();
        write_new(
            &source.path().join("manifest.json"),
            &manifest.canonical_bytes().unwrap(),
        )
        .unwrap();
        let entry = &manifest.entries[0];
        for (artifact, bytes) in [
            (&entry.contract, contract.as_slice()),
            (&entry.stub_unsigned_core, stub.as_slice()),
            (&entry.hermesc, hermesc.as_slice()),
        ] {
            let path = source.path().join(artifact.content_address().unwrap());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            write_new(&path, bytes).unwrap();
        }
        let store = tempfile::tempdir().unwrap();
        let installed =
            install_pinned_catalog_directory(source.path(), store.path(), &digest).unwrap();
        assert_eq!(
            installed,
            store.path().join(catalog_store_key(&digest).unwrap())
        );
        assert_eq!(
            install_pinned_catalog_directory(source.path(), store.path(), &digest).unwrap(),
            installed
        );
        admit_catalog_directory(&installed, &digest).unwrap();
        assert!(installed.join("manifest.json").is_file());
    }

    #[test]
    fn pinned_directory_install_refuses_artifact_substitution_before_publish() {
        let (manifest, contract, mut stub, hermesc) = fixture();
        let digest = manifest.digest().unwrap();
        let source = tempfile::tempdir().unwrap();
        write_new(
            &source.path().join("manifest.json"),
            &manifest.canonical_bytes().unwrap(),
        )
        .unwrap();
        stub[0] ^= 1;
        let entry = &manifest.entries[0];
        for (artifact, bytes) in [
            (&entry.contract, contract.as_slice()),
            (&entry.stub_unsigned_core, stub.as_slice()),
            (&entry.hermesc, hermesc.as_slice()),
        ] {
            let path = source.path().join(artifact.content_address().unwrap());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            write_new(&path, bytes).unwrap();
        }
        let store = tempfile::tempdir().unwrap();
        assert!(matches!(
            install_pinned_catalog_directory(source.path(), store.path(), &digest),
            Err(Error::Artifact(_))
        ));
        assert!(!store
            .path()
            .join(catalog_store_key(&digest).unwrap())
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_directory_install_refuses_symlinked_catalog_root() {
        use std::os::unix::fs::symlink;

        let (manifest, _, _, _) = fixture();
        let digest = manifest.digest().unwrap();
        let parent = tempfile::tempdir().unwrap();
        let source = parent.path().join("source");
        std::fs::create_dir(&source).unwrap();
        write_new(
            &source.join("manifest.json"),
            &manifest.canonical_bytes().unwrap(),
        )
        .unwrap();
        let linked = parent.path().join("linked");
        symlink(&source, &linked).unwrap();

        let store = tempfile::tempdir().unwrap();
        assert!(matches!(
            install_pinned_catalog_directory(&linked, store.path(), &digest),
            Err(Error::Installation(_))
        ));
    }
}
