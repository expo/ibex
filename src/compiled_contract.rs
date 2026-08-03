//! Generated-authority assembly for the diagnostic compiled-stub contract.
//!
//! Release catalog construction replaces only target/engine/compiler facts;
//! schema, ABI, transform, CapSec, runtime-identity, and environment identities
//! remain sourced from the same committed authorities.
//! @ref LLP 0029#2-executable-layout-stub-envelope-footer — contract facts are assembled from generated authorities, never packager arguments

use ibex_sfe_format::{
    EngineCompatibilityV1, HermescCompatibilityV1, StubAbisV1, StubAcceptedSchemasV1,
    StubBackendInventoryV1, StubBootContractV3, StubContractV3, StubTargetV1,
    ENTRY_DESIGNATION_SCHEMA_V1, ENVELOPE_SCHEMA_V2, STUB_CONTRACT_SCHEMA_V3,
};

use crate::capsec_runtime_projection_generated::{
    CAPSEC_RUNTIME_PROJECTION_DIGEST, CAPSEC_RUNTIME_PROJECTION_SCHEMA,
};
use crate::compiled_environment_profile_generated::{
    COMPILED_ENVIRONMENT_PROFILE_DIGEST, COMPILED_ENVIRONMENT_PROFILE_RELEASE_ELIGIBLE,
    COMPILED_ENVIRONMENT_PROFILE_SCHEMA,
};

#[derive(Clone, Debug)]
pub struct ReleaseStubFactsV1 {
    pub profile: String,
    pub target_triple: String,
    pub minimum_platform: String,
    pub engine_build_profile: String,
    pub static_archive_digest: String,
    pub hbc_version: u32,
    pub hermesc_binary_digest: String,
    pub hermesc_recipe_digest: String,
}

pub fn release_stub_contract(facts: ReleaseStubFactsV1) -> ibex_sfe_format::Result<StubContractV3> {
    if !COMPILED_ENVIRONMENT_PROFILE_RELEASE_ELIGIBLE {
        return Err(ibex_sfe_format::Error::Contract(
            "compiled environment profile is not release eligible; resolve LLP 0029 register item 2"
                .into(),
        ));
    }
    let backends = StubBackendInventoryV1::release_for_target(&facts.target_triple)?;
    let contract = StubContractV3 {
        schema: STUB_CONTRACT_SCHEMA_V3.into(),
        profile: facts.profile,
        release_eligible: true,
        target: StubTargetV1 {
            triple: facts.target_triple,
            minimum_platform: facts.minimum_platform,
        },
        engine: EngineCompatibilityV1::static_hermes(
            facts.engine_build_profile,
            facts.static_archive_digest,
            facts.hbc_version,
        )?,
        hermesc: HermescCompatibilityV1::catalog_artifact(
            facts.hermesc_binary_digest,
            facts.hbc_version,
            facts.hermesc_recipe_digest,
        )?,
        accepted_schemas: accepted_schemas(),
        abis: stub_abis(),
        transform_profile_digest: TRANSFORM_CONFIGURATION_DIGEST.into(),
        runtime_capsec_projection_digest: CAPSEC_RUNTIME_PROJECTION_DIGEST.into(),
        runtime_identity_digest: RUNTIME_IDENTITY_DIGEST.into(),
        environment_profile_digest: COMPILED_ENVIRONMENT_PROFILE_DIGEST.into(),
        boot: StubBootContractV3::dual_mode(""),
        backends,
    };
    contract.canonical_bytes()?;
    Ok(contract)
}
use crate::identity_generated::{RUNTIME_IDENTITY_DIGEST, RUNTIME_IDENTITY_SCHEMA};
use crate::module_loader::transform_config_generated::{
    MODULE_RUNNER_ABI, TRANSFORM_CONFIGURATION_DIGEST,
};

pub fn diagnostic_development_stub_contract() -> ibex_sfe_format::Result<StubContractV3> {
    let contract = StubContractV3 {
        schema: STUB_CONTRACT_SCHEMA_V3.into(),
        profile: "dynamic-development-source-carrier".into(),
        release_eligible: false,
        target: StubTargetV1 {
            triple: host_target_triple().into(),
            minimum_platform: "diagnostic-host-unpinned".into(),
        },
        engine: EngineCompatibilityV1::diagnostic_source("dynamic-hermes-source-carrier-v1")?,
        hermesc: HermescCompatibilityV1::diagnostic_unused(
            "factory-source-carrier-does-not-consume-hermesc",
        ),
        accepted_schemas: accepted_schemas(),
        abis: stub_abis(),
        transform_profile_digest: TRANSFORM_CONFIGURATION_DIGEST.into(),
        runtime_capsec_projection_digest: CAPSEC_RUNTIME_PROJECTION_DIGEST.into(),
        runtime_identity_digest: RUNTIME_IDENTITY_DIGEST.into(),
        environment_profile_digest: COMPILED_ENVIRONMENT_PROFILE_DIGEST.into(),
        boot: StubBootContractV3::dual_mode(""),
        backends: StubBackendInventoryV1::diagnostic_development(),
    };
    contract.canonical_bytes()?;
    Ok(contract)
}

/// Verify that a parsed contract names the schema/ABI/semantic authorities
/// compiled into this runtime. Target, engine, and compiler facts are allowed
/// to vary by catalog entry; these generated facts are not.
/// @ref LLP 0029#2-executable-layout-stub-envelope-footer — a newer producer
/// cannot make an older stub accept an ABI merely by describing it in the
/// embedded contract
pub fn validate_stub_contract_local_authorities(
    contract: &StubContractV3,
) -> ibex_sfe_format::Result<()> {
    if contract.accepted_schemas != accepted_schemas()
        || contract.abis != stub_abis()
        || contract.transform_profile_digest != TRANSFORM_CONFIGURATION_DIGEST
        || contract.runtime_capsec_projection_digest != CAPSEC_RUNTIME_PROJECTION_DIGEST
        || contract.runtime_identity_digest != RUNTIME_IDENTITY_DIGEST
        || contract.environment_profile_digest != COMPILED_ENVIRONMENT_PROFILE_DIGEST
    {
        return Err(ibex_sfe_format::Error::Contract(
            "stub contract schema, ABI, or generated semantic identity disagrees with the compiled runtime"
                .into(),
        ));
    }
    Ok(())
}

fn accepted_schemas() -> StubAcceptedSchemasV1 {
    StubAcceptedSchemasV1 {
        envelope: ENVELOPE_SCHEMA_V2.into(),
        entry_designation: ENTRY_DESIGNATION_SCHEMA_V1.into(),
        embedded_graph: "ibex/embedded-module-graph/1".into(),
        authenticated_graph_snapshot: "ibex/authenticated-graph-snapshot/1".into(),
        computed_candidates: "ibex/computed-candidates/1".into(),
        carrier: "ibex/module-carrier/2".into(),
        canonical_policy: capsec_semantics::policy::POLICY_SCHEMA.into(),
        armed_snapshot: capsec_semantics::arming::ARMED_SNAPSHOT_SCHEMA.into(),
        runtime_capsec_projection: CAPSEC_RUNTIME_PROJECTION_SCHEMA.into(),
        runtime_identity: RUNTIME_IDENTITY_SCHEMA.into(),
        environment_profile: COMPILED_ENVIRONMENT_PROFILE_SCHEMA.into(),
    }
}

fn stub_abis() -> StubAbisV1 {
    StubAbisV1 {
        module_runner: MODULE_RUNNER_ABI.into(),
        arming: capsec_semantics::arming::ARMING_ABI.into(),
    }
}

const fn host_target_triple() -> &'static str {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        "aarch64-apple-darwin"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        "aarch64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        "x86_64-unknown-linux-gnu"
    }
    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "linux")
    )))]
    {
        "unsupported-diagnostic-target"
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use crate::module_loader::artifact::source_integrity;

    #[test]
    fn producer_newer_stub_older_authority_matrix_refuses() {
        let contract = diagnostic_development_stub_contract().unwrap();
        validate_stub_contract_local_authorities(&contract).unwrap();

        let mut newer_abi = contract.clone();
        newer_abi.abis.module_runner.push_str("-producer-newer");
        newer_abi.canonical_bytes().unwrap();
        assert!(validate_stub_contract_local_authorities(&newer_abi).is_err());

        let mut newer_transform = contract.clone();
        newer_transform.transform_profile_digest = source_integrity(b"producer-newer-transform")
            .unwrap()
            .to_string();
        newer_transform.canonical_bytes().unwrap();
        assert!(validate_stub_contract_local_authorities(&newer_transform).is_err());

        let mut newer_runtime = contract;
        newer_runtime.runtime_identity_digest = source_integrity(b"producer-newer-runtime")
            .unwrap()
            .to_string();
        newer_runtime.canonical_bytes().unwrap();
        assert!(validate_stub_contract_local_authorities(&newer_runtime).is_err());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn diagnostic_contract_is_closed_and_not_release_eligible() {
        let contract = super::diagnostic_development_stub_contract().unwrap();
        assert!(!contract.release_eligible);
        assert_eq!(contract.target.triple, super::host_target_triple());
        assert_eq!(
            contract.engine.identity(),
            "sha256-x3tdd9UwEb3H3y3sCnX4wtCJJzBCfeoyhR5dp3WUNAA"
        );
        assert_eq!(
            contract.canonical_bytes().unwrap(),
            contract.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn release_contract_accepts_the_decided_empty_capsec_restore_allowlist() {
        let contract = super::release_stub_contract(super::ReleaseStubFactsV1 {
            profile: "release-v1".into(),
            target_triple: "aarch64-apple-darwin".into(),
            minimum_platform: "macos-13.0-arm64".into(),
            engine_build_profile: "hermes-full-static-release-v1".into(),
            static_archive_digest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            hbc_version: 99,
            hermesc_binary_digest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            hermesc_recipe_digest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        })
        .unwrap();
        assert!(contract.release_eligible);
        assert_eq!(
            contract.environment_profile_digest,
            super::COMPILED_ENVIRONMENT_PROFILE_DIGEST
        );
    }
}
