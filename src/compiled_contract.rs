//! Generated-authority assembly for the diagnostic compiled-stub contract.
//!
//! Release catalog construction replaces only target/engine/compiler facts;
//! schema, ABI, transform, CapSec, runtime-identity, and environment identities
//! remain sourced from the same committed authorities.
//! @ref LLP 0029#2-executable-layout-stub-envelope-footer — contract facts are assembled from generated authorities, never packager arguments

use ibex_sfe_format::{
    EngineCompatibilityV1, HermescCompatibilityV1, StubAbisV1, StubAcceptedSchemasV1,
    StubContractV1, StubTargetV1, ENTRY_DESIGNATION_SCHEMA_V1, ENVELOPE_SCHEMA_V1,
    STUB_CONTRACT_SCHEMA_V1,
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

pub fn release_stub_contract(facts: ReleaseStubFactsV1) -> ibex_sfe_format::Result<StubContractV1> {
    if !COMPILED_ENVIRONMENT_PROFILE_RELEASE_ELIGIBLE {
        return Err(ibex_sfe_format::Error::Contract(
            "compiled environment profile is not release eligible; resolve LLP 0029 register item 2"
                .into(),
        ));
    }
    let contract = StubContractV1 {
        schema: STUB_CONTRACT_SCHEMA_V1.into(),
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
    };
    contract.canonical_bytes()?;
    Ok(contract)
}
use crate::identity_generated::{RUNTIME_IDENTITY_DIGEST, RUNTIME_IDENTITY_SCHEMA};
use crate::module_loader::transform_config_generated::{
    MODULE_RUNNER_ABI, TRANSFORM_CONFIGURATION_DIGEST,
};

pub fn diagnostic_development_stub_contract() -> ibex_sfe_format::Result<StubContractV1> {
    let contract = StubContractV1 {
        schema: STUB_CONTRACT_SCHEMA_V1.into(),
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
    };
    contract.canonical_bytes()?;
    Ok(contract)
}

fn accepted_schemas() -> StubAcceptedSchemasV1 {
    StubAcceptedSchemasV1 {
        envelope: ENVELOPE_SCHEMA_V1.into(),
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
    fn release_contract_refuses_an_undecided_environment_profile() {
        let error = super::release_stub_contract(super::ReleaseStubFactsV1 {
            profile: "release-v1".into(),
            target_triple: "aarch64-apple-darwin".into(),
            minimum_platform: "macos-13.0-arm64".into(),
            engine_build_profile: "hermes-full-static-release-v1".into(),
            static_archive_digest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            hbc_version: 99,
            hermesc_binary_digest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            hermesc_recipe_digest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("register item 2"));
    }
}
