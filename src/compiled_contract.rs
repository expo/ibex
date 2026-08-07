//! Generated-authority assembly for the diagnostic compiled-stub contract.
//!
//! Release catalog construction replaces only target/engine/compiler facts;
//! schema, ABI, transform, CapSec, runtime-identity, and environment identities
//! remain sourced from the same committed authorities.
//! @ref LLP 0029#2-executable-layout-stub-envelope-footer — contract facts are assembled from generated authorities, never packager arguments

use ibex_sfe_format::app_bound::{
    ExternalWorkerV1, LimitsV1, StubAbisV2, StubAcceptedSchemasV2, StubContractV4,
    APPLICATION_BINDING_SCHEMA_V1, ENVELOPE_SCHEMA_V3, RESTRICTED_WORKER_ABI_V1,
    RESTRICTED_WORKER_ARMING_SCHEMA_V1, RESTRICTED_WORKER_BROKER_V1,
    RESTRICTED_WORKER_LANGUAGE_PROFILE_V1, RESTRICTED_WORKER_POLICY_V1, STANDALONE_INFO_SCHEMA_V2,
    STUB_CONTRACT_SCHEMA_V4, TARGET_ADVERTISEMENT_SCHEMA_V1,
};
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

/// One diagnostic-only schema compiled into the runtime contract registry.
/// The document is a review artifact and the type identifier is the runtime
/// dispatch identity; tests below keep the two in lockstep.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompiledDiagnosticAuditSchemaV1 {
    pub type_id: &'static str,
    pub document: &'static str,
}

/// Closed schema registry for the foreground source-audit protocol.
///
/// This registry is deliberately separate from `accepted_schemas()`: the
/// latter is the armed/compiled-stub admission contract, while these documents
/// are non-authorizing diagnostic evidence. Registering them as production
/// accepted schemas would erase the boundary this phase is establishing.
///
/// @ref LLP 0030#1-workflow-and-type-separation — diagnostic evidence is not
/// an armed snapshot or production artifact admission
pub const DIAGNOSTIC_AUDIT_SCHEMAS_V1: [CompiledDiagnosticAuditSchemaV1; 2] = [
    CompiledDiagnosticAuditSchemaV1 {
        type_id: capsec_semantics::diagnostic_audit::DIAGNOSTIC_GRAPH_SNAPSHOT_SCHEMA_V1,
        document: include_str!("../schemas/diagnostic-graph-snapshot-v1.schema.json"),
    },
    CompiledDiagnosticAuditSchemaV1 {
        type_id: capsec_semantics::diagnostic_audit::DIAGNOSTIC_AUDIT_EXECUTION_RECEIPT_SCHEMA_V1,
        document: include_str!("../schemas/diagnostic-audit-execution-receipt-v1.schema.json"),
    },
];

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

#[derive(Clone, Debug)]
pub struct ReleaseExternalWorkerFactsV1 {
    pub language_profile_digest: String,
    pub worker_policy_digest: String,
    pub global_inventory_digest: String,
    pub target_advertisement_digest: String,
}

/// Assemble the lockstep V4 app-bound contract from the same release facts as
/// the general V3 stub plus target-specific restricted-worker evidence.
/// @ref LLP 0048#8-app-bound-executable-contract
pub fn release_app_bound_stub_contract(
    facts: ReleaseStubFactsV1,
    worker: ReleaseExternalWorkerFactsV1,
) -> ibex_sfe_format::Result<StubContractV4> {
    let base = release_stub_contract(facts)?;
    let mut boot = base.boot;
    boot.information_selector.report_schema = STANDALONE_INFO_SCHEMA_V2.into();
    let contract = StubContractV4 {
        schema: STUB_CONTRACT_SCHEMA_V4.into(),
        profile: "app-bound-parent-v1".into(),
        release_eligible: base.release_eligible,
        target: base.target,
        engine: base.engine,
        hermesc: base.hermesc,
        accepted_schemas: StubAcceptedSchemasV2 {
            envelope: ENVELOPE_SCHEMA_V3.into(),
            application_binding: APPLICATION_BINDING_SCHEMA_V1.into(),
            target_advertisement: TARGET_ADVERTISEMENT_SCHEMA_V1.into(),
            entry_designation: base.accepted_schemas.entry_designation,
            embedded_graph: base.accepted_schemas.embedded_graph,
            authenticated_graph_snapshot: base.accepted_schemas.authenticated_graph_snapshot,
            computed_candidates: base.accepted_schemas.computed_candidates,
            carrier: base.accepted_schemas.carrier,
            canonical_policy: base.accepted_schemas.canonical_policy,
            armed_snapshot: base.accepted_schemas.armed_snapshot,
            runtime_capsec_projection: base.accepted_schemas.runtime_capsec_projection,
            runtime_identity: base.accepted_schemas.runtime_identity,
            environment_profile: base.accepted_schemas.environment_profile,
        },
        abis: StubAbisV2 {
            module_runner: base.abis.module_runner,
            arming: base.abis.arming,
            restricted_worker: RESTRICTED_WORKER_ABI_V1.into(),
        },
        transform_profile_digest: base.transform_profile_digest,
        runtime_capsec_projection_digest: base.runtime_capsec_projection_digest,
        runtime_identity_digest: base.runtime_identity_digest,
        environment_profile_digest: base.environment_profile_digest,
        boot,
        backends: base.backends,
        external_worker: ExternalWorkerV1 {
            enabled: true,
            language_profile: RESTRICTED_WORKER_LANGUAGE_PROFILE_V1.into(),
            language_profile_digest: worker.language_profile_digest,
            arming_schema: RESTRICTED_WORKER_ARMING_SCHEMA_V1.into(),
            worker_policy: RESTRICTED_WORKER_POLICY_V1.into(),
            worker_policy_digest: worker.worker_policy_digest,
            broker_protocol: RESTRICTED_WORKER_BROKER_V1.into(),
            global_inventory_digest: worker.global_inventory_digest,
            target_advertisement_digest: Some(worker.target_advertisement_digest),
            defaults: LimitsV1::defaults(),
            maxima: LimitsV1::maxima(),
        },
    };
    contract.canonical_bytes()?;
    Ok(contract)
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

/// Verify the generated authorities carried by an app-bound V4 stub. The
/// application binding and target evidence are envelope/catalog inputs; they
/// cannot revise any schema, ABI, transform, or runtime identity compiled into
/// this image.
/// @ref LLP 0048#8-app-bound-executable-contract
pub fn validate_app_bound_stub_contract_local_authorities(
    contract: &StubContractV4,
) -> ibex_sfe_format::Result<()> {
    let expected = StubAcceptedSchemasV2 {
        envelope: ENVELOPE_SCHEMA_V3.into(),
        application_binding: APPLICATION_BINDING_SCHEMA_V1.into(),
        target_advertisement: TARGET_ADVERTISEMENT_SCHEMA_V1.into(),
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
    };
    if contract.accepted_schemas != expected
        || contract.abis.module_runner != MODULE_RUNNER_ABI
        || contract.abis.arming != capsec_semantics::arming::ARMING_ABI
        || contract.abis.restricted_worker != RESTRICTED_WORKER_ABI_V1
        || contract.transform_profile_digest != TRANSFORM_CONFIGURATION_DIGEST
        || contract.runtime_capsec_projection_digest != CAPSEC_RUNTIME_PROJECTION_DIGEST
        || contract.runtime_identity_digest != RUNTIME_IDENTITY_DIGEST
        || contract.environment_profile_digest != COMPILED_ENVIRONMENT_PROFILE_DIGEST
    {
        return Err(ibex_sfe_format::Error::Contract(
            "app-bound stub contract schema, ABI, or generated semantic identity disagrees with the compiled runtime"
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

    #[test]
    fn app_bound_v4_catalog_v2_lockstep_round_trip() {
        use ibex_sfe_catalog::app_bound::{CatalogManifestV2, PinnedCatalogV2};
        use ibex_sfe_format::app_bound::{
            TargetAdvertisementV1, TargetEvidenceV1, RESTRICTED_WORKER_ABI_V1,
            TARGET_ADVERTISEMENT_SCHEMA_V1, TARGET_EVIDENCE_SCHEMA_V1,
        };
        let hermesc = b"authenticated hermesc fixture";
        let facts = ReleaseStubFactsV1 {
            profile: "sfe-v1".into(),
            target_triple: "aarch64-apple-darwin".into(),
            minimum_platform: "macos-14.0-arm64".into(),
            engine_build_profile: "full".into(),
            static_archive_digest: source_integrity(b"archives").unwrap().to_string(),
            hbc_version: 96,
            hermesc_binary_digest: source_integrity(hermesc).unwrap().to_string(),
            hermesc_recipe_digest: ibex_sfe_format::HermescRecipeV1::production()
                .digest()
                .unwrap(),
        };
        let base = release_stub_contract(facts.clone()).unwrap();
        let semantic = source_integrity(b"semantic fixture").unwrap().to_string();
        let advertisement = TargetAdvertisementV1 {
            schema: TARGET_ADVERTISEMENT_SCHEMA_V1.into(),
            target: base.target.clone(),
            engine_compatibility_digest: base.engine.identity().into(),
            native_abi: RESTRICTED_WORKER_ABI_V1.into(),
            language_profile: RESTRICTED_WORKER_LANGUAGE_PROFILE_V1.into(),
            language_profile_digest: semantic.clone(),
            worker_policy: RESTRICTED_WORKER_POLICY_V1.into(),
            worker_policy_digest: semantic.clone(),
            broker_protocol: RESTRICTED_WORKER_BROKER_V1.into(),
            global_inventory_digest: semantic.clone(),
            defaults_digest: LimitsV1::defaults().digest().unwrap(),
            maxima_digest: LimitsV1::maxima().digest().unwrap(),
            evidence: TargetEvidenceV1 {
                schema: TARGET_EVIDENCE_SCHEMA_V1.into(),
                suite_digest: semantic.clone(),
                engine_artifact_digest: semantic.clone(),
                policy_artifact_digest: semantic.clone(),
                broker_corpus_digest: semantic.clone(),
            },
        };
        let advertisement_bytes = advertisement.canonical_bytes().unwrap();
        let contract = release_app_bound_stub_contract(
            facts,
            ReleaseExternalWorkerFactsV1 {
                language_profile_digest: semantic.clone(),
                worker_policy_digest: semantic.clone(),
                global_inventory_digest: semantic,
                target_advertisement_digest: advertisement.digest().unwrap(),
            },
        )
        .unwrap();
        let contract_bytes = contract.canonical_bytes().unwrap();
        let manifest = CatalogManifestV2::from_target_artifacts(
            "test",
            1,
            &contract_bytes,
            b"stub",
            hermesc,
            &advertisement_bytes,
        )
        .unwrap();
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let digest = manifest.digest().unwrap();
        let pinned = PinnedCatalogV2::load(&manifest_bytes, &digest).unwrap();
        pinned
            .admit_target(
                "aarch64-apple-darwin",
                &contract_bytes,
                b"stub",
                hermesc,
                &advertisement_bytes,
            )
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn diagnostic_audit_schema_registry_is_closed_and_non_authorizing() {
        let registered_ids = super::DIAGNOSTIC_AUDIT_SCHEMAS_V1
            .iter()
            .map(|schema| schema.type_id)
            .collect::<Vec<_>>();
        assert_eq!(
            registered_ids,
            [
                capsec_semantics::diagnostic_audit::DIAGNOSTIC_GRAPH_SNAPSHOT_SCHEMA_V1,
                capsec_semantics::diagnostic_audit::DIAGNOSTIC_AUDIT_EXECUTION_RECEIPT_SCHEMA_V1,
            ]
        );

        for registered in super::DIAGNOSTIC_AUDIT_SCHEMAS_V1 {
            let document: serde_json::Value =
                serde_json::from_str(registered.document).expect("registered schema is JSON");
            assert_eq!(
                document["properties"]["schema"]["const"], registered.type_id,
                "compiled type id must match the schema's closed dispatch value"
            );
            assert_eq!(document["additionalProperties"], false);
        }

        let production_contract = super::diagnostic_development_stub_contract().unwrap();
        let production_schemas =
            serde_json::to_value(production_contract.accepted_schemas).unwrap();
        let production_schema_ids = production_schemas
            .as_object()
            .unwrap()
            .values()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>();
        for diagnostic in registered_ids {
            assert!(
                !production_schema_ids.contains(&diagnostic),
                "diagnostic evidence must not enter production acceptedSchemas"
            );
        }
    }

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
