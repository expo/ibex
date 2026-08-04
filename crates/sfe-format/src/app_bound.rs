//! Canonical contracts for app-bound standalone executables.
//!
//! This module is deliberately separate from the general V2/V3 standalone
//! format. An app-bound reader selects the complete V3/V4/V2 profile by footer
//! magic; field presence never upgrades an older artifact's authority.
//! @ref LLP 0048#8-app-bound-executable-contract — lockstep schemas and the
//! immutable application binding are the admission boundary.

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization as _;

use super::{
    valid_digest, EngineCompatibilityV1, Error, HermescCompatibilityV1, Result,
    StubBackendInventoryV1, StubBootContractV3, StubTargetV1,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const ENVELOPE_SCHEMA_V3: &str = "ibex/single-file-executable/3";
pub const STUB_CONTRACT_SCHEMA_V4: &str = "ibex/stub-contract/4";
pub const STUB_CONTRACT_DOMAIN_V4: &str = "ibex:stub-contract:4";
pub const COMPILE_PLAN_SCHEMA_V2: &str = "ibex/compile-plan/2";
pub const COMPILE_PLAN_DOMAIN_V2: &str = "ibex:compile-plan:2";
pub const PACKAGE_PROVENANCE_SCHEMA_V2: &str = "ibex/package-provenance/2";
pub const APPLICATION_BINDING_SCHEMA_V1: &str = "ibex/app-bound-parent/1";
pub const APPLICATION_BINDING_DOMAIN_V1: &str = "ibex:app-bound-parent:1";
pub const RELEASE_LINEAGE_SCHEMA_V1: &str = "ibex/app-cli-release-lineage/1";
pub const STANDALONE_INFO_SCHEMA_V2: &str = "ibex/standalone-executable-info/2";
pub const RESTRICTED_WORKER_ABI_V1: &str = "ibex/restricted-worker-abi/1";
pub const RESTRICTED_WORKER_BROKER_V1: &str = "ibex/restricted-worker-broker/1";
pub const RESTRICTED_WORKER_ARMING_SCHEMA_V1: &str = "ibex/restricted-worker-arming/1";
pub const RESTRICTED_WORKER_LANGUAGE_PROFILE_V1: &str = "ibex/external-script-profile/1";
pub const RESTRICTED_WORKER_POLICY_V1: &str = "ibex/restricted-external-worker-policy/1";
pub const RESTRICTED_WORKER_LANGUAGE_PROFILE_DOMAIN_V1: &str = "ibex:external-script-profile:1";
pub const RESTRICTED_WORKER_POLICY_DOMAIN_V1: &str = "ibex:restricted-external-worker-policy:1";
pub const RESTRICTED_WORKER_GLOBAL_INVENTORY_DOMAIN_V1: &str =
    "ibex:restricted-worker-global-inventory:1";
pub const TARGET_ADVERTISEMENT_SCHEMA_V1: &str = "ibex/restricted-worker-target-advertisement/1";
pub const TARGET_ADVERTISEMENT_DOMAIN_V1: &str = "ibex:restricted-worker-target-advertisement:1";
pub const TARGET_EVIDENCE_SCHEMA_V1: &str = "ibex/restricted-worker-target-evidence/1";
pub const LIMITS_DOMAIN_V1: &str = "ibex:restricted-worker-limits:1";
pub const FORMAT_VERSION_V3: u32 = 3;
pub const FOOTER_MAGIC_V3: [u8; 16] = *b"IBEX_SFE_V3\0\0\0\0\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LimitsV1 {
    pub source_bytes: u64,
    pub transformed_source_bytes: u64,
    pub source_map_bytes: u64,
    pub transform_arena_bytes: u64,
    pub run_wall_ms: u64,
    pub call_establishment_ms: u64,
    pub broker_operations: u64,
    pub open_subscriptions: u64,
    pub frame_bytes: u64,
    pub result_bytes: u64,
    pub stderr_bytes: u64,
    pub heap_bytes: u64,
    pub grace_ms: u64,
    pub open_timers: u64,
}

impl LimitsV1 {
    pub const fn defaults() -> Self {
        Self {
            source_bytes: 1 << 20,
            transformed_source_bytes: 4 << 20,
            source_map_bytes: 8 << 20,
            transform_arena_bytes: 64 << 20,
            run_wall_ms: 120_000,
            call_establishment_ms: 60_000,
            broker_operations: 1_000,
            open_subscriptions: 16,
            frame_bytes: 1 << 20,
            result_bytes: 1 << 20,
            stderr_bytes: 1 << 20,
            heap_bytes: 128 << 20,
            grace_ms: 2_000,
            open_timers: 1_024,
        }
    }

    pub const fn maxima() -> Self {
        Self {
            source_bytes: 1 << 20,
            transformed_source_bytes: 4 << 20,
            source_map_bytes: 8 << 20,
            transform_arena_bytes: 64 << 20,
            run_wall_ms: 1_800_000,
            call_establishment_ms: 300_000,
            broker_operations: 10_000,
            open_subscriptions: 256,
            frame_bytes: 4 << 20,
            result_bytes: 16 << 20,
            stderr_bytes: 16 << 20,
            heap_bytes: 512 << 20,
            grace_ms: 10_000,
            open_timers: 8_192,
        }
    }

    pub fn validate_effective(&self) -> Result<()> {
        let max = Self::maxima();
        let fixed = self.source_bytes == max.source_bytes
            && self.transformed_source_bytes == max.transformed_source_bytes
            && self.source_map_bytes == max.source_map_bytes
            && self.transform_arena_bytes == max.transform_arena_bytes;
        let bounded = self.run_wall_ms > 0
            && self.run_wall_ms <= max.run_wall_ms
            && self.call_establishment_ms > 0
            && self.call_establishment_ms <= max.call_establishment_ms
            && self.broker_operations > 0
            && self.broker_operations <= max.broker_operations
            && self.open_subscriptions > 0
            && self.open_subscriptions <= max.open_subscriptions
            && self.frame_bytes >= 64 * 1024
            && self.frame_bytes <= max.frame_bytes
            && self.result_bytes > 0
            && self.result_bytes <= max.result_bytes
            && self.stderr_bytes > 0
            && self.stderr_bytes <= max.stderr_bytes
            && self.heap_bytes > 0
            && self.heap_bytes <= max.heap_bytes
            && self.grace_ms > 0
            && self.grace_ms <= max.grace_ms
            && self.open_timers > 0
            && self.open_timers <= max.open_timers;
        if !fixed || !bounded {
            return Err(Error::Contract(
                "restricted-worker limits are invalid".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate_effective()?;
        let value = serde_json::to_value(self).map_err(|e| Error::Contract(e.to_string()))?;
        capsec_semantics::digest::compute_domain_digest(LIMITS_DOMAIN_V1, &value, &[])
            .map_err(|e| Error::Contract(e.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseLineageV1 {
    pub schema: String,
    pub publisher_key_id: String,
    pub channel: String,
    pub recipe_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationBindingV1 {
    pub schema: String,
    pub origin: String,
    pub app_id: String,
    pub engine_compatibility: Vec<String>,
    pub broker_protocols: Vec<String>,
    pub release_lineage: ReleaseLineageV1,
}

fn clean_nfc(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.nfc().eq(value.chars())
        && !value.chars().any(char::is_control)
}

impl ApplicationBindingV1 {
    pub fn validate(&self) -> Result<()> {
        let origin = self
            .origin
            .strip_prefix("https://")
            .filter(|v| !v.is_empty());
        let origin_ok = origin.is_some_and(|v| {
            !v.contains(['/', '?', '#', '@']) && v == v.to_ascii_lowercase() && !v.ends_with(":443")
        });
        let engine_ok = !self.engine_compatibility.is_empty()
            && self.engine_compatibility.len() <= 32
            && self.engine_compatibility.windows(2).all(|w| w[0] < w[1])
            && self.engine_compatibility.iter().all(|v| clean_nfc(v, 256));
        let lineage = &self.release_lineage;
        if self.schema != APPLICATION_BINDING_SCHEMA_V1
            || !origin_ok
            || !clean_nfc(&self.app_id, 256)
            || !engine_ok
            || self.broker_protocols != [RESTRICTED_WORKER_BROKER_V1]
            || lineage.schema != RELEASE_LINEAGE_SCHEMA_V1
            || !clean_nfc(&lineage.publisher_key_id, 128)
            || !clean_nfc(&lineage.channel, 128)
            || !valid_digest(&lineage.recipe_digest)
        {
            return Err(Error::Contract("application binding is invalid".into()));
        }
        if self.canonical_bytes_unchecked()?.len() > 16 * 1024 {
            return Err(Error::Contract("application binding exceeds 16 KiB".into()));
        }
        Ok(())
    }
    fn canonical_bytes_unchecked(&self) -> Result<Vec<u8>> {
        let v = serde_json::to_value(self).map_err(|e| Error::Contract(e.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&v).map_err(|e| Error::Contract(e.to_string()))
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        self.canonical_bytes_unchecked()
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let v = serde_json::to_value(self).map_err(|e| Error::Contract(e.to_string()))?;
        capsec_semantics::digest::compute_domain_digest(APPLICATION_BINDING_DOMAIN_V1, &v, &[])
            .map_err(|e| Error::Contract(e.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubAcceptedSchemasV2 {
    pub envelope: String,
    pub application_binding: String,
    pub target_advertisement: String,
    pub entry_designation: String,
    pub embedded_graph: String,
    pub authenticated_graph_snapshot: String,
    pub computed_candidates: String,
    pub carrier: String,
    pub canonical_policy: String,
    pub armed_snapshot: String,
    pub runtime_capsec_projection: String,
    pub runtime_identity: String,
    pub environment_profile: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubAbisV2 {
    pub module_runner: String,
    pub arming: String,
    pub restricted_worker: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExternalWorkerV1 {
    pub enabled: bool,
    pub language_profile: String,
    pub language_profile_digest: String,
    pub arming_schema: String,
    pub worker_policy: String,
    pub worker_policy_digest: String,
    pub broker_protocol: String,
    pub global_inventory_digest: String,
    pub target_advertisement_digest: Option<String>,
    pub defaults: LimitsV1,
    pub maxima: LimitsV1,
}

impl ExternalWorkerV1 {
    pub fn availability(&self) -> Result<AppBoundAvailabilityV1> {
        match (self.enabled, self.target_advertisement_digest.is_some()) {
            (true, true) => Ok(AppBoundAvailabilityV1::EnabledAndAdvertised),
            (false, true) => Ok(AppBoundAvailabilityV1::DisabledAdvertised),
            (false, false) => Ok(AppBoundAvailabilityV1::DisabledUnadvertised),
            (true, false) => Err(Error::Contract(
                "enabled app-bound worker has no target advertisement".into(),
            )),
        }
    }
}

/// The shared authenticated projection emitted by inspection V4 and
/// standalone-info V2. Keeping this as one strict type prevents the two
/// non-evaluating readers from drifting apart.
/// @ref LLP 0048#8.1-strict-schema-and-binary-definitions — both reports carry
/// this exact closed projection and only the enabled/advertised state may run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppBoundAvailabilityV1 {
    EnabledAndAdvertised,
    DisabledAdvertised,
    DisabledUnadvertised,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppBoundReportV1 {
    pub binding_digest: String,
    pub origin: String,
    pub app_id: String,
    pub external_worker_enabled: bool,
    pub availability: AppBoundAvailabilityV1,
    pub language_profile: String,
    pub language_profile_digest: String,
    pub worker_policy: String,
    pub worker_policy_digest: String,
    pub broker_protocol: String,
    pub global_inventory_digest: String,
    pub target_advertisement_digest: Option<String>,
    pub defaults: LimitsV1,
    pub maxima: LimitsV1,
}

impl AppBoundReportV1 {
    pub fn admitted(binding: &ApplicationBindingV1, contract: &StubContractV4) -> Result<Self> {
        binding.validate()?;
        contract.validate()?;
        let worker = &contract.external_worker;
        let availability = worker.availability()?;
        Ok(Self {
            binding_digest: binding.digest()?,
            origin: binding.origin.clone(),
            app_id: binding.app_id.clone(),
            external_worker_enabled: worker.enabled,
            availability,
            language_profile: worker.language_profile.clone(),
            language_profile_digest: worker.language_profile_digest.clone(),
            worker_policy: worker.worker_policy.clone(),
            worker_policy_digest: worker.worker_policy_digest.clone(),
            broker_protocol: worker.broker_protocol.clone(),
            global_inventory_digest: worker.global_inventory_digest.clone(),
            target_advertisement_digest: worker.target_advertisement_digest.clone(),
            defaults: worker.defaults.clone(),
            maxima: worker.maxima.clone(),
        })
    }

    pub fn may_execute_worker(&self) -> bool {
        self.availability == AppBoundAvailabilityV1::EnabledAndAdvertised
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubContractV4 {
    pub schema: String,
    pub profile: String,
    pub release_eligible: bool,
    pub target: StubTargetV1,
    pub engine: EngineCompatibilityV1,
    pub hermesc: HermescCompatibilityV1,
    pub accepted_schemas: StubAcceptedSchemasV2,
    pub abis: StubAbisV2,
    pub transform_profile_digest: String,
    pub runtime_capsec_projection_digest: String,
    pub runtime_identity_digest: String,
    pub environment_profile_digest: String,
    pub boot: StubBootContractV3,
    pub backends: StubBackendInventoryV1,
    pub external_worker: ExternalWorkerV1,
}

impl StubContractV4 {
    pub fn validate(&self) -> Result<()> {
        let s = &self.accepted_schemas;
        let w = &self.external_worker;
        let worker_ok = w.language_profile == RESTRICTED_WORKER_LANGUAGE_PROFILE_V1
            && valid_digest(&w.language_profile_digest)
            && w.arming_schema == RESTRICTED_WORKER_ARMING_SCHEMA_V1
            && w.worker_policy == RESTRICTED_WORKER_POLICY_V1
            && valid_digest(&w.worker_policy_digest)
            && w.broker_protocol == RESTRICTED_WORKER_BROKER_V1
            && valid_digest(&w.global_inventory_digest)
            && w.maxima == LimitsV1::maxima()
            && (!w.enabled
                || w.target_advertisement_digest
                    .as_deref()
                    .is_some_and(valid_digest))
            && w.target_advertisement_digest
                .as_deref()
                .is_none_or(valid_digest);
        if self.schema != STUB_CONTRACT_SCHEMA_V4
            || self.profile != "app-bound-parent-v1"
            || !self.release_eligible
            || s.envelope != ENVELOPE_SCHEMA_V3
            || s.application_binding != APPLICATION_BINDING_SCHEMA_V1
            || s.target_advertisement != TARGET_ADVERTISEMENT_SCHEMA_V1
            || s.entry_designation != super::ENTRY_DESIGNATION_SCHEMA_V1
            || s.embedded_graph != "ibex/embedded-module-graph/1"
            || s.authenticated_graph_snapshot != "ibex/authenticated-graph-snapshot/1"
            || s.computed_candidates != "ibex/computed-candidates/1"
            || s.carrier != "ibex/module-carrier/2"
            || s.canonical_policy != "ibex/capsec-policy/2"
            || s.armed_snapshot != "ibex/capsec-armed/1"
            || s.runtime_capsec_projection != "ibex/capsec-runtime-projection/1"
            || s.runtime_identity != "ibex/runtime-identity/1"
            || s.environment_profile != "ibex/compiled-environment-profile/1"
            || self.abis.restricted_worker != RESTRICTED_WORKER_ABI_V1
            || self.abis.module_runner.is_empty()
            || self.abis.arming.is_empty()
            || !worker_ok
            || !valid_digest(&self.transform_profile_digest)
            || !valid_digest(&self.runtime_capsec_projection_digest)
            || !valid_digest(&self.runtime_identity_digest)
            || !valid_digest(&self.environment_profile_digest)
        {
            return Err(Error::Contract("app-bound stub contract is invalid".into()));
        }
        w.defaults.validate_effective()?;
        w.maxima.validate_effective()?;
        if !self
            .boot
            .information_selector
            .report_schema
            .eq(STANDALONE_INFO_SCHEMA_V2)
        {
            return Err(Error::Contract(
                "app-bound information schema is invalid".into(),
            ));
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let v = serde_json::to_value(self).map_err(|e| Error::Contract(e.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&v).map_err(|e| Error::Contract(e.to_string()))
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let v = serde_json::to_value(self).map_err(|e| Error::Contract(e.to_string()))?;
        capsec_semantics::digest::compute_domain_digest(STUB_CONTRACT_DOMAIN_V4, &v, &[])
            .map_err(|e| Error::Contract(e.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetEvidenceV1 {
    pub schema: String,
    pub suite_digest: String,
    pub engine_artifact_digest: String,
    pub policy_artifact_digest: String,
    pub broker_corpus_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetAdvertisementV1 {
    pub schema: String,
    pub target: StubTargetV1,
    pub engine_compatibility_digest: String,
    pub native_abi: String,
    pub language_profile: String,
    pub language_profile_digest: String,
    pub worker_policy: String,
    pub worker_policy_digest: String,
    pub broker_protocol: String,
    pub global_inventory_digest: String,
    pub defaults_digest: String,
    pub maxima_digest: String,
    pub evidence: TargetEvidenceV1,
}

impl TargetAdvertisementV1 {
    pub fn validate(&self) -> Result<()> {
        let e = &self.evidence;
        let digests = [
            &self.engine_compatibility_digest,
            &self.language_profile_digest,
            &self.worker_policy_digest,
            &self.global_inventory_digest,
            &self.defaults_digest,
            &self.maxima_digest,
            &e.suite_digest,
            &e.engine_artifact_digest,
            &e.policy_artifact_digest,
            &e.broker_corpus_digest,
        ];
        if self.schema != TARGET_ADVERTISEMENT_SCHEMA_V1
            || self.target.triple.is_empty()
            || self.target.minimum_platform.is_empty()
            || self.native_abi != RESTRICTED_WORKER_ABI_V1
            || self.language_profile != RESTRICTED_WORKER_LANGUAGE_PROFILE_V1
            || self.worker_policy != RESTRICTED_WORKER_POLICY_V1
            || self.broker_protocol != RESTRICTED_WORKER_BROKER_V1
            || e.schema != TARGET_EVIDENCE_SCHEMA_V1
            || !digests.iter().all(|v| valid_digest(v))
        {
            return Err(Error::Contract(
                "restricted-worker target advertisement is invalid".into(),
            ));
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let v = serde_json::to_value(self).map_err(|e| Error::Contract(e.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&v).map_err(|e| Error::Contract(e.to_string()))
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let v = serde_json::to_value(self).map_err(|e| Error::Contract(e.to_string()))?;
        capsec_semantics::digest::compute_domain_digest(TARGET_ADVERTISEMENT_DOMAIN_V1, &v, &[])
            .map_err(|e| Error::Contract(e.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompilePlanV2 {
    pub schema: String,
    pub graph_snapshot_digest: String,
    pub policy_digest: String,
    pub stub_contract_digest: String,
    pub catalog_digest: String,
    pub compiler_identity: String,
    pub carrier_encoding: super::CompileCarrierEncodingV1,
    pub target: String,
    pub environment_profile_digest: String,
    pub application_binding_digest: String,
    pub target_advertisement_digest: Option<String>,
}

impl CompilePlanV2 {
    pub fn validate(&self) -> Result<()> {
        let required = [
            &self.graph_snapshot_digest,
            &self.policy_digest,
            &self.stub_contract_digest,
            &self.catalog_digest,
            &self.compiler_identity,
            &self.environment_profile_digest,
            &self.application_binding_digest,
        ];
        if self.schema != COMPILE_PLAN_SCHEMA_V2
            || self.target.is_empty()
            || !required.iter().all(|v| valid_digest(v))
            || !self
                .target_advertisement_digest
                .as_deref()
                .is_none_or(valid_digest)
        {
            return Err(Error::Contract("app-bound compile plan is invalid".into()));
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let v = serde_json::to_value(self).map_err(|e| Error::Contract(e.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&v).map_err(|e| Error::Contract(e.to_string()))
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let v = serde_json::to_value(self).map_err(|e| Error::Contract(e.to_string()))?;
        capsec_semantics::digest::compute_domain_digest(COMPILE_PLAN_DOMAIN_V2, &v, &[])
            .map_err(|e| Error::Contract(e.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageProvenanceV2 {
    pub schema: String,
    pub compile_plan: CompilePlanV2,
    pub compile_plan_digest: String,
    pub catalog_sequence: u64,
    pub catalog_entry_target: String,
    pub stub_core_digest: String,
    pub stub_core_reconstruction: super::StubCoreReconstructionV1,
    pub producer_identity: String,
}

impl PackageProvenanceV2 {
    pub fn validate(&self) -> Result<()> {
        self.compile_plan.validate()?;
        if self.schema != PACKAGE_PROVENANCE_SCHEMA_V2
            || self.compile_plan_digest != self.compile_plan.digest()?
            || self.catalog_sequence == 0
            || self.catalog_entry_target != self.compile_plan.target
            || !valid_digest(&self.stub_core_digest)
            || self.stub_core_reconstruction.size == 0
            || self.producer_identity.is_empty()
        {
            return Err(Error::Contract(
                "app-bound package provenance is invalid".into(),
            ));
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let v = serde_json::to_value(self).map_err(|e| Error::Contract(e.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&v).map_err(|e| Error::Contract(e.to_string()))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SectionKindV2 {
    StubContract,
    ProvenanceManifest,
    EmbeddedModuleGraph,
    ResolvedPolicy,
    EntryDesignation,
    CandidateTable,
    CarrierManifest,
    CarrierPayload,
    ApplicationBinding,
}

#[derive(Clone, Debug)]
pub struct SectionInputV2 {
    pub id: String,
    pub kind: SectionKindV2,
    pub pair_id: Option<String>,
    pub alignment: u32,
    pub bytes: Vec<u8>,
}

impl SectionInputV2 {
    pub fn canonical(id: impl Into<String>, kind: SectionKindV2, bytes: Vec<u8>) -> Self {
        Self {
            id: id.into(),
            kind,
            pair_id: None,
            alignment: if kind == SectionKindV2::CarrierPayload {
                super::CARRIER_ALIGNMENT_V1
            } else {
                8
            },
            bytes,
        }
    }
    pub fn carrier(
        id: impl Into<String>,
        kind: SectionKindV2,
        pair_id: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        let mut v = Self::canonical(id, kind, bytes);
        v.pair_id = Some(pair_id.into());
        v
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeDirectoryV2 {
    pub schema: String,
    pub stub_contract_digest: String,
    pub sections: Vec<SectionDirectoryRowV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SectionDirectoryRowV2 {
    pub id: String,
    pub kind: SectionKindV2,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pair_id: Option<String>,
    pub offset: u64,
    pub length: u64,
    pub alignment: u32,
    pub digest: String,
}

#[derive(Clone, Debug)]
pub struct AdmittedEnvelopeV2<'a> {
    pub stub_len: usize,
    pub envelope_digest: String,
    pub directory: EnvelopeDirectoryV2,
    file: &'a [u8],
}
impl<'a> AdmittedEnvelopeV2<'a> {
    pub fn section(&'a self, id: &str) -> Option<&'a [u8]> {
        self.directory
            .sections
            .iter()
            .find(|r| r.id == id)
            .map(|r| {
                let start = self.stub_len + r.offset as usize;
                &self.file[start..start + r.length as usize]
            })
    }
}

fn section_digest(bytes: &[u8]) -> String {
    format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

pub fn build_executable_v2(
    stub: &[u8],
    stub_contract_digest: &str,
    mut sections: Vec<SectionInputV2>,
) -> Result<Vec<u8>> {
    if !valid_digest(stub_contract_digest)
        || sections.is_empty()
        || sections.len() > super::MAX_SECTIONS_V1
    {
        return Err(Error::Contract("invalid app-bound envelope inputs".into()));
    }
    sections.sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
    let mut output = stub.to_vec();
    let envelope_start = output.len();
    let mut rows = Vec::with_capacity(sections.len());
    for section in sections {
        if !super::valid_id(&section.id) {
            return Err(Error::Contract("invalid app-bound section id".into()));
        }
        super::push_padding(&mut output, section.alignment as usize)?;
        let offset = (output.len() - envelope_start) as u64;
        let length = section.bytes.len() as u64;
        rows.push(SectionDirectoryRowV2 {
            id: section.id,
            kind: section.kind,
            pair_id: section.pair_id,
            offset,
            length,
            alignment: section.alignment,
            digest: section_digest(&section.bytes),
        });
        output.extend_from_slice(&section.bytes);
    }
    super::push_padding(&mut output, 8)?;
    let directory_offset = (output.len() - envelope_start) as u64;
    let directory = EnvelopeDirectoryV2 {
        schema: ENVELOPE_SCHEMA_V3.into(),
        stub_contract_digest: stub_contract_digest.into(),
        sections: rows,
    };
    validate_directory_v2(&directory)?;
    let value = serde_json::to_value(&directory).map_err(|e| Error::Directory(e.to_string()))?;
    let bytes = capsec_semantics::canonical::to_jcs_bytes(&value)
        .map_err(|e| Error::Directory(e.to_string()))?;
    if bytes.len() > super::MAX_DIRECTORY_BYTES_V1 {
        return Err(Error::Contract("section directory exceeds limit".into()));
    }
    output.extend_from_slice(&bytes);
    let footer_start = output.len();
    if footer_start - envelope_start > super::MAX_ENVELOPE_BYTES_V1 {
        return Err(Error::Contract("envelope exceeds limit".into()));
    }
    let hash: [u8; 32] = Sha256::digest(&output[envelope_start..footer_start]).into();
    write_footer_v3(
        &mut output,
        super::FooterV1 {
            envelope_start: envelope_start as u64,
            directory_offset,
            directory_length: bytes.len() as u64,
            section_count: directory.sections.len() as u32,
            digest: hash,
        },
    );
    Ok(output)
}

pub fn admit_executable_v2<'a>(
    file: &'a [u8],
    expected_stub_contract: Option<&str>,
) -> Result<AdmittedEnvelopeV2<'a>> {
    let footer_start = super::macho::embedded_footer_offset(file)?.unwrap_or(
        file.len()
            .checked_sub(super::FOOTER_LEN_V1)
            .ok_or(Error::Footer)?,
    );
    let footer = read_footer_v3(file, footer_start)?;
    let envelope_start =
        usize::try_from(footer.envelope_start).map_err(|_| Error::EnvelopeRange)?;
    let directory_offset =
        usize::try_from(footer.directory_offset).map_err(|_| Error::EnvelopeRange)?;
    let directory_length =
        usize::try_from(footer.directory_length).map_err(|_| Error::EnvelopeRange)?;
    if envelope_start > footer_start
        || footer_start - envelope_start > super::MAX_ENVELOPE_BYTES_V1
        || directory_length > super::MAX_DIRECTORY_BYTES_V1
    {
        return Err(Error::EnvelopeRange);
    }
    let directory_start = envelope_start
        .checked_add(directory_offset)
        .ok_or(Error::EnvelopeRange)?;
    let directory_end = directory_start
        .checked_add(directory_length)
        .ok_or(Error::EnvelopeRange)?;
    if directory_end != footer_start {
        return Err(Error::EnvelopeRange);
    }
    let actual: [u8; 32] = Sha256::digest(&file[envelope_start..footer_start]).into();
    if actual != footer.digest {
        return Err(Error::EnvelopeDigest);
    }
    let bytes = &file[directory_start..directory_end];
    let text = std::str::from_utf8(bytes).map_err(|e| Error::Directory(e.to_string()))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|e| Error::Directory(e.to_string()))?;
    if capsec_semantics::canonical::to_jcs_bytes(&value)
        .map_err(|e| Error::Directory(e.to_string()))?
        != bytes
    {
        return Err(Error::Directory("directory bytes are not JCS".into()));
    }
    let directory: EnvelopeDirectoryV2 =
        serde_json::from_value(value).map_err(|e| Error::Directory(e.to_string()))?;
    if directory.sections.len() != footer.section_count as usize
        || expected_stub_contract.is_some_and(|v| v != directory.stub_contract_digest)
    {
        return Err(Error::Contract(
            "app-bound footer/directory contract mismatch".into(),
        ));
    }
    validate_directory_v2(&directory)?;
    let projected = project_directory(&directory);
    super::validate_ranges_and_digests(file, envelope_start, directory_offset, &projected)?;
    super::validate_entry_section(file, envelope_start, &projected)?;
    let contract_bytes = section_bytes(
        file,
        envelope_start,
        &directory,
        SectionKindV2::StubContract,
    )?;
    let contract_value = strict_canonical_value(contract_bytes, "stub contract")?;
    let contract: StubContractV4 =
        serde_json::from_value(contract_value).map_err(|e| Error::Contract(e.to_string()))?;
    if contract.canonical_bytes()? != contract_bytes
        || contract.digest()? != directory.stub_contract_digest
    {
        return Err(Error::Contract(
            "V4 stub contract disagrees with envelope pin".into(),
        ));
    }
    let binding_bytes = section_bytes(
        file,
        envelope_start,
        &directory,
        SectionKindV2::ApplicationBinding,
    )?;
    let binding_value = strict_canonical_value(binding_bytes, "application binding")?;
    let binding: ApplicationBindingV1 =
        serde_json::from_value(binding_value).map_err(|e| Error::Contract(e.to_string()))?;
    if binding.canonical_bytes()? != binding_bytes
        || !binding
            .engine_compatibility
            .iter()
            .any(|v| v == contract.engine.identity())
        || !binding
            .broker_protocols
            .iter()
            .any(|v| v == &contract.external_worker.broker_protocol)
    {
        return Err(Error::Contract(
            "application binding does not admit the stub identities".into(),
        ));
    }
    Ok(AdmittedEnvelopeV2 {
        stub_len: envelope_start,
        envelope_digest: format!("sha256-{}", URL_SAFE_NO_PAD.encode(footer.digest)),
        directory,
        file,
    })
}

pub fn rehash_stub_core_v2(
    file: &[u8],
    envelope: &AdmittedEnvelopeV2<'_>,
    reconstruction: &super::StubCoreReconstructionV1,
) -> Result<String> {
    if file.get(..4) == Some(&0xfeedfacfu32.to_le_bytes()) {
        let vmsize = reconstruction.macho_linkedit_vmsize.ok_or_else(|| {
            Error::Contract("Mach-O stub reconstruction omits __LINKEDIT vmsize".into())
        })?;
        return Ok(section_digest(&super::macho::reconstruct_stub_core_v1(
            file,
            reconstruction.size,
            vmsize,
        )?));
    }
    if reconstruction.macho_linkedit_vmsize.is_some() {
        return Err(Error::Contract(
            "non-Mach-O stub reconstruction carries Mach-O facts".into(),
        ));
    }
    let size = usize::try_from(reconstruction.size).map_err(|_| Error::EnvelopeRange)?;
    if size != envelope.stub_len {
        return Err(Error::Contract(
            "appended-envelope stub size disagrees with its envelope boundary".into(),
        ));
    }
    Ok(section_digest(
        file.get(..size).ok_or(Error::EnvelopeRange)?,
    ))
}

fn strict_canonical_value(bytes: &[u8], name: &str) -> Result<serde_json::Value> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::Contract(format!("{name} is not UTF-8: {e}")))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|e| Error::Contract(e.to_string()))?;
    if capsec_semantics::canonical::to_jcs_bytes(&value)
        .map_err(|e| Error::Contract(e.to_string()))?
        != bytes
    {
        return Err(Error::Contract(format!("{name} is not canonical")));
    }
    Ok(value)
}
fn section_bytes<'a>(
    file: &'a [u8],
    start: usize,
    d: &EnvelopeDirectoryV2,
    kind: SectionKindV2,
) -> Result<&'a [u8]> {
    let r = d
        .sections
        .iter()
        .find(|r| r.kind == kind)
        .ok_or_else(|| Error::Contract("required section absent".into()))?;
    let s = start + r.offset as usize;
    Ok(&file[s..s + r.length as usize])
}

fn project_directory(d: &EnvelopeDirectoryV2) -> super::EnvelopeDirectoryV1 {
    super::EnvelopeDirectoryV1 {
        schema: super::ENVELOPE_SCHEMA_V2.into(),
        stub_contract_digest: d.stub_contract_digest.clone(),
        sections: d
            .sections
            .iter()
            .map(|r| super::SectionDirectoryRowV1 {
                id: r.id.clone(),
                kind: match r.kind {
                    SectionKindV2::StubContract => super::SectionKindV1::StubContract,
                    SectionKindV2::ProvenanceManifest => super::SectionKindV1::ProvenanceManifest,
                    SectionKindV2::EmbeddedModuleGraph => super::SectionKindV1::EmbeddedModuleGraph,
                    SectionKindV2::ResolvedPolicy => super::SectionKindV1::ResolvedPolicy,
                    SectionKindV2::EntryDesignation => super::SectionKindV1::EntryDesignation,
                    SectionKindV2::CandidateTable => super::SectionKindV1::CandidateTable,
                    SectionKindV2::CarrierManifest => super::SectionKindV1::CarrierManifest,
                    SectionKindV2::CarrierPayload => super::SectionKindV1::CarrierPayload,
                    SectionKindV2::ApplicationBinding => super::SectionKindV1::CandidateTable,
                },
                pair_id: r.pair_id.clone(),
                offset: r.offset,
                length: r.length,
                alignment: r.alignment,
                digest: r.digest.clone(),
            })
            .collect(),
    }
}

fn validate_directory_v2(d: &EnvelopeDirectoryV2) -> Result<()> {
    if d.schema != ENVELOPE_SCHEMA_V3
        || !valid_digest(&d.stub_contract_digest)
        || d.sections.is_empty()
        || d.sections.len() > super::MAX_SECTIONS_V1
    {
        return Err(Error::Contract(
            "unsupported app-bound envelope directory".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    let mut counts = BTreeMap::new();
    let mut pairs: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut previous = None;
    for r in &d.sections {
        let order = (r.kind, r.id.as_str());
        if previous.is_some_and(|p| p >= order) {
            return Err(Error::Contract("sections are not strictly ordered".into()));
        }
        previous = Some(order);
        if !super::valid_id(&r.id)
            || !ids.insert(r.id.as_str())
            || !valid_digest(&r.digest)
            || !r.alignment.is_power_of_two()
            || r.alignment > super::CARRIER_ALIGNMENT_V1
            || r.length == 0
        {
            return Err(Error::Contract("section metadata is malformed".into()));
        }
        match r.kind {
            SectionKindV2::CarrierManifest | SectionKindV2::CarrierPayload => {
                let p = r
                    .pair_id
                    .as_deref()
                    .filter(|v| super::valid_id(v))
                    .ok_or_else(|| Error::Contract("carrier pair is absent".into()))?;
                let c = pairs.entry(p).or_default();
                if r.kind == SectionKindV2::CarrierManifest {
                    c.0 += 1
                } else {
                    c.1 += 1
                }
            }
            SectionKindV2::CandidateTable => {
                if r.pair_id.is_some() {
                    return Err(Error::Contract("candidate table carries pair id".into()));
                }
            }
            k => {
                if r.pair_id.is_some() {
                    return Err(Error::Contract("singleton carries pair id".into()));
                }
                *counts.entry(k).or_insert(0usize) += 1;
            }
        }
        if r.kind == SectionKindV2::ApplicationBinding
            && (r.id != "application-binding" || r.alignment != 8 || r.length > 16 * 1024)
        {
            return Err(Error::Contract(
                "application binding row is malformed".into(),
            ));
        }
    }
    for k in [
        SectionKindV2::StubContract,
        SectionKindV2::ProvenanceManifest,
        SectionKindV2::EmbeddedModuleGraph,
        SectionKindV2::ResolvedPolicy,
        SectionKindV2::EntryDesignation,
        SectionKindV2::ApplicationBinding,
    ] {
        if counts.get(&k) != Some(&1) {
            return Err(Error::Contract(format!(
                "required {k:?} section is not singular"
            )));
        }
    }
    if pairs.is_empty() || pairs.values().any(|v| *v != (1, 1)) {
        return Err(Error::Contract("carrier pairing is incomplete".into()));
    }
    Ok(())
}

fn write_footer_v3(out: &mut Vec<u8>, f: super::FooterV1) {
    out.extend_from_slice(&FOOTER_MAGIC_V3);
    out.extend_from_slice(&FORMAT_VERSION_V3.to_le_bytes());
    out.extend_from_slice(&(super::FOOTER_LEN_V1 as u32).to_le_bytes());
    out.extend_from_slice(&f.envelope_start.to_le_bytes());
    out.extend_from_slice(&f.directory_offset.to_le_bytes());
    out.extend_from_slice(&f.directory_length.to_le_bytes());
    out.extend_from_slice(&f.section_count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&f.digest);
}
fn read_footer_v3(file: &[u8], start: usize) -> Result<super::FooterV1> {
    let f = file
        .get(
            start
                ..start
                    .checked_add(super::FOOTER_LEN_V1)
                    .ok_or(Error::Footer)?,
        )
        .ok_or(Error::Footer)?;
    if f[..16] != FOOTER_MAGIC_V3
        || u32::from_le_bytes(f[16..20].try_into().map_err(|_| Error::Footer)?) != FORMAT_VERSION_V3
        || u32::from_le_bytes(f[20..24].try_into().map_err(|_| Error::Footer)?) as usize
            != super::FOOTER_LEN_V1
        || f[52..56] != [0; 4]
    {
        return Err(Error::Footer);
    }
    Ok(super::FooterV1 {
        envelope_start: u64::from_le_bytes(f[24..32].try_into().map_err(|_| Error::Footer)?),
        directory_offset: u64::from_le_bytes(f[32..40].try_into().map_err(|_| Error::Footer)?),
        directory_length: u64::from_le_bytes(f[40..48].try_into().map_err(|_| Error::Footer)?),
        section_count: u32::from_le_bytes(f[48..52].try_into().map_err(|_| Error::Footer)?),
        digest: f[56..88].try_into().map_err(|_| Error::Footer)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const DIGEST: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn worker(enabled: bool, advertised: bool) -> ExternalWorkerV1 {
        ExternalWorkerV1 {
            enabled,
            language_profile: RESTRICTED_WORKER_LANGUAGE_PROFILE_V1.into(),
            language_profile_digest: DIGEST.into(),
            arming_schema: RESTRICTED_WORKER_ARMING_SCHEMA_V1.into(),
            worker_policy: RESTRICTED_WORKER_POLICY_V1.into(),
            worker_policy_digest: DIGEST.into(),
            broker_protocol: RESTRICTED_WORKER_BROKER_V1.into(),
            global_inventory_digest: DIGEST.into(),
            target_advertisement_digest: advertised.then(|| DIGEST.into()),
            defaults: LimitsV1::defaults(),
            maxima: LimitsV1::maxima(),
        }
    }

    #[test]
    fn limits_are_closed_and_domain_bound() {
        assert_ne!(
            LimitsV1::defaults().digest().unwrap(),
            LimitsV1::maxima().digest().unwrap()
        );
    }
    #[test]
    fn binding_rejects_runtime_selected_or_credential_bearing_origins() {
        let binding = ApplicationBindingV1 {
            schema: APPLICATION_BINDING_SCHEMA_V1.into(),
            origin: "https://EXAMPLE.com/path".into(),
            app_id: "app".into(),
            engine_compatibility: vec!["sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()],
            broker_protocols: vec![RESTRICTED_WORKER_BROKER_V1.into()],
            release_lineage: ReleaseLineageV1 {
                schema: RELEASE_LINEAGE_SCHEMA_V1.into(),
                publisher_key_id: "publisher".into(),
                channel: "stable".into(),
                recipe_digest: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            },
        };
        assert!(binding.validate().is_err());
    }

    #[test]
    fn worker_availability_is_closed_and_enabled_requires_evidence() {
        assert_eq!(
            worker(true, true).availability().unwrap(),
            AppBoundAvailabilityV1::EnabledAndAdvertised
        );
        assert_eq!(
            worker(false, true).availability().unwrap(),
            AppBoundAvailabilityV1::DisabledAdvertised
        );
        assert_eq!(
            worker(false, false).availability().unwrap(),
            AppBoundAvailabilityV1::DisabledUnadvertised
        );
        assert!(worker(true, false).availability().is_err());
    }

    #[test]
    fn app_bound_report_shape_is_closed() {
        let report = AppBoundReportV1 {
            binding_digest: DIGEST.into(),
            origin: "https://example.com".into(),
            app_id: "app".into(),
            external_worker_enabled: true,
            availability: AppBoundAvailabilityV1::EnabledAndAdvertised,
            language_profile: RESTRICTED_WORKER_LANGUAGE_PROFILE_V1.into(),
            language_profile_digest: DIGEST.into(),
            worker_policy: RESTRICTED_WORKER_POLICY_V1.into(),
            worker_policy_digest: DIGEST.into(),
            broker_protocol: RESTRICTED_WORKER_BROKER_V1.into(),
            global_inventory_digest: DIGEST.into(),
            target_advertisement_digest: Some(DIGEST.into()),
            defaults: LimitsV1::defaults(),
            maxima: LimitsV1::maxima(),
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 14);
        assert_eq!(value["availability"], "enabled-and-advertised");
        let mut with_unknown = value;
        with_unknown
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), true.into());
        assert!(serde_json::from_value::<AppBoundReportV1>(with_unknown).is_err());
    }
}
