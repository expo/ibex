//! Canonical `ibex/single-file-executable/2` envelope encoding and admission.
//!
//! The parser bulk-preflights every range, digest, singleton, entry row, and
//! carrier manifest/payload pair before returning any section bytes.
//! @ref LLP 0029#2-executable-layout-stub-envelope-footer — the canonical envelope and footer are preflighted before evaluation

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub mod app_bound;
pub mod macho;

pub const ENVELOPE_SCHEMA_V2: &str = "ibex/single-file-executable/2";
pub const ENTRY_DESIGNATION_SCHEMA_V1: &str = "ibex/entry-designation/1";
pub const STUB_CONTRACT_SCHEMA_V3: &str = "ibex/stub-contract/3";
pub const STUB_CONTRACT_DOMAIN_V3: &str = "ibex:stub-contract:3";
pub const STANDALONE_INFO_SCHEMA_V1: &str = "ibex/standalone-executable-info/1";
pub const STUB_BACKEND_INVENTORY_SCHEMA_V1: &str = "ibex/sfe-backend-inventory/1";
pub const ENGINE_COMPATIBILITY_SCHEMA_V1: &str = "ibex/engine-compatibility/1";
pub const ENGINE_COMPATIBILITY_DOMAIN_V1: &str = "ibex:engine-compatibility:1";
pub const HERMESC_COMPATIBILITY_SCHEMA_V1: &str = "ibex/hermesc-compatibility/1";
pub const HERMESC_COMPATIBILITY_DOMAIN_V1: &str = "ibex:hermesc-compatibility:1";
pub const HERMESC_RECIPE_SCHEMA_V1: &str = "ibex/hermesc-recipe/1";
pub const HERMESC_RECIPE_DOMAIN_V1: &str = "ibex:hermesc-recipe:1";
pub const COMPILE_PLAN_SCHEMA_V1: &str = "ibex/compile-plan/1";
pub const COMPILE_PLAN_DOMAIN_V1: &str = "ibex:compile-plan:1";
pub const PACKAGE_PROVENANCE_SCHEMA_V1: &str = "ibex/package-provenance/1";
pub const FORMAT_VERSION_V2: u32 = 2;
pub const FOOTER_LEN_V1: usize = 88;
pub const CARRIER_ALIGNMENT_V1: u32 = 4096;
pub const MAX_SECTIONS_V1: usize = 100_000;
pub const MAX_DIRECTORY_BYTES_V1: usize = 16 * 1024 * 1024;
pub const MAX_ENVELOPE_BYTES_V1: usize = 2 * 1024 * 1024 * 1024;
pub const FOOTER_MAGIC_V2: [u8; 16] = *b"IBEX_SFE_V2\0\0\0\0\0";

/// The immutable, path-independent input to final SFE assembly. Mutable source
/// paths and caller-selected tool locations deliberately cannot enter this
/// contract: every input is already authenticated and named by its semantic or
/// content digest.
/// @ref LLP 0029#1-command-surface-and-producer-pipeline — one CompilePlanV1 drives pure final assembly
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompilePlanV1 {
    pub schema: String,
    pub graph_snapshot_digest: String,
    pub policy_digest: String,
    pub stub_contract_digest: String,
    pub catalog_digest: String,
    pub compiler_identity: String,
    pub carrier_encoding: CompileCarrierEncodingV1,
    pub target: String,
    pub environment_profile_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompileCarrierEncodingV1 {
    HermesBytecode,
    FactoryTable,
}

impl CompilePlanV1 {
    fn validate(&self) -> Result<()> {
        if self.schema != COMPILE_PLAN_SCHEMA_V1
            || self.target.is_empty()
            || !valid_digest(&self.graph_snapshot_digest)
            || !valid_digest(&self.policy_digest)
            || !valid_digest(&self.stub_contract_digest)
            || !valid_digest(&self.catalog_digest)
            || !valid_digest(&self.compiler_identity)
            || !valid_digest(&self.environment_profile_digest)
        {
            return Err(Error::Contract("compile plan is invalid".into()));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|error| Error::Contract(error.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| Error::Contract(error.to_string()))
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|error| Error::Contract(error.to_string()))?;
        capsec_semantics::digest::compute_domain_digest(COMPILE_PLAN_DOMAIN_V1, &value, &[])
            .map_err(|error| Error::Contract(error.to_string()))
    }
}

/// Immutable build provenance embedded inside the envelope. Publisher
/// authentication is intentionally a separate, optional statement so this
/// self-described record is never presented as external authenticity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageProvenanceV1 {
    pub schema: String,
    pub compile_plan: CompilePlanV1,
    pub compile_plan_digest: String,
    pub catalog_sequence: u64,
    pub catalog_entry_target: String,
    pub stub_core_digest: String,
    pub stub_core_reconstruction: StubCoreReconstructionV1,
    pub producer_identity: String,
}

/// Authenticated facts needed to project the catalog's signature-stripped stub
/// bytes back out of a completed executable. Mach-O signing rewrites the
/// `__LINKEDIT` virtual size, so its catalog value cannot be inferred from the
/// signed image alone.
/// @ref LLP 0029#2-executable-layout-stub-envelope-footer — inspection rehashes the instance descriptor instead of repeating its claimed digest
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubCoreReconstructionV1 {
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macho_linkedit_vmsize: Option<u64>,
}

impl StubCoreReconstructionV1 {
    pub fn from_stub(stub: &[u8]) -> Result<Self> {
        let size = u64::try_from(stub.len())
            .map_err(|_| Error::Contract("stub core size exceeds u64".into()))?;
        if size == 0 {
            return Err(Error::Contract("stub core is empty".into()));
        }
        let macho_linkedit_vmsize = if stub.get(..4) == Some(&0xfeedfacfu32.to_le_bytes()) {
            Some(macho::linkedit_vmsize_v1(stub)?)
        } else {
            None
        };
        Ok(Self {
            size,
            macho_linkedit_vmsize,
        })
    }
}

impl PackageProvenanceV1 {
    fn validate(&self) -> Result<()> {
        self.compile_plan.validate()?;
        if self.schema != PACKAGE_PROVENANCE_SCHEMA_V1
            || self.compile_plan_digest != self.compile_plan.digest()?
            || self.catalog_sequence == 0
            || self.catalog_entry_target != self.compile_plan.target
            || !valid_digest(&self.stub_core_digest)
            || self.stub_core_reconstruction.size == 0
            || self
                .stub_core_reconstruction
                .macho_linkedit_vmsize
                .is_some_and(|value| value == 0 || value % 0x1000 != 0)
            || self.producer_identity.is_empty()
        {
            return Err(Error::Contract("package provenance is invalid".into()));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|error| Error::Contract(error.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| Error::Contract(error.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubContractV3 {
    pub schema: String,
    pub profile: String,
    pub release_eligible: bool,
    pub target: StubTargetV1,
    pub engine: EngineCompatibilityV1,
    pub hermesc: HermescCompatibilityV1,
    pub accepted_schemas: StubAcceptedSchemasV1,
    pub abis: StubAbisV1,
    pub transform_profile_digest: String,
    pub runtime_capsec_projection_digest: String,
    pub runtime_identity_digest: String,
    pub environment_profile_digest: String,
    pub boot: StubBootContractV3,
    pub backends: StubBackendInventoryV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubBootContractV3 {
    pub default_mode: StubDefaultBootModeV3,
    pub capsec_selector: StubReservedSelectorV3,
    pub information_selector: StubInformationSelectorV3,
    /// Empty means the stub carries no accepted CapSec advertisement. The
    /// required field keeps empty distinct from an absent contract claim.
    pub capsec_advertisement_identity: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StubDefaultBootModeV3 {
    AmbientCompatibility,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubReservedSelectorV3 {
    pub spelling: String,
    pub position: StubSelectorPositionV3,
    pub escape: StubSelectorEscapeV3,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubInformationSelectorV3 {
    pub spelling: String,
    pub position: StubSelectorPositionV3,
    pub escape: StubSelectorEscapeV3,
    pub report_schema: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StubSelectorPositionV3 {
    FirstArgumentOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StubSelectorEscapeV3 {
    LeadingDoubleDash,
}

impl StubBootContractV3 {
    pub fn dual_mode(capsec_advertisement_identity: impl Into<String>) -> Self {
        Self {
            default_mode: StubDefaultBootModeV3::AmbientCompatibility,
            capsec_selector: StubReservedSelectorV3 {
                spelling: "--ibex-capsec".into(),
                position: StubSelectorPositionV3::FirstArgumentOnly,
                escape: StubSelectorEscapeV3::LeadingDoubleDash,
            },
            information_selector: StubInformationSelectorV3 {
                spelling: "--ibex-info".into(),
                position: StubSelectorPositionV3::FirstArgumentOnly,
                escape: StubSelectorEscapeV3::LeadingDoubleDash,
                report_schema: STANDALONE_INFO_SCHEMA_V1.into(),
            },
            capsec_advertisement_identity: capsec_advertisement_identity.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.default_mode != StubDefaultBootModeV3::AmbientCompatibility
            || self.capsec_selector.spelling != "--ibex-capsec"
            || self.capsec_selector.position != StubSelectorPositionV3::FirstArgumentOnly
            || self.capsec_selector.escape != StubSelectorEscapeV3::LeadingDoubleDash
            || self.information_selector.spelling != "--ibex-info"
            || self.information_selector.position != StubSelectorPositionV3::FirstArgumentOnly
            || self.information_selector.escape != StubSelectorEscapeV3::LeadingDoubleDash
            || self.information_selector.report_schema != STANDALONE_INFO_SCHEMA_V1
            || (!self.capsec_advertisement_identity.is_empty()
                && !valid_digest(&self.capsec_advertisement_identity))
        {
            return Err(Error::Contract("stub boot-mode contract is invalid".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubTargetV1 {
    pub triple: String,
    pub minimum_platform: String,
}

/// Authenticated description of the native facilities compiled into one
/// standalone target stub. `limited` is deliberately distinct from
/// `unavailable`: callers can use the named implementation, but must not infer
/// ordinary-runtime parity beyond the recorded limitation.
/// @ref LLP 0047#7-milestone-4--application-process-contract
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubBackendInventoryV1 {
    pub schema: String,
    pub entries: Vec<StubBackendV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubBackendV1 {
    pub surface: String,
    pub status: StubBackendStatusV1,
    pub implementation: String,
    /// Empty for an available backend; required for limited/unavailable rows.
    pub limitation: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StubBackendStatusV1 {
    Available,
    Limited,
    Unavailable,
}

impl StubBackendInventoryV1 {
    pub fn release_for_target(target: &str) -> Result<Self> {
        let (crypto_status, crypto_implementation, crypto_limitation) = match target {
            "aarch64-apple-darwin" => (StubBackendStatusV1::Available, "commoncrypto-security", ""),
            "x86_64-unknown-linux-gnu" => (
                StubBackendStatusV1::Limited,
                "portable-reduced-no-openssl",
                "AES and asymmetric/key import-export require an OpenSSL crypto profile",
            ),
            _ => {
                return Err(Error::Contract(format!(
                    "no standalone backend inventory exists for target {target:?}"
                )))
            }
        };
        let (fetch, websocket) = match target {
            "aarch64-apple-darwin" => ("nsurlsession", "nsurlsession-websocket-task"),
            "x86_64-unknown-linux-gnu" => (
                "static-libcurl-vendored-openssl",
                "static-libcurl-websocket-vendored-openssl",
            ),
            _ => unreachable!("target was checked above"),
        };
        let mut entries = vec![
            available_backend("child-process", "posix-spawn-registry"),
            available_backend("console-stdio", "engine-host-output-broker"),
            StubBackendV1 {
                surface: "crypto".into(),
                status: crypto_status,
                implementation: crypto_implementation.into(),
                limitation: crypto_limitation.into(),
            },
            available_backend("dns", "posix-raw-udp-libresolv"),
            available_backend("fetch", fetch),
            available_backend("filesystem", "posix-host-abi"),
            available_backend("http-server", "node-http-over-posix-sockets"),
            unavailable_backend(
                "http2",
                "compatibility-stub",
                "a native HTTP/2 backend is not present",
            ),
            unavailable_backend(
                "inspector",
                "compatibility-stub",
                "an inspector backend is not present",
            ),
            available_backend("os-info", "posix-syscalls"),
            limited_backend(
                "signals",
                "compiled-posix-sigwait-coordinator",
                "SIGINT/SIGTERM/SIGHUP terminate with bounded flush; JavaScript signal dispatch is unavailable",
            ),
            available_backend("sqlite", "bundled-rusqlite"),
            available_backend("tcp-udp-unix-sockets", "posix-sockets"),
            available_backend("timers-event-loop", "engine-host-event-loop"),
            available_backend("tls-client", "rustls-ring"),
            unavailable_backend(
                "wasi",
                "compatibility-stub",
                "a WASI backend is not present",
            ),
            available_backend("websocket", websocket),
            unavailable_backend(
                "workers",
                "compatibility-stub",
                "a worker_threads backend is not present",
            ),
        ];
        entries.sort_by(|left, right| left.surface.cmp(&right.surface));
        let inventory = Self {
            schema: STUB_BACKEND_INVENTORY_SCHEMA_V1.into(),
            entries,
        };
        inventory.validate()?;
        Ok(inventory)
    }

    pub fn diagnostic_development() -> Self {
        Self {
            schema: STUB_BACKEND_INVENTORY_SCHEMA_V1.into(),
            entries: vec![limited_backend(
                "development-runtime",
                "host-build-dependent",
                "diagnostic contracts do not make a release backend-closure claim",
            )],
        }
    }

    fn validate(&self) -> Result<()> {
        if self.schema != STUB_BACKEND_INVENTORY_SCHEMA_V1 || self.entries.is_empty() {
            return Err(Error::Contract("stub backend inventory is invalid".into()));
        }
        let mut previous: Option<&str> = None;
        for entry in &self.entries {
            if entry.surface.is_empty()
                || entry.implementation.is_empty()
                || previous.is_some_and(|value| value >= entry.surface.as_str())
                || match entry.status {
                    StubBackendStatusV1::Available => !entry.limitation.is_empty(),
                    StubBackendStatusV1::Limited | StubBackendStatusV1::Unavailable => {
                        entry.limitation.is_empty()
                    }
                }
            {
                return Err(Error::Contract("stub backend inventory is invalid".into()));
            }
            previous = Some(&entry.surface);
        }
        Ok(())
    }
}

fn available_backend(surface: &str, implementation: &str) -> StubBackendV1 {
    StubBackendV1 {
        surface: surface.into(),
        status: StubBackendStatusV1::Available,
        implementation: implementation.into(),
        limitation: String::new(),
    }
}

fn limited_backend(surface: &str, implementation: &str, limitation: &str) -> StubBackendV1 {
    StubBackendV1 {
        surface: surface.into(),
        status: StubBackendStatusV1::Limited,
        implementation: implementation.into(),
        limitation: limitation.into(),
    }
}

fn unavailable_backend(surface: &str, implementation: &str, limitation: &str) -> StubBackendV1 {
    StubBackendV1 {
        surface: surface.into(),
        status: StubBackendStatusV1::Unavailable,
        implementation: implementation.into(),
        limitation: limitation.into(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EngineCompatibilityV1 {
    DiagnosticSource {
        profile: String,
        #[serde(rename = "compatibilityIdentity")]
        compatibility_identity: String,
    },
    StaticHermes {
        #[serde(rename = "buildProfile")]
        build_profile: String,
        #[serde(rename = "staticArchiveDigest")]
        static_archive_digest: String,
        #[serde(rename = "hbcVersion")]
        hbc_version: u32,
        #[serde(rename = "compatibilityIdentity")]
        compatibility_identity: String,
    },
}

impl EngineCompatibilityV1 {
    pub fn diagnostic_source(profile: impl Into<String>) -> Result<Self> {
        let mut value = Self::DiagnosticSource {
            profile: profile.into(),
            compatibility_identity: String::new(),
        };
        let identity = value.compute_identity()?;
        match &mut value {
            Self::DiagnosticSource {
                compatibility_identity,
                ..
            } => *compatibility_identity = identity,
            Self::StaticHermes { .. } => unreachable!(),
        }
        Ok(value)
    }

    pub fn static_hermes(
        build_profile: impl Into<String>,
        static_archive_digest: impl Into<String>,
        hbc_version: u32,
    ) -> Result<Self> {
        let mut value = Self::StaticHermes {
            build_profile: build_profile.into(),
            static_archive_digest: static_archive_digest.into(),
            hbc_version,
            compatibility_identity: String::new(),
        };
        let identity = value.compute_identity()?;
        match &mut value {
            Self::StaticHermes {
                compatibility_identity,
                ..
            } => *compatibility_identity = identity,
            Self::DiagnosticSource { .. } => unreachable!(),
        }
        Ok(value)
    }

    pub fn identity(&self) -> &str {
        match self {
            Self::DiagnosticSource {
                compatibility_identity,
                ..
            }
            | Self::StaticHermes {
                compatibility_identity,
                ..
            } => compatibility_identity,
        }
    }

    fn compute_identity(&self) -> Result<String> {
        let descriptor = match self {
            Self::DiagnosticSource { profile, .. } => serde_json::json!({
                "schema": ENGINE_COMPATIBILITY_SCHEMA_V1,
                "kind": "diagnostic-source",
                "profile": profile,
            }),
            Self::StaticHermes {
                build_profile,
                static_archive_digest,
                hbc_version,
                ..
            } => serde_json::json!({
                "schema": ENGINE_COMPATIBILITY_SCHEMA_V1,
                "kind": "static-hermes",
                "buildProfile": build_profile,
                "staticArchiveDigest": static_archive_digest,
                "hbcVersion": hbc_version,
            }),
        };
        capsec_semantics::digest::compute_domain_digest(
            ENGINE_COMPATIBILITY_DOMAIN_V1,
            &descriptor,
            &[],
        )
        .map_err(|error| Error::Contract(error.to_string()))
    }

    fn validate(&self, release_eligible: bool) -> Result<()> {
        match self {
            Self::DiagnosticSource { profile, .. } if profile.is_empty() || release_eligible => {
                return Err(Error::Contract(
                    "diagnostic engine compatibility cannot identify a release stub".into(),
                ));
            }
            Self::StaticHermes {
                build_profile,
                static_archive_digest,
                hbc_version,
                ..
            } if build_profile.is_empty()
                || !valid_digest(static_archive_digest)
                || *hbc_version == 0 =>
            {
                return Err(Error::Contract(
                    "static Hermes compatibility facts are invalid".into(),
                ));
            }
            _ => {}
        }
        if !valid_digest(self.identity()) || self.identity() != self.compute_identity()? {
            return Err(Error::Contract(
                "engine compatibility identity is stale or malformed".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HermescCompatibilityV1 {
    DiagnosticUnused {
        reason: String,
    },
    CatalogArtifact {
        #[serde(rename = "binaryDigest")]
        binary_digest: String,
        #[serde(rename = "hbcVersion")]
        hbc_version: u32,
        #[serde(rename = "recipeDigest")]
        recipe_digest: String,
        #[serde(rename = "compilerIdentity")]
        compiler_identity: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HermescRecipeV1 {
    pub schema: String,
    pub arguments: Vec<String>,
    pub input_encoding: String,
    pub output_encoding: String,
}

impl HermescRecipeV1 {
    pub fn production() -> Self {
        Self {
            schema: HERMESC_RECIPE_SCHEMA_V1.into(),
            arguments: vec![
                // @ref LLP 0034#decision — catalog-produced executable HBC
                // must use the same block-scoping semantics as the stub.
                "-Xes6-block-scoping".into(),
                "-emit-binary".into(),
                "-out".into(),
                "{output}".into(),
                "{input}".into(),
            ],
            input_encoding: "utf8-javascript-factory-table".into(),
            output_encoding: "hermes-bytecode-file".into(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self != &Self::production() {
            return Err(Error::Contract(
                "hermesc recipe differs from the fixed v1 production invocation".into(),
            ));
        }
        let value =
            serde_json::to_value(self).map_err(|error| Error::Contract(error.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| Error::Contract(error.to_string()))
    }

    pub fn digest(&self) -> Result<String> {
        let bytes = self.canonical_bytes()?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|error| Error::Contract(error.to_string()))?;
        capsec_semantics::digest::compute_domain_digest(HERMESC_RECIPE_DOMAIN_V1, &value, &[])
            .map_err(|error| Error::Contract(error.to_string()))
    }
}

impl HermescCompatibilityV1 {
    pub fn diagnostic_unused(reason: impl Into<String>) -> Self {
        Self::DiagnosticUnused {
            reason: reason.into(),
        }
    }

    pub fn catalog_artifact(
        binary_digest: impl Into<String>,
        hbc_version: u32,
        recipe_digest: impl Into<String>,
    ) -> Result<Self> {
        let mut value = Self::CatalogArtifact {
            binary_digest: binary_digest.into(),
            hbc_version,
            recipe_digest: recipe_digest.into(),
            compiler_identity: String::new(),
        };
        let identity = value.compute_identity()?.ok_or_else(|| {
            Error::Contract("catalog hermesc identity unexpectedly absent".into())
        })?;
        if let Self::CatalogArtifact {
            compiler_identity, ..
        } = &mut value
        {
            *compiler_identity = identity;
        }
        Ok(value)
    }

    pub fn identity(&self) -> Option<&str> {
        match self {
            Self::DiagnosticUnused { .. } => None,
            Self::CatalogArtifact {
                compiler_identity, ..
            } => Some(compiler_identity),
        }
    }

    fn compute_identity(&self) -> Result<Option<String>> {
        let Self::CatalogArtifact {
            binary_digest,
            hbc_version,
            recipe_digest,
            ..
        } = self
        else {
            return Ok(None);
        };
        let descriptor = serde_json::json!({
            "schema": HERMESC_COMPATIBILITY_SCHEMA_V1,
            "binaryDigest": binary_digest,
            "hbcVersion": hbc_version,
            "recipeDigest": recipe_digest,
        });
        capsec_semantics::digest::compute_domain_digest(
            HERMESC_COMPATIBILITY_DOMAIN_V1,
            &descriptor,
            &[],
        )
        .map(Some)
        .map_err(|error| Error::Contract(error.to_string()))
    }

    fn validate(&self, release_eligible: bool) -> Result<()> {
        match self {
            Self::DiagnosticUnused { reason } => {
                if reason.is_empty() || release_eligible {
                    return Err(Error::Contract(
                        "a release stub requires a catalog hermesc identity".into(),
                    ));
                }
            }
            Self::CatalogArtifact {
                binary_digest,
                hbc_version,
                recipe_digest,
                compiler_identity,
            } => {
                if !valid_digest(binary_digest)
                    || *hbc_version == 0
                    || !valid_digest(recipe_digest)
                    || !valid_digest(compiler_identity)
                    || Some(compiler_identity.as_str()) != self.compute_identity()?.as_deref()
                {
                    return Err(Error::Contract(
                        "catalog hermesc compatibility facts are invalid".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StubAcceptedSchemasV1 {
    pub envelope: String,
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
pub struct StubAbisV1 {
    pub module_runner: String,
    pub arming: String,
}

impl StubContractV3 {
    fn validate(&self) -> Result<()> {
        let schemas = &self.accepted_schemas;
        if self.schema != STUB_CONTRACT_SCHEMA_V3
            || self.profile.is_empty()
            || self.target.triple.is_empty()
            || self.target.minimum_platform.is_empty()
            || (self.release_eligible
                && !valid_release_target_baseline_v1(
                    &self.target.triple,
                    &self.target.minimum_platform,
                ))
            || schemas.envelope != ENVELOPE_SCHEMA_V2
            || schemas.entry_designation != ENTRY_DESIGNATION_SCHEMA_V1
            || schemas.embedded_graph != "ibex/embedded-module-graph/1"
            || schemas.authenticated_graph_snapshot != "ibex/authenticated-graph-snapshot/1"
            || schemas.computed_candidates != "ibex/computed-candidates/1"
            || schemas.carrier != "ibex/module-carrier/2"
            || schemas.canonical_policy != "ibex/capsec-policy/2"
            || schemas.armed_snapshot != "ibex/capsec-armed/1"
            || schemas.runtime_capsec_projection != "ibex/capsec-runtime-projection/1"
            || schemas.runtime_identity != "ibex/runtime-identity/1"
            || schemas.environment_profile != "ibex/compiled-environment-profile/1"
            || self.abis.module_runner.is_empty()
            || self.abis.arming.is_empty()
            || !valid_digest(&self.transform_profile_digest)
            || !valid_digest(&self.runtime_capsec_projection_digest)
            || !valid_digest(&self.runtime_identity_digest)
            || !valid_digest(&self.environment_profile_digest)
        {
            return Err(Error::Contract("stub contract is invalid".into()));
        }
        self.boot.validate()?;
        self.backends.validate()?;
        if self.release_eligible
            && self.backends != StubBackendInventoryV1::release_for_target(&self.target.triple)?
        {
            return Err(Error::Contract(
                "release stub backend inventory disagrees with its target profile".into(),
            ));
        }
        self.engine.validate(self.release_eligible)?;
        self.hermesc.validate(self.release_eligible)?;
        if let (
            EngineCompatibilityV1::StaticHermes {
                hbc_version: engine_hbc_version,
                ..
            },
            HermescCompatibilityV1::CatalogArtifact {
                hbc_version: compiler_hbc_version,
                ..
            },
        ) = (&self.engine, &self.hermesc)
        {
            if engine_hbc_version != compiler_hbc_version {
                return Err(Error::Contract(
                    "static Hermes and catalog hermesc HBC versions disagree".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|error| Error::Contract(error.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| Error::Contract(error.to_string()))
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|error| Error::Contract(error.to_string()))?;
        capsec_semantics::digest::compute_domain_digest(STUB_CONTRACT_DOMAIN_V3, &value, &[])
            .map_err(|error| Error::Contract(error.to_string()))
    }
}

/// Release baselines are typed strings because they participate in the v1
/// catalog key and contract digest. Linux records both the maximum permitted
/// GLIBC symbol version and the x86-64 ISA level checked from the final ELF;
/// macOS records the deployment target and architecture.
/// @ref LLP 0029#2-executable-layout-stub-envelope-footer —
/// release catalog entries bind a concrete, audit-verifiable platform floor
pub fn valid_release_target_baseline_v1(triple: &str, baseline: &str) -> bool {
    match triple {
        "x86_64-unknown-linux-gnu" => baseline
            .strip_prefix("linux-glibc-")
            .and_then(|value| value.strip_suffix("-x86-64-v1"))
            .is_some_and(valid_major_minor),
        "aarch64-apple-darwin" => baseline
            .strip_prefix("macos-")
            .and_then(|value| value.strip_suffix("-arm64"))
            .is_some_and(valid_major_minor),
        _ => false,
    }
}

fn valid_major_minor(value: &str) -> bool {
    let mut pieces = value.split('.');
    matches!(
        (pieces.next(), pieces.next(), pieces.next()),
        (Some(major), Some(minor), None)
            if !major.is_empty()
                && !minor.is_empty()
                && major.bytes().all(|byte| byte.is_ascii_digit())
                && minor.bytes().all(|byte| byte.is_ascii_digit())
    )
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("SFE001 footer is absent or malformed")]
    Footer,
    #[error("SFE002 envelope range is invalid")]
    EnvelopeRange,
    #[error("SFE003 section directory is not canonical strict JSON: {0}")]
    Directory(String),
    #[error("SFE004 section directory contract is invalid: {0}")]
    Contract(String),
    #[error("SFE005 section range is invalid: {0}")]
    SectionRange(String),
    #[error("SFE006 section digest mismatch: {0}")]
    SectionDigest(String),
    #[error("SFE007 envelope digest mismatch")]
    EnvelopeDigest,
    #[error("SFE008 entry designation is invalid: {0}")]
    EntryDesignation(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SectionKindV1 {
    StubContract,
    ProvenanceManifest,
    EmbeddedModuleGraph,
    ResolvedPolicy,
    EntryDesignation,
    CandidateTable,
    CarrierManifest,
    CarrierPayload,
}

#[derive(Clone, Debug)]
pub struct SectionInputV1 {
    pub id: String,
    pub kind: SectionKindV1,
    pub pair_id: Option<String>,
    pub alignment: u32,
    pub bytes: Vec<u8>,
}

impl SectionInputV1 {
    pub fn canonical(id: impl Into<String>, kind: SectionKindV1, bytes: Vec<u8>) -> Self {
        let alignment = if kind == SectionKindV1::CarrierPayload {
            CARRIER_ALIGNMENT_V1
        } else {
            8
        };
        Self {
            id: id.into(),
            kind,
            pair_id: None,
            alignment,
            bytes,
        }
    }

    pub fn carrier(
        id: impl Into<String>,
        kind: SectionKindV1,
        pair_id: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        let mut section = Self::canonical(id, kind, bytes);
        section.pair_id = Some(pair_id.into());
        section
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntryDesignationV1 {
    pub schema: String,
    pub entries: Vec<EntryDesignationRowV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntryDesignationRowV1 {
    pub name: String,
    pub source_id: String,
}

impl EntryDesignationV1 {
    pub fn one(source_id: impl Into<String>) -> Self {
        Self {
            schema: ENTRY_DESIGNATION_SCHEMA_V1.into(),
            entries: vec![EntryDesignationRowV1 {
                name: "main".into(),
                source_id: source_id.into(),
            }],
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)
            .map_err(|error| Error::EntryDesignation(error.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| Error::EntryDesignation(error.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeDirectoryV1 {
    pub schema: String,
    pub stub_contract_digest: String,
    pub sections: Vec<SectionDirectoryRowV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SectionDirectoryRowV1 {
    pub id: String,
    pub kind: SectionKindV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pair_id: Option<String>,
    pub offset: u64,
    pub length: u64,
    pub alignment: u32,
    pub digest: String,
}

#[derive(Clone, Debug)]
pub struct AdmittedSectionV1<'a> {
    pub record: &'a SectionDirectoryRowV1,
    pub bytes: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct AdmittedEnvelopeV1<'a> {
    pub stub_len: usize,
    pub envelope_digest: String,
    pub directory: EnvelopeDirectoryV1,
    file: &'a [u8],
}

impl<'a> AdmittedEnvelopeV1<'a> {
    pub fn section(&'a self, id: &str) -> Option<AdmittedSectionV1<'a>> {
        self.directory
            .sections
            .iter()
            .find(|row| row.id == id)
            .map(|row| {
                let start = self.stub_len + row.offset as usize;
                let end = start + row.length as usize;
                AdmittedSectionV1 {
                    record: row,
                    bytes: &self.file[start..end],
                }
            })
    }

    pub fn sections(&'a self) -> impl Iterator<Item = AdmittedSectionV1<'a>> + 'a {
        self.directory.sections.iter().map(|row| {
            let start = self.stub_len + row.offset as usize;
            let end = start + row.length as usize;
            AdmittedSectionV1 {
                record: row,
                bytes: &self.file[start..end],
            }
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct FooterV1 {
    envelope_start: u64,
    directory_offset: u64,
    directory_length: u64,
    section_count: u32,
    digest: [u8; 32],
}

fn digest(bytes: &[u8]) -> String {
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

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_source_id(value: &str) -> bool {
    let Some(payload) = value.strip_prefix("ibex-source-id-v1:") else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    if URL_SAFE_NO_PAD.encode(&bytes) != payload {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return false;
    };
    let Ok(decoded) = capsec_semantics::strict_json::parse_strict(text) else {
        return false;
    };
    capsec_semantics::canonical::to_jcs_bytes(&decoded)
        .ok()
        .as_deref()
        == Some(bytes.as_slice())
        && matches!(
            decoded.get("kind").and_then(serde_json::Value::as_str),
            Some("file" | "builtin" | "synthetic")
        )
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|sum| sum & !(alignment - 1))
}

fn push_padding(output: &mut Vec<u8>, alignment: usize) -> Result<()> {
    if !alignment.is_power_of_two() {
        return Err(Error::Contract("alignment is not a power of two".into()));
    }
    let aligned = align_up(output.len(), alignment)
        .ok_or_else(|| Error::Contract("alignment overflow".into()))?;
    output.resize(aligned, 0);
    Ok(())
}

pub fn build_executable_v1(
    stub: &[u8],
    stub_contract_digest: &str,
    mut sections: Vec<SectionInputV1>,
) -> Result<Vec<u8>> {
    if !valid_digest(stub_contract_digest) {
        return Err(Error::Contract("stub contract digest is malformed".into()));
    }
    if sections.is_empty() || sections.len() > MAX_SECTIONS_V1 {
        return Err(Error::Contract("section count is outside v1 limits".into()));
    }
    sections.sort_by(|left, right| (&left.kind, &left.id).cmp(&(&right.kind, &right.id)));
    let mut output = stub.to_vec();
    let envelope_start = output.len();
    let mut rows = Vec::with_capacity(sections.len());
    for section in sections {
        if !valid_id(&section.id) {
            return Err(Error::Contract(format!(
                "invalid section id {:?}",
                section.id
            )));
        }
        push_padding(&mut output, section.alignment as usize)?;
        let offset = output
            .len()
            .checked_sub(envelope_start)
            .ok_or(Error::EnvelopeRange)? as u64;
        let length = section.bytes.len() as u64;
        let section_digest = digest(&section.bytes);
        output.extend_from_slice(&section.bytes);
        rows.push(SectionDirectoryRowV1 {
            id: section.id,
            kind: section.kind,
            pair_id: section.pair_id,
            offset,
            length,
            alignment: section.alignment,
            digest: section_digest,
        });
    }
    push_padding(&mut output, 8)?;
    let directory_offset = (output.len() - envelope_start) as u64;
    let directory = EnvelopeDirectoryV1 {
        schema: ENVELOPE_SCHEMA_V2.into(),
        stub_contract_digest: stub_contract_digest.into(),
        sections: rows,
    };
    validate_directory(&directory)?;
    let directory_value =
        serde_json::to_value(&directory).map_err(|error| Error::Directory(error.to_string()))?;
    let directory_bytes = capsec_semantics::canonical::to_jcs_bytes(&directory_value)
        .map_err(|error| Error::Directory(error.to_string()))?;
    if directory_bytes.len() > MAX_DIRECTORY_BYTES_V1 {
        return Err(Error::Contract("section directory exceeds v1 limit".into()));
    }
    output.extend_from_slice(&directory_bytes);
    let footer_start = output.len();
    let envelope_bytes = output
        .get(envelope_start..footer_start)
        .ok_or(Error::EnvelopeRange)?;
    if envelope_bytes.len() > MAX_ENVELOPE_BYTES_V1 {
        return Err(Error::Contract("envelope exceeds v1 limit".into()));
    }
    let envelope_hash: [u8; 32] = Sha256::digest(envelope_bytes).into();
    write_footer(
        &mut output,
        FooterV1 {
            envelope_start: envelope_start as u64,
            directory_offset,
            directory_length: directory_bytes.len() as u64,
            section_count: directory.sections.len() as u32,
            digest: envelope_hash,
        },
    );
    debug_assert_eq!(output.len(), footer_start + FOOTER_LEN_V1);
    Ok(output)
}

pub fn admit_executable_v1<'a>(
    file: &'a [u8],
    expected_stub_contract: &str,
) -> Result<AdmittedEnvelopeV1<'a>> {
    admit_executable_with_contract_v1(file, Some(expected_stub_contract))
}

/// Authenticate an envelope for read-only inspection using the contract digest
/// carried by the envelope itself. This establishes internal consistency only;
/// it intentionally does not turn a self-described contract into a release
/// trust root. Callers that will execute bytes must use `admit_executable_v1`
/// with an independently expected contract digest.
/// @ref LLP 0029#1-command-surface-and-producer-pipeline — inspection reports envelope consistency independently from authenticity
pub fn inspect_executable_v1(file: &[u8]) -> Result<AdmittedEnvelopeV1<'_>> {
    admit_executable_with_contract_v1(file, None)
}

/// Reconstruct and hash the executable's actual catalog stub projection.
/// Internal envelope admission authenticates the descriptor; this check proves
/// that the outer executable bytes still agree with the recorded instance.
pub fn rehash_stub_core_v1(
    file: &[u8],
    envelope: &AdmittedEnvelopeV1<'_>,
    reconstruction: &StubCoreReconstructionV1,
) -> Result<String> {
    if file.get(..4) == Some(&0xfeedfacfu32.to_le_bytes()) {
        let vmsize = reconstruction.macho_linkedit_vmsize.ok_or_else(|| {
            Error::Contract("Mach-O stub reconstruction omits __LINKEDIT vmsize".into())
        })?;
        return Ok(digest(&macho::reconstruct_stub_core_v1(
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
    Ok(digest(file.get(..size).ok_or(Error::EnvelopeRange)?))
}

fn admit_executable_with_contract_v1<'a>(
    file: &'a [u8],
    expected_stub_contract: Option<&str>,
) -> Result<AdmittedEnvelopeV1<'a>> {
    let footer_start = macho::embedded_footer_offset(file)?
        .unwrap_or(file.len().checked_sub(FOOTER_LEN_V1).ok_or(Error::Footer)?);
    let footer = read_footer(file, footer_start)?;
    let envelope_start =
        usize::try_from(footer.envelope_start).map_err(|_| Error::EnvelopeRange)?;
    let directory_offset =
        usize::try_from(footer.directory_offset).map_err(|_| Error::EnvelopeRange)?;
    let directory_length =
        usize::try_from(footer.directory_length).map_err(|_| Error::EnvelopeRange)?;
    if envelope_start > footer_start
        || footer_start - envelope_start > MAX_ENVELOPE_BYTES_V1
        || directory_length > MAX_DIRECTORY_BYTES_V1
    {
        return Err(Error::EnvelopeRange);
    }
    let directory_start = envelope_start
        .checked_add(directory_offset)
        .ok_or(Error::EnvelopeRange)?;
    let directory_end = directory_start
        .checked_add(directory_length)
        .ok_or(Error::EnvelopeRange)?;
    if directory_start < envelope_start || directory_end != footer_start {
        return Err(Error::EnvelopeRange);
    }
    let actual_envelope_hash: [u8; 32] = Sha256::digest(&file[envelope_start..footer_start]).into();
    if actual_envelope_hash != footer.digest {
        return Err(Error::EnvelopeDigest);
    }
    let directory_bytes = &file[directory_start..directory_end];
    let text = std::str::from_utf8(directory_bytes)
        .map_err(|error| Error::Directory(error.to_string()))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|error| Error::Directory(error.to_string()))?;
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
        .map_err(|error| Error::Directory(error.to_string()))?;
    if canonical != directory_bytes {
        return Err(Error::Directory("directory bytes are not JCS".into()));
    }
    let directory: EnvelopeDirectoryV1 =
        serde_json::from_value(value).map_err(|error| Error::Directory(error.to_string()))?;
    if directory.sections.len() != footer.section_count as usize {
        return Err(Error::Contract(
            "footer section count disagrees with directory".into(),
        ));
    }
    if let Some(expected_stub_contract) = expected_stub_contract {
        if directory.stub_contract_digest != expected_stub_contract {
            return Err(Error::Contract("stub contract digest mismatch".into()));
        }
    }
    validate_directory(&directory)?;
    validate_ranges_and_digests(file, envelope_start, directory_offset, &directory)?;
    validate_stub_contract_section(file, envelope_start, &directory)?;
    validate_entry_section(file, envelope_start, &directory)?;
    Ok(AdmittedEnvelopeV1 {
        stub_len: envelope_start,
        envelope_digest: format!("sha256-{}", URL_SAFE_NO_PAD.encode(footer.digest)),
        directory,
        file,
    })
}

fn validate_directory(directory: &EnvelopeDirectoryV1) -> Result<()> {
    if directory.schema != ENVELOPE_SCHEMA_V2 {
        return Err(Error::Contract("unsupported envelope schema".into()));
    }
    if !valid_digest(&directory.stub_contract_digest) {
        return Err(Error::Contract("stub contract digest is malformed".into()));
    }
    if directory.sections.is_empty() || directory.sections.len() > MAX_SECTIONS_V1 {
        return Err(Error::Contract("section count is outside v1 limits".into()));
    }
    let mut ids = BTreeSet::new();
    let mut singleton_counts = BTreeMap::new();
    let mut pair_rows: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut previous_order: Option<(SectionKindV1, &str)> = None;
    for row in &directory.sections {
        let order = (row.kind, row.id.as_str());
        if previous_order.is_some_and(|previous| previous >= order) {
            return Err(Error::Contract(
                "sections must be strictly ordered by kind and id".into(),
            ));
        }
        previous_order = Some(order);
        if !valid_id(&row.id) || !ids.insert(row.id.as_str()) {
            return Err(Error::Contract(
                "section ids must be canonical and unique".into(),
            ));
        }
        if !valid_digest(&row.digest)
            || !row.alignment.is_power_of_two()
            || row.alignment > CARRIER_ALIGNMENT_V1
        {
            return Err(Error::Contract(format!(
                "section {} metadata is malformed",
                row.id
            )));
        }
        if row.kind == SectionKindV1::CarrierPayload && row.alignment != CARRIER_ALIGNMENT_V1 {
            return Err(Error::Contract(format!(
                "carrier payload {} is not page aligned",
                row.id
            )));
        }
        match row.kind {
            SectionKindV1::StubContract
            | SectionKindV1::ProvenanceManifest
            | SectionKindV1::EmbeddedModuleGraph
            | SectionKindV1::ResolvedPolicy
            | SectionKindV1::EntryDesignation => {
                if row.pair_id.is_some() {
                    return Err(Error::Contract(format!(
                        "singleton {} has a pair id",
                        row.id
                    )));
                }
                *singleton_counts.entry(row.kind).or_insert(0usize) += 1;
            }
            SectionKindV1::CarrierManifest | SectionKindV1::CarrierPayload => {
                let pair = row
                    .pair_id
                    .as_deref()
                    .filter(|pair| valid_id(pair))
                    .ok_or_else(|| {
                        Error::Contract(format!("carrier {} has no canonical pair id", row.id))
                    })?;
                let counts = pair_rows.entry(pair).or_insert((0, 0));
                if row.kind == SectionKindV1::CarrierManifest {
                    counts.0 += 1;
                } else {
                    counts.1 += 1;
                }
            }
            SectionKindV1::CandidateTable => {
                if row.pair_id.is_some() {
                    return Err(Error::Contract(format!(
                        "candidate table {} has a pair id",
                        row.id
                    )));
                }
            }
        }
    }
    for kind in [
        SectionKindV1::StubContract,
        SectionKindV1::ProvenanceManifest,
        SectionKindV1::EmbeddedModuleGraph,
        SectionKindV1::ResolvedPolicy,
        SectionKindV1::EntryDesignation,
    ] {
        if singleton_counts.get(&kind) != Some(&1) {
            return Err(Error::Contract(format!(
                "required {kind:?} section is not singular"
            )));
        }
    }
    if pair_rows.is_empty() || pair_rows.values().any(|counts| *counts != (1, 1)) {
        return Err(Error::Contract(
            "carrier manifest/payload bijection is incomplete".into(),
        ));
    }
    Ok(())
}

fn validate_stub_contract_section(
    file: &[u8],
    envelope_start: usize,
    directory: &EnvelopeDirectoryV1,
) -> Result<()> {
    let row = directory
        .sections
        .iter()
        .find(|row| row.kind == SectionKindV1::StubContract)
        .ok_or_else(|| Error::Contract("stub contract section is absent".into()))?;
    let start = envelope_start + row.offset as usize;
    let end = start + row.length as usize;
    let bytes = &file[start..end];
    let text = std::str::from_utf8(bytes)
        .map_err(|error| Error::Contract(format!("stub contract is not UTF-8: {error}")))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|error| Error::Contract(error.to_string()))?;
    let contract: StubContractV3 =
        serde_json::from_value(value).map_err(|error| Error::Contract(error.to_string()))?;
    if contract
        .canonical_bytes()
        .map_err(|error| Error::Contract(error.to_string()))?
        != bytes
        || contract
            .digest()
            .map_err(|error| Error::Contract(error.to_string()))?
            != directory.stub_contract_digest
    {
        return Err(Error::Contract(
            "embedded stub contract bytes disagree with the envelope pin".into(),
        ));
    }
    Ok(())
}

fn validate_ranges_and_digests(
    file: &[u8],
    envelope_start: usize,
    directory_offset: usize,
    directory: &EnvelopeDirectoryV1,
) -> Result<()> {
    let mut previous_end = 0usize;
    for row in &directory.sections {
        let start = usize::try_from(row.offset).map_err(|_| Error::SectionRange(row.id.clone()))?;
        let length =
            usize::try_from(row.length).map_err(|_| Error::SectionRange(row.id.clone()))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| Error::SectionRange(row.id.clone()))?;
        let absolute = envelope_start
            .checked_add(start)
            .ok_or_else(|| Error::SectionRange(row.id.clone()))?;
        if start < previous_end || end > directory_offset || absolute % row.alignment as usize != 0
        {
            return Err(Error::SectionRange(row.id.clone()));
        }
        let bytes = file
            .get(absolute..absolute + length)
            .ok_or_else(|| Error::SectionRange(row.id.clone()))?;
        let padding = file
            .get(envelope_start + previous_end..absolute)
            .ok_or_else(|| Error::SectionRange(row.id.clone()))?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(Error::SectionRange(format!(
                "nonzero padding before {}",
                row.id
            )));
        }
        if digest(bytes) != row.digest {
            return Err(Error::SectionDigest(row.id.clone()));
        }
        previous_end = end;
    }
    if file[envelope_start + previous_end..envelope_start + directory_offset]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::SectionRange(
            "nonzero padding before section directory".into(),
        ));
    }
    Ok(())
}

fn validate_entry_section(
    file: &[u8],
    envelope_start: usize,
    directory: &EnvelopeDirectoryV1,
) -> Result<()> {
    let row = directory
        .sections
        .iter()
        .find(|row| row.kind == SectionKindV1::EntryDesignation)
        .ok_or_else(|| Error::EntryDesignation("entry section is absent".into()))?;
    let start = envelope_start + row.offset as usize;
    let end = start + row.length as usize;
    let bytes = &file[start..end];
    let text =
        std::str::from_utf8(bytes).map_err(|error| Error::EntryDesignation(error.to_string()))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|error| Error::EntryDesignation(error.to_string()))?;
    if capsec_semantics::canonical::to_jcs_bytes(&value)
        .map_err(|error| Error::EntryDesignation(error.to_string()))?
        != bytes
    {
        return Err(Error::EntryDesignation("entry section is not JCS".into()));
    }
    let entry: EntryDesignationV1 = serde_json::from_value(value)
        .map_err(|error| Error::EntryDesignation(error.to_string()))?;
    if entry.schema != ENTRY_DESIGNATION_SCHEMA_V1
        || entry.entries.len() != 1
        || entry.entries[0].name != "main"
        || !valid_source_id(&entry.entries[0].source_id)
    {
        return Err(Error::EntryDesignation(
            "v1 requires exactly one main row".into(),
        ));
    }
    Ok(())
}

fn write_footer(output: &mut Vec<u8>, footer: FooterV1) {
    output.extend_from_slice(&FOOTER_MAGIC_V2);
    output.extend_from_slice(&FORMAT_VERSION_V2.to_le_bytes());
    output.extend_from_slice(&(FOOTER_LEN_V1 as u32).to_le_bytes());
    output.extend_from_slice(&footer.envelope_start.to_le_bytes());
    output.extend_from_slice(&footer.directory_offset.to_le_bytes());
    output.extend_from_slice(&footer.directory_length.to_le_bytes());
    output.extend_from_slice(&footer.section_count.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&footer.digest);
}

fn read_footer(file: &[u8], footer_start: usize) -> Result<FooterV1> {
    let footer = file
        .get(
            footer_start
                ..footer_start
                    .checked_add(FOOTER_LEN_V1)
                    .ok_or(Error::Footer)?,
        )
        .ok_or(Error::Footer)?;
    if footer[..16] != FOOTER_MAGIC_V2
        || u32::from_le_bytes(footer[16..20].try_into().map_err(|_| Error::Footer)?)
            != FORMAT_VERSION_V2
        || u32::from_le_bytes(footer[20..24].try_into().map_err(|_| Error::Footer)?) as usize
            != FOOTER_LEN_V1
        || footer[52..56] != [0; 4]
    {
        return Err(Error::Footer);
    }
    Ok(FooterV1 {
        envelope_start: u64::from_le_bytes(footer[24..32].try_into().map_err(|_| Error::Footer)?),
        directory_offset: u64::from_le_bytes(footer[32..40].try_into().map_err(|_| Error::Footer)?),
        directory_length: u64::from_le_bytes(footer[40..48].try_into().map_err(|_| Error::Footer)?),
        section_count: u32::from_le_bytes(footer[48..52].try_into().map_err(|_| Error::Footer)?),
        digest: footer[56..88].try_into().map_err(|_| Error::Footer)?,
    })
}

#[cfg(test)]
fn fixture_stub_contract() -> StubContractV3 {
    StubContractV3 {
        schema: STUB_CONTRACT_SCHEMA_V3.into(),
        profile: "test-v2".into(),
        release_eligible: false,
        target: StubTargetV1 {
            triple: "aarch64-apple-darwin".into(),
            minimum_platform: "diagnostic-host-unpinned".into(),
        },
        engine: EngineCompatibilityV1::diagnostic_source("diagnostic-test").unwrap(),
        hermesc: HermescCompatibilityV1::diagnostic_unused("test does not compile HBC"),
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
        transform_profile_digest: digest(b"transform"),
        runtime_capsec_projection_digest: digest(b"capsec"),
        runtime_identity_digest: digest(b"identity"),
        environment_profile_digest: digest(b"environment"),
        boot: StubBootContractV3::dual_mode(""),
        backends: StubBackendInventoryV1::diagnostic_development(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_target_baselines_are_typed_and_auditable() {
        assert!(valid_release_target_baseline_v1(
            "x86_64-unknown-linux-gnu",
            "linux-glibc-2.35-x86-64-v1"
        ));
        assert!(valid_release_target_baseline_v1(
            "aarch64-apple-darwin",
            "macos-13.0-arm64"
        ));
        assert!(!valid_release_target_baseline_v1(
            "x86_64-unknown-linux-gnu",
            "ubuntu-latest"
        ));
        assert!(!valid_release_target_baseline_v1(
            "x86_64-unknown-linux-gnu",
            "linux-glibc-2.35-x86-64-v3"
        ));
        assert!(!valid_release_target_baseline_v1(
            "x86_64-apple-darwin",
            "macos-13.0-x86_64"
        ));
    }

    fn plan() -> CompilePlanV1 {
        CompilePlanV1 {
            schema: COMPILE_PLAN_SCHEMA_V1.into(),
            graph_snapshot_digest: digest(b"graph"),
            policy_digest: digest(b"policy"),
            stub_contract_digest: digest(b"stub contract"),
            catalog_digest: digest(b"catalog"),
            compiler_identity: digest(b"compiler"),
            carrier_encoding: CompileCarrierEncodingV1::HermesBytecode,
            target: "aarch64-apple-darwin".into(),
            environment_profile_digest: digest(b"environment"),
        }
    }

    #[test]
    fn compile_plan_is_canonical_domain_bound_and_path_independent() {
        let plan = plan();
        let bytes = plan.canonical_bytes().unwrap();
        assert_eq!(
            serde_json::from_slice::<CompilePlanV1>(&bytes).unwrap(),
            plan
        );
        assert!(plan.digest().unwrap().starts_with("sha256-"));
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("/tmp/"));

        let mut stale = plan;
        stale.policy_digest = "sha256-not-canonical".into();
        assert!(stale.canonical_bytes().is_err());
    }

    #[test]
    fn provenance_cross_binds_the_plan_catalog_target_and_stub() {
        let plan = plan();
        let provenance = PackageProvenanceV1 {
            schema: PACKAGE_PROVENANCE_SCHEMA_V1.into(),
            compile_plan_digest: plan.digest().unwrap(),
            catalog_sequence: 1,
            catalog_entry_target: plan.target.clone(),
            stub_core_digest: digest(b"stub"),
            stub_core_reconstruction: StubCoreReconstructionV1 {
                size: 4,
                macho_linkedit_vmsize: Some(0x4000),
            },
            producer_identity: "ibex/0.1.0".into(),
            compile_plan: plan,
        };
        assert!(provenance.canonical_bytes().is_ok());
        let mut mismatch = provenance;
        mismatch.catalog_entry_target = "x86_64-unknown-linux-gnu".into();
        assert!(mismatch.canonical_bytes().is_err());
    }

    #[test]
    fn hermesc_recipe_is_fixed_and_domain_bound() {
        let recipe = HermescRecipeV1::production();
        assert_eq!(
            recipe.arguments,
            [
                "-Xes6-block-scoping",
                "-emit-binary",
                "-out",
                "{output}",
                "{input}",
            ]
        );
        assert!(recipe.digest().unwrap().starts_with("sha256-"));
        let mut changed = recipe;
        changed.arguments.push("-O".into());
        assert!(changed.digest().is_err());
    }

    #[test]
    fn release_contract_refuses_compiler_engine_hbc_mismatch() {
        let engine = EngineCompatibilityV1::static_hermes(
            "hermes-full-static-release-v1",
            digest(b"engine"),
            98,
        )
        .unwrap();
        let compiler = HermescCompatibilityV1::catalog_artifact(
            digest(b"hermesc"),
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
            engine,
            hermesc: compiler,
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
            transform_profile_digest: digest(b"transform"),
            runtime_capsec_projection_digest: digest(b"capsec"),
            runtime_identity_digest: digest(b"identity"),
            environment_profile_digest: digest(b"environment"),
            boot: StubBootContractV3::dual_mode(""),
            backends: StubBackendInventoryV1::release_for_target("aarch64-apple-darwin").unwrap(),
        };
        assert!(contract
            .canonical_bytes()
            .unwrap_err()
            .to_string()
            .contains("HBC versions disagree"));
    }

    #[test]
    fn v3_boot_contract_authenticates_both_reserved_selectors() {
        let contract = fixture_stub_contract();
        assert_eq!(contract.schema, STUB_CONTRACT_SCHEMA_V3);
        assert_eq!(contract.accepted_schemas.envelope, ENVELOPE_SCHEMA_V2);
        assert_eq!(
            contract.boot.default_mode,
            StubDefaultBootModeV3::AmbientCompatibility
        );
        assert_eq!(contract.boot.capsec_selector.spelling, "--ibex-capsec");
        assert_eq!(
            contract.boot.capsec_selector.position,
            StubSelectorPositionV3::FirstArgumentOnly
        );
        assert_eq!(
            contract.boot.capsec_selector.escape,
            StubSelectorEscapeV3::LeadingDoubleDash
        );
        assert_eq!(contract.boot.information_selector.spelling, "--ibex-info");
        assert_eq!(
            contract.boot.information_selector.report_schema,
            STANDALONE_INFO_SCHEMA_V1
        );
        assert!(contract.boot.capsec_advertisement_identity.is_empty());

        let mut changed = contract;
        changed.boot.information_selector.spelling = "--info".into();
        assert!(changed.canonical_bytes().is_err());
    }

    #[test]
    fn release_backend_inventory_is_target_exact_and_exposes_limitations() {
        let mac = StubBackendInventoryV1::release_for_target("aarch64-apple-darwin").unwrap();
        let linux = StubBackendInventoryV1::release_for_target("x86_64-unknown-linux-gnu").unwrap();
        let mac_fetch = mac
            .entries
            .iter()
            .find(|entry| entry.surface == "fetch")
            .unwrap();
        let linux_fetch = linux
            .entries
            .iter()
            .find(|entry| entry.surface == "fetch")
            .unwrap();
        assert_eq!(mac_fetch.implementation, "nsurlsession");
        assert_eq!(
            linux_fetch.implementation,
            "static-libcurl-vendored-openssl"
        );
        assert!(linux.entries.iter().any(|entry| {
            entry.surface == "crypto" && entry.status == StubBackendStatusV1::Limited
        }));
        assert!(mac.entries.iter().any(|entry| {
            entry.surface == "workers" && entry.status == StubBackendStatusV1::Unavailable
        }));

        let mut changed = mac;
        changed.entries.retain(|entry| entry.surface != "fetch");
        let mut contract = fixture_stub_contract();
        contract.release_eligible = true;
        contract.profile = "release-v1".into();
        contract.target.minimum_platform = "macos-13.0-arm64".into();
        contract.backends = changed;
        assert!(contract
            .canonical_bytes()
            .unwrap_err()
            .to_string()
            .contains("backend inventory disagrees"));
    }
    use proptest::prelude::*;

    fn contract() -> String {
        fixture_stub_contract().digest().unwrap()
    }

    fn fixture() -> Vec<u8> {
        let entry = EntryDesignationV1::one(
            "ibex-source-id-v1:eyJkb21haW4iOiJpYmV4LXJ1bnRpbWUiLCJraW5kIjoiYnVpbHRpbiIsInNvdXJjZV9rZXkiOiJleGFjdDpmcyJ9",
        )
        .canonical_bytes()
        .unwrap();
        build_executable_v1(
            b"dynamic-development-stub",
            &contract(),
            vec![
                SectionInputV1::canonical(
                    "stub-contract",
                    SectionKindV1::StubContract,
                    fixture_stub_contract().canonical_bytes().unwrap(),
                ),
                SectionInputV1::canonical(
                    "provenance",
                    SectionKindV1::ProvenanceManifest,
                    br#"{"schema":"ibex/package-provenance/1"}"#.to_vec(),
                ),
                SectionInputV1::canonical(
                    "graph",
                    SectionKindV1::EmbeddedModuleGraph,
                    br#"{"schema":"ibex/embedded-module-graph/1"}"#.to_vec(),
                ),
                SectionInputV1::canonical(
                    "policy",
                    SectionKindV1::ResolvedPolicy,
                    br#"{"policySchema":"ibex/capsec-policy/2"}"#.to_vec(),
                ),
                SectionInputV1::canonical("entry", SectionKindV1::EntryDesignation, entry),
                SectionInputV1::carrier(
                    "carrier-manifest-0",
                    SectionKindV1::CarrierManifest,
                    "module-0",
                    br#"{"schema":"ibex/module-carrier/2"}"#.to_vec(),
                ),
                SectionInputV1::carrier(
                    "carrier-payload-0",
                    SectionKindV1::CarrierPayload,
                    "module-0",
                    b"factory bytes".to_vec(),
                ),
            ],
        )
        .unwrap()
    }

    #[test]
    fn appended_envelope_rehashes_the_exact_outer_stub_projection() {
        let file = fixture();
        let admitted = inspect_executable_v1(&file).unwrap();
        let descriptor = StubCoreReconstructionV1::from_stub(b"dynamic-development-stub").unwrap();
        assert_eq!(
            rehash_stub_core_v1(&file, &admitted, &descriptor).unwrap(),
            digest(b"dynamic-development-stub")
        );

        let mut mutated = file;
        mutated[0] ^= 1;
        let admitted = inspect_executable_v1(&mutated).unwrap();
        assert_ne!(
            rehash_stub_core_v1(&mutated, &admitted, &descriptor).unwrap(),
            digest(b"dynamic-development-stub")
        );
    }

    fn rewrite_directory(
        baseline: &[u8],
        mutate: impl FnOnce(&mut EnvelopeDirectoryV1),
    ) -> Vec<u8> {
        let footer = read_footer(baseline, baseline.len() - FOOTER_LEN_V1).unwrap();
        let envelope_start = footer.envelope_start as usize;
        let directory_start = envelope_start + footer.directory_offset as usize;
        let footer_start = baseline.len() - FOOTER_LEN_V1;
        let mut directory: EnvelopeDirectoryV1 =
            serde_json::from_slice(&baseline[directory_start..footer_start]).unwrap();
        mutate(&mut directory);
        let directory_bytes =
            capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(&directory).unwrap())
                .unwrap();
        let mut rewritten = baseline[..directory_start].to_vec();
        rewritten.extend_from_slice(&directory_bytes);
        let envelope_hash: [u8; 32] = Sha256::digest(&rewritten[envelope_start..]).into();
        write_footer(
            &mut rewritten,
            FooterV1 {
                envelope_start: envelope_start as u64,
                directory_offset: footer.directory_offset,
                directory_length: directory_bytes.len() as u64,
                section_count: directory.sections.len() as u32,
                digest: envelope_hash,
            },
        );
        rewritten
    }

    fn rehash_footer(mut baseline: Vec<u8>) -> Vec<u8> {
        let footer = read_footer(&baseline, baseline.len() - FOOTER_LEN_V1).unwrap();
        let footer_start = baseline.len() - FOOTER_LEN_V1;
        let envelope_start = footer.envelope_start as usize;
        let envelope_hash: [u8; 32] =
            Sha256::digest(&baseline[envelope_start..footer_start]).into();
        baseline.truncate(footer_start);
        write_footer(
            &mut baseline,
            FooterV1 {
                digest: envelope_hash,
                ..footer
            },
        );
        baseline
    }

    #[test]
    fn deterministic_round_trip_bulk_preflights_every_section() {
        let first = fixture();
        let second = fixture();
        assert_eq!(first, second);
        let admitted = admit_executable_v1(&first, &contract()).unwrap();
        let inspected = inspect_executable_v1(&first).unwrap();
        let actual_golden = serde_json::json!({
            "schema": "ibex/single-file-executable-golden/2",
            "description": "Deterministic development-stub envelope vector for ibex/single-file-executable/2",
            "fileLength": first.len(),
            "fileDigest": digest(&first),
            "envelopeDigest": admitted.envelope_digest,
            "stubContractDigest": contract(),
            "directory": &admitted.directory,
        });
        if std::env::var_os("IBEX_UPDATE_SFE_V2_GOLDEN").is_some() {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/envelope-v2-golden.json");
            std::fs::write(&path, serde_json::to_vec_pretty(&actual_golden).unwrap()).unwrap();
            return;
        }
        let golden: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/envelope-v2-golden.json"))
                .unwrap();
        assert_eq!(actual_golden, golden);
        assert_eq!(admitted.stub_len, b"dynamic-development-stub".len());
        assert_eq!(inspected.envelope_digest, admitted.envelope_digest);
        assert_eq!(
            inspected.directory.stub_contract_digest,
            admitted.directory.stub_contract_digest
        );
        assert_eq!(admitted.directory.sections.len(), 7);
        assert_eq!(
            admitted.section("carrier-payload-0").unwrap().bytes,
            b"factory bytes"
        );
        assert_eq!(
            admitted.envelope_digest,
            digest(&first[admitted.stub_len..first.len() - FOOTER_LEN_V1])
        );
        assert_eq!(first.len() as u64, golden["fileLength"].as_u64().unwrap());
        assert_eq!(digest(&first), golden["fileDigest"].as_str().unwrap());
        assert_eq!(
            admitted.envelope_digest,
            golden["envelopeDigest"].as_str().unwrap()
        );
        assert_eq!(contract(), golden["stubContractDigest"].as_str().unwrap());
        assert_eq!(
            serde_json::to_value(&admitted.directory).unwrap(),
            golden["directory"]
        );
    }

    #[test]
    fn malformed_footer_range_digest_overlap_alignment_and_pairing_refuse() {
        let baseline = fixture();
        for mutation in [16usize, 24, 32, 40, 48, 52, 56] {
            let mut bytes = baseline.clone();
            let footer = bytes.len() - FOOTER_LEN_V1;
            bytes[footer + mutation] ^= 0x55;
            assert!(
                admit_executable_v1(&bytes, &contract()).is_err(),
                "mutation {mutation}"
            );
        }
        let mut section = baseline.clone();
        let (stub_len, offset) = {
            let admitted = admit_executable_v1(&section, &contract()).unwrap();
            (
                admitted.stub_len,
                admitted.section("carrier-payload-0").unwrap().record.offset as usize,
            )
        };
        section[stub_len + offset] ^= 1;
        assert!(matches!(
            admit_executable_v1(&section, &contract()),
            Err(Error::EnvelopeDigest)
        ));

        let entry = EntryDesignationV1::one(
            "ibex-source-id-v1:eyJkb21haW4iOiJpYmV4LXJ1bnRpbWUiLCJraW5kIjoiYnVpbHRpbiIsInNvdXJjZV9rZXkiOiJleGFjdDpmcyJ9",
        )
        .canonical_bytes()
        .unwrap();
        let incomplete = build_executable_v1(
            b"stub",
            &contract(),
            vec![
                SectionInputV1::canonical("p", SectionKindV1::ProvenanceManifest, vec![]),
                SectionInputV1::canonical("g", SectionKindV1::EmbeddedModuleGraph, vec![]),
                SectionInputV1::canonical("r", SectionKindV1::ResolvedPolicy, vec![]),
                SectionInputV1::canonical("e", SectionKindV1::EntryDesignation, entry),
                SectionInputV1::carrier("m", SectionKindV1::CarrierManifest, "pair", vec![]),
            ],
        );
        assert!(matches!(incomplete, Err(Error::Contract(_))));

        let duplicate = rewrite_directory(&baseline, |directory| {
            directory.sections[1].id = directory.sections[0].id.clone();
        });
        assert!(matches!(
            admit_executable_v1(&duplicate, &contract()),
            Err(Error::Contract(_))
        ));

        let unordered = rewrite_directory(&baseline, |directory| {
            directory.sections.swap(0, 1);
        });
        assert!(matches!(
            admit_executable_v1(&unordered, &contract()),
            Err(Error::Contract(_))
        ));

        let overlap = rewrite_directory(&baseline, |directory| {
            directory.sections[1].offset = 0;
        });
        assert!(matches!(
            admit_executable_v1(&overlap, &contract()),
            Err(Error::SectionRange(_))
        ));

        let bad_alignment = rewrite_directory(&baseline, |directory| {
            directory
                .sections
                .iter_mut()
                .find(|row| row.kind == SectionKindV1::CarrierPayload)
                .unwrap()
                .alignment = 8;
        });
        assert!(matches!(
            admit_executable_v1(&bad_alignment, &contract()),
            Err(Error::Contract(_))
        ));

        let mut nonzero_padding = baseline.clone();
        let admitted = admit_executable_v1(&nonzero_padding, &contract()).unwrap();
        let padding_index = admitted
            .directory
            .sections
            .windows(2)
            .find_map(|pair| {
                let end = pair[0].offset + pair[0].length;
                (end < pair[1].offset).then_some(admitted.stub_len + end as usize)
            })
            .expect("fixture must contain inter-section alignment padding");
        nonzero_padding[padding_index] = 1;
        let nonzero_padding = rehash_footer(nonzero_padding);
        assert!(matches!(
            admit_executable_v1(&nonzero_padding, &contract()),
            Err(Error::SectionRange(_))
        ));

        assert!(matches!(
            build_executable_v1(b"stub", &contract(), Vec::new()),
            Err(Error::Contract(_))
        ));
    }

    proptest! {
        #[test]
        fn arbitrary_single_byte_mutation_never_panics(index in 0usize..20000, value in any::<u8>()) {
            let baseline = fixture();
            let mut bytes = baseline.clone();
            let selected = index % bytes.len();
            bytes[selected] = value;
            let _ = admit_executable_v1(&bytes, &contract());
        }
    }
}
