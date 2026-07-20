//! Fail-closed build-script surface for platforms without the Unix process,
//! no-follow, ownership, and live-claim primitives required by portable macOS
//! v1. Keeping this stub lets ordinary Windows build scripts compile without
//! pretending portable authority exists there.

use std::path::PathBuf;

pub const SOURCE_REVISION_ENV: &str = "IBEX_PORTABLE_HERMES_SOURCE_REVISION";
pub const CURRENT_REVISION_ENV: &str = "IBEX_PORTABLE_HERMES_CURRENT_REVISION";
pub const PREFLIGHT_RECEIPT_ENV: &str = "IBEX_PORTABLE_HERMES_PREFLIGHT_RECEIPT";
pub const PREFLIGHT_NONCE_ENV: &str = "IBEX_PORTABLE_HERMES_PREFLIGHT_NONCE";
pub const CHECKOUT_ROOT_ENV: &str = "IBEX_PORTABLE_HERMES_CHECKOUT_ROOT";
pub const CARGO_TARGET_MAP_ENV: &str = "IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP";
pub const CARGO_TARGET_MAP_DIGEST_ENV: &str = "IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP_DIGEST";
pub const PROMOTION_ADMISSION_ENV: &str = "IBEX_PORTABLE_HERMES_PROMOTION_ADMISSION";
pub const PROMOTION_ADMISSION_DIGEST_ENV: &str = "IBEX_PORTABLE_HERMES_PROMOTION_ADMISSION_DIGEST";

#[derive(Debug, Clone)]
pub struct PortableBuildAuthorization {
    pub receipt_path: PathBuf,
    pub rustc_wrapper_path: PathBuf,
    pub cargo_target_map_path: PathBuf,
    pub promotion_admission_path: PathBuf,
    promotion_admission_bytes: Vec<u8>,
}

impl PortableBuildAuthorization {
    pub fn promotion_admission_bytes(&self) -> &[u8] {
        &self.promotion_admission_bytes
    }

    pub fn bind_consumed_authority(
        &self,
        _manifest_digest: &str,
        _installation_receipt_digest: &str,
        _verification_policy_digest: &str,
        _attestation_verification_digest: &str,
        _provenance_bundle_digest: &str,
    ) -> Result<(), String> {
        Err("portable Hermes build authorization is unavailable on this build host".to_owned())
    }

    #[cfg(test)]
    pub(crate) fn unbound_test_only() -> Self {
        Self {
            receipt_path: PathBuf::from("/test-only/unbound-preflight-receipt"),
            rustc_wrapper_path: PathBuf::from("/test-only/unbound-rustc-wrapper"),
            cargo_target_map_path: PathBuf::from("/test-only/unbound-cargo-target-map"),
            promotion_admission_path: PathBuf::from("/test-only/unbound-promotion-admission"),
            promotion_admission_bytes: b"{\"authorized\":false}\n".to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortableBuildPreflightRequest {
    pub repo_root: PathBuf,
    pub artifact_id: String,
    pub archive_digest: String,
    pub source_revision: String,
    pub current_revision: String,
    pub target_triple: String,
    pub receipt_path: PathBuf,
    pub nonce: String,
    pub selected_rustc_wrapper: PathBuf,
    pub cargo_target_map_path: PathBuf,
    pub cargo_target_map_digest: String,
    pub promotion_admission_path: PathBuf,
    pub promotion_admission_digest: String,
}

pub fn validate_portable_build_preflight(
    request: &PortableBuildPreflightRequest,
) -> Result<PortableBuildAuthorization, String> {
    let _ = request;
    Err("portable Hermes v1 build preflight is supported only on macOS/Darwin hosts".to_owned())
}
