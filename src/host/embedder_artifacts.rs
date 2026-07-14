//! Public production-artifact preparation for native embedders.
//!
//! The caller supplies a paired authenticated snapshot template and expected
//! identity. This module binds the pair to the actually loaded engine and the
//! checked CapSec identities, validates protected files/package roots, replaces
//! the template nonce with OS randomness, and returns a new paired artifact.
//! Target advertisement remains enforced by `Host::new_armed` during install;
//! preparing bytes never promotes an unsupported target.
//! @ref LLP 0021#wp4--arm-immutable-snapshots-through-the-cli-host-and-engine

use anyhow::{Context as _, Result};
use base64::Engine as _;
use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
use capsec_semantics::digest::{compute_checked_contract_digest, DigestKind};
use capsec_semantics::model::Digest;

const PRODUCTION_RUN_NONCE_BYTES: usize = 16;
const CONTRACT_FIXTURE_RUN_NONCE: &str = "AQIDBAUGBwgJCgsMDQ4PEA";

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedEmbedderArtifacts {
    pub artifact_schema: &'static str,
    pub armed_snapshot_digest: String,
    pub snapshot: serde_json::Value,
    pub expected_identity: ExpectedArmingIdentity,
}

fn runtime_target_triple() -> String {
    let architecture = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        "x86" => "i686",
        other => other,
    };
    let suffix = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "ios" => "apple-ios",
        "linux" => "unknown-linux-gnu",
        "android" => "linux-android",
        "windows" => "pc-windows-msvc",
        other => other,
    };
    format!("{architecture}-{suffix}")
}

fn checked_identity_digests() -> Result<(Digest, Digest)> {
    let checked: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/armed-snapshot.canonical.json"
    )))?;
    let digest_at = |field: &str| -> Result<Digest> {
        Digest::new(
            checked[field]
                .as_str()
                .with_context(|| format!("checked CapSec identity lacks {field}"))?,
        )
        .map_err(anyhow::Error::msg)
    };
    Ok((digest_at("vocabDigest")?, digest_at("registryDigest")?))
}

pub fn verify_expected_identity(
    supplied: ExpectedArmingIdentity,
) -> Result<ExpectedArmingIdentity> {
    let (vocab_digest, registry_digest) = checked_identity_digests()?;
    let engine = crate::engine::loaded_engine_binary_identity().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        supplied.profile == crate::capsec_registry_generated::CAPSEC_PROFILE,
        "expected identity profile does not match the checked Ibex profile"
    );
    anyhow::ensure!(
        supplied.semantic_core == crate::capsec_registry_generated::CAPSEC_SEMANTIC_CORE,
        "expected identity semantic core does not match the checked Ibex core"
    );
    anyhow::ensure!(
        supplied.vocab_digest == vocab_digest,
        "expected identity vocabulary digest does not match the checked vocabulary"
    );
    anyhow::ensure!(
        supplied.registry_digest == registry_digest,
        "expected identity registry digest does not match the checked registry"
    );
    anyhow::ensure!(
        supplied.target == runtime_target_triple(),
        "expected identity target does not match the running embedder"
    );
    anyhow::ensure!(
        supplied.features == engine.structural_features,
        "expected identity feature set does not match the loaded engine"
    );
    anyhow::ensure!(
        supplied.engine_binary_digest
            == Digest::new(engine.binary_digest).map_err(anyhow::Error::msg)?,
        "expected identity engine digest does not match the loaded engine"
    );
    Ok(supplied)
}

fn fresh_production_nonce() -> Result<String> {
    let mut bytes = [0_u8; PRODUCTION_RUN_NONCE_BYTES];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| anyhow::anyhow!("OS randomness unavailable for run nonce: {error}"))?;
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    anyhow::ensure!(
        nonce != CONTRACT_FIXTURE_RUN_NONCE,
        "OS randomness produced the reserved contract-fixture run nonce"
    );
    Ok(nonce)
}

fn freshen_document(document: &mut serde_json::Value, nonce: String) -> Result<Digest> {
    document["runNonce"] = serde_json::Value::String(nonce);
    let digest = compute_checked_contract_digest(DigestKind::ArmedSnapshot, document)?;
    document["armedSnapshotDigest"] = serde_json::Value::String(digest.clone());
    Digest::new(digest).map_err(anyhow::Error::msg)
}

/// Authenticate, bind, and freshen one embedder artifact pair.
///
/// This validates everything that can be established before installation,
/// including the exact mapped engine object, checked semantic identities,
/// protected artifact bytes, package graph/root bindings, and a construction-
/// fresh nonce. `Host::new_armed` subsequently authenticates the report-derived
/// target advertisement; unsupported targets still refuse there.
pub fn prepare_embedder_artifacts(
    template_bytes: &[u8],
    expected_identity_bytes: &[u8],
) -> Result<PreparedEmbedderArtifacts> {
    super::reject_closed_startup_environment()?;
    let expected_text = std::str::from_utf8(expected_identity_bytes)
        .context("expected arming identity is not UTF-8")?;
    let expected_value = capsec_semantics::strict_json::parse_strict(expected_text)
        .context("expected arming identity is not strict JSON")?;
    let supplied: ExpectedArmingIdentity =
        serde_json::from_value(expected_value).context("invalid expected arming identity")?;
    let mut expected = verify_expected_identity(supplied)?;

    // Authenticate the caller's pair before mutating the nonce or digest. A
    // wrong target/engine/registry/graph/identity cannot be rewritten into a
    // valid artifact by this API.
    let template = ArmedSnapshot::load(template_bytes, &expected)
        .context("snapshot template authentication refused")?;
    super::validate_loaded_engine_identity(&template)?;
    super::validate_snapshot_protected_artifacts(&template)?;
    super::validate_snapshot_root_bindings(&template)?;

    let mut document = template.document().clone();
    let digest = freshen_document(&mut document, fresh_production_nonce()?)?;
    expected.armed_snapshot_digest = digest.clone();

    // Re-ingest the freshly serialized pair before returning it. This catches
    // any mismatch between the digest projection and the public output shape.
    let fresh_bytes = serde_json::to_vec(&document)?;
    let fresh = ArmedSnapshot::load(&fresh_bytes, &expected)
        .context("freshened snapshot authentication refused")?;
    super::validate_loaded_engine_identity(&fresh)?;
    super::validate_snapshot_protected_artifacts(&fresh)?;
    super::validate_snapshot_root_bindings(&fresh)?;

    Ok(PreparedEmbedderArtifacts {
        artifact_schema: "ibex/armed-embedder-artifacts/1",
        armed_snapshot_digest: digest.as_str().to_owned(),
        snapshot: document,
        expected_identity: expected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_for_static_verification() -> ExpectedArmingIdentity {
        let checked: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        let digest = |path: &[&str]| {
            let value = path
                .iter()
                .fold(&checked, |current, segment| &current[*segment]);
            Digest::new(value.as_str().unwrap()).unwrap()
        };
        let engine = crate::engine::loaded_engine_binary_identity().unwrap();
        ExpectedArmingIdentity {
            profile: checked["capsVocab"].as_str().unwrap().into(),
            semantic_core: checked["semanticCore"].as_str().unwrap().into(),
            vocab_digest: digest(&["vocabDigest"]),
            registry_digest: digest(&["registryDigest"]),
            policy_digest: digest(&["policyDigest"]),
            armed_snapshot_digest: digest(&["armedSnapshotDigest"]),
            target: runtime_target_triple(),
            engine_binary_digest: Digest::new(engine.binary_digest).unwrap(),
            features: engine.structural_features,
            package_graph_digest: digest(&["packageGraph", "digest"]),
            protected_artifacts: Vec::new(),
        }
    }

    #[test]
    fn expected_identity_verification_refuses_wrong_target_and_registry() {
        let expected = expected_for_static_verification();
        assert_eq!(
            verify_expected_identity(expected.clone()).unwrap(),
            expected
        );

        let mut wrong_target = expected.clone();
        wrong_target.target = if runtime_target_triple() == "x86_64-unknown-linux-gnu" {
            "aarch64-apple-darwin"
        } else {
            "x86_64-unknown-linux-gnu"
        }
        .into();
        assert!(verify_expected_identity(wrong_target)
            .unwrap_err()
            .to_string()
            .contains("target does not match"));

        let mut wrong_registry = expected;
        wrong_registry.registry_digest =
            Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert!(verify_expected_identity(wrong_registry)
            .unwrap_err()
            .to_string()
            .contains("registry digest does not match"));
    }

    #[test]
    fn freshening_replaces_reserved_nonce_and_is_replay_distinct() {
        let source = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        ));
        let original: serde_json::Value = serde_json::from_slice(source).unwrap();
        let mut first = original.clone();
        let mut second = original;
        let first_digest = freshen_document(&mut first, fresh_production_nonce().unwrap()).unwrap();
        let second_digest =
            freshen_document(&mut second, fresh_production_nonce().unwrap()).unwrap();
        assert_ne!(first["runNonce"], CONTRACT_FIXTURE_RUN_NONCE);
        assert_ne!(second["runNonce"], CONTRACT_FIXTURE_RUN_NONCE);
        assert_ne!(first["runNonce"], second["runNonce"]);
        assert_ne!(first_digest, second_digest);
    }

    #[test]
    fn freshening_binds_nonce_into_checked_digest() {
        let source = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        ));
        let mut document: serde_json::Value = serde_json::from_slice(source).unwrap();
        let digest = freshen_document(&mut document, "EREREREREREREREREREREQ".to_owned()).unwrap();
        assert_eq!(document["armedSnapshotDigest"], digest.as_str());
        assert_eq!(
            compute_checked_contract_digest(DigestKind::ArmedSnapshot, &document).unwrap(),
            digest.as_str()
        );
    }
}
