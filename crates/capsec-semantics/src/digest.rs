//! Domain-separated semantic digests.

use crate::canonical::{canonicalize, to_jcs_bytes, DigestContract, DigestProjection};
use crate::error::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub const VOCABULARY_DOMAIN: &str = "ibex:capsec:vocab:1";
pub const REGISTRY_DOMAIN: &str = "ibex:capsec:registry:1";
pub const POLICY_DOMAIN: &str = "ibex:capsec:policy:1";
pub const ARMED_SNAPSHOT_DOMAIN: &str = "ibex:capsec:armed:1";
pub const CONFORMANCE_DOMAIN: &str = "ibex:capsec:conformance:1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestKind {
    Vocabulary,
    Registry,
    Policy,
    ArmedSnapshot,
    Conformance,
}

/// Compute `SHA-256(UTF8(domain) || NUL || JCS(projected payload))`.
///
/// This low-level operation assumes schema-declared semantic sets have already
/// been normalized. Production callers should use [`compute_contract_digest`].
pub fn compute_domain_digest(
    domain: &str,
    payload: &Value,
    omit_fields: &[String],
) -> Result<String> {
    if domain.is_empty() || domain.as_bytes().contains(&0) {
        return Err(Error::InvalidCanonicalData {
            path: "domain".into(),
            message: "digest domain must be non-empty and contain no NUL".into(),
        });
    }
    let projected = project_payload(payload, omit_fields)?;
    let canonical = to_jcs_bytes(&projected)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    Ok(format!(
        "sha256-{}",
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    ))
}

/// Compute one of the frozen profile digests using the corresponding domain
/// and omission projection supplied by the checked digest contract.
pub fn compute_contract_digest(
    kind: DigestKind,
    payload: &Value,
    contract: &DigestContract,
) -> Result<String> {
    let (domain, projection) = contract_parts(kind, contract);
    validate_frozen_projection(kind, domain, projection)?;
    validate_payload_schema(kind, payload, &projection.input_schema)?;
    let projected = project_payload(payload, &projection.omit_fields)?;
    let canonical = canonicalize(&projected, Some(&projection.input_schema), contract)?;
    compute_domain_digest(domain, &canonical, &[])
}

fn validate_payload_schema(kind: DigestKind, payload: &Value, expected: &str) -> Result<()> {
    let field = match kind {
        DigestKind::Vocabulary | DigestKind::Registry => "bundleSchema",
        DigestKind::Policy => "policySchema",
        DigestKind::ArmedSnapshot => "snapshotSchema",
        DigestKind::Conformance => "conformanceSchema",
    };
    if payload.get(field).and_then(Value::as_str) != Some(expected) {
        return Err(Error::InvalidCanonicalData {
            path: format!("$/{field}"),
            message: format!("payload is not the frozen {expected} schema"),
        });
    }
    Ok(())
}

fn project_payload(payload: &Value, omit_fields: &[String]) -> Result<Value> {
    let mut projected = payload.clone();
    if omit_fields.is_empty() {
        return Ok(projected);
    }
    let object = projected
        .as_object_mut()
        .ok_or_else(|| Error::InvalidCanonicalData {
            path: "$".into(),
            message: "a digest projection with omitted fields requires an object payload".into(),
        })?;
    for field in omit_fields {
        object.remove(field);
    }
    Ok(projected)
}

fn contract_parts(kind: DigestKind, contract: &DigestContract) -> (&str, &DigestProjection) {
    match kind {
        DigestKind::Vocabulary => (
            &contract.domains.vocabulary,
            &contract.projections.vocabulary,
        ),
        DigestKind::Registry => (&contract.domains.registry, &contract.projections.registry),
        DigestKind::Policy => (&contract.domains.policy, &contract.projections.policy),
        DigestKind::ArmedSnapshot => (
            &contract.domains.armed_snapshot,
            &contract.projections.armed_snapshot,
        ),
        DigestKind::Conformance => (
            &contract.domains.conformance,
            &contract.projections.conformance,
        ),
    }
}

fn validate_frozen_projection(
    kind: DigestKind,
    actual_domain: &str,
    projection: &DigestProjection,
) -> Result<()> {
    let (expected_domain, expected_schema, expected_omissions): (&str, &str, &[&str]) = match kind {
        DigestKind::Vocabulary => (VOCABULARY_DOMAIN, "ibex/capsec-digest-bundle/1", &[]),
        DigestKind::Registry => (REGISTRY_DOMAIN, "ibex/capsec-digest-bundle/1", &[]),
        DigestKind::Policy => (POLICY_DOMAIN, "ibex/capsec-policy/1", &["policyDigest"]),
        DigestKind::ArmedSnapshot => (
            ARMED_SNAPSHOT_DOMAIN,
            "ibex/capsec-armed/1",
            &["armedSnapshotDigest"],
        ),
        DigestKind::Conformance => (
            CONFORMANCE_DOMAIN,
            "ibex/capsec-conformance/1",
            &["conformanceDigest"],
        ),
    };
    if actual_domain != expected_domain
        || projection.input_schema != expected_schema
        || projection
            .omit_fields
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_omissions
    {
        return Err(Error::InvalidCanonicalData {
            path: "digestContract.projections".into(),
            message: format!("{kind:?} domain or omission projection is not frozen contract"),
        });
    }
    Ok(())
}
