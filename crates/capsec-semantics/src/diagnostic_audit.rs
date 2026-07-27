//! Foreground source-audit types: the diagnostic graph snapshot and the
//! diagnostic execution receipt.
//!
//! These types are deliberately sealed away from the armed/production ones.
//! A `ForegroundAuditGraphSnapshotV1` carries no authorities, denials,
//! ceilings, bootstrap floor, protected-artifact grants, target-cell
//! promotions, or policy digest, and **no conversion to `ArmedSnapshot` or
//! any production admission type exists or may be added** — the separation is
//! the security property, not a refactoring convenience. The wire projection
//! is evidence, never a credential: deserializing one does not recreate the
//! live handle (which additionally retains the opened root/source/package
//! objects), so a new audit run must recapture and reauthenticate.
//!
//! @ref LLP 0030#1-workflow-and-type-separation — the type separation this
//! module implements.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::digest::compute_domain_digest;
use crate::error::{Error, Result};
use crate::model::{Digest, NonEmptyString};

pub const DIAGNOSTIC_GRAPH_SNAPSHOT_SCHEMA_V1: &str = "ibex/diagnostic-graph-snapshot/1";
pub const DIAGNOSTIC_GRAPH_SNAPSHOT_DOMAIN_V1: &str = "ibex/diagnostic-graph-snapshot/1";
pub const DIAGNOSTIC_AUDIT_EXECUTION_RECEIPT_SCHEMA_V1: &str =
    "ibex/diagnostic-audit-execution-receipt/1";
pub const DIAGNOSTIC_AUDIT_EXECUTION_RECEIPT_DOMAIN_V1: &str =
    "ibex/diagnostic-audit-execution-receipt/1";
/// Digest domain for the diagnostic decision baseline: the canonical
/// dispositions of LLP 0030 §1's table plus the protected-object set. It is
/// never a canonical-policy digest.
pub const FOREGROUND_AUDIT_BASELINE_DOMAIN_V1: &str = "ibex/foreground-audit-baseline/1";

/// The only workflow value this projection may carry. Intentionally disjoint
/// from the historical armed `diagnostic-audit` schema arm, which is
/// decode-only for existing contract artifacts and must never be armed by new
/// code.
pub const FOREGROUND_SOURCE_AUDIT_WORKFLOW: &str = "foreground-source-audit";

/// V1 audit is inline-only: no prepared cache, no HBC, no diagnostic
/// promotion. @ref LLP 0030#5-artifact-admission
pub const DIAGNOSTIC_CARRIER_KIND_INLINE_SOURCE: &str = "inline-source";

/// The bounded would-deny stream retains this many ordered entries; the
/// stream digest covers exactly that retained suffix.
pub const WOULD_DENY_RETAINED_LIMIT: usize = 1024;

/// Identity of a retained opened object. Path text is diagnostic display
/// only — the device/inode pair is what capture authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedObjectIdentityV1 {
    pub device_id: String,
    pub inode_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_path: Option<NonEmptyString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticTargetV1 {
    pub triple: NonEmptyString,
    pub native_runner_abi: NonEmptyString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticNodeV1 {
    pub source_id: String,
    pub source_integrity: Digest,
    pub object: RetainedObjectIdentityV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticPackageV1 {
    pub kind: String,
    pub name: NonEmptyString,
    pub locator: NonEmptyString,
    pub integrity: Digest,
    pub root: RetainedObjectIdentityV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticEdgeV1 {
    pub requester: String,
    pub specifier: NonEmptyString,
    pub resolution_kind: crate::graph_snapshot::GraphResolutionKindV1,
    pub attributes: BTreeMap<String, String>,
    pub target: String,
}

/// Wire projection of the live `ForegroundAuditGraphSnapshotV1` handle.
///
/// Evidence only. Round-tripping this struct never yields execution
/// authority; the live handle's retained objects are not serializable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticGraphSnapshotV1 {
    pub schema: String,
    pub workflow: String,
    pub run_nonce: NonEmptyString,
    pub target: DiagnosticTargetV1,
    pub root: RetainedObjectIdentityV1,
    pub entry: String,
    pub graph_identity: Digest,
    pub producer_binary_digest: Digest,
    pub transform_fingerprint_digest: Digest,
    pub baseline_digest: Digest,
    pub nodes: Vec<DiagnosticNodeV1>,
    pub packages: Vec<DiagnosticPackageV1>,
    pub edges: Vec<DiagnosticEdgeV1>,
}

impl DiagnosticGraphSnapshotV1 {
    /// Validate the closed shape of a decoded projection. Fail-closed: an
    /// unexpected schema or workflow value is refused rather than coerced,
    /// so an armed snapshot's `diagnostic-audit` arm can never be read as a
    /// foreground audit graph.
    pub fn validate(&self) -> Result<()> {
        if self.schema != DIAGNOSTIC_GRAPH_SNAPSHOT_SCHEMA_V1 {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: format!(
                    "diagnostic graph snapshot schema must be {DIAGNOSTIC_GRAPH_SNAPSHOT_SCHEMA_V1}"
                ),
            });
        }
        if self.workflow != FOREGROUND_SOURCE_AUDIT_WORKFLOW {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: format!(
                    "diagnostic graph snapshot workflow must be {FOREGROUND_SOURCE_AUDIT_WORKFLOW}"
                ),
            });
        }
        if self.nodes.is_empty() {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: "diagnostic graph snapshot must retain at least one node".into(),
            });
        }
        for package in &self.packages {
            if package.kind != "package" {
                return Err(Error::InvalidCanonicalData {
                    path: "diagnostic-audit".into(),
                    message: "diagnostic graph snapshot package kind must be \"package\"".into(),
                });
            }
        }
        Ok(())
    }

    /// Digest over the projection with the baseline slot omitted — the
    /// baseline digest never covers itself.
    pub fn baseline_digest_input(&self) -> Result<String> {
        let payload = serde_json::to_value(self).map_err(|error| Error::InvalidCanonicalData {
            path: "diagnostic-audit".into(),
            message: format!("diagnostic graph snapshot is not serializable: {error}"),
        })?;
        compute_domain_digest(
            FOREGROUND_AUDIT_BASELINE_DOMAIN_V1,
            &payload,
            &["baselineDigest".to_string()],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticExecutedRecordV1 {
    pub source_id: String,
    pub semantic_digest: Digest,
    pub principal: NonEmptyString,
}

/// One relaxed final missing-authority decision. It preserves everything the
/// unrelaxed decision would have carried, so the evidence is a faithful
/// record of what production would have refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WouldDenyEntryV1 {
    pub would_deny: bool,
    pub terminal_branch: NonEmptyString,
    pub principals: Vec<NonEmptyString>,
    pub effect: NonEmptyString,
    pub resource: NonEmptyString,
    pub source_site: NonEmptyString,
    pub missing_selector: NonEmptyString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WouldDenyEvidenceV1 {
    pub observed_count: u64,
    pub retained_count: u64,
    pub dropped_count: u64,
    pub truncated: bool,
    pub stream_digest: Digest,
    pub terminal_class_totals: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<WouldDenyEntryV1>,
}

impl WouldDenyEvidenceV1 {
    /// Overflow may discard detail only by admitting it: a nonzero dropped
    /// count requires `truncated`, and vice versa. Counts must also add up,
    /// so a receipt cannot quietly under-report what it observed.
    pub fn validate(&self) -> Result<()> {
        if self.truncated != (self.dropped_count > 0) {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: "would-deny truncation flag and dropped count disagree".into(),
            });
        }
        if self.retained_count as usize > WOULD_DENY_RETAINED_LIMIT {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: format!(
                    "would-deny stream retains at most {WOULD_DENY_RETAINED_LIMIT} entries"
                ),
            });
        }
        if self.retained_count + self.dropped_count != self.observed_count {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: "would-deny retained + dropped must equal observed".into(),
            });
        }
        if !self.entries.is_empty() && self.entries.len() as u64 != self.retained_count {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: "would-deny entry count disagrees with the retained count".into(),
            });
        }
        if self.entries.iter().any(|entry| !entry.would_deny) {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: "would-deny entries must all carry wouldDeny: true".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticOutcomeKindV1 {
    Completed,
    ApplicationThrow,
    ApplicationRejection,
    LifecycleExit,
    HardRefusal,
}

/// LLP 0030 §6 failure classes, classified before any prose formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticFailureClassV1 {
    CaptureIdentity,
    Generation,
    Admission,
    HardSecurityDecision,
    Invocation,
    Execution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticOutcomeV1 {
    pub kind: DiagnosticOutcomeKindV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<DiagnosticFailureClassV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<NonEmptyString>,
}

/// The one receipt emitted at audit completion.
///
/// `diagnostic_only`/`authorizes_production` are validated constants rather
/// than caller-supplied booleans: the schema has no authority-bearing
/// variant, so a receipt can never be replayed as an authority, grant, cache
/// admission, or production receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticAuditExecutionReceiptV1 {
    pub schema: String,
    pub diagnostic_only: bool,
    pub authorizes_production: bool,
    pub run_nonce: NonEmptyString,
    pub target: DiagnosticTargetV1,
    pub entry: String,
    pub graph_identity: Digest,
    pub producer_binary_digest: Digest,
    pub transform_fingerprint_digest: Digest,
    pub loaded_engine_digest: Digest,
    pub carrier_kind: String,
    pub executed_records: Vec<DiagnosticExecutedRecordV1>,
    pub would_deny_evidence: WouldDenyEvidenceV1,
    pub outcome: DiagnosticOutcomeV1,
}

impl DiagnosticAuditExecutionReceiptV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema != DIAGNOSTIC_AUDIT_EXECUTION_RECEIPT_SCHEMA_V1 {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: format!(
                    "diagnostic receipt schema must be {DIAGNOSTIC_AUDIT_EXECUTION_RECEIPT_SCHEMA_V1}"
                ),
            });
        }
        if !self.diagnostic_only || self.authorizes_production {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: "diagnostic receipt must be diagnosticOnly and never authorize production"
                    .into(),
            });
        }
        if self.carrier_kind != DIAGNOSTIC_CARRIER_KIND_INLINE_SOURCE {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: format!(
                    "v1 audit is inline-only; carrier kind must be {DIAGNOSTIC_CARRIER_KIND_INLINE_SOURCE}"
                ),
            });
        }
        if matches!(self.outcome.kind, DiagnosticOutcomeKindV1::Completed)
            != self.outcome.failure_class.is_none()
        {
            return Err(Error::InvalidCanonicalData {
                path: "diagnostic-audit".into(),
                message: "every non-completed diagnostic outcome carries exactly one failure class"
                    .into(),
            });
        }
        self.would_deny_evidence.validate()
    }

    pub fn digest(&self) -> Result<String> {
        let payload = serde_json::to_value(self).map_err(|error| Error::InvalidCanonicalData {
            path: "diagnostic-audit".into(),
            message: format!("diagnostic receipt is not serializable: {error}"),
        })?;
        compute_domain_digest(DIAGNOSTIC_AUDIT_EXECUTION_RECEIPT_DOMAIN_V1, &payload, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest {
        let raw = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            [byte; 32],
        );
        Digest::new(format!("sha256-{raw}")).expect("test digest")
    }

    fn non_empty(value: &str) -> NonEmptyString {
        NonEmptyString::new(value).expect("test string")
    }

    fn object() -> RetainedObjectIdentityV1 {
        RetainedObjectIdentityV1 {
            device_id: "16777232".into(),
            inode_id: "421337".into(),
            display_path: Some(non_empty("/project")),
        }
    }

    fn snapshot() -> DiagnosticGraphSnapshotV1 {
        DiagnosticGraphSnapshotV1 {
            schema: DIAGNOSTIC_GRAPH_SNAPSHOT_SCHEMA_V1.into(),
            workflow: FOREGROUND_SOURCE_AUDIT_WORKFLOW.into(),
            run_nonce: non_empty("K5s7yqhs3Ttq2Yv1v0hE0Q"),
            target: DiagnosticTargetV1 {
                triple: non_empty("aarch64-apple-darwin"),
                native_runner_abi: non_empty("ibex/module-runner/1"),
            },
            root: object(),
            entry: "ibex-source-id-v1:entry".into(),
            graph_identity: digest(1),
            producer_binary_digest: digest(2),
            transform_fingerprint_digest: digest(3),
            baseline_digest: digest(4),
            nodes: vec![DiagnosticNodeV1 {
                source_id: "ibex-source-id-v1:entry".into(),
                source_integrity: digest(5),
                object: object(),
            }],
            packages: Vec::new(),
            edges: Vec::new(),
        }
    }

    fn evidence() -> WouldDenyEvidenceV1 {
        WouldDenyEvidenceV1 {
            observed_count: 0,
            retained_count: 0,
            dropped_count: 0,
            truncated: false,
            stream_digest: digest(6),
            terminal_class_totals: BTreeMap::new(),
            entries: Vec::new(),
        }
    }

    fn receipt() -> DiagnosticAuditExecutionReceiptV1 {
        DiagnosticAuditExecutionReceiptV1 {
            schema: DIAGNOSTIC_AUDIT_EXECUTION_RECEIPT_SCHEMA_V1.into(),
            diagnostic_only: true,
            authorizes_production: false,
            run_nonce: non_empty("K5s7yqhs3Ttq2Yv1v0hE0Q"),
            target: DiagnosticTargetV1 {
                triple: non_empty("aarch64-apple-darwin"),
                native_runner_abi: non_empty("ibex/module-runner/1"),
            },
            entry: "ibex-source-id-v1:entry".into(),
            graph_identity: digest(1),
            producer_binary_digest: digest(2),
            transform_fingerprint_digest: digest(3),
            loaded_engine_digest: digest(7),
            carrier_kind: DIAGNOSTIC_CARRIER_KIND_INLINE_SOURCE.into(),
            executed_records: Vec::new(),
            would_deny_evidence: evidence(),
            outcome: DiagnosticOutcomeV1 {
                kind: DiagnosticOutcomeKindV1::Completed,
                failure_class: None,
                lifecycle_exit_code: None,
                detail: None,
            },
        }
    }

    #[test]
    fn canonical_snapshot_and_receipt_validate_and_round_trip() {
        let snapshot = snapshot();
        snapshot.validate().expect("canonical snapshot validates");
        let encoded = serde_json::to_string(&snapshot).unwrap();
        let decoded: DiagnosticGraphSnapshotV1 = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, snapshot);

        let receipt = receipt();
        receipt.validate().expect("canonical receipt validates");
        let encoded = serde_json::to_string(&receipt).unwrap();
        let decoded: DiagnosticAuditExecutionReceiptV1 = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn armed_workflow_values_are_refused() {
        for workflow in ["diagnostic-audit", "production-enforce", "contract-fixture"] {
            let mut mutated = snapshot();
            mutated.workflow = workflow.into();
            assert!(
                mutated.validate().is_err(),
                "{workflow} must not decode as a foreground audit graph"
            );
        }
    }

    #[test]
    fn baseline_digest_excludes_its_own_slot() {
        let first = snapshot();
        let mut second = snapshot();
        second.baseline_digest = digest(9);
        assert_eq!(
            first.baseline_digest_input().unwrap(),
            second.baseline_digest_input().unwrap(),
            "the baseline digest must not cover the slot that carries it"
        );

        let mut third = snapshot();
        third.entry = "ibex-source-id-v1:other".into();
        assert_ne!(
            first.baseline_digest_input().unwrap(),
            third.baseline_digest_input().unwrap(),
            "the baseline digest must cover the rest of the projection"
        );
    }

    #[test]
    fn receipts_cannot_claim_production_authority() {
        let mut authority = receipt();
        authority.authorizes_production = true;
        assert!(authority.validate().is_err());

        let mut not_diagnostic = receipt();
        not_diagnostic.diagnostic_only = false;
        assert!(not_diagnostic.validate().is_err());
    }

    #[test]
    fn prepared_and_hbc_carriers_refuse_in_v1() {
        for carrier in ["prepared-graph", "hbc", "module-carrier/2"] {
            let mut mutated = receipt();
            mutated.carrier_kind = carrier.into();
            assert!(mutated.validate().is_err(), "{carrier} must refuse in v1");
        }
    }

    #[test]
    fn overflow_must_be_admitted_and_counts_must_reconcile() {
        let mut silent_drop = receipt();
        silent_drop.would_deny_evidence.observed_count = 5;
        silent_drop.would_deny_evidence.dropped_count = 5;
        silent_drop.would_deny_evidence.truncated = false;
        assert!(silent_drop.validate().is_err(), "silent truncation refused");

        let mut mismatched = receipt();
        mismatched.would_deny_evidence.observed_count = 9;
        mismatched.would_deny_evidence.retained_count = 3;
        mismatched.would_deny_evidence.dropped_count = 3;
        mismatched.would_deny_evidence.truncated = true;
        assert!(mismatched.validate().is_err(), "counts must reconcile");

        let mut over_limit = receipt();
        over_limit.would_deny_evidence.observed_count = 2048;
        over_limit.would_deny_evidence.retained_count = 2048;
        over_limit.would_deny_evidence.dropped_count = 0;
        assert!(over_limit.validate().is_err(), "retention bound enforced");
    }

    #[test]
    fn failure_outcomes_require_a_failure_class() {
        let mut unclassified = receipt();
        unclassified.outcome.kind = DiagnosticOutcomeKindV1::HardRefusal;
        assert!(unclassified.validate().is_err());

        let mut classified = receipt();
        classified.outcome.kind = DiagnosticOutcomeKindV1::HardRefusal;
        classified.outcome.failure_class = Some(DiagnosticFailureClassV1::CaptureIdentity);
        classified.validate().expect("classified failure validates");

        let mut completed_with_class = receipt();
        completed_with_class.outcome.failure_class = Some(DiagnosticFailureClassV1::Execution);
        assert!(completed_with_class.validate().is_err());
    }
}
