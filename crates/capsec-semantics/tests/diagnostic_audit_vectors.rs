//! Drive the shared diagnostic-audit vectors through the Rust types, so the
//! vector files are executable evidence rather than documentation.
//!
//! @ref LLP 0030#1-workflow-and-type-separation

use std::path::{Path, PathBuf};

use capsec_semantics::diagnostic_audit::{
    DiagnosticAuditExecutionReceiptV1, DiagnosticGraphSnapshotV1, WouldDenyEvidenceV1,
};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/vectors")
}

fn read(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!("read vector {}: {error}", path.display());
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!("parse vector {}: {error}", path.display());
    })
}

/// Apply `mutation` at `mutationPath` ("" = document root, dotted segments
/// with an optional `[index]` suffix elsewhere).
fn apply_mutation(document: &mut Value, path: &str, mutation: &Value) {
    let mut cursor = document;
    if !path.is_empty() {
        for segment in path.split('.') {
            let (key, index) = match segment.split_once('[') {
                Some((key, rest)) => {
                    let index: usize = rest
                        .trim_end_matches(']')
                        .parse()
                        .expect("vector mutation index is a number");
                    (key, Some(index))
                }
                None => (segment, None),
            };
            cursor = cursor.get_mut(key).expect("vector mutation path exists");
            if let Some(index) = index {
                cursor = cursor.get_mut(index).expect("vector mutation index exists");
            }
        }
    }
    let object = cursor
        .as_object_mut()
        .expect("mutation target is an object");
    for (key, value) in mutation.as_object().expect("mutation is an object") {
        object.insert(key.clone(), value.clone());
    }
}

/// Decode + validate; either step failing is a refusal, which is what the
/// invalid vectors assert. Both paths must be fail-closed.
fn accepts(document_name: &str, document: &Value) -> bool {
    match document_name {
        "graphSnapshot" => serde_json::from_value::<DiagnosticGraphSnapshotV1>(document.clone())
            .is_ok_and(|decoded| decoded.validate().is_ok()),
        "executionReceipt" => {
            serde_json::from_value::<DiagnosticAuditExecutionReceiptV1>(document.clone())
                .is_ok_and(|decoded| decoded.validate().is_ok())
        }
        other => panic!("unknown vector document {other}"),
    }
}

#[test]
fn valid_vectors_decode_and_validate() {
    let vectors = read("diagnostic-audit-v1.valid.json");
    let documents = &vectors["documents"];

    let snapshot: DiagnosticGraphSnapshotV1 =
        serde_json::from_value(documents["graphSnapshot"].clone())
            .expect("canonical graph snapshot decodes");
    snapshot
        .validate()
        .expect("canonical graph snapshot validates");

    let receipt: DiagnosticAuditExecutionReceiptV1 =
        serde_json::from_value(documents["executionReceipt"].clone())
            .expect("canonical receipt decodes");
    receipt.validate().expect("canonical receipt validates");

    // A truncated stream is valid precisely when it admits the overflow.
    let truncated: WouldDenyEvidenceV1 =
        serde_json::from_value(documents["truncatedReceiptEvidence"].clone())
            .expect("truncated evidence decodes");
    truncated
        .validate()
        .expect("admitted truncation is a valid stream");

    // Serialized forms round-trip through the canonical projection.
    let reencoded = serde_json::to_value(&snapshot).expect("snapshot re-encodes");
    assert_eq!(reencoded, documents["graphSnapshot"]);
    let reencoded = serde_json::to_value(&receipt).expect("receipt re-encodes");
    assert_eq!(reencoded, documents["executionReceipt"]);
}

#[test]
fn every_invalid_vector_is_refused() {
    let valid = read("diagnostic-audit-v1.valid.json");
    let mutations = read("diagnostic-audit-v1.invalid.json");
    let cases = mutations["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty(), "the mutation corpus must not be empty");

    for case in cases {
        let id = case["id"].as_str().expect("case id");
        let document_name = case["document"].as_str().expect("case document");
        let mut document = valid["documents"][document_name].clone();
        assert!(
            !document.is_null(),
            "{id}: names an unknown document {document_name}"
        );
        assert!(
            accepts(document_name, &document),
            "{id}: the unmutated document must be accepted, or the case proves nothing"
        );

        let path = case["mutationPath"].as_str().unwrap_or("");
        apply_mutation(&mut document, path, &case["mutation"]);
        assert_eq!(
            case["expected"].as_str(),
            Some("invalid"),
            "{id}: this corpus holds only refusal cases"
        );
        assert!(
            !accepts(document_name, &document),
            "{id}: mutation was accepted but must be refused ({})",
            case["why"].as_str().unwrap_or("no rationale recorded")
        );
    }
}
