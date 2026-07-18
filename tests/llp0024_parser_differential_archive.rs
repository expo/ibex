use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

const REPORT: &str = "llp/evidence/0024-parser-differential-3fe06fe530d01655be8abf390ff65c05d66dd34b2ecdc0d63017e9cce88dd29a.json";
const PROJECTION: &str = "config/llp0024-parser-differential-projection.json";
const CORPUS: &str = "tests/fixtures/llp0024-parser-differential/corpus.json";

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn archived_parser_differential_is_content_addressed_and_fail_closed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let report_bytes = std::fs::read(root.join(REPORT)).unwrap();
    assert!(
        REPORT.contains(&digest(&report_bytes)),
        "report filename must contain its exact SHA-256"
    );
    let report: Value = serde_json::from_slice(&report_bytes).unwrap();
    assert_eq!(
        report["projectionDigest"],
        digest(&std::fs::read(root.join(PROJECTION)).unwrap())
    );
    assert_eq!(
        report["corpusDigest"],
        digest(&std::fs::read(root.join(CORPUS)).unwrap())
    );
    assert_eq!(report["summary"]["total"], 536);
    assert_eq!(report["summary"]["corpusCases"], 24);
    assert_eq!(report["summary"]["nodeModulesFiles"], 256);

    let cases = report["cases"].as_array().unwrap();
    assert!(cases
        .iter()
        .all(|case| { case["swc"]["outcome"] == case["oxc"]["outcome"] }));
    let divergences = cases
        .iter()
        .filter(|case| case["equivalent"] == false)
        .collect::<Vec<_>>();
    assert_eq!(divergences.len(), 5);
    assert!(divergences.iter().all(|case| {
        case["swc"]["outcome"] == "diagnostic"
            && case["oxc"]["outcome"] == "diagnostic"
            && case["swc"]["astAvailable"] == false
            && case["oxc"]["astAvailable"] == true
    }));
}
