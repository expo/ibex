//! Native Tier-3 disposition completeness plus real-binary source/prepared
//! execution receipts for every corpus row currently admitted to Hermes.
//!
//! @ref LLP 0019#tier-3-the-rustoxc-module-artifact-producer — corpus rows may
//! execute only as a named native pass or a stable typed quarantine.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use ibex_runtime::module_loader::artifact::{source_integrity, ModuleArtifactV1};
use ibex_runtime::module_loader::compatibility::LegacyModuleRunnerRequirementKind;
use ibex_runtime::module_loader::identity::SourceId;
use ibex_runtime::module_loader::producer_spike::{
    produce_module_artifact_v1, produce_spike_artifact, unsupported_module_runner_reason,
};
use serde::Deserialize;

#[cfg(any(
    all(
        feature = "capsec-conformance-observer",
        target_os = "macos",
        target_arch = "aarch64"
    ),
    all(
        feature = "capsec-conformance-observer",
        target_os = "linux",
        target_arch = "x86_64"
    )
))]
const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Mapping {
    schema: String,
    cases: Vec<MappingRow>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MappingRow {
    kind: String,
    id: String,
    disposition: String,
    stable_code: Option<String>,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct CorpusRow {
    kind: String,
    id: String,
    source: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TargetMatrix {
    schema: String,
    profiles: Vec<String>,
    rows: Vec<TargetMatrixRow>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TargetMatrixRow {
    id: String,
    family: String,
    source: String,
    extension: Option<String>,
    disposition: String,
    expected_output: Option<String>,
    stable_code: Option<String>,
    reason: Option<String>,
    required_pass: Option<String>,
    source_map_expectation: Option<String>,
    blocked_by: Option<String>,
    current_stable_code: Option<String>,
    current_reason: Option<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn node() -> &'static str {
    for candidate in ["node", "bun"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return candidate;
        }
    }
    panic!("native Tier-3 conformance requires node or bun");
}

fn corpus_rows() -> Vec<CorpusRow> {
    let expression = r#"
import {forOfScopingCorpus, asyncGeneratorCorpus} from './packages/ibex-devtools/src/scripts/hermes-compat-corpus.mjs';
console.log(JSON.stringify([
  ...forOfScopingCorpus.map(({id, source}) => ({kind:'for-of', id, source})),
  ...asyncGeneratorCorpus.map(({id, source}) => ({kind:'async-generator', id, source})),
]));
"#;
    let output = Command::new(node())
        .args(["--input-type=module", "-e", expression])
        .current_dir(repo_root())
        .output()
        .expect("read LLP 0019 corpus through its owning JS module");
    assert!(
        output.status.success(),
        "cannot load LLP 0019 corpus: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("corpus projection must be JSON")
}

fn quarantine_reason(kind: &LegacyModuleRunnerRequirementKind) -> Option<&'static str> {
    match kind {
        LegacyModuleRunnerRequirementKind::Tier3ForOf(reason) => Some(reason.as_str()),
        LegacyModuleRunnerRequirementKind::HermesSyntax(reason) => Some(reason.as_str()),
        _ => None,
    }
}

fn produce_target_matrix_row(row: &TargetMatrixRow) -> anyhow::Result<ModuleArtifactV1> {
    let extension = row.extension.as_deref().unwrap_or("mjs");
    let source_name = format!("entry.{extension}");
    produce_module_artifact_v1(
        SourceId::synthetic("llp0019-hermes-target-matrix", &row.id).unwrap(),
        &source_name,
        Path::new(&source_name),
        &row.source,
        source_integrity(b"llp0019-hermes-target-matrix-producer").unwrap(),
    )
}

#[test]
fn hermes_target_matrix_is_exhaustive_and_matches_the_producer_contract() {
    let matrix: TargetMatrix = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/llp0019-hermes-target-matrix.json"
    )))
    .unwrap();
    assert_eq!(matrix.schema, "ibex/llp0019-hermes-target-matrix/1");
    assert_eq!(matrix.profiles, ["source", "prepared"]);
    let expected_families = [
        "async-generator",
        "bigint",
        "decorators",
        "explicit-resource-management",
        "for-await",
        "for-of",
        "source-maps",
    ];
    let families = matrix
        .rows
        .iter()
        .map(|row| row.family.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(families.into_iter().collect::<Vec<_>>(), expected_families);

    for row in &matrix.rows {
        let produced = produce_target_matrix_row(row);
        match row.disposition.as_str() {
            "pass" => {
                let artifact = produced.unwrap_or_else(|error| {
                    panic!("target-matrix row {} no longer passes: {error:#}", row.id)
                });
                assert!(row.expected_output.is_some(), "{} lacks an oracle", row.id);
                assert!(row.stable_code.is_none() && row.reason.is_none());
                if let Some(required_pass) = row.required_pass.as_deref() {
                    let extension = row.extension.as_deref().unwrap_or("mjs");
                    let source_name = format!("entry.{extension}");
                    let spike = produce_spike_artifact(
                        &row.id,
                        &source_name,
                        Path::new(&source_name),
                        &row.source,
                    )
                    .unwrap();
                    assert!(
                        spike
                            .hermes_compat_passes
                            .iter()
                            .any(|pass| pass == required_pass),
                        "{} did not run {required_pass}",
                        row.id
                    );
                }
                if row.source_map_expectation.as_deref()
                    == Some("v3-source-id-bound-nonempty-mappings")
                {
                    let map = &artifact.semantics.source_map;
                    assert_eq!(map.version, 3);
                    assert_eq!(map.source_ids.len(), 1);
                    assert_eq!(map.source_ids[0], artifact.semantics.source_id);
                    assert!(!map.mappings.is_empty());
                }
            }
            "quarantine" => {
                let error = produced.unwrap_err();
                let requirement = unsupported_module_runner_reason(&error)
                    .unwrap_or_else(|| panic!("{} has no typed quarantine: {error:#}", row.id));
                assert_eq!(
                    Some(requirement.kind.stable_code()),
                    row.stable_code.as_deref(),
                    "{} stable code drifted",
                    row.id
                );
                assert_eq!(
                    quarantine_reason(&requirement.kind),
                    row.reason.as_deref(),
                    "{} quarantine reason drifted",
                    row.id
                );
            }
            "blocked-on-decision" => {
                assert_eq!(
                    row.blocked_by.as_deref(),
                    Some("LLP 0028 author-decision register item 4")
                );
                let error = produced.unwrap_err();
                let requirement = unsupported_module_runner_reason(&error).unwrap_or_else(|| {
                    panic!(
                        "{} current behavior has no typed quarantine: {error:#}",
                        row.id
                    )
                });
                assert_eq!(
                    Some(requirement.kind.stable_code()),
                    row.current_stable_code.as_deref()
                );
                assert_eq!(
                    quarantine_reason(&requirement.kind),
                    row.current_reason.as_deref()
                );
            }
            other => panic!("unknown target-matrix disposition {other:?}"),
        }
    }
}

#[test]
fn native_tier3_mapping_is_complete_and_matches_the_producer() {
    let mapping: Mapping = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/llp0019-native-tier3-corpus.json"
    )))
    .unwrap();
    assert_eq!(mapping.schema, "ibex/llp0019-native-tier3-corpus/1");
    let mapped = mapping
        .cases
        .iter()
        .map(|row| ((row.kind.as_str(), row.id.as_str()), row))
        .collect::<BTreeMap<_, _>>();
    let corpus = corpus_rows();
    assert_eq!(
        mapped.len(),
        corpus.len(),
        "mapping has extra or missing rows"
    );

    for row in corpus {
        let expected = mapped
            .get(&(row.kind.as_str(), row.id.as_str()))
            .unwrap_or_else(|| panic!("missing mapping for {}:{}", row.kind, row.id));
        let produced: anyhow::Result<ModuleArtifactV1> = produce_module_artifact_v1(
            SourceId::synthetic("llp0019-native-corpus", &row.id).unwrap(),
            &format!("{}.mjs", row.id),
            Path::new("entry.mjs"),
            &row.source,
            source_integrity(b"native-tier3-conformance-producer").unwrap(),
        );
        match expected.disposition.as_str() {
            "pass" => {
                produced.unwrap_or_else(|error| {
                    panic!(
                        "{}:{} no longer passes natively: {error:#}",
                        row.kind, row.id
                    )
                });
                assert!(expected.stable_code.is_none() && expected.reason.is_none());
            }
            "quarantine" => {
                let error = produced.unwrap_err();
                let requirement = unsupported_module_runner_reason(&error).unwrap_or_else(|| {
                    panic!("{}:{} has no typed quarantine: {error:#}", row.kind, row.id)
                });
                assert_eq!(
                    Some(requirement.kind.stable_code()),
                    expected.stable_code.as_deref(),
                    "{}:{} stable code drifted",
                    row.kind,
                    row.id
                );
                assert_eq!(
                    quarantine_reason(&requirement.kind),
                    expected.reason.as_deref(),
                    "{}:{} quarantine reason drifted",
                    row.kind,
                    row.id
                );
            }
            other => panic!("unknown disposition {other:?}"),
        }
    }
}

#[cfg(any(
    all(
        feature = "capsec-conformance-observer",
        target_os = "macos",
        target_arch = "aarch64"
    ),
    all(
        feature = "capsec-conformance-observer",
        target_os = "linux",
        target_arch = "x86_64"
    )
))]
#[test]
fn native_tier3_pass_rows_execute_source_and_prepared_with_receipts() {
    let script =
        repo_root().join("packages/ibex-devtools/src/scripts/run-native-tier3-conformance.mjs");
    let telemetry_dir = tempfile::tempdir().expect("create telemetry report directory");
    let telemetry_path = std::env::var_os("IBEX_LEGACY_REQUIRED_TELEMETRY_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| telemetry_dir.path().join("legacy-required-telemetry.json"));
    let output = Command::new(node())
        .arg(script)
        .args(["--ibex", IBEX, "--write-telemetry"])
        .arg(&telemetry_path)
        .current_dir(repo_root())
        .output()
        .expect("run native Tier-3 real-binary conformance");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "native Tier-3 runner failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let summary = stdout
        .lines()
        .find(|line| line.starts_with("hermes-compat native:"))
        .unwrap_or_else(|| panic!("native runner emitted no summary: {stdout}"));
    let counts = summary
        .split_whitespace()
        .find_map(|token| token.split_once('/'))
        .and_then(|(passed, total)| Some((passed.parse::<u32>().ok()?, total.parse::<u32>().ok()?)))
        .expect("native summary counts");
    assert_eq!(counts.0, counts.1);
    assert!(counts.1 > 0);
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&telemetry_path).expect("read typed telemetry report"),
    )
    .expect("typed telemetry report");
    assert_eq!(report["schema"], "ibex/legacy-required-telemetry-report/1");
    assert_eq!(
        report["population"]["id"],
        "ibex-native-tier3-controlled-fixtures"
    );
    assert_eq!(report["population"]["controlledTestPopulation"], true);
    assert_eq!(report["population"]["advisoryOnly"], true);
    assert!(report["events"]["count"].as_u64().unwrap() > 0);
    assert!(report["events"]["digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256-"));
}
