use super::*;
use base64::Engine as _;
use std::io::Write as _;

// @ref LLP 0035#reports-and-advertisements — a promotion-facing fixture row
// must be written by the same physical public batch bracketed by its retained
// mapped-engine observation; earlier rich evidence cannot be borrowed.

const PLAN_ENV: &str = "IBEX_CAPSEC_PORTABLE_EVIDENCE_PLAN";
const MAPPED_OUTPUT_ENV: &str = "IBEX_CAPSEC_MAPPED_ENGINE_EVIDENCE_OUTPUT";
const SUPERVISOR_COMMAND_IDENTITY_ENV: &str =
    "IBEX_CAPSEC_SUPERVISOR_COMMAND_IDENTITY_DIGEST";
const PORTABLE_FIXTURE_EVIDENCE_DOMAIN: &str =
    "ibex:capsec:portable-fixture-evidence:1";
const PORTABLE_EXECUTION_BINDING_DOMAIN: &str =
    "ibex:capsec:portable-execution-binding:1";
const MAPPED_ENGINE_EXECUTION_EVIDENCE_DOMAIN: &str =
    "ibex:capsec:mapped-engine-execution-evidence:1";

#[derive(Clone, Debug)]
struct PortableFixtureOutput {
    fixture_id: String,
    path: std::path::PathBuf,
}

#[derive(Clone, Debug)]
struct PortablePublicBatchPlan {
    bindings: serde_json::Value,
    binding_digest: String,
    executor: String,
    phase_id: String,
    command_id: String,
    fixture_outputs: Vec<PortableFixtureOutput>,
    mapped_output_path: std::path::PathBuf,
}

pub(super) struct PortablePublicBatchContext {
    engine: ibex_runtime::engine::portable_identity::PortableEngineArtifactIdentity,
    plan: PortablePublicBatchPlan,
    observation: ibex_runtime::engine::portable_identity::LoadedEngineMappedObservation,
}

fn domain_digest(value: &serde_json::Value, domain: &str, omit: &[&str]) -> String {
    capsec_semantics::digest::compute_domain_digest(
        domain,
        value,
        &omit.iter().map(|field| (*field).to_owned()).collect::<Vec<_>>(),
    )
    .unwrap_or_else(|error| panic!("compute {domain} digest: {error}"))
}

fn tagged_jcs_digest(value: &serde_json::Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("public fixture evidence must have canonical JSON bytes");
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(bytes))
    )
}

fn tagged_bytes_digest(bytes: &[u8]) -> String {
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(bytes))
    )
}

fn pretty_json_bytes(value: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("portable evidence must serialize");
    bytes.push(b'\n');
    bytes
}

fn write_new_synced(path: &std::path::Path, bytes: &[u8], label: &str) {
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| panic!("create {label} {}: {error}", path.display()));
    output
        .write_all(bytes)
        .unwrap_or_else(|error| panic!("write {label} {}: {error}", path.display()));
    output
        .sync_all()
        .unwrap_or_else(|error| panic!("sync {label} {}: {error}", path.display()));
}

fn load_strict_json(path: &std::path::Path, label: &str) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("read {label}: {error}"));
    let text =
        std::str::from_utf8(&bytes).unwrap_or_else(|error| panic!("{label} is not UTF-8: {error}"));
    capsec_semantics::strict_json::parse_strict(text)
        .unwrap_or_else(|error| panic!("{label} is not strict JSON: {error}"))
}

fn assert_exact_keys(value: &serde_json::Value, keys: &[&str], label: &str) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("{label} must be an object"));
    let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = keys.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected, "{label} has unexpected or missing fields");
}

fn stable_id(value: &str) -> bool {
    let mut previous_was_scalar = false;
    for byte in value.bytes() {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_was_scalar = true;
        } else if previous_was_scalar && matches!(byte, b'.' | b'_' | b'/' | b'-') {
            previous_was_scalar = false;
        } else {
            return false;
        }
    }
    previous_was_scalar
}

fn compiled_target_triple() -> String {
    #[cfg(target_os = "macos")]
    {
        format!("{}-apple-darwin", std::env::consts::ARCH)
    }
    #[cfg(target_os = "windows")]
    {
        format!("{}-pc-windows-msvc", std::env::consts::ARCH)
    }
    #[cfg(target_os = "android")]
    {
        format!("{}-linux-android", std::env::consts::ARCH)
    }
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "android"))))]
    {
        format!("{}-unknown-linux-gnu", std::env::consts::ARCH)
    }
}

fn load_plan(
    expected_executor: &str,
    schema_field: &str,
    schema_value: &str,
) -> Option<PortablePublicBatchPlan> {
    let plan_path = std::env::var(PLAN_ENV).ok()?;
    let plan_path = std::fs::canonicalize(&plan_path)
        .unwrap_or_else(|error| panic!("canonicalize portable public-batch plan: {error}"));
    let plan_directory = plan_path
        .parent()
        .expect("portable public-batch plan has no parent")
        .to_path_buf();
    let value = load_strict_json(&plan_path, "portable public-batch plan");
    assert_exact_keys(
        &value,
        &[
            schema_field,
            "profile",
            "bindings",
            "bindingDigest",
            "executor",
            "phaseId",
            "commandId",
            "fixtureOutputs",
        ],
        "portable public-batch plan",
    );
    assert_eq!(value[schema_field], schema_value);
    assert_eq!(value["profile"], "ibex/capsec/1");
    assert_eq!(value["executor"], expected_executor);
    let phase_id = value["phaseId"]
        .as_str()
        .expect("portable public-batch phaseId must be a string")
        .to_owned();
    let command_id = value["commandId"]
        .as_str()
        .expect("portable public-batch commandId must be a string")
        .to_owned();
    assert!(
        stable_id(&phase_id) && stable_id(&command_id) && stable_id(expected_executor),
        "portable public-batch plan has an invalid stable ID"
    );

    let bindings = value["bindings"].clone();
    assert_exact_keys(
        &bindings,
        &[
            "sourceRevision",
            "sourceTreeDigest",
            "conformanceRunner",
            "target",
            "engine",
            "vocabularyDigest",
            "registryDigest",
            "implementationManifestDigest",
            "fixtureCatalogDigest",
            "targetCellsRawContentDigest",
            "recipeCatalogDigest",
            "recipeCatalogRawContentDigest",
            "publicSurfaceExecutionDigest",
            "publicSurfaceExecutionRawContentDigest",
            "outputDispositionEvidenceRawContentDigest",
        ],
        "portable public-batch bindings",
    );
    assert_eq!(bindings["target"]["triple"], compiled_target_triple());
    let engine = HermesEngine::loaded_engine_portable_identity()
        .expect("portable public-batch evidence requires authenticated engine identity");
    assert_eq!(
        bindings["engine"],
        serde_json::to_value(&engine).expect("portable engine identity must serialize"),
        "portable public-batch plan names another engine"
    );
    let binding_digest = value["bindingDigest"]
        .as_str()
        .expect("portable public-batch plan has no binding digest")
        .to_owned();
    assert_eq!(
        binding_digest,
        domain_digest(&bindings, PORTABLE_EXECUTION_BINDING_DOMAIN, &[]),
        "portable public-batch execution binding digest is stale"
    );

    let outputs = value["fixtureOutputs"]
        .as_array()
        .expect("portable public-batch fixtureOutputs must be an array");
    assert!(!outputs.is_empty(), "portable public batch has no fixtures");
    let mut fixture_outputs = Vec::with_capacity(outputs.len());
    for output in outputs {
        assert_exact_keys(output, &["fixtureId", "path"], "portable fixture output");
        let fixture_id = output["fixtureId"]
            .as_str()
            .expect("portable fixture output has no fixtureId")
            .to_owned();
        assert!(stable_id(&fixture_id), "portable fixture ID is invalid");
        let output_path = std::path::PathBuf::from(
            output["path"]
                .as_str()
                .expect("portable fixture output has no path"),
        );
        assert!(
            output_path.is_absolute() && !output_path.exists(),
            "portable fixture output must be a new absolute path: {}",
            output_path.display()
        );
        assert_eq!(
            std::fs::canonicalize(
                output_path
                    .parent()
                    .expect("portable fixture output has no parent"),
            )
            .expect("canonicalize portable fixture output parent"),
            plan_directory,
            "portable fixture output must remain in the plan directory"
        );
        fixture_outputs.push(PortableFixtureOutput {
            fixture_id,
            path: output_path,
        });
    }
    let fixture_ids = fixture_outputs
        .iter()
        .map(|output| output.fixture_id.as_str())
        .collect::<Vec<_>>();
    let mut canonical_fixture_ids = fixture_ids.clone();
    canonical_fixture_ids.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    canonical_fixture_ids.dedup();
    assert_eq!(
        fixture_ids, canonical_fixture_ids,
        "portable public-batch fixture IDs must be canonical and unique"
    );
    let unique_paths = fixture_outputs
        .iter()
        .map(|output| output.path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        unique_paths.len(),
        fixture_outputs.len(),
        "portable public-batch fixture outputs repeat a path"
    );
    let mapped_output_path = std::path::PathBuf::from(
        std::env::var(MAPPED_OUTPUT_ENV)
            .expect("portable public-batch evidence requires a mapped output path"),
    );
    assert!(
        mapped_output_path.is_absolute() && !mapped_output_path.exists(),
        "mapped evidence output must be a new absolute path"
    );
    assert_eq!(
        std::fs::canonicalize(
            mapped_output_path
                .parent()
                .expect("mapped evidence output has no parent"),
        )
        .expect("canonicalize mapped evidence output parent"),
        plan_directory,
        "mapped evidence output must remain in the plan directory"
    );
    assert!(
        fixture_outputs
            .iter()
            .all(|output| output.path != mapped_output_path),
        "mapped evidence path collides with a fixture output"
    );

    Some(PortablePublicBatchPlan {
        bindings,
        binding_digest,
        executor: expected_executor.to_owned(),
        phase_id,
        command_id,
        fixture_outputs,
        mapped_output_path,
    })
}

impl PortablePublicBatchContext {
    pub(super) fn begin(expected_executor: &'static str) -> Option<Self> {
        let plan = load_plan(
            expected_executor,
            "portablePublicBatchEvidencePlanSchema",
            "ibex/capsec-portable-public-batch-evidence-plan/1",
        )?;
        let engine = HermesEngine::loaded_engine_portable_identity()
            .expect("reconstruct portable identity before public fixtures");
        let observation = HermesEngine::begin_loaded_engine_mapped_observation()
            .expect("begin mapped-engine observation before public fixtures");
        Some(Self {
            engine,
            plan,
            observation,
        })
    }

    pub(super) fn begin_internal(expected_executor: &'static str) -> Option<Self> {
        let plan = load_plan(
            expected_executor,
            "portableInternalBatchEvidencePlanSchema",
            "ibex/capsec-portable-internal-batch-evidence-plan/1",
        )?;
        let engine = HermesEngine::loaded_engine_portable_identity()
            .expect("reconstruct portable identity before internal fixtures");
        let observation = HermesEngine::begin_loaded_engine_mapped_observation()
            .expect("begin mapped-engine observation before internal fixtures");
        Some(Self {
            engine,
            plan,
            observation,
        })
    }

    pub(super) fn finish(self, executions: &[serde_json::Value]) {
        self.finish_with_evidence_kind(executions, false);
    }

    pub(super) fn finish_internal(self, executions: &[serde_json::Value]) {
        self.finish_with_evidence_kind(executions, true);
    }

    fn finish_with_evidence_kind(self, executions: &[serde_json::Value], internal: bool) {
        assert_eq!(
            HermesEngine::loaded_engine_portable_identity()
                .expect("reconstruct portable identity after fixtures"),
            self.engine,
            "portable engine identity changed across fixtures"
        );
        assert_eq!(
            executions.len(),
            self.plan.fixture_outputs.len(),
            "portable public-batch execution membership is incomplete"
        );
        for (execution, output) in executions.iter().zip(&self.plan.fixture_outputs) {
            let fixture_id = execution["fixtureId"]
                .as_str()
                .expect("public execution has no fixtureId");
            assert_eq!(fixture_id, output.fixture_id);
            assert_eq!(execution["outcome"], "passed");
            assert_eq!(execution["executor"], self.plan.executor);
            let evidence = execution["evidence"]
                .as_object()
                .expect("portable execution has no evidence");
            assert_eq!(
                evidence.get("fixtureId").and_then(|value| value.as_str()),
                Some(fixture_id)
            );
            assert_eq!(
                evidence.get("exitCode").and_then(|value| value.as_i64()),
                Some(0)
            );
            if internal {
                assert_eq!(
                    evidence
                        .get("resultMarker")
                        .and_then(|value| value.as_str()),
                    Some(format!("ibex-capsec-internal-invariant:{fixture_id}:passed").as_str())
                );
                assert_eq!(
                    execution["artifactDigest"],
                    tagged_jcs_digest(&serde_json::Value::Object(evidence.clone())),
                    "internal execution evidence digest is stale"
                );
            } else {
                assert_eq!(
                    evidence
                        .get("resultMarker")
                        .and_then(|value| value.as_str()),
                    Some(format!("ibex-capsec-public-fixture:{fixture_id}:passed").as_str())
                );
                let mut evidence_without_digest = serde_json::Value::Object(evidence.clone());
                let evidence_digest = evidence_without_digest["evidenceDigest"]
                    .as_str()
                    .expect("public execution evidence has no digest")
                    .to_owned();
                evidence_without_digest
                    .as_object_mut()
                    .unwrap()
                    .remove("evidenceDigest");
                assert_eq!(
                    evidence_digest,
                    tagged_jcs_digest(&evidence_without_digest),
                    "public execution evidence digest is stale"
                );
            }

            let mut artifact = serde_json::json!({
                "fixtureEvidenceSchema": "ibex/capsec-portable-fixture-evidence/1",
                "profile": "ibex/capsec/1",
                "sourceRevision": self.plan.bindings["sourceRevision"],
                "sourceTreeDigest": self.plan.bindings["sourceTreeDigest"],
                "target": self.plan.bindings["target"],
                "engine": self.engine,
                "fixtureId": fixture_id,
                "outcome": "passed",
                "executor": self.plan.executor,
                "bindingDigest": self.plan.binding_digest,
                "artifactDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            });
            artifact["artifactDigest"] = serde_json::Value::String(domain_digest(
                &artifact,
                PORTABLE_FIXTURE_EVIDENCE_DOMAIN,
                &["artifactDigest"],
            ));
            write_new_synced(
                &output.path,
                &pretty_json_bytes(&artifact),
                "portable public fixture evidence",
            );
        }

        let mut output_digests = self
            .plan
            .fixture_outputs
            .iter()
            .map(|output| {
                let bytes = std::fs::read(&output.path).unwrap_or_else(|error| {
                    panic!(
                        "read portable public fixture output {}: {error}",
                        output.path.display()
                    )
                });
                tagged_bytes_digest(&bytes)
            })
            .collect::<Vec<_>>();
        output_digests.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        output_digests.dedup();
        assert_eq!(
            output_digests.len(),
            self.plan.fixture_outputs.len(),
            "portable public fixture outputs have ambiguous equal raw digests"
        );

        let mapped_engine = self
            .observation
            .finish()
            .expect("finalize mapped-engine observation after public fixtures");
        assert_eq!(mapped_engine.portable, self.engine);
        let command_identity = std::env::var(SUPERVISOR_COMMAND_IDENTITY_ENV)
            .expect("portable public evidence requires supervisor command identity");
        capsec_semantics::model::Digest::new(command_identity.clone())
            .expect("supervisor command identity must be a semantic digest");
        let fixture_ids = self
            .plan
            .fixture_outputs
            .iter()
            .map(|output| output.fixture_id.clone())
            .collect::<Vec<_>>();
        let mut mapped_evidence = serde_json::json!({
            "mappedEngineExecutionEvidenceSchema":
                "ibex/capsec-mapped-engine-execution-evidence/1",
            "profile": "ibex/capsec/1",
            "authorityClass": "same-runner-authoritative",
            "sourceRevision": self.plan.bindings["sourceRevision"],
            "sourceTreeDigest": self.plan.bindings["sourceTreeDigest"],
            "target": self.plan.bindings["target"],
            "phaseId": self.plan.phase_id,
            "commandId": self.plan.command_id,
            "commandIdentityDigest": command_identity,
            "fixtureIds": fixture_ids,
            "outputDigests": output_digests,
            "engine": self.engine,
            "mappedEngine": mapped_engine,
            "evidenceDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        });
        mapped_evidence["evidenceDigest"] = serde_json::Value::String(domain_digest(
            &mapped_evidence,
            MAPPED_ENGINE_EXECUTION_EVIDENCE_DOMAIN,
            &["evidenceDigest"],
        ));
        write_new_synced(
            &self.plan.mapped_output_path,
            &pretty_json_bytes(&mapped_evidence),
            "mapped-engine public-batch evidence",
        );
    }
}
