use super::*;
use base64::Engine as _;
#[cfg(not(feature = "host-http-server"))]
use std::io::Write as _;

const FIXTURE_COMMAND: [&str; 11] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--no-default-features",
    "--features",
    "standard,capsec-conformance-observer,openssl-crypto",
    "capsec_exact_fixture_evidence_batch",
    "--",
    "--test-threads=1",
    "--nocapture",
];

const PORTABLE_FIXTURE_EVIDENCE_DOMAIN: &str =
    "ibex:capsec:portable-fixture-evidence:1";
const PORTABLE_EXECUTION_BINDING_DOMAIN: &str = "ibex:capsec:portable-execution-binding:1";
const MAPPED_ENGINE_EXECUTION_EVIDENCE_DOMAIN: &str =
    "ibex:capsec:mapped-engine-execution-evidence:1";
const PORTABLE_COMMAND_ID: &str = "exact-fixture-evidence-portable-pilot";
const PORTABLE_PHASE_ID: &str = "fixture-evidence";
const PORTABLE_EXECUTOR: &str = "ibex-exact-fixture-evidence-pilot";
const SUPERVISOR_COMMAND_IDENTITY_ENV: &str =
    "IBEX_CAPSEC_SUPERVISOR_COMMAND_IDENTITY_DIGEST";

#[derive(Clone, Debug)]
struct PortableFixtureOutput {
    fixture_id: String,
    path: std::path::PathBuf,
}

#[derive(Clone, Debug)]
struct PortableEvidencePlan {
    bindings: serde_json::Value,
    binding_digest: String,
    fixture_outputs: Vec<PortableFixtureOutput>,
}

// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — this
// is the reviewed Exact fixture pilot, not every scenario later promoted on
// the same surfaces. Keep it aligned with the independent JS binding builder.
const EXACT_PILOT_EXPECTATIONS: [(&str, &str, &str); 9] = [
    (
        "callback:exact-host-call-async-resolve",
        "non-capability",
        "exact-host-call-round-trip",
    ),
    (
        "callback:producer:src/engine/hermes_runtime.cc:ex_hermes_resolve_exact_host_call:pushRuntimeCallback",
        "non-capability",
        "exact-host-call-round-trip",
    ),
    (
        "host-abi:ex_hermes_resolve_exact_host_call",
        "non-capability",
        "exact-host-call-round-trip",
    ),
    (
        "host-abi:ex_hermes_set_exact_host_call_async",
        "non-capability",
        "exact-endowment-install",
    ),
    (
        "host-abi:ex_host_authorize_exact_endowment",
        "non-capability",
        "exact-endowment-authorize",
    ),
    (
        "host-abi:ex_host_build_exact_armed_embedder_artifacts",
        "non-capability",
        "exact-artifact-prepare-round-trip",
    ),
    (
        "host-abi:ex_host_prepare_armed_embedder_artifacts",
        "non-capability",
        "exact-artifact-prepare-round-trip",
    ),
    (
        "host-abi:ex_host_prepare_exact_armed_embedder_artifacts",
        "non-capability",
        "exact-artifact-prepare-round-trip",
    ),
    (
        "native-op:global:exact.invokeHostAsync",
        "closed",
        "exact-unendowed-operation",
    ),
];

fn tagged_jcs_digest(value: &serde_json::Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("Exact fixture evidence must have canonical JSON bytes");
    let digest = sha2::Sha256::digest(bytes);
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

fn tagged_bytes_digest(bytes: &[u8]) -> String {
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(bytes))
    )
}

fn domain_digest(value: &serde_json::Value, domain: &str, omit: &[&str]) -> String {
    capsec_semantics::digest::compute_domain_digest(
        domain,
        value,
        &omit.iter().map(|field| (*field).to_owned()).collect::<Vec<_>>(),
    )
    .unwrap_or_else(|error| panic!("compute {domain} digest: {error}"))
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

fn portable_fixture_artifact(
    plan: &PortableEvidencePlan,
    engine: &ibex_runtime::engine::portable_identity::PortableEngineArtifactIdentity,
    fixture_id: &str,
) -> serde_json::Value {
    let mut artifact = serde_json::json!({
        "fixtureEvidenceSchema": "ibex/capsec-portable-fixture-evidence/1",
        "profile": "ibex/capsec/1",
        "sourceRevision": plan.bindings["sourceRevision"],
        "sourceTreeDigest": plan.bindings["sourceTreeDigest"],
        "target": plan.bindings["target"],
        "engine": engine,
        "fixtureId": fixture_id,
        "outcome": "passed",
        "executor": PORTABLE_EXECUTOR,
        "bindingDigest": plan.binding_digest,
        "artifactDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    artifact["artifactDigest"] = serde_json::Value::String(domain_digest(
        &artifact,
        PORTABLE_FIXTURE_EVIDENCE_DOMAIN,
        &["artifactDigest"],
    ));
    artifact
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

fn git(args: &[&str]) -> std::process::Output {
    let output = std::process::Command::new("git")
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run git {}: {error}", args.join(" ")));
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    output
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

fn recipe_mechanism(recipe: &serde_json::Value) -> Option<&str> {
    recipe["publicSurfaceProbe"]["invocation"]["sourceDescriptor"]["executionMechanism"]
        .as_str()
        .or_else(|| recipe["publicSurfaceProbe"]["invocation"]["operation"]["kind"].as_str())
}

fn exact_recipes(catalog: &serde_json::Value) -> Vec<serde_json::Value> {
    assert_eq!(
        catalog["recipeCatalogSchema"],
        "ibex/capsec-executable-recipes/1"
    );
    let expected_digest = catalog["recipeCatalogDigest"]
        .as_str()
        .expect("recipe catalog has no digest");
    let mut projected = catalog.clone();
    projected
        .as_object_mut()
        .unwrap()
        .remove("recipeCatalogDigest");
    assert_eq!(tagged_jcs_digest(&projected), expected_digest);
    let mut recipes = catalog["recipes"]
        .as_array()
        .expect("recipe catalog has no recipes")
        .iter()
        .filter(|recipe| {
            EXACT_PILOT_EXPECTATIONS
                .iter()
                .any(|(terminal, scenario, mechanism)| {
                    recipe["terminalObservedKey"].as_str() == Some(*terminal)
                        && recipe["scenario"].as_str() == Some(*scenario)
                        && recipe["status"] == "fully-executable"
                        && recipe_mechanism(recipe) == Some(*mechanism)
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    recipes.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
    assert_eq!(
        recipes.len(),
        EXACT_PILOT_EXPECTATIONS.len(),
        "Exact fixture pilot must contain one recipe for every reviewed surface"
    );
    for recipe in &recipes {
        assert_eq!(recipe["status"], "fully-executable");
        assert!(EXACT_PILOT_EXPECTATIONS
            .iter()
            .any(|(terminal, scenario, mechanism)| {
                recipe["terminalObservedKey"].as_str() == Some(*terminal)
                    && recipe["scenario"].as_str() == Some(*scenario)
                    && recipe_mechanism(recipe) == Some(*mechanism)
            }));
    }
    recipes
}

#[test]
fn exact_recipe_selection_excludes_promoted_sibling_scenarios() {
    let mut recipes = EXACT_PILOT_EXPECTATIONS
        .iter()
        .enumerate()
        .map(|(index, (terminal, scenario, mechanism))| {
            let invocation = if *scenario == "closed" {
                serde_json::json!({ "operation": { "kind": mechanism } })
            } else {
                serde_json::json!({
                    "sourceDescriptor": { "executionMechanism": mechanism }
                })
            };
            serde_json::json!({
                "fixtureId": format!("fixture.exact-pilot-{index}"),
                "terminalObservedKey": terminal,
                "scenario": scenario,
                "status": "fully-executable",
                "publicSurfaceProbe": { "invocation": invocation },
            })
        })
        .collect::<Vec<_>>();
    recipes.push(serde_json::json!({
        "fixtureId": "fixture.promoted-sibling",
        "terminalObservedKey": EXACT_PILOT_EXPECTATIONS[0].0,
        "scenario": "attribution-missing-deny",
        "status": "fully-executable",
        "publicSurfaceProbe": {
            "invocation": {
                "sourceDescriptor": {
                    "executionMechanism": "scheduled-public-attribution-guard"
                }
            }
        },
    }));
    let mut catalog = serde_json::json!({
        "recipeCatalogSchema": "ibex/capsec-executable-recipes/1",
        "recipes": recipes,
    });
    catalog["recipeCatalogDigest"] = serde_json::Value::String(tagged_jcs_digest(&catalog));

    let selected = exact_recipes(&catalog);

    assert_eq!(selected.len(), EXACT_PILOT_EXPECTATIONS.len());
    assert!(selected
        .iter()
        .all(|recipe| recipe["fixtureId"] != "fixture.promoted-sibling"));
}

#[test]
fn portable_fixture_domain_matches_the_frozen_cross_language_vector() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../schemas/vectors/portable-engine-provenance-v1.valid.json"
    ))
    .unwrap();
    let engine: ibex_runtime::engine::portable_identity::PortableEngineArtifactIdentity =
        serde_json::from_value(vectors["documents"]["portableIdentity"].clone()).unwrap();
    let plan = PortableEvidencePlan {
        bindings: serde_json::json!({
            "sourceRevision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sourceTreeDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "target": {
                "triple": "aarch64-apple-darwin",
                "features": [
                    "hermes-frame-attribution",
                    "native-compartments",
                    "native-lockdown"
                ]
            }
        }),
        binding_digest: "sha256-YRBVCE6H6u5yTEnh8f4r4YneABEr_A3ZsLv0yLMkGXI".into(),
        fixture_outputs: Vec::new(),
    };
    let artifact = portable_fixture_artifact(
        &plan,
        &engine,
        "fixture.portable-engine-example",
    );
    assert_exact_keys(
        &artifact,
        &[
            "fixtureEvidenceSchema",
            "profile",
            "sourceRevision",
            "sourceTreeDigest",
            "target",
            "engine",
            "fixtureId",
            "outcome",
            "executor",
            "bindingDigest",
            "artifactDigest",
        ],
        "portable fixture evidence",
    );
    assert_eq!(
        artifact["artifactDigest"],
        "sha256-swK95uvOY_8ch8RLuQDEVKtG2PPRIpsay-nUU6dUAEw"
    );
}

fn validate_binding(
    binding_artifact: &serde_json::Value,
    catalog: &serde_json::Value,
    loaded_engine: &ibex_runtime::engine::LoadedEngineBinaryIdentity,
) -> (serde_json::Value, String, Vec<serde_json::Value>) {
    assert_exact_keys(
        binding_artifact,
        &[
            "fixtureEvidenceBindingSchema",
            "executionBinding",
            "bindingDigest",
            "fixturePlans",
        ],
        "Exact fixture binding artifact",
    );
    assert_eq!(
        binding_artifact["fixtureEvidenceBindingSchema"],
        "ibex/capsec-fixture-evidence-binding/1"
    );
    let execution_binding = binding_artifact["executionBinding"].clone();
    assert_exact_keys(
        &execution_binding,
        &[
            "sourceRevision",
            "sourceTreeDigest",
            "target",
            "engine",
            "vocabularyDigest",
            "registryDigest",
            "implementationManifestDigest",
            "fixtureCatalogDigest",
            "recipeCatalogDigest",
            "publicSurfaceExecutionDigest",
        ],
        "Exact fixture execution binding",
    );
    let binding_digest = binding_artifact["bindingDigest"]
        .as_str()
        .expect("Exact fixture binding has no digest")
        .to_owned();
    assert_eq!(tagged_jcs_digest(&execution_binding), binding_digest);

    let status = git(&["status", "--porcelain"]);
    assert!(
        status.stdout.is_empty(),
        "Exact fixture evidence requires a clean tree"
    );
    let revision = git(&["rev-parse", "HEAD"]);
    assert_eq!(
        execution_binding["sourceRevision"],
        String::from_utf8(revision.stdout)
            .expect("git revision must be UTF-8")
            .trim()
    );
    let tree = git(&["rev-parse", "HEAD^{tree}"]);
    assert_eq!(
        execution_binding["sourceTreeDigest"],
        tagged_bytes_digest(&tree.stdout)
    );
    assert_eq!(
        execution_binding["target"]["triple"],
        compiled_target_triple()
    );
    let loaded_engine_value =
        serde_json::to_value(loaded_engine).expect("loaded engine identity must serialize");
    assert_eq!(execution_binding["engine"], loaded_engine_value);
    assert_eq!(
        execution_binding["target"]["features"],
        loaded_engine_value["structuralFeatures"]
    );
    assert_eq!(
        execution_binding["recipeCatalogDigest"],
        catalog["recipeCatalogDigest"]
    );

    let plans = binding_artifact["fixturePlans"]
        .as_array()
        .expect("Exact fixture binding has no plans")
        .clone();
    assert_eq!(plans.len(), EXACT_PILOT_EXPECTATIONS.len());
    (execution_binding, binding_digest, plans)
}

fn load_portable_evidence_plan(
    path: &std::path::Path,
    recipes: &[serde_json::Value],
    legacy_execution_binding: &serde_json::Value,
    portable_engine: &ibex_runtime::engine::portable_identity::PortableEngineArtifactIdentity,
) -> PortableEvidencePlan {
    let value = load_strict_json(
        &std::fs::canonicalize(path).expect("canonicalize portable evidence plan"),
        "portable evidence plan",
    );
    assert_exact_keys(
        &value,
        &[
            "portableEvidencePlanSchema",
            "profile",
            "bindings",
            "bindingDigest",
            "fixtureOutputs",
        ],
        "portable evidence plan",
    );
    assert_eq!(
        value["portableEvidencePlanSchema"],
        "ibex/capsec-portable-evidence-plan/1"
    );
    assert_eq!(value["profile"], "ibex/capsec/1");
    let bindings = value["bindings"].clone();
    assert_exact_keys(
        &bindings,
        &[
            "sourceRevision",
            "sourceTreeDigest",
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
        "portable execution bindings",
    );
    assert_eq!(bindings["sourceRevision"], legacy_execution_binding["sourceRevision"]);
    assert_eq!(
        bindings["sourceTreeDigest"],
        legacy_execution_binding["sourceTreeDigest"]
    );
    assert_eq!(bindings["target"], legacy_execution_binding["target"]);
    assert_eq!(
        bindings["engine"],
        serde_json::to_value(portable_engine).expect("portable engine identity must serialize")
    );
    assert_eq!(bindings["target"]["triple"], compiled_target_triple());
    let target_features = bindings["target"]["features"]
        .as_array()
        .expect("portable binding target features must be an array")
        .iter()
        .map(|feature| {
            feature
                .as_str()
                .expect("portable binding target feature must be a string")
                .to_owned()
        })
        .collect::<Vec<_>>();
    let mut sorted_features = target_features.clone();
    sorted_features.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    sorted_features.dedup();
    assert_eq!(target_features, sorted_features, "target features must be a set");

    let binding_digest = value["bindingDigest"]
        .as_str()
        .expect("portable evidence plan has no bindingDigest")
        .to_owned();
    assert_eq!(
        binding_digest,
        domain_digest(&bindings, PORTABLE_EXECUTION_BINDING_DOMAIN, &[]),
        "portable execution binding digest is stale"
    );

    let output_values = value["fixtureOutputs"]
        .as_array()
        .expect("portable evidence plan fixtureOutputs must be an array");
    let mut fixture_outputs = Vec::with_capacity(output_values.len());
    for output in output_values {
        assert_exact_keys(
            output,
            &["fixtureId", "path"],
            "portable fixture output",
        );
        let fixture_id = output["fixtureId"]
            .as_str()
            .expect("portable fixture output has no fixtureId")
            .to_owned();
        let output_path = std::path::PathBuf::from(
            output["path"]
                .as_str()
                .expect("portable fixture output has no path"),
        );
        assert!(output_path.is_absolute(), "portable fixture output path must be absolute");
        assert!(
            !output_path.exists(),
            "portable fixture output must not already exist: {}",
            output_path.display()
        );
        fixture_outputs.push(PortableFixtureOutput {
            fixture_id,
            path: output_path,
        });
    }
    let expected_fixture_ids = recipes
        .iter()
        .map(|recipe| recipe["fixtureId"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let actual_fixture_ids = fixture_outputs
        .iter()
        .map(|output| output.fixture_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        actual_fixture_ids, expected_fixture_ids,
        "portable output membership must equal the canonical recipe membership"
    );
    let unique_paths = fixture_outputs
        .iter()
        .map(|output| output.path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        unique_paths.len(),
        fixture_outputs.len(),
        "portable fixture outputs repeat a path"
    );

    PortableEvidencePlan {
        bindings,
        binding_digest,
        fixture_outputs,
    }
}

#[test]
fn exact_fixture_pilot_terminal_contract_includes_both_exact_artifact_abis() {
    assert_eq!(EXACT_PILOT_EXPECTATIONS.len(), 9);
    for terminal in [
        "host-abi:ex_host_build_exact_armed_embedder_artifacts",
        "host-abi:ex_host_prepare_exact_armed_embedder_artifacts",
    ] {
        let (_, scenario, mechanism) = EXACT_PILOT_EXPECTATIONS
            .iter()
            .find(|(candidate, _, _)| *candidate == terminal)
            .expect("reviewed Exact artifact ABI must remain in the pilot");
        assert_eq!(*scenario, "non-capability");
        assert_eq!(*mechanism, "exact-artifact-prepare-round-trip");
    }
}

// The mapped-observation guard is deliberately thread-owned. Keep this
// authority-bearing pilot on Tokio's current-thread runtime so the before and
// after observations bracket engine work on the same Hermes owner thread.
#[tokio::test(flavor = "current_thread")]
async fn capsec_exact_fixture_evidence_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping Exact fixture evidence batch");
        return;
    };
    let binding_path = std::env::var("IBEX_CAPSEC_FIXTURE_EVIDENCE_BINDING")
        .expect("Exact fixture evidence requires an owned binding input");
    let legacy_output_path = std::env::var("IBEX_CAPSEC_FIXTURE_EVIDENCE_OUTPUT").ok();
    let portable_plan_path = std::env::var("IBEX_CAPSEC_PORTABLE_EVIDENCE_PLAN").ok();
    assert_ne!(
        legacy_output_path.is_some(),
        portable_plan_path.is_some(),
        "Exact fixture evidence requires exactly one legacy output or portable plan"
    );
    let catalog = load_strict_json(
        &std::fs::canonicalize(recipe_path).expect("canonicalize recipe catalog"),
        "Exact fixture recipe catalog",
    );
    let binding_artifact = load_strict_json(
        &std::fs::canonicalize(binding_path).expect("canonicalize fixture binding"),
        "Exact fixture binding artifact",
    );
    let recipes = exact_recipes(&catalog);

    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest loaded Hermes before Exact fixture evidence");
    let (execution_binding, binding_digest, plans) =
        validate_binding(&binding_artifact, &catalog, &identity_before);
    assert!(recipes.iter().zip(&plans).all(|(recipe, plan)| {
        recipe["fixtureId"] == plan["fixtureId"]
            && recipe["planDigest"].as_str() == Some(tagged_jcs_digest(plan).as_str())
    }));

    let portable_context = portable_plan_path.map(|plan_path| {
        let portable_engine = HermesEngine::loaded_engine_portable_identity()
            .expect("portable evidence requires authenticated embedded engine identity");
        let plan = load_portable_evidence_plan(
            std::path::Path::new(&plan_path),
            &recipes,
            &execution_binding,
            &portable_engine,
        );
        let observation = HermesEngine::begin_loaded_engine_mapped_observation()
            .expect("begin mapped-engine observation before Exact fixture execution");
        (portable_engine, plan, observation)
    });

    let mut executions = Vec::with_capacity(recipes.len());
    for (recipe, plan) in recipes.iter().zip(&plans) {
        let fixture_id = recipe["fixtureId"].as_str().unwrap();
        let runtime_observation = if recipe["scenario"] == "closed" {
            super::capsec_public_closed_batch::execute_exact_fixture_runtime_observation(
                recipe,
                &identity_before.binary_digest,
            )
            .await
        } else {
            super::capsec_public_callback_invariant_batch::execute_exact_fixture_runtime_observation(
                recipe,
            )
            .await
        };
        assert_eq!(
            runtime_observation["invocation"]["surfaceObservedKey"],
            recipe["terminalObservedKey"]
        );
        let mut observation = plan["expectedObservation"].clone();
        observation
            .as_object_mut()
            .expect("fixture plan observation must be an object")
            .insert("result".into(), "passed".into());
        let evidence = serde_json::json!({
            "evidenceSchema": "ibex/capsec-fixture-evidence/2",
            "fixtureId": fixture_id,
            "command": FIXTURE_COMMAND,
            "exitCode": 0,
            "resultMarker": format!("ibex-capsec-fixture:{fixture_id}:passed"),
            "planDigest": recipe["planDigest"],
            "engineBinaryDigest": identity_before.binary_digest,
            "fixturePlan": plan,
            "executionBinding": execution_binding,
            "observation": observation,
            "runtimeObservation": runtime_observation,
        });
        executions.push(serde_json::json!({
            "fixtureId": fixture_id,
            "outcome": "passed",
            "executor": "ibex-exact-fixture-evidence-pilot",
            "artifactDigest": tagged_jcs_digest(&evidence),
            "bindingDigest": binding_digest,
            "evidence": evidence,
        }));
    }

    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest loaded Hermes after Exact fixture evidence");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after Exact fixture evidence");
    if let Some((portable_engine, portable_plan, observation)) = portable_context {
        assert_eq!(
            HermesEngine::loaded_engine_portable_identity()
                .expect("reconstruct portable identity after fixture execution"),
            portable_engine,
            "portable engine identity changed across fixture execution"
        );
        let mapped_output_path = std::path::PathBuf::from(
            std::env::var("IBEX_CAPSEC_MAPPED_ENGINE_EVIDENCE_OUTPUT")
                .expect("portable evidence requires a mapped-engine output path"),
        );
        assert!(
            mapped_output_path.is_absolute(),
            "mapped-engine evidence output path must be absolute"
        );
        assert!(
            !mapped_output_path.exists(),
            "mapped-engine evidence output must not already exist"
        );
        assert!(
            portable_plan
                .fixture_outputs
                .iter()
                .all(|output| output.path != mapped_output_path),
            "mapped-engine evidence path collides with a fixture output"
        );

        for output in &portable_plan.fixture_outputs {
            let artifact = portable_fixture_artifact(
                &portable_plan,
                &portable_engine,
                &output.fixture_id,
            );
            write_new_synced(
                &output.path,
                &pretty_json_bytes(&artifact),
                "portable fixture evidence",
            );
        }
        // Re-read every declared non-mapped output before finalizing the
        // evidence. A missing output therefore prevents mapped evidence from
        // being written, while later substitution is caught by the
        // supervisor's finalized output rows.
        let mut output_digests = portable_plan
            .fixture_outputs
            .iter()
            .map(|output| {
                let bytes = std::fs::read(&output.path).unwrap_or_else(|error| {
                    panic!(
                        "read declared portable fixture output {}: {error}",
                        output.path.display()
                    )
                });
                tagged_bytes_digest(&bytes)
            })
            .collect::<Vec<_>>();
        output_digests.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        output_digests.dedup();
        assert_eq!(
            output_digests.len(),
            portable_plan.fixture_outputs.len(),
            "portable fixture outputs have ambiguous equal raw digests"
        );

        let mapped_engine = observation
            .finish()
            .expect("finalize mapped-engine observation after Exact fixture execution");
        assert_eq!(mapped_engine.portable, portable_engine);
        let command_identity = std::env::var(SUPERVISOR_COMMAND_IDENTITY_ENV)
            .expect("portable evidence requires supervisor-injected command identity");
        capsec_semantics::model::Digest::new(command_identity.clone())
            .expect("supervisor command identity must be a semantic digest");
        let fixture_ids = portable_plan
            .fixture_outputs
            .iter()
            .map(|output| output.fixture_id.clone())
            .collect::<Vec<_>>();
        let mut mapped_evidence = serde_json::json!({
            "mappedEngineExecutionEvidenceSchema":
                "ibex/capsec-mapped-engine-execution-evidence/1",
            "profile": "ibex/capsec/1",
            "authorityClass": "same-runner-authoritative",
            "sourceRevision": portable_plan.bindings["sourceRevision"],
            "sourceTreeDigest": portable_plan.bindings["sourceTreeDigest"],
            "target": portable_plan.bindings["target"],
            "phaseId": PORTABLE_PHASE_ID,
            "commandId": PORTABLE_COMMAND_ID,
            "commandIdentityDigest": command_identity,
            "fixtureIds": fixture_ids,
            "outputDigests": output_digests,
            "engine": portable_engine,
            "mappedEngine": mapped_engine,
            "evidenceDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        });
        mapped_evidence["evidenceDigest"] = serde_json::Value::String(domain_digest(
            &mapped_evidence,
            MAPPED_ENGINE_EXECUTION_EVIDENCE_DOMAIN,
            &["evidenceDigest"],
        ));
        write_new_synced(
            &mapped_output_path,
            &pretty_json_bytes(&mapped_evidence),
            "mapped-engine execution evidence",
        );
    } else {
        let artifact = serde_json::json!({
            "executionArtifactSchema": "ibex/capsec-executions/1",
            "executionBinding": execution_binding,
            "bindingDigest": binding_digest,
            "executions": executions,
        });
        write_new_synced(
            std::path::Path::new(
                legacy_output_path
                    .as_deref()
                    .expect("legacy Exact fixture evidence requires an output path"),
            ),
            &pretty_json_bytes(&artifact),
            "Exact fixture evidence artifact",
        );
    }
}
