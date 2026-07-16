use super::*;
use base64::Engine as _;
use std::io::Write as _;

const FIXTURE_COMMAND: [&str; 10] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--features",
    "capsec-conformance-observer",
    "capsec_exact_fixture_evidence_batch",
    "--",
    "--test-threads=1",
    "--nocapture",
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

fn expected_exact_mechanism(recipe: &serde_json::Value) -> &'static str {
    let terminal = recipe["terminalObservedKey"]
        .as_str()
        .expect("Exact recipe has no terminal observed key");
    match terminal {
        "callback:exact-host-call-async-resolve"
        | "callback:producer:src/engine/hermes_runtime.cc:ex_hermes_resolve_exact_host_call:pushRuntimeCallback"
        | "host-abi:ex_hermes_resolve_exact_host_call" => "exact-host-call-round-trip",
        "host-abi:ex_hermes_set_exact_host_call_async" => "exact-endowment-install",
        "host-abi:ex_host_authorize_exact_endowment" => "exact-endowment-authorize",
        "host-abi:ex_host_build_exact_gpu_armed_embedder_artifacts" => {
            "exact-gpu-artifact-prepare-round-trip"
        }
        "host-abi:ex_host_build_exact_armed_embedder_artifacts"
        | "host-abi:ex_host_prepare_armed_embedder_artifacts"
        | "host-abi:ex_host_prepare_exact_armed_embedder_artifacts" => {
            "exact-artifact-prepare-round-trip"
        }
        "native-op:global:exact.invokeHostAsync" => "exact-unendowed-operation",
        other => panic!("unsupported Exact pilot terminal {other}"),
    }
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
            matches!(
                recipe["terminalObservedKey"].as_str(),
                Some(
                    "callback:exact-host-call-async-resolve"
                        | "callback:producer:src/engine/hermes_runtime.cc:ex_hermes_resolve_exact_host_call:pushRuntimeCallback"
                        | "host-abi:ex_hermes_resolve_exact_host_call"
                        | "host-abi:ex_hermes_set_exact_host_call_async"
                        | "host-abi:ex_host_authorize_exact_endowment"
                        | "host-abi:ex_host_build_exact_armed_embedder_artifacts"
                        | "host-abi:ex_host_build_exact_gpu_armed_embedder_artifacts"
                        | "host-abi:ex_host_prepare_armed_embedder_artifacts"
                        | "host-abi:ex_host_prepare_exact_armed_embedder_artifacts"
                        | "native-op:global:exact.invokeHostAsync"
                )
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    recipes.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
    assert_eq!(
        recipes.len(),
        10,
        "Exact fixture pilot must contain ten recipes"
    );
    for recipe in &recipes {
        assert_eq!(recipe["status"], "fully-executable");
        let mechanism = if recipe["scenario"] == "closed" {
            recipe["publicSurfaceProbe"]["invocation"]["operation"]["kind"]
                .as_str()
                .expect("closed Exact recipe has no mechanism")
        } else {
            assert_eq!(recipe["scenario"], "non-capability");
            recipe["publicSurfaceProbe"]["invocation"]["sourceDescriptor"]["executionMechanism"]
                .as_str()
                .expect("callback Exact recipe has no mechanism")
        };
        assert_eq!(mechanism, expected_exact_mechanism(recipe));
    }
    recipes
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
    assert_eq!(plans.len(), 10);
    (execution_binding, binding_digest, plans)
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_exact_fixture_evidence_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping Exact fixture evidence batch");
        return;
    };
    let binding_path = std::env::var("IBEX_CAPSEC_FIXTURE_EVIDENCE_BINDING")
        .expect("Exact fixture evidence requires an owned binding input");
    let output_path = std::env::var("IBEX_CAPSEC_FIXTURE_EVIDENCE_OUTPUT")
        .expect("Exact fixture evidence requires an owned output path");
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
    let artifact = serde_json::json!({
        "executionArtifactSchema": "ibex/capsec-executions/1",
        "executionBinding": execution_binding,
        "bindingDigest": binding_digest,
        "executions": executions,
    });
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("create owned Exact fixture evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize Exact fixture evidence artifact");
    output
        .write_all(b"\n")
        .expect("finish Exact fixture evidence artifact");
    output
        .sync_all()
        .expect("sync Exact fixture evidence artifact");
}
