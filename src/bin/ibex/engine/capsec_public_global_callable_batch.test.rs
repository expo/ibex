// Source-bound public evidence for decision-free callable globals. This is a
// child of the builtin public batch so it reuses the authenticated submission
// and bounded publication controller without introducing a second test-only
// engine ingress.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
// @ref LLP 0023#6-path-bearing-observables

use super::*;

const GLOBAL_CALLABLE_HARNESS: &str = include_str!("capsec_global_callable_invocation.js");
const INVOCATION_SCHEMA: &str = "ibex/capsec-global-callable-invocation/1";
const COMPLETION_TIMEOUT_MILLISECONDS: u64 = 1_000;

fn global_callable_recipes(
    catalog: &RecipeCatalog,
) -> Vec<(&Recipe, &GlobalCallablePublicSurfaceProbe)> {
    catalog
        .recipes
        .iter()
        .filter_map(|recipe| {
            let probe = match recipe.public_surface_probe.as_ref()? {
                PublicSurfaceProbe::GlobalCallable(probe) => probe.as_ref(),
                _ => return None,
            };
            (recipe.classification == "non-capability"
                && recipe.scenario == "non-capability"
                && recipe.status == "fully-executable"
                && probe.invocation.invocation_schema == INVOCATION_SCHEMA)
                .then_some((recipe, probe))
        })
        .collect()
}

fn expected_recipe_count(target: &str) -> usize {
    match target {
        "aarch64-apple-darwin" => 575,
        "x86_64-pc-windows-msvc" => 561,
        target => {
            panic!("global callable public batch has no reviewed target shape for {target}")
        }
    }
}

fn assert_object_keys(value: &serde_json::Value, expected: &[&str], context: &str) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("{context} must be an object"));
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "{context} has unexpected fields");
}

fn validate_probe(
    recipe: &Recipe,
    probe: &GlobalCallablePublicSurfaceProbe,
    terminals: &BTreeMap<String, String>,
) {
    let invocation = &probe.invocation;
    assert_eq!(probe.kind, "public-surface-invocation");
    assert_eq!(
        probe.command,
        [
            "cargo",
            "test",
            "--bin",
            "ibex",
            "--no-default-features",
            "--features",
            "standard,capsec-conformance-observer,openssl-crypto",
            "capsec_public_global_callable_batch",
            "--",
            "--test-threads=1",
        ]
    );
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(recipe.route.surface_observed_keys, [probe.surface_observed_key.as_str()]);
    assert_eq!(recipe.route.alternatives.len(), 1);
    assert_eq!(
        recipe.route.alternatives[0].terminal_observed_key,
        probe.surface_observed_key
    );
    assert!(!recipe.route.alternatives[0].proof_paths.is_empty());
    assert!(recipe.route.ambiguous_callees.is_empty());
    assert_eq!(invocation.kind, "global-callable-invocation");
    assert_eq!(invocation.coverage_edge_id, recipe.edge_ids[0]);
    assert_eq!(invocation.coverage_classification, "non-capability");
    assert_eq!(
        terminals.get(&invocation.coverage_edge_id),
        Some(&probe.surface_observed_key),
        "{}: callable edge no longer names its public terminal",
        recipe.fixture_id
    );
    assert_eq!(
        tagged_jcs_digest(&invocation.source_descriptor),
        invocation.source_descriptor_digest,
        "{}: callable source descriptor digest drift",
        recipe.fixture_id
    );
    assert_object_keys(
        &invocation.source_descriptor,
        &[
            "kind",
            "globalName",
            "memberName",
            "memberKinds",
            "sourceRefs",
        ],
        "global callable source descriptor",
    );
    let descriptor = &invocation.source_descriptor;
    assert_eq!(descriptor["kind"], "global-api-callable");
    let global_name = descriptor["globalName"]
        .as_str()
        .expect("global callable descriptor has no global name");
    assert!(!global_name.is_empty());
    let member_name = descriptor["memberName"].as_str();
    assert!(descriptor["memberName"].is_null() || member_name.is_some());
    let shared_runtime_surface = format!(
        "native-op:global:{global_name}{}",
        member_name
            .map(|member_name| format!(".{member_name}"))
            .unwrap_or_default()
    );
    let direct_native_surface =
        member_name.is_none().then(|| format!("native-op:{global_name}"));
    assert!(
        probe.surface_observed_key == shared_runtime_surface
            || direct_native_surface
                .as_ref()
                .is_some_and(|surface| probe.surface_observed_key == *surface),
        "{}: callable descriptor names a different public surface",
        recipe.fixture_id
    );
    assert!(
        descriptor["memberKinds"]
            .as_array()
            .is_some_and(|values| !values.is_empty() && values.iter().all(|value| value
                .as_str()
                .is_some_and(|value| !value.is_empty())))
    );
    assert!(
        descriptor["sourceRefs"]
            .as_array()
            .is_some_and(|values| !values.is_empty() && values.iter().all(|value| value
                .as_str()
                .is_some_and(|value| !value.is_empty())))
    );
    assert_object_keys(
        &invocation.completion,
        &["kind", "timeoutMilliseconds"],
        "global callable completion",
    );
    assert_eq!(
        invocation.completion,
        serde_json::json!({
            "kind": "event-loop-quiescence",
            "timeoutMilliseconds": COMPLETION_TIMEOUT_MILLISECONDS,
        })
    );
    let operation = invocation.route["operation"]
        .as_str()
        .expect("global callable route has no operation");
    assert!(matches!(operation, "call" | "construct" | "get"));
    assert!(
        invocation.route.get("authority").is_none(),
        "{}: decision-free callable route unexpectedly requests authority",
        recipe.fixture_id
    );
    assert!(invocation.route["receiver"].is_object());
    assert!(invocation.route["arguments"].is_array());
    assert_eq!(invocation.expected_result, "source-completion");
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert_eq!(
        invocation.allowed_coverage_edge_ids,
        [invocation.coverage_edge_id.as_str()]
    );
    assert!(invocation.expected_action_ids.is_empty());
}

fn harness_invocation(invocation: &GlobalCallableInvocation) -> serde_json::Value {
    serde_json::json!({
        "invocationSchema": invocation.invocation_schema,
        "kind": invocation.kind,
        "coverageEdgeId": invocation.coverage_edge_id,
        "coverageClassification": invocation.coverage_classification,
        "sourceDescriptor": invocation.source_descriptor,
        "sourceDescriptorDigest": invocation.source_descriptor_digest,
        "route": invocation.route,
        "completion": invocation.completion,
    })
}

fn invocation_script(invocation: &GlobalCallableInvocation) -> String {
    format!(
        "JSON.stringify(({})({}))",
        GLOBAL_CALLABLE_HARNESS.trim(),
        serde_json::to_string(&harness_invocation(invocation))
            .expect("serialize authored global callable invocation"),
    )
}

fn validate_source_completion(
    recipe: &Recipe,
    result: &serde_json::Value,
) -> Result<(), String> {
    let keys = result
        .as_object()
        .ok_or_else(|| format!("{}: callable result is not an object", recipe.fixture_id))?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = [
        "kind",
        "sourceOperationAttempted",
        "descriptorProof",
        "cleanupPerformed",
        "cleanupError",
        "rawOutput",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if keys != expected {
        return Err(format!(
            "{}: callable result has unexpected fields",
            recipe.fixture_id
        ));
    }
    if result["sourceOperationAttempted"] != true {
        return Err(format!(
            "{}: callable receiver/setup never reached the exact source operation: {}",
            recipe.fixture_id, result
        ));
    }
    if result["cleanupPerformed"] != true || !result["cleanupError"].is_null() {
        return Err(format!(
            "{}: callable cleanup was not proven: {}",
            recipe.fixture_id, result
        ));
    }
    let descriptor = &result["descriptorProof"];
    let descriptor_keys = descriptor
        .as_object()
        .ok_or_else(|| {
            format!(
                "{}: callable descriptor proof is not an object",
                recipe.fixture_id
            )
        })?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if descriptor_keys
        != ["presence", "descriptorKind", "valueType"]
            .into_iter()
            .collect::<BTreeSet<_>>()
    {
        return Err(format!(
            "{}: callable descriptor proof has unexpected fields",
            recipe.fixture_id
        ));
    }
    let raw = &result["rawOutput"];
    let raw_kind = raw["kind"].as_str();
    let valid_raw = match raw_kind {
        Some("return") => {
            raw["rawValueShape"]
                .as_str()
                .is_some_and(|shape| shape != "throw" && shape != "absent")
                && raw["errorCode"].is_null()
        }
        Some("throw") => {
            raw["rawValueShape"] == "throw"
                && raw["value"].is_null()
                && (raw["errorCode"]
                    .as_str()
                    .is_some_and(|code| !code.is_empty())
                    || raw["errorName"]
                        .as_str()
                        .is_some_and(|name| !name.is_empty()))
        }
        Some("absent") => {
            raw["rawValueShape"] == "absent"
                && raw["value"].is_null()
                && raw["errorCode"].is_null()
        }
        _ => false,
    };
    if !valid_raw {
        return Err(format!(
            "{}: exact callable produced no valid source completion: {}",
            recipe.fixture_id, raw
        ));
    }
    let descriptor_kind = descriptor["descriptorKind"].as_str();
    let descriptor_matches = match raw_kind {
        Some("absent") => descriptor_kind == Some("absent"),
        Some("return") | Some("throw") => {
            matches!(descriptor_kind, Some("data") | Some("accessor"))
        }
        _ => false,
    };
    if !descriptor_matches {
        return Err(format!(
            "{}: callable descriptor does not match its source completion",
            recipe.fixture_id
        ));
    }
    Ok(())
}

async fn execute_recipe(
    engine: &mut AuthenticatedBuiltinEngine,
    recipe: &Recipe,
    probe: &GlobalCallablePublicSurfaceProbe,
    engine_binary_digest: &str,
) -> Result<serde_json::Value, String> {
    let observer_id = format!("public-global-callable:{}", recipe.plan_digest);
    if !ibex_runtime::host::abi::begin_installed_conformance_observation(&observer_id) {
        return Err(format!(
            "{}: installed host refused the callable observer",
            recipe.fixture_id
        ));
    }
    let execution = engine
        .eval_immediate(&invocation_script(&probe.invocation))
        .await;
    let completion = tokio::time::timeout(
        std::time::Duration::from_millis(COMPLETION_TIMEOUT_MILLISECONDS),
        engine.engine.drive_event_loop(),
    )
    .await;
    let publications = engine
        .drain_publications("global callable public event-loop drive")
        .map_err(|error| {
            format!(
                "{}: callable publication stream failed: {error:#}",
                recipe.fixture_id
            )
        });
    let (legacy, typed) =
        ibex_runtime::host::abi::take_installed_conformance_observations();
    if !legacy.is_empty() || !typed.is_empty() {
        return Err(format!(
            "{}: decision-free callable observed {} legacy and {} typed decisions",
            recipe.fixture_id,
            legacy.len(),
            typed.len()
        ));
    }
    completion
        .map_err(|_| {
            format!(
                "{}: callable event loop did not quiesce within one second",
                recipe.fixture_id
            )
        })?
        .map_err(|error| {
            format!(
                "{}: callable event-loop completion failed: {error:#}",
                recipe.fixture_id
            )
        })?;
    publications?;
    let encoded = execution
        .map_err(|error| {
            format!(
                "{}: authenticated callable evaluation failed: {error:#}",
                recipe.fixture_id
            )
        })?
        .ok_or_else(|| {
            format!(
                "{}: authenticated callable evaluation returned no result",
                recipe.fixture_id
            )
        })?;
    let harness_result: serde_json::Value = serde_json::from_str(&encoded)
        .map_err(|error| {
            format!(
                "{}: callable harness returned invalid JSON: {error}",
                recipe.fixture_id
            )
        })?;
    validate_source_completion(recipe, &harness_result)?;
    let result = serde_json::json!({
        "kind": "source-completion",
        "sourceCompletionKind": harness_result["kind"],
        "sourceOperationAttempted": harness_result["sourceOperationAttempted"],
        "descriptorProof": harness_result["descriptorProof"],
        "cleanupPerformed": harness_result["cleanupPerformed"],
        "cleanupError": harness_result["cleanupError"],
        "rawOutput": harness_result["rawOutput"],
        "engineExecuted": true,
        "projectCodeExecuted": true,
    });
    let descriptor = &probe.invocation.source_descriptor;
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": probe.invocation.invocation_schema,
            "kind": probe.invocation.kind,
            "surfaceObservedKey": probe.surface_observed_key,
            "globalName": descriptor["globalName"],
            "memberName": descriptor["memberName"],
            "sourceDescriptorDigest": probe.invocation.source_descriptor_digest,
            "completion": {
                "kind": "event-loop-quiescence",
                "timeoutMilliseconds": COMPLETION_TIMEOUT_MILLISECONDS,
                "status": "quiescent",
            },
            "result": result,
        },
        "legacyObservationCount": 0,
        "typedDecisions": [],
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected observation must be an object")
        .insert("result".into(), serde_json::Value::String("passed".into()));
    let mut evidence = serde_json::json!({
        "evidenceSchema": "ibex/capsec-public-surface-fixture-evidence/2",
        "fixtureId": recipe.fixture_id,
        "planDigest": recipe.plan_digest,
        "engineBinaryDigest": engine_binary_digest,
        "probe": probe,
        "terminalObservedKey": probe.surface_observed_key,
        "exitCode": 0,
        "resultMarker": format!("ibex-capsec-public-fixture:{}:passed", recipe.fixture_id),
        "observation": observation,
        "runtimeObservation": runtime_observation,
    });
    let digest = tagged_jcs_digest(&evidence);
    evidence
        .as_object_mut()
        .expect("callable evidence must be an object")
        .insert("evidenceDigest".into(), serde_json::Value::String(digest));
    Ok(serde_json::json!({
        "fixtureId": recipe.fixture_id,
        "outcome": "passed",
        "executor": "ibex-global-callable-public-surface-harness",
        "evidence": evidence,
    }))
}

#[test]
fn capsec_public_global_callable_recipe_counts_are_target_specific() {
    assert_eq!(expected_recipe_count("aarch64-apple-darwin"), 575);
    assert_eq!(expected_recipe_count("x86_64-pc-windows-msvc"), 561);
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_public_global_callable_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping global callable public batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT").ok();
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipes = global_callable_recipes(&catalog);
    assert_eq!(
        recipes.len(),
        expected_recipe_count(&catalog.target.triple),
        "expected the exact authority-free authored global callable slice"
    );
    let terminals = coverage_terminals();
    for (recipe, probe) in &recipes {
        validate_probe(recipe, probe, &terminals);
    }

    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before global callable public probes");
    let portable =
        super::super::capsec_portable_public_batch::PortablePublicBatchContext::begin(
            "ibex-global-callable-public-surface-harness",
        );
    assert_ne!(
        output_path.is_some(),
        portable.is_some(),
        "global callable public batch requires exactly one legacy output or portable plan"
    );
    let (host, digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |_| {});
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))
        .expect("create exact global callable public engine");
    engine
        .load_runtime()
        .await
        .expect("load exact global callable public runtime");
    let mut engine = AuthenticatedBuiltinEngine {
        host,
        engine,
        publications: AuthenticatedPublicationTracker::default(),
    };
    let mut executions = Vec::with_capacity(recipes.len());
    let mut failures = Vec::new();
    let trace_fixtures =
        std::env::var_os("IBEX_CAPSEC_GLOBAL_CALLABLE_TRACE").is_some();
    for (index, (recipe, probe)) in recipes.iter().enumerate() {
        if trace_fixtures {
            eprintln!(
                "CapSec public global callable probe {}/{}: {}",
                index + 1,
                recipes.len(),
                recipe.fixture_id
            );
        }
        match execute_recipe(
            &mut engine,
            recipe,
            probe,
            &identity_before.binary_digest,
        )
        .await
        {
            Ok(execution) => executions.push(execution),
            Err(error) => {
                failures.push(error);
                break;
            }
        }
        if index % 100 == 99 {
            eprintln!(
                "CapSec public global callable probes passed: {}/{}",
                index + 1,
                recipes.len()
            );
        }
    }
    if let Err(error) = engine.finish() {
        failures.push(format!(
            "finish authenticated global callable publication stream: {error:#}"
        ));
    }
    assert!(
        failures.is_empty(),
        "{} global callable public probe(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    executions.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
    assert_eq!(executions.len(), recipes.len());
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after global callable public probes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after global callable public probes");
    if let Some(portable) = portable {
        portable.finish(&executions);
        return;
    }
    let artifact = PublicBatchArtifact {
        public_batch_evidence_schema: "ibex/capsec-public-batch-evidence/1",
        recipe_catalog_digest: catalog.recipe_catalog_digest,
        loaded_engine_identity: identity_before,
        executions,
    };
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path.expect("legacy global callable public batch has no output path"))
        .expect("create owned global callable public evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize global callable public evidence artifact");
    output
        .write_all(b"\n")
        .expect("finish global callable public evidence");
    output
        .sync_all()
        .expect("sync global callable public evidence");
}
