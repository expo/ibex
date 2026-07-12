use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write as _;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecipeCatalog {
    recipe_catalog_schema: String,
    recipe_catalog_digest: String,
    recipes: Vec<Recipe>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recipe {
    fixture_id: String,
    plan_digest: String,
    classification: String,
    scenario: String,
    action_ids: Vec<String>,
    expected_observation: serde_json::Value,
    route: PublicRoute,
    status: String,
    public_surface_probe: Option<PublicSurfaceProbe>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicRoute {
    alternatives: Vec<RouteAlternative>,
    ambiguous_callees: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteAlternative {
    terminal_observed_key: String,
    proof_paths: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicSurfaceProbe {
    kind: String,
    surface_observed_key: String,
    command: Vec<String>,
    invocation: BuiltinInvocation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BuiltinInvocation {
    invocation_schema: String,
    kind: String,
    module_specifier: String,
    export_name: String,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    arguments: Vec<serde_json::Value>,
    setup: serde_json::Value,
    required_authority: Vec<serde_json::Value>,
    expected_result: String,
    expected_typed_decision_count: usize,
    expected_typed_stages: Vec<String>,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BuiltinSourceDescriptor {
    kind: String,
    source_key: String,
    export_name: String,
    export_idioms: Vec<String>,
    module_specifiers: Vec<String>,
    source_ref: String,
    value_shape: String,
    #[serde(default)]
    platform_availability: Option<Vec<String>>,
    access: BuiltinAccess,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct BuiltinAccess {
    kind: String,
    path: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicBatchArtifact {
    public_batch_evidence_schema: &'static str,
    recipe_catalog_digest: String,
    loaded_engine_identity: ibex_runtime::engine::LoadedEngineBinaryIdentity,
    executions: Vec<serde_json::Value>,
}

fn tagged_jcs_digest(value: &serde_json::Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("public recipe evidence must have a canonical JSON encoding");
    let digest = sha2::Sha256::digest(bytes);
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

fn load_catalog(path: &std::path::Path) -> RecipeCatalog {
    let bytes = std::fs::read(path).expect("read CapSec executable recipe catalog");
    let text = std::str::from_utf8(&bytes).expect("recipe catalog must be UTF-8");
    let value = capsec_semantics::strict_json::parse_strict(text)
        .expect("recipe catalog must be strict JSON");
    let expected_digest = value["recipeCatalogDigest"]
        .as_str()
        .expect("recipe catalog has no digest");
    let mut projected = value.clone();
    projected
        .as_object_mut()
        .expect("recipe catalog must be an object")
        .remove("recipeCatalogDigest");
    assert_eq!(
        tagged_jcs_digest(&projected),
        expected_digest,
        "recipe catalog digest mismatch"
    );
    let catalog: RecipeCatalog =
        serde_json::from_value(value).expect("recipe catalog shape must be valid");
    assert_eq!(
        catalog.recipe_catalog_schema,
        "ibex/capsec-executable-recipes/1"
    );
    assert!(
        catalog
            .recipes
            .windows(2)
            .all(|pair| pair[0].fixture_id < pair[1].fixture_id),
        "recipe fixtures must be a strictly sorted set"
    );
    catalog
}

fn is_sorted_set(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn module_specifier_rank(value: &str) -> u8 {
    if value.starts_with("node:") {
        0
    } else if value.starts_with("exact:") {
        1
    } else if value.starts_with("bun:") {
        2
    } else if value.starts_with("internal/") {
        3
    } else {
        4
    }
}

fn canonical_module_specifier(values: &[String]) -> Option<&str> {
    values
        .iter()
        .min_by_key(|value| (module_specifier_rank(value), value.as_str()))
        .map(String::as_str)
}

fn expected_access(descriptor: &BuiltinSourceDescriptor) -> Option<BuiltinAccess> {
    if descriptor.export_name.contains("[[") || descriptor.export_name.contains("]]") {
        return None;
    }
    let segments = descriptor
        .export_name
        .split('.')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if segments.iter().any(String::is_empty) {
        return None;
    }
    let prototype_idioms = descriptor
        .export_idioms
        .iter()
        .filter(|idiom| {
            matches!(
                idiom.as_str(),
                "exported-constructor-prototype" | "exported-constructor-inherited-prototype"
            )
        })
        .collect::<Vec<_>>();
    if !prototype_idioms.is_empty() {
        if prototype_idioms.len() != descriptor.export_idioms.len() || segments.len() < 2 {
            return None;
        }
        let mut path = vec![segments[0].clone(), "prototype".to_owned()];
        path.extend_from_slice(&segments[1..]);
        return Some(BuiltinAccess {
            kind: if prototype_idioms[0].as_str() == "exported-constructor-inherited-prototype" {
                "inherited-prototype-property".to_owned()
            } else {
                "prototype-property".to_owned()
            },
            path,
        });
    }
    if descriptor.export_name == "default"
        && descriptor
            .export_idioms
            .iter()
            .any(|idiom| idiom == "module-exports-assignment")
    {
        return Some(BuiltinAccess {
            kind: "module-value".to_owned(),
            path: Vec::new(),
        });
    }
    Some(BuiltinAccess {
        kind: "export-property".to_owned(),
        path: segments,
    })
}

fn validate_probe(recipe: &Recipe, probe: &PublicSurfaceProbe) {
    let invocation = &probe.invocation;
    let descriptor: BuiltinSourceDescriptor =
        serde_json::from_value(invocation.source_descriptor.clone())
            .expect("non-capability builtin source descriptor must be typed");
    assert_eq!(recipe.classification, "non-capability");
    assert_eq!(recipe.scenario, "non-capability");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(!probe.command.is_empty());
    assert_eq!(
        invocation.invocation_schema,
        "ibex/capsec-builtin-export-invocation/1"
    );
    assert_eq!(invocation.kind, "builtin-export-read");
    assert_eq!(invocation.expected_result, "return");
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert!(invocation.allowed_coverage_edge_ids.is_empty());
    assert!(invocation.expected_action_ids.is_empty());
    assert!(invocation.arguments.is_empty());
    assert!(invocation.required_authority.is_empty());
    assert_eq!(invocation.setup, serde_json::json!({"kind": "none"}));
    assert_eq!(descriptor.kind, "builtin-export");
    assert!(!descriptor.source_key.is_empty());
    assert_ne!(descriptor.source_key, "node_os");
    assert_eq!(descriptor.export_name, invocation.export_name);
    assert!(!descriptor.source_ref.is_empty());
    assert!(matches!(
        descriptor.value_shape.as_str(),
        "accessor" | "data"
    ));
    if let Some(platforms) = descriptor.platform_availability.as_deref() {
        assert!(!platforms.is_empty());
        assert!(is_sorted_set(platforms));
        assert!(platforms
            .iter()
            .all(|platform| matches!(platform.as_str(), "android" | "darwin" | "linux")));
        assert!(platforms.iter().any(|platform| platform == "darwin"));
    }
    assert!(!descriptor.export_idioms.is_empty());
    assert!(is_sorted_set(&descriptor.export_idioms));
    assert!(!descriptor.module_specifiers.is_empty());
    assert!(is_sorted_set(&descriptor.module_specifiers));
    assert_eq!(
        canonical_module_specifier(&descriptor.module_specifiers),
        Some(invocation.module_specifier.as_str())
    );
    assert_eq!(
        expected_access(&descriptor).as_ref(),
        Some(&descriptor.access)
    );
    assert!(matches!(
        descriptor.access.kind.as_str(),
        "export-property" | "module-value"
    ));
    if descriptor.value_shape == "accessor" {
        assert_eq!(descriptor.access.kind, "export-property");
    }
    assert_eq!(
        probe.surface_observed_key,
        format!(
            "builtin:export:{}:{}",
            descriptor.source_key, descriptor.export_name
        )
    );
    assert_eq!(recipe.route.ambiguous_callees, Vec::<String>::new());
    assert_eq!(recipe.route.alternatives.len(), 1);
    assert_eq!(
        recipe.route.alternatives[0].terminal_observed_key,
        probe.surface_observed_key
    );
    assert!(!recipe.route.alternatives[0].proof_paths.is_empty());
    assert_eq!(
        tagged_jcs_digest(&invocation.source_descriptor),
        invocation.source_descriptor_digest,
        "{}: source descriptor digest drift",
        recipe.fixture_id
    );
}

fn noncap_builtin_recipes(catalog: &RecipeCatalog) -> Vec<&Recipe> {
    catalog
        .recipes
        .iter()
        .filter(|recipe| {
            recipe.status == "fully-executable"
                && recipe.public_surface_probe.as_ref().is_some_and(|probe| {
                    probe.invocation.invocation_schema == "ibex/capsec-builtin-export-invocation/1"
                        && probe.invocation.kind == "builtin-export-read"
                })
        })
        .inspect(|recipe| validate_probe(recipe, recipe.public_surface_probe.as_ref().unwrap()))
        .collect()
}

fn invocation_script(invocation: &BuiltinInvocation) -> String {
    let descriptor: BuiltinSourceDescriptor =
        serde_json::from_value(invocation.source_descriptor.clone())
            .expect("non-capability builtin source descriptor must be typed");
    let access = &descriptor.access;
    format!(
        "JSON.stringify((function(){{var m={};var e={};var access={};var shape={};try{{var value=require(m);var own=Object.prototype.hasOwnProperty;if(access.kind!==\"module-value\"){{for(var i=0;i<access.path.length;i++){{var key=access.path[i];if(value===null||(typeof value!==\"object\"&&typeof value!==\"function\"))return {{kind:\"missing\",moduleSpecifier:m,exportName:e,segment:key,available:[]}};if(!own.call(value,key))return {{kind:\"missing\",moduleSpecifier:m,exportName:e,segment:key,available:Object.getOwnPropertyNames(value).slice(0,32)}};if(i===access.path.length-1){{var propertyDescriptor=Object.getOwnPropertyDescriptor(value,key);if(shape===\"accessor\"&&(!propertyDescriptor||typeof propertyDescriptor.get!==\"function\"))return {{kind:\"shape-mismatch\",moduleSpecifier:m,exportName:e,expectedShape:shape}};if(shape===\"data\"&&(!propertyDescriptor||!(\"value\" in propertyDescriptor)))return {{kind:\"shape-mismatch\",moduleSpecifier:m,exportName:e,expectedShape:shape}};}}value=value[key];}}}}if(shape===\"data\"&&typeof value===\"function\")return {{kind:\"shape-mismatch\",moduleSpecifier:m,exportName:e,expectedShape:shape,actualType:typeof value}};return {{kind:\"return\",moduleSpecifier:m,exportName:e,valueType:value===null?\"null\":typeof value}};}}catch(error){{return {{kind:\"throw\",moduleSpecifier:m,exportName:e,errorName:String(error&&error.name||\"Error\"),errorMessage:String(error&&error.message||error)}};}}}})())",
        serde_json::to_string(&invocation.module_specifier).expect("serialize builtin module"),
        serde_json::to_string(&invocation.export_name).expect("serialize builtin export"),
        serde_json::to_string(access).expect("serialize builtin access path"),
        serde_json::to_string(&descriptor.value_shape).expect("serialize builtin value shape")
    )
}

async fn execute_recipe(
    engine: &HermesEngine,
    recipe: &Recipe,
    engine_binary_digest: &str,
) -> std::result::Result<serde_json::Value, String> {
    let probe = recipe
        .public_surface_probe
        .as_ref()
        .expect("builtin recipe has no public probe");
    let session_id = format!("public-observation:{}", recipe.plan_digest);
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id),
        "public builtin observer has no installed host"
    );
    let encoded = engine
        .eval_immediate(&invocation_script(&probe.invocation))
        .await
        .expect("execute public builtin read")
        .expect("public builtin read returned no result");
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    let invocation_result: serde_json::Value =
        serde_json::from_str(&encoded).expect("public builtin returned invalid JSON");
    if invocation_result["kind"] != "return" {
        return Err(format!(
            "{}: public export read failed: {invocation_result}",
            recipe.fixture_id
        ));
    }
    if !legacy.is_empty() || !typed.is_empty() {
        return Err(format!(
            "{}: non-capability export read observed {} legacy and {} typed decisions",
            recipe.fixture_id,
            legacy.len(),
            typed.len()
        ));
    }
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": probe.invocation.invocation_schema,
            "kind": probe.invocation.kind,
            "surfaceObservedKey": probe.surface_observed_key,
            "moduleSpecifier": probe.invocation.module_specifier,
            "exportName": probe.invocation.export_name,
            "sourceDescriptorDigest": probe.invocation.source_descriptor_digest,
            "result": invocation_result,
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
        .unwrap()
        .insert("evidenceDigest".into(), serde_json::Value::String(digest));
    Ok(serde_json::json!({
        "fixtureId": recipe.fixture_id,
        "outcome": "passed",
        "executor": "ibex-noncap-builtin-public-surface-harness",
        "evidence": evidence,
    }))
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_public_noncap_builtin_recipe_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping noncap builtin public batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT")
        .expect("noncap builtin public batch requires an owned evidence output path");
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipes = noncap_builtin_recipes(&catalog);
    assert!(
        !recipes.is_empty(),
        "recipe catalog contains no non-capability builtin reads"
    );
    let builtin_imports = recipes
        .iter()
        .map(|recipe| {
            recipe
                .public_surface_probe
                .as_ref()
                .unwrap()
                .invocation
                .module_specifier
                .clone()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let _lock = hermes_engine_test_lock().lock().await;
    let (host, digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] = serde_json::json!(builtin_imports);
        });
    assert_ne!(crate::host::abi::install_host(host), 0);
    let _reset = HostResetGuard;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before noncap builtin public recipes");
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))
        .expect("create exact noncap builtin engine");
    engine
        .load_runtime()
        .await
        .expect("load exact noncap builtin runtime");
    let mut executions = Vec::with_capacity(recipes.len());
    let mut failures = Vec::new();
    for (index, recipe) in recipes.iter().enumerate() {
        match execute_recipe(&engine, recipe, &identity_before.binary_digest).await {
            Ok(execution) => executions.push(execution),
            Err(error) => failures.push(error),
        }
        if index % 256 == 255 {
            eprintln!(
                "CapSec public non-capability builtin reads passed: {}/{}",
                index + 1,
                recipes.len()
            );
        }
    }
    assert!(
        failures.is_empty(),
        "{} non-capability builtin public reads failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    executions.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
    assert_eq!(executions.len(), recipes.len());
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after noncap builtin public recipes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after noncap builtin public recipes");
    let artifact = PublicBatchArtifact {
        public_batch_evidence_schema: "ibex/capsec-public-batch-evidence/1",
        recipe_catalog_digest: catalog.recipe_catalog_digest,
        loaded_engine_identity: identity_before,
        executions,
    };
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("create owned noncap builtin public evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize noncap builtin public evidence artifact");
    output.write_all(b"\n").expect("finish builtin evidence");
    output.sync_all().expect("sync builtin evidence artifact");
}

#[tokio::test(flavor = "current_thread")]
async fn manifest_builtin_fanout_preserves_terminal_authority_checks() {
    let temp = tempfile::tempdir().expect("create builtin terminal fixture root");
    let root = std::fs::canonicalize(temp.path()).expect("canonicalize builtin terminal root");
    let secret = root.join("secret.txt");
    std::fs::write(&secret, b"must stay unread").expect("write builtin terminal fixture");
    let _lock = hermes_engine_test_lock().lock().await;
    let (host, digest) = build_armed_test_host_custom(
        Some(&root),
        false,
        false,
        false,
        Vec::new(),
        None,
        |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] = serde_json::json!(["node:fs"]);
        },
    );
    assert_ne!(crate::host::abi::install_host(host), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))
        .expect("create exact builtin terminal authority engine");
    engine
        .load_runtime()
        .await
        .expect("load exact builtin terminal authority runtime");
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(
            "public.builtin.internal-fanout-terminal-denial"
        )
    );
    let script = format!(
        "(function(){{var fs;try{{fs=require('node:fs');}}catch(error){{return 'import-denied';}}try{{fs.readFileSync({},'utf8');return 'terminal-allowed';}}catch(error){{return 'terminal-denied';}}}})()",
        serde_json::to_string(&secret.to_string_lossy()).expect("serialize terminal fixture path")
    );
    let result = engine
        .eval_immediate(&script)
        .await
        .expect("execute builtin terminal denial")
        .expect("builtin terminal denial returned no result");
    assert_eq!(
        result, "terminal-denied",
        "builtin import must succeed but its terminal must deny"
    );
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(
        legacy.is_empty(),
        "rev2 terminal must not consult legacy gates"
    );
    assert!(
        !typed.is_empty(),
        "the fs terminal must execute a typed decision"
    );
    assert!(typed.iter().any(|decision| {
        decision.evidence.outcome == capsec_semantics::decision::DecisionOutcome::Deny
    }));
}
