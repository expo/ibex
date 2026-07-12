use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteAlternative {
    terminal_observed_key: String,
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

fn coverage_terminals() -> BTreeMap<String, String> {
    let value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/registry/coverage-edges.json"
    )))
    .expect("checked coverage registry must be JSON");
    value["edges"]
        .as_array()
        .expect("coverage registry must contain edges")
        .iter()
        .map(|edge| {
            let id = edge["id"]
                .as_str()
                .expect("coverage edge must have an id")
                .to_owned();
            let kind = edge["surface"]["kind"]
                .as_str()
                .expect("coverage edge must have a surface kind");
            let name = edge["surface"]["name"]
                .as_str()
                .expect("coverage edge must have a surface name");
            (id, format!("{kind}:{name}"))
        })
        .collect()
}

fn canonical_values(values: impl IntoIterator<Item = serde_json::Value>) -> Vec<serde_json::Value> {
    let mut values = values
        .into_iter()
        .map(|value| {
            (
                capsec_semantics::canonical::to_jcs_bytes(&value)
                    .expect("authority selector must be canonical"),
                value,
            )
        })
        .collect::<Vec<_>>();
    values.sort_by(|left, right| left.0.cmp(&right.0));
    values.dedup_by(|left, right| left.0 == right.0);
    values.into_iter().map(|(_, value)| value).collect()
}

fn builtin_recipes(catalog: &RecipeCatalog) -> Vec<&Recipe> {
    catalog
        .recipes
        .iter()
        .filter(|recipe| {
            recipe.status == "fully-executable"
                && recipe.public_surface_probe.as_ref().is_some_and(|probe| {
                    probe.invocation.invocation_schema
                        == "ibex/capsec-builtin-export-invocation/1"
                })
        })
        .collect()
}

fn invocation_script(invocation: &BuiltinInvocation) -> String {
    format!(
        "JSON.stringify((function(){{var m={};var e={};try{{var api=require(m);var f=api[e];if(typeof f!==\"function\")return {{kind:\"missing\",moduleSpecifier:m,exportName:e}};var value=Reflect.apply(f,api,{});return {{kind:\"return\",moduleSpecifier:m,exportName:e,valueType:value===null?\"null\":typeof value}};}}catch(error){{return {{kind:\"throw\",moduleSpecifier:m,exportName:e,errorName:String(error&&error.name||\"Error\"),errorMessage:String(error&&error.message||error)}};}}}})())",
        serde_json::to_string(&invocation.module_specifier).expect("serialize builtin module"),
        serde_json::to_string(&invocation.export_name).expect("serialize builtin export"),
        serde_json::to_string(&invocation.arguments).expect("serialize builtin arguments")
    )
}

fn typed_decision_values(
    session_id: &str,
    decisions: Vec<ibex_runtime::host::ObservedTypedDecision>,
) -> Vec<serde_json::Value> {
    decisions
        .into_iter()
        .map(|decision| {
            assert_eq!(
                decision.terminal_branch_id, session_id,
                "observer session marker is not terminal evidence"
            );
            let mut value =
                serde_json::to_value(decision).expect("serialize observed typed decision");
            value
                .as_object_mut()
                .expect("observed decision must be an object")
                .remove("terminalBranchId");
            value
        })
        .collect()
}

fn validate_observation(
    recipe: &Recipe,
    probe: &PublicSurfaceProbe,
    invocation_result: &serde_json::Value,
    legacy_count: usize,
    typed_decisions: &[serde_json::Value],
    terminal_by_edge: &BTreeMap<String, String>,
) -> String {
    let invocation = &probe.invocation;
    assert_eq!(recipe.classification, "effects");
    assert!(matches!(recipe.scenario.as_str(), "allow" | "deny"));
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(!probe.command.is_empty());
    assert_eq!(
        invocation.invocation_schema,
        "ibex/capsec-builtin-export-invocation/1"
    );
    assert_eq!(invocation.kind, "builtin-export-call");
    assert_eq!(invocation.expected_action_ids, recipe.action_ids);
    assert_eq!(invocation.setup, serde_json::json!({"kind": "none"}));
    assert_eq!(
        tagged_jcs_digest(&invocation.source_descriptor),
        invocation.source_descriptor_digest,
        "{}: source descriptor digest drift",
        recipe.fixture_id
    );
    assert_eq!(legacy_count, 0, "legacy checks are not typed evidence");
    assert_eq!(
        typed_decisions.len(),
        invocation.expected_typed_decision_count,
        "{}: wrong typed decision count",
        recipe.fixture_id
    );
    match invocation.expected_result.as_str() {
        "return" => assert_eq!(invocation_result["kind"], "return"),
        "permission-denied" => {
            assert_eq!(invocation_result["kind"], "throw");
            assert!(
                invocation_result["errorMessage"]
                    .as_str()
                    .is_some_and(|message| message.contains("Permission denied")),
                "{}: denial threw the wrong error: {invocation_result}",
                recipe.fixture_id
            );
        }
        other => panic!("unsupported expected builtin result {other}"),
    }

    let stages = typed_decisions
        .iter()
        .map(|decision| {
            decision["decisionSet"]["context"]["stage"]
                .as_str()
                .expect("observed decision has no stage")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(stages, invocation.expected_typed_stages);
    let allowed_edges = invocation
        .allowed_coverage_edge_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(!allowed_edges.is_empty());
    let mut observed_edges = BTreeSet::new();
    let mut observed_actions = BTreeSet::new();
    let mut observed_terminals = BTreeSet::new();
    for decision in typed_decisions {
        let set = &decision["decisionSet"];
        let effects = set["effects"]
            .as_array()
            .expect("observed decision has no effects");
        let gates = decision["gates"]
            .as_array()
            .expect("observed decision has no gates");
        assert_eq!(effects.len(), gates.len());
        for effect in effects {
            observed_actions.insert(
                effect["cap"]
                    .as_str()
                    .expect("observed effect has no action")
                    .to_owned(),
            );
        }
        for gate in gates {
            let edge_id = gate["coverageEdgeId"]
                .as_str()
                .expect("observed gate has no coverage edge");
            assert!(allowed_edges.contains(edge_id));
            assert_eq!(set["atomicityGroup"], format!("{edge_id}.decision"));
            assert_eq!(gate["targetCell"], "complete");
            assert_eq!(gate["definitionAndEdgePredicatesSatisfied"], true);
            observed_edges.insert(edge_id.to_owned());
            observed_terminals.insert(
                terminal_by_edge
                    .get(edge_id)
                    .unwrap_or_else(|| panic!("unknown observed edge {edge_id}"))
                    .clone(),
            );
        }
        let expected_outcome = if recipe.scenario == "deny" {
            "deny"
        } else {
            "allow"
        };
        assert_eq!(decision["evidence"]["outcome"], expected_outcome);
        let decisive = decision["evidence"]["evidence"]
            .as_array()
            .expect("observed decision has no decisive evidence");
        assert_eq!(
            decisive.len(),
            1,
            "{}: system-info decision must have one decisive authority row",
            recipe.fixture_id
        );
        let (expected_stratum, expected_reason, expected_source) =
            if recipe.scenario == "deny" {
                (
                    "principal-denial",
                    "principal-denial",
                    "principal.000000.denial.000000",
                )
            } else {
                (
                    "static-floor",
                    "static-floor",
                    "principal.000000.floor.000000",
                )
            };
        assert_eq!(decisive[0]["stratum"], expected_stratum);
        assert_eq!(decisive[0]["reason"], expected_reason);
        assert_eq!(decisive[0]["sourceId"], expected_source);
    }
    assert!(!observed_edges.is_empty());
    assert!(observed_edges.is_subset(&allowed_edges));
    assert_eq!(
        observed_actions.into_iter().collect::<Vec<_>>(),
        invocation.expected_action_ids
    );
    assert_eq!(observed_terminals.len(), 1);
    let terminal = observed_terminals.into_iter().next().unwrap();
    assert!(
        recipe
            .route
            .alternatives
            .iter()
            .any(|alternative| alternative.terminal_observed_key == terminal),
        "{}: runtime terminal {terminal} is outside the source-derived route",
        recipe.fixture_id
    );
    terminal
}

async fn execute_recipe(
    engine: &HermesEngine,
    recipe: &Recipe,
    terminal_by_edge: &BTreeMap<String, String>,
    engine_binary_digest: &str,
) -> serde_json::Value {
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
        .expect("execute public builtin invocation")
        .expect("public builtin invocation returned no result");
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    let invocation_result: serde_json::Value =
        serde_json::from_str(&encoded).expect("public builtin returned invalid JSON");
    let typed_decisions = typed_decision_values(&session_id, typed);
    let terminal = validate_observation(
        recipe,
        probe,
        &invocation_result,
        legacy.len(),
        &typed_decisions,
        terminal_by_edge,
    );
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
        "legacyObservationCount": legacy.len(),
        "typedDecisions": typed_decisions,
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
        "terminalObservedKey": terminal,
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
    serde_json::json!({
        "fixtureId": recipe.fixture_id,
        "outcome": "passed",
        "executor": "ibex-builtin-public-surface-harness",
        "evidence": evidence,
    })
}

async fn execute_isolated_recipe(
    recipe: &Recipe,
    terminal_by_edge: &BTreeMap<String, String>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let authority = canonical_values(
        recipe
            .public_surface_probe
            .as_ref()
            .unwrap()
            .invocation
            .required_authority
            .clone(),
    );
    assert_eq!(
        authority.len(),
        1,
        "{}: isolated OS recipe must bind one exact authority selector",
        recipe.fixture_id
    );
    let (host, digest) = build_armed_test_host_custom(
        None,
        false,
        false,
        false,
        Vec::new(),
        None,
        |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] =
                serde_json::json!(["node:os"]);
            snapshot["principals"][0]["floor"] =
                serde_json::Value::Array(authority.clone());
            if recipe.scenario == "deny" {
                snapshot["principals"][0]["denials"] =
                    serde_json::Value::Array(authority.clone());
            }
        },
    );
    assert_ne!(crate::host::abi::install_host(host), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))
        .expect("create exact public builtin engine");
    engine
        .load_runtime()
        .await
        .expect("load exact public builtin runtime");
    execute_recipe(
        &engine,
        recipe,
        terminal_by_edge,
        engine_binary_digest,
    )
    .await
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn capsec_public_builtin_recipe_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping builtin public recipe batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT")
        .expect("builtin public recipe batch requires an owned evidence output path");
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipes = builtin_recipes(&catalog);
    assert_eq!(recipes.len(), 36, "expected the authored node:os recipe slice");
    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before builtin public recipes");
    let terminal_by_edge = coverage_terminals();
    let mut executions = Vec::with_capacity(recipes.len());
    for recipe in &recipes {
        executions.push(
            execute_isolated_recipe(
                recipe,
                &terminal_by_edge,
                &identity_before.binary_digest,
            )
            .await,
        );
    }
    executions.sort_by(|left, right| {
        left["fixtureId"]
            .as_str()
            .cmp(&right["fixtureId"].as_str())
    });
    assert_eq!(executions.len(), recipes.len());
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after builtin public recipes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after builtin public recipes");
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
        .expect("create owned builtin public evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize builtin public evidence artifact");
    output.write_all(b"\n").expect("finish builtin public evidence");
    output.sync_all().expect("sync builtin public evidence");
}
