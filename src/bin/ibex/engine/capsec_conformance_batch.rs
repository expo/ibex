use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecipeCatalog {
    recipe_catalog_schema: String,
    recipe_catalog_digest: String,
    summary: RecipeSummary,
    recipes: Vec<Recipe>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecipeSummary {
    required_fixtures: usize,
    adapter_executable_fixtures: usize,
    fully_executable_fixtures: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recipe {
    fixture_id: String,
    plan_digest: String,
    classification: String,
    scenario: String,
    edge_ids: Vec<String>,
    action_ids: Vec<String>,
    terminal_observed_key: String,
    expected_observation: serde_json::Value,
    route: RecipeRoute,
    adapter_probe: Option<AdapterProbe>,
    public_surface_probe: Option<PublicSurfaceProbe>,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecipeRoute {
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
    invocation: PublicInvocation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "invocationSchema")]
enum PublicInvocation {
    #[serde(rename = "ibex/capsec-native-global-invocation/1")]
    NativeGlobal {
        #[serde(flatten)]
        details: NativePublicInvocation,
    },
    #[serde(rename = "ibex/capsec-builtin-export-invocation/1")]
    BuiltinExport {
        #[serde(flatten)]
        details: BuiltinPublicInvocation,
    },
}

impl PublicInvocation {
    fn native(&self) -> Option<&NativePublicInvocation> {
        match self {
            Self::NativeGlobal { details } => Some(details),
            Self::BuiltinExport { .. } => None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativePublicInvocation {
    kind: String,
    global_name: String,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    arguments: Vec<NativeProbeArgument>,
    setup: Vec<NativeProbeSetup>,
    expected_result: String,
    expected_typed_stages: Vec<String>,
    expected_typed_decision_count: usize,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BuiltinPublicInvocation {
    kind: String,
    module_specifier: String,
    export_name: String,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    arguments: Vec<serde_json::Value>,
    expected_result: String,
    expected_typed_stages: Vec<String>,
    expected_typed_decision_count: usize,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum NativeProbeArgument {
    JsonLiteral { value: serde_json::Value },
    HarnessLoopbackAddress { family: String },
    HarnessLoopbackListenerPort,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum NativeProbeSetup {
    InvokeNativeGlobal {
        #[serde(rename = "globalName")]
        global_name: String,
        arguments: Vec<serde_json::Value>,
    },
    TcpLoopbackListener,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdapterProbe {
    operation: String,
    terminal_branch_id: String,
    cases: Vec<ProbeCase>,
    required_floor: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProbeCase {
    stage: String,
    action_ids: Vec<String>,
    decision_set_json: String,
    gates_json: String,
    expected: ExpectedProbe,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedProbe {
    adapter: String,
    legacy_observations: usize,
    typed_observations: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseEvidence {
    stage: String,
    action_ids: Vec<String>,
    adapter_result: String,
    response_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FixtureEvidence {
    fixture_id: String,
    plan_digest: String,
    cases: Vec<CaseEvidence>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceSummary {
    adapter_executable_fixtures: usize,
    executed_cases: usize,
    passed_cases: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdapterEvidenceArtifact {
    adapter_evidence_schema: &'static str,
    recipe_catalog_digest: String,
    loaded_engine_identity: ibex_runtime::engine::LoadedEngineBinaryIdentity,
    summary: EvidenceSummary,
    fixtures: Vec<FixtureEvidence>,
}

struct WorkItem<'a> {
    recipe: &'a Recipe,
    probe: &'a AdapterProbe,
    case: &'a ProbeCase,
}

fn tagged_jcs_digest(value: &serde_json::Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("recipe evidence must have a canonical JSON encoding");
    let digest = sha2::Sha256::digest(bytes);
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

fn load_recipe_catalog(path: &std::path::Path) -> RecipeCatalog {
    let bytes = std::fs::read(path).expect("read CapSec executable recipe catalog");
    let text = std::str::from_utf8(&bytes).expect("recipe catalog must be UTF-8");
    let value = capsec_semantics::strict_json::parse_strict(text)
        .expect("recipe catalog must be strict JSON");
    let expected_digest = value
        .get("recipeCatalogDigest")
        .and_then(serde_json::Value::as_str)
        .expect("recipe catalog has no digest")
        .to_owned();
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
    assert_eq!(catalog.summary.required_fixtures, catalog.recipes.len());
    assert!(
        catalog
            .recipes
            .windows(2)
            .all(|pair| pair[0].fixture_id < pair[1].fixture_id),
        "recipe fixtures must be a strictly sorted set"
    );
    let observed_adapter_recipes = catalog
        .recipes
        .iter()
        .filter(|recipe| recipe.adapter_probe.is_some())
        .count();
    assert_eq!(
        observed_adapter_recipes, catalog.summary.adapter_executable_fixtures,
        "adapter recipe summary drift"
    );
    let observed_fully_executable = catalog
        .recipes
        .iter()
        .filter(|recipe| recipe.status == "fully-executable")
        .count();
    assert_eq!(
        observed_fully_executable, catalog.summary.fully_executable_fixtures,
        "fully executable recipe summary drift"
    );
    catalog
}

fn required_floor(catalog: &RecipeCatalog) -> Vec<serde_json::Value> {
    let mut selectors = BTreeMap::new();
    for selector in catalog
        .recipes
        .iter()
        .filter_map(|recipe| recipe.adapter_probe.as_ref())
        .flat_map(|probe| &probe.required_floor)
    {
        let key = capsec_semantics::canonical::to_jcs_bytes(selector)
            .expect("authority selector must have canonical JSON");
        selectors.entry(key).or_insert_with(|| selector.clone());
    }
    selectors.into_values().collect()
}

fn validate_response(item: &WorkItem<'_>, response: &serde_json::Value) -> CaseEvidence {
    let legacy = response["legacyObservations"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: response has no legacy observations", item.recipe.fixture_id));
    let typed = response["typedObservations"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: response has no typed observations", item.recipe.fixture_id));
    assert_eq!(
        legacy.len(),
        item.case.expected.legacy_observations,
        "{}:{}: unexpected legacy observation count: {response}",
        item.recipe.fixture_id,
        item.case.stage
    );
    assert_eq!(
        typed.len(),
        item.case.expected.typed_observations,
        "{}:{}: unexpected typed observation count: {response}",
        item.recipe.fixture_id,
        item.case.stage
    );

    let adapter_result = if item.case.expected.adapter == "error" {
        assert!(
            response["adapter"]["error"].as_str().is_some(),
            "{}:{}: adapter did not reject malformed input: {response}",
            item.recipe.fixture_id,
            item.case.stage
        );
        "error".to_owned()
    } else {
        let outcome = response["adapter"]["decision"]["outcome"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "{}:{}: adapter returned no decision: {response}",
                    item.recipe.fixture_id, item.case.stage
                )
            });
        assert_eq!(
            outcome, item.case.expected.adapter,
            "{}:{}: adapter outcome mismatch: {response}",
            item.recipe.fixture_id, item.case.stage
        );
        outcome.to_owned()
    };

    if let Some(observed) = typed.first() {
        assert_eq!(
            observed["terminalBranchId"].as_str(),
            Some(item.probe.terminal_branch_id.as_str()),
            "{}:{}: observer branch mismatch",
            item.recipe.fixture_id,
            item.case.stage
        );
        let decision = capsec_semantics::strict_json::parse_strict(&item.case.decision_set_json)
            .expect("non-malformed decision case must be strict JSON");
        let gates = capsec_semantics::strict_json::parse_strict(&item.case.gates_json)
            .expect("effect gates must be strict JSON");
        assert_eq!(
            observed["decisionSet"], decision,
            "{}:{}: observer decision-set mismatch",
            item.recipe.fixture_id, item.case.stage
        );
        assert_eq!(
            observed["gates"], gates,
            "{}:{}: observer gates mismatch",
            item.recipe.fixture_id, item.case.stage
        );
    }

    CaseEvidence {
        stage: item.case.stage.clone(),
        action_ids: item.case.action_ids.clone(),
        adapter_result,
        response_digest: tagged_jcs_digest(response),
    }
}

async fn execute_chunk(
    engine: &HermesEngine,
    items: &[WorkItem<'_>],
) -> Vec<CaseEvidence> {
    let requests = items
        .iter()
        .map(|item| {
            serde_json::json!({
                "operation": item.probe.operation,
                "request": {
                    "terminalBranchId": item.probe.terminal_branch_id,
                    "decisionSetJson": item.case.decision_set_json,
                    "gatesJson": item.case.gates_json,
                }
            })
        })
        .collect::<Vec<_>>();
    let script = format!(
        "JSON.stringify(({}).map(function(r){{try{{return {{value:__hostCall(r.operation,r.request)}};}}catch(e){{return {{threw:String(e)}};}}}}))",
        serde_json::to_string(&requests).expect("serialize adapter request chunk")
    );
    let encoded = engine
        .eval_immediate(&script)
        .await
        .expect("execute adapter request chunk in Hermes")
        .expect("Hermes adapter request chunk returned no result");
    let responses: Vec<serde_json::Value> =
        serde_json::from_str(&encoded).expect("Hermes adapter chunk returned invalid JSON");
    assert_eq!(responses.len(), items.len());
    items
        .iter()
        .zip(responses)
        .map(|(item, wrapper)| {
            if let Some(error) = wrapper["threw"].as_str() {
                panic!(
                    "{}:{}: Hermes host call threw: {error}",
                    item.recipe.fixture_id, item.case.stage
                );
            }
            validate_response(item, &wrapper["value"])
        })
        .collect()
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_executable_recipe_adapter_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping external recipe batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT")
        .expect("recipe batch requires an owned adapter evidence output path");
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_recipe_catalog(&recipe_path);
    let _lock = hermes_engine_test_lock().lock().await;
    let (_reset, snapshot_digest) =
        install_armed_test_host_at(None, false, false, false, required_floor(&catalog));
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before adapter recipes");
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create recipe engine with exact armed snapshot");
    engine
        .load_runtime()
        .await
        .expect("load runtime in exact recipe engine");

    let work = catalog
        .recipes
        .iter()
        .flat_map(|recipe| {
            recipe.adapter_probe.iter().flat_map(move |probe| {
                probe.cases.iter().map(move |case| WorkItem {
                    recipe,
                    probe,
                    case,
                })
            })
        })
        .collect::<Vec<_>>();
    let mut fixtures = BTreeMap::<String, FixtureEvidence>::new();
    let mut passed_cases = 0usize;
    for chunk in work.chunks(64) {
        let evidence = execute_chunk(&engine, chunk).await;
        for (item, case_evidence) in chunk.iter().zip(evidence) {
            fixtures
                .entry(item.recipe.fixture_id.clone())
                .or_insert_with(|| FixtureEvidence {
                    fixture_id: item.recipe.fixture_id.clone(),
                    plan_digest: item.recipe.plan_digest.clone(),
                    cases: Vec::new(),
                })
                .cases
                .push(case_evidence);
            passed_cases += 1;
        }
        if passed_cases % 1024 < chunk.len() {
            eprintln!("CapSec typed-adapter cases passed: {passed_cases}/{}", work.len());
        }
    }
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after adapter recipes");
    assert_eq!(
        identity_after, identity_before,
        "loaded engine identity changed across recipe execution"
    );
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after adapter recipes");
    assert_eq!(fixtures.len(), catalog.summary.adapter_executable_fixtures);
    assert_eq!(passed_cases, work.len());
    let artifact = AdapterEvidenceArtifact {
        adapter_evidence_schema: "ibex/capsec-adapter-probe-evidence/1",
        recipe_catalog_digest: catalog.recipe_catalog_digest,
        loaded_engine_identity: identity_before,
        summary: EvidenceSummary {
            adapter_executable_fixtures: fixtures.len(),
            executed_cases: work.len(),
            passed_cases,
        },
        fixtures: fixtures.into_values().collect(),
    };
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("create owned CapSec adapter evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize CapSec adapter evidence artifact");
    output.write_all(b"\n").expect("finish adapter evidence");
    output.sync_all().expect("sync adapter evidence artifact");
}
