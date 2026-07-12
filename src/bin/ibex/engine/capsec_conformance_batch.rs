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
    #[serde(default)]
    required_floor: Vec<serde_json::Value>,
    setup: Vec<NativeProbeSetup>,
    expected_result: String,
    expected_typed_stages: Vec<String>,
    expected_typed_decision_count: usize,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GlobalReadSourceDescriptor {
    kind: String,
    source_key: String,
    export_name: String,
    global_name: String,
    member_kinds: Vec<String>,
    source_refs: Vec<String>,
    value_shape: String,
    access: GlobalReadAccess,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GlobalReadAccess {
    kind: String,
    path: Vec<String>,
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
    JsonLiteral {
        value: serde_json::Value,
    },
    HarnessNoopCallback,
    HarnessLoopbackClientHandle,
    HarnessLoopbackAddress {
        family: String,
    },
    HarnessLoopbackListenerPort,
    NativeGlobalResult {
        #[serde(rename = "globalName")]
        global_name: String,
        arguments: Vec<NativeProbeArgument>,
        #[serde(rename = "sourceDescriptor")]
        source_descriptor: serde_json::Value,
        #[serde(rename = "sourceDescriptorDigest")]
        source_descriptor_digest: String,
    },
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // dependent key arguments must project the same source-bound producer
    // result rather than silently generating unrelated fixtures.
    NativeGlobalResultProperty {
        property: String,
        #[serde(rename = "globalName")]
        global_name: String,
        arguments: Vec<NativeProbeArgument>,
        #[serde(rename = "sourceDescriptor")]
        source_descriptor: serde_json::Value,
        #[serde(rename = "sourceDescriptorDigest")]
        source_descriptor_digest: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum NativeProbeSetup {
    InvokeNativeGlobal {
        #[serde(rename = "globalName")]
        global_name: String,
        arguments: Vec<serde_json::Value>,
    },
    TcpLoopbackClient {
        #[serde(rename = "globalName")]
        global_name: String,
        #[serde(rename = "sourceDescriptor")]
        source_descriptor: serde_json::Value,
        #[serde(rename = "sourceDescriptorDigest")]
        source_descriptor_digest: String,
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

fn is_sorted_set(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
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

#[test]
fn generated_derived_env_write_template_is_accepted_by_rust_registry() {
    let value = capsec_semantics::strict_json::parse_slice_strict(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/packages/ibex-devtools/src/scripts/fixtures/capsec-derived-env-write-template.json"
    )))
    .expect("shared derived-action template must be strict JSON");
    let profile = capsec_semantics::registry::ValidatedProfile::from_json(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/capability-definitions.json"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/policy-rules.json"
        )),
    )
    .expect("checked CapSec registry must load in Rust");
    let selector: capsec_semantics::model::AuthoritySelector =
        serde_json::from_value(value["selector"].clone())
            .expect("generated selector must deserialize in Rust");
    profile
        .definitions
        .validate_selector(&selector)
        .expect("generated selector must satisfy Rust action constraints");

    let occurrence: capsec_semantics::model::EffectOccurrence =
        serde_json::from_value(value["occurrence"].clone())
            .expect("generated occurrence must deserialize in Rust");
    let requested = occurrence
        .resource
        .requested_selector_resource()
        .expect("generated occurrence must expose a requested selector");
    profile
        .definitions
        .validate_requested_resource(&occurrence.action, &requested)
        .expect("generated occurrence must satisfy Rust action constraints");
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
        .unwrap_or_else(|| {
            panic!(
                "{}: response has no legacy observations",
                item.recipe.fixture_id
            )
        });
    let typed = response["typedObservations"].as_array().unwrap_or_else(|| {
        panic!(
            "{}: response has no typed observations",
            item.recipe.fixture_id
        )
    });
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

fn execute_adapter_chunk(items: &[WorkItem<'_>]) -> Vec<CaseEvidence> {
    items
        .iter()
        .map(|item| {
            assert_eq!(
                item.probe.operation, "capsec.conformance.evaluate",
                "{}:{}: unsupported diagnostic adapter operation",
                item.recipe.fixture_id, item.case.stage
            );
            let request = serde_json::json!({
                "terminalBranchId": item.probe.terminal_branch_id,
                "decisionSetJson": item.case.decision_set_json,
                "gatesJson": item.case.gates_json,
            });
            let response_text = evaluate_capsec_conformance_adapter(
                &serde_json::to_string(&request).expect("serialize adapter request"),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{}:{}: direct typed adapter failed: {error}",
                    item.recipe.fixture_id, item.case.stage
                )
            });
            let response = capsec_semantics::strict_json::parse_strict(&response_text)
                .unwrap_or_else(|error| {
                    panic!(
                        "{}:{}: direct typed adapter returned invalid JSON: {error}",
                        item.recipe.fixture_id, item.case.stage
                    )
                });
            validate_response(item, &response)
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
    // Adapter evidence remains bound to an exact loaded-engine identity for
    // stale-artifact detection, but adapter cases are diagnostic and execute
    // in-process. They never cross a public JavaScript bridge and never count
    // as public-surface execution evidence.
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
        let evidence = execute_adapter_chunk(chunk);
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
            eprintln!(
                "CapSec typed-adapter cases passed: {passed_cases}/{}",
                work.len()
            );
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

fn native_coverage_terminals() -> BTreeMap<String, String> {
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

fn tagged_value_digest<T: Serialize>(value: &T) -> String {
    tagged_jcs_digest(&serde_json::to_value(value).expect("evidence must serialize"))
}

fn native_public_floor(port: u16) -> serde_json::Value {
    serde_json::json!({
        "cap": "network:connect",
        "resource": {
            "kind": "connect-endpoint",
            "transport": "tcp",
            "host": {"kind": "ip", "address": "127.0.0.1"},
            "port": {"kind": "exact", "value": port},
            "peerClasses": ["loopback"],
            "route": {"kind": "direct"}
        }
    })
}

fn install_native_public_test_host(
    invocation: &NativePublicInvocation,
    listener_port: Option<u16>,
    deny: bool,
) -> (HostResetGuard, String) {
    let floor = if invocation.required_floor.is_empty() {
        listener_port
            .map(native_public_floor)
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        assert!(
            listener_port.is_none(),
            "a static native public floor cannot also use a listener selector"
        );
        invocation.required_floor.clone()
    };
    assert!(
        !deny || !floor.is_empty(),
        "an explicit native public denial requires an exact selector"
    );
    let denials = deny.then(|| floor.clone()).unwrap_or_default();
    let (host, digest) =
        build_armed_test_host_custom(None, false, false, false, floor, None, move |value| {
            if !denials.is_empty() {
                value["principals"][0]["denials"] = serde_json::Value::Array(denials);
            }
        });
    assert_ne!(
        crate::host::abi::install_host(host),
        0,
        "native public test Host context token allocation"
    );
    (HostResetGuard, digest)
}

fn setup_script(global_name: &str, arguments: &[serde_json::Value]) -> String {
    format!(
        "JSON.stringify((function(){{var n={};var f=globalThis[n];if(typeof f!==\"function\")return {{kind:\"missing\",globalName:n}};try{{var value=Reflect.apply(f,globalThis,{});return {{kind:\"return\",globalName:n,value:typeof value===\"number\"?value:null}};}}catch(e){{return {{kind:\"throw\",globalName:n,errorName:String(e&&e.name||\"Error\"),errorMessage:String(e&&e.message||e)}};}}}})())",
        serde_json::to_string(global_name).expect("serialize setup global"),
        serde_json::to_string(arguments).expect("serialize setup arguments")
    )
}

#[derive(Default)]
struct NativeSetupState {
    tcp_loopback_client_handle: Option<f64>,
}

async fn run_native_setup(
    engine: &HermesEngine,
    invocation: &NativePublicInvocation,
    listener_port: Option<u16>,
) -> NativeSetupState {
    let mut state = NativeSetupState::default();
    for setup in &invocation.setup {
        match setup {
            NativeProbeSetup::InvokeNativeGlobal {
                global_name,
                arguments,
            } => {
                let encoded = engine
                    .eval_immediate(&setup_script(global_name, arguments))
                    .await
                    .expect("execute native public probe setup")
                    .expect("native public probe setup returned no result");
                let result: serde_json::Value = serde_json::from_str(&encoded)
                    .expect("native public probe setup returned invalid JSON");
                assert_eq!(
                    result["kind"], "return",
                    "native public setup {global_name} failed: {result}"
                );
            }
            NativeProbeSetup::TcpLoopbackClient {
                global_name,
                source_descriptor,
                source_descriptor_digest,
            } => {
                assert_eq!(global_name, "__exactTcpConnect");
                assert_eq!(source_descriptor_digest, &tagged_value_digest(source_descriptor));
                assert_eq!(source_descriptor["kind"], "native-global-function");
                assert_eq!(source_descriptor["globalName"], global_name.as_str());
                assert_eq!(source_descriptor["arity"], 4);
                assert!(state.tcp_loopback_client_handle.is_none());
                let port = listener_port
                    .expect("loopback client setup requires an owned listener port");
                let encoded = engine
                    .eval_immediate(&setup_script(
                        global_name,
                        &[serde_json::json!("127.0.0.1"), serde_json::json!(port)],
                    ))
                    .await
                    .expect("execute native loopback client setup")
                    .expect("native loopback client setup returned no result");
                let result: serde_json::Value = serde_json::from_str(&encoded)
                    .expect("native loopback client setup returned invalid JSON");
                assert_eq!(
                    result["kind"], "return",
                    "native public setup {global_name} failed: {result}"
                );
                state.tcp_loopback_client_handle = Some(
                    result["value"]
                        .as_f64()
                        .expect("native loopback client setup must return a numeric handle"),
                );
            }
            NativeProbeSetup::TcpLoopbackListener => {}
        }
    }
    state
}

fn materialize_native_arguments(
    invocation: &NativePublicInvocation,
    listener_port: Option<u16>,
    setup_state: &NativeSetupState,
) -> Vec<serde_json::Value> {
    fn materialize(
        argument: &NativeProbeArgument,
        listener_port: Option<u16>,
        setup_state: &NativeSetupState,
    ) -> serde_json::Value {
        match argument {
            NativeProbeArgument::JsonLiteral { value } => serde_json::json!({
                "kind": "json-literal",
                "value": value,
            }),
            NativeProbeArgument::HarnessNoopCallback => serde_json::json!({
                "kind": "harness-noop-callback",
            }),
            NativeProbeArgument::HarnessLoopbackClientHandle => serde_json::json!({
                "kind": "json-literal",
                "value": setup_state
                    .tcp_loopback_client_handle
                    .expect("loopback client argument requires client setup"),
            }),
            NativeProbeArgument::HarnessLoopbackAddress { family } => {
                assert_eq!(
                    family, "ipv4",
                    "only the bounded IPv4 loopback fixture exists"
                );
                serde_json::json!({
                    "kind": "json-literal",
                    "value": "127.0.0.1",
                })
            }
            NativeProbeArgument::HarnessLoopbackListenerPort => serde_json::json!({
                "kind": "json-literal",
                "value": listener_port
                    .expect("loopback listener argument requires listener setup"),
            }),
            NativeProbeArgument::NativeGlobalResult {
                global_name,
                arguments,
                source_descriptor,
                source_descriptor_digest,
            } => {
                assert_eq!(
                    source_descriptor_digest,
                    &tagged_value_digest(source_descriptor),
                    "native argument producer source descriptor digest drift"
                );
                assert_eq!(
                    source_descriptor["kind"], "native-global-function",
                    "native argument producer must bind a source-derived function"
                );
                assert_eq!(
                    source_descriptor["globalName"],
                    global_name.as_str(),
                    "native argument producer source global drift"
                );
                serde_json::json!({
                    "kind": "native-global-result",
                    "globalName": global_name,
                    "arguments": arguments
                        .iter()
                        .map(|nested| materialize(nested, listener_port, setup_state))
                        .collect::<Vec<_>>(),
                })
            }
            NativeProbeArgument::NativeGlobalResultProperty {
                property,
                global_name,
                arguments,
                source_descriptor,
                source_descriptor_digest,
            } => {
                assert!(
                    matches!(property.as_str(), "privateKey" | "publicKey"),
                    "native argument producer property must be an owned key-pair field"
                );
                assert_eq!(
                    source_descriptor_digest,
                    &tagged_value_digest(source_descriptor),
                    "native argument producer source descriptor digest drift"
                );
                assert_eq!(
                    source_descriptor["kind"], "native-global-function",
                    "native argument producer must bind a source-derived function"
                );
                assert_eq!(
                    source_descriptor["globalName"],
                    global_name.as_str(),
                    "native argument producer source global drift"
                );
                serde_json::json!({
                    "kind": "native-global-result-property",
                    "property": property,
                    "globalName": global_name,
                    "sourceDescriptorDigest": source_descriptor_digest,
                    "arguments": arguments
                        .iter()
                        .map(|nested| materialize(nested, listener_port, setup_state))
                        .collect::<Vec<_>>(),
                })
            }
        }
    }

    invocation
        .arguments
        .iter()
        .map(|argument| materialize(argument, listener_port, setup_state))
        .collect()
}

fn native_invocation_script(
    invocation: &NativePublicInvocation,
    arguments: &[serde_json::Value],
) -> String {
    if invocation.kind == "global-property-read" {
        let descriptor: GlobalReadSourceDescriptor =
            serde_json::from_value(invocation.source_descriptor.clone())
                .expect("global read source descriptor must be typed");
        return format!(
            "JSON.stringify((function(){{var n={};var path={};var shape={};var value=globalThis;function lookup(receiver,key){{var owner=receiver;var depth=0;while(owner!==null){{var descriptor=Object.getOwnPropertyDescriptor(owner,key);if(descriptor)return {{descriptor:descriptor,depth:depth}};owner=Object.getPrototypeOf(owner);depth++;}}return null;}}try{{var ownerDepths=[];for(var i=0;i<path.length;i++){{var key=path[i];if(value===null||(typeof value!==\"object\"&&typeof value!==\"function\"))return {{kind:\"missing\",globalName:n,segment:key}};var found=lookup(value,key);if(!found)return {{kind:\"missing\",globalName:n,segment:key,available:Object.getOwnPropertyNames(value).slice(0,32)}};var propertyDescriptor=found.descriptor;ownerDepths.push(found.depth);if(i===path.length-1){{if(shape===\"accessor\"&&typeof propertyDescriptor.get!==\"function\")return {{kind:\"shape-mismatch\",globalName:n,expectedShape:shape}};if(shape===\"data\"&&(!(\"value\" in propertyDescriptor)||typeof propertyDescriptor.value===\"function\"))return {{kind:\"shape-mismatch\",globalName:n,expectedShape:shape,actualType:\"value\" in propertyDescriptor?typeof propertyDescriptor.value:\"absent\"}};}}value=value[key];}}return {{kind:\"return\",globalName:n,valueType:value===null?\"null\":typeof value,ownerDepths:ownerDepths,cleanup:\"none\"}};}}catch(e){{return {{kind:\"throw\",globalName:n,errorName:String(e&&e.name||\"Error\"),errorMessage:String(e&&e.message||e)}};}}}})())",
            serde_json::to_string(&invocation.global_name).expect("serialize global read root"),
            serde_json::to_string(&descriptor.access.path).expect("serialize global read path"),
            serde_json::to_string(&descriptor.value_shape).expect("serialize global read shape")
        );
    }
    format!(
        "JSON.stringify((function(){{var n={};var f=globalThis[n];if(typeof f!==\"function\")return {{kind:\"missing\",globalName:n}};var specs={};var producerResults=new Map();function invokeProducer(spec){{var producer=globalThis[spec.globalName];if(typeof producer!==\"function\")throw new Error(\"missing native argument producer: \"+spec.globalName);return Reflect.apply(producer,globalThis,spec.arguments.map(materialize));}}function materialize(spec){{if(spec.kind===\"json-literal\")return spec.value;if(spec.kind===\"harness-noop-callback\")return function(){{}};if(spec.kind===\"native-global-result\")return invokeProducer(spec);if(spec.kind===\"native-global-result-property\"){{var cacheKey=spec.sourceDescriptorDigest+\"\\n\"+JSON.stringify(spec.arguments);var result;if(producerResults.has(cacheKey))result=producerResults.get(cacheKey);else{{result=invokeProducer(spec);producerResults.set(cacheKey,result);}}if(result===null||(typeof result!==\"object\"&&typeof result!==\"function\")||!Object.prototype.hasOwnProperty.call(result,spec.property))throw new Error(\"native argument producer missing own property: \"+spec.property);return result[spec.property];}}throw new Error(\"unsupported native argument kind: \"+String(spec&&spec.kind));}}var args;try{{args=specs.map(materialize);}}catch(e){{return {{kind:\"argument-throw\",globalName:n,errorName:String(e&&e.name||\"Error\"),errorMessage:String(e&&e.message||e)}};}}try{{var value=Reflect.apply(f,globalThis,args);var valueType=value===null?\"null\":typeof value;var cleanup=\"none\";if(n===\"__exactTcpConnect\"&&typeof value===\"number\"&&typeof globalThis.__exactTcpClose===\"function\"){{globalThis.__exactTcpClose(value);cleanup=\"closed-tcp-handle\";}}else if(n===\"__exactUdpSocket\"&&typeof value===\"number\"&&typeof globalThis.__exactUdpClose===\"function\"){{globalThis.__exactUdpClose(value);cleanup=\"closed-udp-handle\";}}else if(n===\"__exactTcpClose\"&&typeof args[0]===\"number\"){{cleanup=\"consumed-tcp-handle\";}}else if((n===\"__exactTcpReset\"||n===\"__exactTcpShutdown\")&&typeof args[0]===\"number\"&&typeof globalThis.__exactTcpClose===\"function\"){{globalThis.__exactTcpClose(args[0]);cleanup=\"closed-tcp-handle\";}}else if(n===\"setTimeout\"&&typeof globalThis.clearTimeout===\"function\"){{globalThis.clearTimeout(value);cleanup=\"cleared-timeout\";}}else if(n===\"setInterval\"&&typeof globalThis.clearInterval===\"function\"){{globalThis.clearInterval(value);cleanup=\"cleared-interval\";}}return {{kind:\"return\",globalName:n,valueType:valueType,cleanup:cleanup}};}}catch(e){{return {{kind:\"throw\",globalName:n,errorName:String(e&&e.name||\"Error\"),errorMessage:String(e&&e.message||e)}};}}}})())",
        serde_json::to_string(&invocation.global_name).expect("serialize native global"),
        serde_json::to_string(arguments).expect("serialize native arguments")
    )
}

struct NativeRuntimeValidation {
    terminal_observed_key: String,
    execution_proof: serde_json::Value,
}

fn observed_typed_values(
    session_id: &str,
    observed: Vec<ibex_runtime::host::ObservedTypedDecision>,
) -> Vec<serde_json::Value> {
    observed
        .into_iter()
        .map(|decision| {
            assert_eq!(
                decision.terminal_branch_id, session_id,
                "the observer session marker is not terminal evidence"
            );
            let mut value =
                serde_json::to_value(decision).expect("serialize observed typed public decision");
            value
                .as_object_mut()
                .expect("observed typed decision must be an object")
                .remove("terminalBranchId");
            value
        })
        .collect()
}

fn validate_global_read_descriptor(
    recipe: &Recipe,
    probe: &PublicSurfaceProbe,
    invocation: &NativePublicInvocation,
) {
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // runtime evidence must remain bound to the exact source-derived path.
    let descriptor: GlobalReadSourceDescriptor =
        serde_json::from_value(invocation.source_descriptor.clone())
            .expect("global read source descriptor must be typed");
    assert_eq!(descriptor.kind, "global-property-read");
    assert_eq!(descriptor.source_key, "shared_runtime");
    assert_eq!(descriptor.global_name, invocation.global_name);
    assert!(matches!(descriptor.value_shape.as_str(), "accessor" | "data"));
    assert!(!descriptor.member_kinds.is_empty());
    assert!(is_sorted_set(&descriptor.member_kinds));
    assert!(!descriptor.source_refs.is_empty());
    assert!(is_sorted_set(&descriptor.source_refs));
    assert!(descriptor
        .source_refs
        .iter()
        .all(|source_ref| source_ref.starts_with("packages/ibex-runtime-js/src/")));
    assert_eq!(descriptor.access.kind, "source-proven-property-path");
    assert_eq!(descriptor.access.path.join("."), descriptor.export_name);
    assert_eq!(
        descriptor.access.path.first().map(String::as_str),
        Some(descriptor.global_name.as_str())
    );
    assert!(descriptor.access.path.iter().all(|segment| {
        let mut chars = segment.chars();
        chars.next().is_some_and(|first| {
            (first == '_' || first == '$' || first.is_ascii_alphabetic())
                && chars.all(|character| {
                    character == '_'
                        || character == '$'
                        || character.is_ascii_alphanumeric()
                })
        })
    }));
    if descriptor.value_shape == "accessor" && descriptor.access.path.len() == 1 {
        assert!(!descriptor
            .source_refs
            .iter()
            .any(|source_ref| source_ref.contains("#defineLazyGlobal:")));
    }
    for forbidden in [
        "dynamic-table",
        "inherited",
        "inherited-shape",
        "instance-property",
        "namespace-alias",
        "namespace-prefix",
        "prototype-accessor",
        "prototype-assignment",
        "prototype-method",
    ] {
        assert!(!descriptor.member_kinds.iter().any(|kind| kind == forbidden));
    }
    let expected_observed_key = if descriptor.export_name.starts_with('_') {
        format!("native-op:{}", descriptor.export_name)
    } else {
        format!("native-op:global:{}", descriptor.export_name)
    };
    assert_eq!(probe.surface_observed_key, expected_observed_key);
    assert_eq!(recipe.classification, "non-capability");
    assert_eq!(recipe.scenario, "non-capability");
    assert!(recipe.action_ids.is_empty());
    assert!(invocation.arguments.is_empty());
    assert!(invocation.required_floor.is_empty());
    assert!(invocation.setup.is_empty());
}

fn validate_native_runtime_observation(
    recipe: &Recipe,
    probe: &PublicSurfaceProbe,
    invocation_result: &serde_json::Value,
    legacy_observations: usize,
    typed_decisions: &[serde_json::Value],
    coverage_terminals: &BTreeMap<String, String>,
) -> NativeRuntimeValidation {
    let invocation = probe
        .invocation
        .native()
        .expect("native executor received a non-native invocation descriptor");
    let expected_probe_kind = if recipe.expected_observation["kind"] == "target-absence" {
        "target-absence-probe"
    } else {
        "public-surface-invocation"
    };
    assert_eq!(probe.kind, expected_probe_kind);
    assert!(matches!(
        invocation.kind.as_str(),
        "native-global-function" | "global-property-read"
    ));
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_value_digest(&invocation.source_descriptor),
        "{}: source-derived native descriptor digest drift",
        recipe.fixture_id
    );
    if invocation.kind == "global-property-read" {
        validate_global_read_descriptor(recipe, probe, invocation);
    } else {
        let expected_observed_key = if invocation.global_name.starts_with('_') {
            format!("native-op:{}", invocation.global_name)
        } else {
            format!("native-op:global:{}", invocation.global_name)
        };
        assert_eq!(
            probe.surface_observed_key,
            expected_observed_key
        );
    }
    assert_eq!(invocation.allowed_coverage_edge_ids, recipe.edge_ids);
    assert_eq!(invocation.expected_action_ids, recipe.action_ids);
    assert_eq!(
        legacy_observations, 0,
        "legacy checks are not public typed evidence"
    );
    assert_eq!(invocation_result["globalName"], invocation.global_name);
    let execution_proof = match invocation.expected_result.as_str() {
        "return" => {
            assert_eq!(
                invocation_result["kind"], "return",
                "{}: public native invocation did not return: {invocation_result}",
                recipe.fixture_id
            );
            serde_json::json!({
                "kind": if invocation.kind == "global-property-read" {
                    "global-property-read"
                } else {
                    "native-return"
                },
                "bodyEntered": true,
            })
        }
        "permission-denied" => {
            assert_eq!(
                invocation_result["kind"], "throw",
                "{}: denied public native invocation did not throw: {invocation_result}",
                recipe.fixture_id
            );
            assert!(
                invocation_result["errorMessage"]
                    .as_str()
                    .is_some_and(|message| message.contains("Permission denied")),
                "{}: denied public native invocation threw the wrong error: {invocation_result}",
                recipe.fixture_id
            );
            serde_json::json!({
                "kind": "typed-permission-denial",
                "bodyEntered": true,
            })
        }
        "absent" => {
            assert_eq!(
                invocation_result["kind"], "missing",
                "{}: native global expected absent but remained public: {invocation_result}",
                recipe.fixture_id
            );
            serde_json::json!({
                "kind": "exact-global-absence",
                "bodyEntered": false,
            })
        }
        other => panic!(
            "{}: unsupported native expected result {other}",
            recipe.fixture_id
        ),
    };

    let stages = typed_decisions
        .iter()
        .map(|decision| {
            decision["decisionSet"]["context"]["stage"]
                .as_str()
                .expect("observed typed decision has no stage")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        stages, invocation.expected_typed_stages,
        "{}: runtime typed stages disagree with the public recipe",
        recipe.fixture_id
    );
    assert_eq!(
        typed_decisions.len(),
        invocation.expected_typed_decision_count,
        "{}: runtime typed decision count disagrees with the public recipe",
        recipe.fixture_id
    );
    let mut observed_actions = BTreeSet::new();
    let mut observed_terminals = BTreeSet::new();
    for decision in typed_decisions {
        let atomicity_group = decision["decisionSet"]["atomicityGroup"]
            .as_str()
            .expect("observed typed decision has no atomicity group");
        let effects = decision["decisionSet"]["effects"]
            .as_array()
            .expect("observed typed decision has no effects");
        for effect in effects {
            observed_actions.insert(
                effect["cap"]
                    .as_str()
                    .expect("observed effect has no action")
                    .to_owned(),
            );
        }
        let gates = decision["gates"]
            .as_array()
            .expect("observed typed decision has no gates");
        assert_eq!(gates.len(), effects.len());
        for gate in gates {
            let edge_id = gate["coverageEdgeId"]
                .as_str()
                .expect("observed typed gate has no coverage edge");
            assert!(
                invocation
                    .allowed_coverage_edge_ids
                    .iter()
                    .any(|expected| expected == edge_id),
                "{}: observed an unbound coverage edge {edge_id}",
                recipe.fixture_id
            );
            assert_eq!(atomicity_group, format!("{edge_id}.decision"));
            assert_eq!(gate["targetCell"], "complete");
            assert_eq!(gate["definitionAndEdgePredicatesSatisfied"], true);
            observed_terminals.insert(
                coverage_terminals
                    .get(edge_id)
                    .unwrap_or_else(|| panic!("observed unknown coverage edge {edge_id}"))
                    .clone(),
            );
        }
        let outcome = decision["evidence"]["outcome"]
            .as_str()
            .expect("observed typed evidence has no outcome");
        let expected_outcome = if invocation.expected_result == "permission-denied" {
            "deny"
        } else {
            "allow"
        };
        assert_eq!(outcome, expected_outcome);
        let authority_evidence = decision["evidence"]["evidence"]
            .as_array()
            .expect("observed typed decision has no authority evidence");
        assert_eq!(
            authority_evidence.len(),
            1,
            "{}: public network probe must have one decisive root authority row: {authority_evidence:?}",
            recipe.fixture_id
        );
        let authority = &authority_evidence[0];
        let (expected_stratum, expected_source_prefix) =
            if invocation.expected_result == "permission-denied" {
                ("principal-denial", "principal.000000.denial.")
            } else {
                ("static-floor", "principal.000000.floor.")
            };
        assert_eq!(authority["stratum"], expected_stratum);
        assert_eq!(authority["reason"], expected_stratum);
        assert!(
            authority["sourceId"]
                .as_str()
                .is_some_and(|source| source.starts_with(expected_source_prefix)),
            "{}: public native decision used the wrong authority source: {authority}",
            recipe.fixture_id
        );
    }
    if invocation.expected_result == "absent" {
        assert!(
            observed_actions.is_empty(),
            "{}: target/lockdown absence cannot invent observed actions",
            recipe.fixture_id
        );
    } else {
        assert_eq!(
            observed_actions.into_iter().collect::<Vec<_>>(),
            invocation.expected_action_ids
        );
    }

    let terminal = if invocation.expected_result == "absent" {
        assert!(
            typed_decisions.is_empty(),
            "{}: an absent global cannot emit typed decisions",
            recipe.fixture_id
        );
        assert_eq!(recipe.terminal_observed_key, probe.surface_observed_key);
        probe.surface_observed_key.clone()
    } else if typed_decisions.is_empty() {
        assert_eq!(recipe.classification, "non-capability");
        assert_eq!(recipe.scenario, "non-capability");
        probe.surface_observed_key.clone()
    } else {
        assert_eq!(observed_terminals.len(), 1);
        observed_terminals.into_iter().next().unwrap()
    };
    if invocation.expected_result != "absent"
        || recipe.expected_observation["kind"] != "target-absence"
    {
        assert!(
            recipe
                .route
                .alternatives
                .iter()
                .any(|alternative| alternative.terminal_observed_key == terminal),
            "{}: runtime-derived terminal {terminal} is outside the static allowed route set",
            recipe.fixture_id
        );
    } else {
        assert!(
            recipe.route.alternatives.is_empty(),
            "{}: target absence unexpectedly retained an implementation route",
            recipe.fixture_id
        );
    }
    NativeRuntimeValidation {
        terminal_observed_key: terminal,
        execution_proof,
    }
}

async fn execute_native_public_recipe(
    engine: &HermesEngine,
    recipe: &Recipe,
    coverage_terminals: &BTreeMap<String, String>,
    supplied_listener: Option<std::net::TcpListener>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let probe = recipe
        .public_surface_probe
        .as_ref()
        .expect("fully executable native recipe must have a public probe");
    let invocation = probe
        .invocation
        .native()
        .expect("native executor received a non-native invocation descriptor");
    assert_eq!(recipe.status, "fully-executable");
    let needs_listener = invocation
        .setup
        .iter()
        .any(|setup| matches!(setup, NativeProbeSetup::TcpLoopbackListener));
    let listener = if needs_listener {
        supplied_listener.or_else(|| {
            Some(
                std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                    .expect("bind bounded native public loopback listener"),
            )
        })
    } else {
        assert!(supplied_listener.is_none());
        None
    };
    let listener_port = listener
        .as_ref()
        .map(|listener| listener.local_addr().unwrap().port());
    let setup_state = run_native_setup(engine, invocation, listener_port).await;
    let arguments = materialize_native_arguments(invocation, listener_port, &setup_state);
    let session_id = format!("public-observation:{}", recipe.plan_digest);
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id),
        "public native observer has no installed host"
    );
    let result = engine
        .eval_immediate(&native_invocation_script(invocation, &arguments))
        .await;
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    let encoded = result
        .expect("execute native public invocation in Hermes")
        .expect("native public invocation returned no result");
    let invocation_result: serde_json::Value =
        serde_json::from_str(&encoded).expect("native public invocation returned invalid JSON");
    let typed_decisions = observed_typed_values(&session_id, typed);
    let validation = validate_native_runtime_observation(
        recipe,
        probe,
        &invocation_result,
        legacy.len(),
        &typed_decisions,
        coverage_terminals,
    );
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": "ibex/capsec-native-global-invocation/1",
            "kind": invocation.kind,
            "surfaceObservedKey": probe.surface_observed_key,
            "globalName": invocation.global_name,
            "sourceDescriptorDigest": invocation.source_descriptor_digest,
            "result": invocation_result,
            "executionProof": validation.execution_proof,
        },
        "legacyObservationCount": legacy.len(),
        "typedDecisions": typed_decisions,
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected public observation must be an object")
        .insert("result".into(), serde_json::Value::String("passed".into()));
    let mut evidence = serde_json::json!({
        "evidenceSchema": "ibex/capsec-public-surface-fixture-evidence/2",
        "fixtureId": recipe.fixture_id,
        "planDigest": recipe.plan_digest,
        "engineBinaryDigest": engine_binary_digest,
        "probe": probe,
        "terminalObservedKey": validation.terminal_observed_key,
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
        "executor": "ibex-native-public-surface-harness",
        "evidence": evidence,
    })
}

const NATIVE_PUBLIC_BATCH_COMMAND: [&str; 9] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--features",
    "capsec-conformance-observer",
    "capsec_public_native_recipe_batch",
    "--",
    "--test-threads=1",
];

fn is_native_public_batch_probe(probe: &PublicSurfaceProbe) -> bool {
    probe.invocation.native().is_some()
        && probe
            .command
            .iter()
            .map(String::as_str)
            .eq(NATIVE_PUBLIC_BATCH_COMMAND)
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn capsec_public_native_recipe_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping native public recipe batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT")
        .expect("native public recipe batch requires an owned evidence output path");
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_recipe_catalog(&recipe_path);
    let native_recipe_indexes = catalog
        .recipes
        .iter()
        .enumerate()
        .filter_map(|(index, recipe)| {
            recipe
                .public_surface_probe
                .as_ref()
                .filter(|probe| {
                    recipe.status == "fully-executable" && is_native_public_batch_probe(probe)
                })
                .map(|_| index)
        })
        .collect::<Vec<_>>();
    assert!(
        !native_recipe_indexes.is_empty(),
        "catalog has no native public recipes"
    );
    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before native public recipes");
    let coverage_terminals = native_coverage_terminals();
    let mut executions = Vec::new();

    for &index in &native_recipe_indexes {
        let recipe = &catalog.recipes[index];
        eprintln!(
            "CapSec native public fixture {}/{}: {}",
            executions.len() + 1,
            native_recipe_indexes.len(),
            recipe.fixture_id
        );
        let invocation = recipe
            .public_surface_probe
            .as_ref()
            .and_then(|probe| probe.invocation.native())
            .expect("native recipe index must contain a native invocation");
        let needs_listener = invocation
            .setup
            .iter()
            .any(|setup| matches!(setup, NativeProbeSetup::TcpLoopbackListener));
        let listener = needs_listener.then(|| {
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .expect("bind bounded native public loopback listener")
        });
        let listener_port = listener
            .as_ref()
            .map(|listener| listener.local_addr().unwrap().port());
        let (_reset, snapshot_digest) =
            install_native_public_test_host(invocation, listener_port, recipe.scenario == "deny");
        let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
            .expect("create isolated native public recipe engine");
        engine
            .load_runtime()
            .await
            .expect("load runtime in isolated native public recipe engine");
        executions.push(
            execute_native_public_recipe(
                &engine,
                recipe,
                &coverage_terminals,
                listener,
                &identity_before.binary_digest,
            )
            .await,
        );
        eprintln!("CapSec native public fixture passed: {}", recipe.fixture_id);
    }

    executions.sort_by(|left, right| {
        left["fixtureId"]
            .as_str()
            .unwrap()
            .cmp(right["fixtureId"].as_str().unwrap())
    });
    assert_eq!(executions.len(), native_recipe_indexes.len());
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after native public recipes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after native public recipes");
    let artifact = serde_json::json!({
        "publicBatchEvidenceSchema": "ibex/capsec-public-batch-evidence/1",
        "recipeCatalogDigest": catalog.recipe_catalog_digest,
        "loadedEngineIdentity": identity_before,
        "executions": executions,
    });
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("create owned native public evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize native public evidence artifact");
    output
        .write_all(b"\n")
        .expect("finish native public evidence");
    output
        .sync_all()
        .expect("sync native public evidence artifact");
}
