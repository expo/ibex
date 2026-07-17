use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "host-http-server"))]
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
    #[serde(rename = "ibex/capsec-host-abi-invocation/1")]
    HostAbi {
        #[serde(flatten)]
        details: HostAbiPublicInvocation,
    },
    #[serde(rename = "ibex/capsec-module-loader-invocation/1")]
    ModuleLoader {
        #[serde(flatten)]
        details: ModuleLoaderPublicInvocation,
    },
    #[serde(other)]
    Other,
}

impl PublicInvocation {
    fn native(&self) -> Option<&NativePublicInvocation> {
        match self {
            Self::NativeGlobal { details } => Some(details),
            Self::BuiltinExport { .. }
            | Self::HostAbi { .. }
            | Self::ModuleLoader { .. }
            | Self::Other => None,
        }
    }

    fn host_abi(&self) -> Option<&HostAbiPublicInvocation> {
        match self {
            Self::HostAbi { details } => Some(details),
            Self::NativeGlobal { .. }
            | Self::BuiltinExport { .. }
            | Self::ModuleLoader { .. }
            | Self::Other => None,
        }
    }

    fn module_loader(&self) -> Option<&ModuleLoaderPublicInvocation> {
        match self {
            Self::ModuleLoader { details } => Some(details),
            Self::NativeGlobal { .. }
            | Self::BuiltinExport { .. }
            | Self::HostAbi { .. }
            | Self::Other => None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct HostAbiPublicInvocation {
    kind: String,
    function_name: String,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    operation: serde_json::Value,
    expected_result: String,
    expected_typed_stages: Vec<String>,
    expected_typed_decision_count: usize,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ModuleLoaderPublicInvocation {
    kind: String,
    surface_name: String,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    operation: serde_json::Value,
    expected_result: String,
    expected_typed_stages: Vec<String>,
    expected_typed_decision_count: usize,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativePublicInvocation {
    kind: String,
    global_name: String,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    arguments: Vec<NativeProbeArgument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion: Option<NativeProbeCompletion>,
    #[serde(default)]
    required_floor: Vec<serde_json::Value>,
    setup: Vec<NativeProbeSetup>,
    expected_result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_cleanup: Option<String>,
    expected_typed_stages: Vec<String>,
    expected_typed_decision_count: usize,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeProbeCompletion {
    kind: String,
    timeout_milliseconds: u64,
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
    HarnessFsFileDescriptor,
    HarnessLoopbackClientHandle,
    HarnessSqliteDatabaseHandle,
    HarnessSqliteStatementHandle,
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
    FsReadFile {
        #[serde(rename = "globalName")]
        global_name: String,
        #[serde(rename = "sourceDescriptor")]
        source_descriptor: serde_json::Value,
        #[serde(rename = "sourceDescriptorDigest")]
        source_descriptor_digest: String,
    },
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
    SqliteMemoryDatabase {
        #[serde(rename = "globalName")]
        global_name: String,
        #[serde(rename = "sourceDescriptor")]
        source_descriptor: serde_json::Value,
        #[serde(rename = "sourceDescriptorDigest")]
        source_descriptor_digest: String,
    },
    SqliteMemoryStatement {
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

#[test]
fn native_public_probe_serialization_preserves_omitted_optional_fields() {
    let invocation = NativePublicInvocation {
        kind: "native-global-function".into(),
        global_name: "__exactGetCwd".into(),
        source_descriptor: serde_json::json!({}),
        source_descriptor_digest: "sha256-test".into(),
        arguments: Vec::new(),
        completion: None,
        required_floor: Vec::new(),
        setup: Vec::new(),
        expected_result: "return".into(),
        expected_cleanup: None,
        expected_typed_stages: Vec::new(),
        expected_typed_decision_count: 0,
        allowed_coverage_edge_ids: Vec::new(),
        expected_action_ids: Vec::new(),
    };

    let serialized = serde_json::to_value(invocation).expect("serialize native public probe");
    assert!(serialized.get("completion").is_none());
    assert!(serialized.get("expectedCleanup").is_none());
}

#[test]
fn native_async_harness_fields_are_not_published_as_runtime_results() {
    let mut result = serde_json::json!({
        "kind": "return",
        "globalName": "__exactFsPathAsync",
        "valueType": "undefined",
        "resultString": null,
        "cleanup": "removed-owned-file",
    });

    remove_native_async_harness_fields(&mut result);

    assert!(result.get("resultString").is_none());
    assert_eq!(result["cleanup"], "removed-owned-file");
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
    let uses_project_path = floor.iter().any(|selector| {
        matches!(
            selector["resource"]["kind"].as_str(),
            Some("path-exact" | "path-tree")
        ) && selector["resource"]["path"]["root"] == "project"
    });
    let mutate = move |value: &mut serde_json::Value| {
            if !denials.is_empty() {
                value["principals"][0]["denials"] = serde_json::Value::Array(denials);
            }
        };
    let (host, digest) = if uses_project_path {
        build_armed_test_host_control(
            Some(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))),
            false,
            false,
            false,
            floor,
            Vec::new(),
            false,
            0,
            None,
            mutate,
        )
    } else {
        build_armed_test_host_custom(None, false, false, false, floor, None, mutate)
    };
    assert_ne!(
        crate::host::abi::install_host(host),
        0,
        "native public test Host context token allocation"
    );
    (HostResetGuard, digest)
}

fn setup_script(global_name: &str, arguments: &[serde_json::Value]) -> String {
    format!(
        "JSON.stringify((function(){{var n={};var f=globalThis[n];if(typeof f!==\"function\")return {{kind:\"missing\",globalName:n}};try{{var value=Reflect.apply(f,globalThis,{});return {{kind:\"return\",globalName:n,value:typeof value===\"number\"?value:null,handle:value!==null&&typeof value===\"object\"&&typeof value.handle===\"number\"?value.handle:null}};}}catch(e){{return {{kind:\"throw\",globalName:n,errorName:String(e&&e.name||\"Error\"),errorMessage:String(e&&e.message||e)}};}}}})())",
        serde_json::to_string(global_name).expect("serialize setup global"),
        serde_json::to_string(arguments).expect("serialize setup arguments")
    )
}

#[derive(Default)]
struct NativeSetupState {
    fs_file_descriptor: Option<f64>,
    tcp_loopback_client_handle: Option<f64>,
    sqlite_database_handle: Option<f64>,
    sqlite_statement_handle: Option<f64>,
}

async fn run_native_setup(
    engine: &HermesEngine,
    invocation: &NativePublicInvocation,
    listener_port: Option<u16>,
) -> NativeSetupState {
    let mut state = NativeSetupState::default();
    for setup in &invocation.setup {
        match setup {
            NativeProbeSetup::FsReadFile {
                global_name,
                source_descriptor,
                source_descriptor_digest,
            } => {
                // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
                // setup owns the descriptor before observation so a close
                // recipe proves the real retained-object path without
                // miscrediting its prerequisite open decisions.
                assert_eq!(global_name, "__exactFsOpen");
                assert_eq!(source_descriptor_digest, &tagged_value_digest(source_descriptor));
                assert_eq!(source_descriptor["kind"], "native-global-function");
                assert_eq!(source_descriptor["globalName"], global_name.as_str());
                assert_eq!(source_descriptor["arity"], 4);
                assert!(state.fs_file_descriptor.is_none());
                let encoded = engine
                    .eval_immediate(&setup_script(
                        global_name,
                        &[serde_json::json!("Cargo.toml"), serde_json::json!("r")],
                    ))
                    .await
                    .expect("execute native filesystem descriptor setup")
                    .expect("native filesystem descriptor setup returned no result");
                let result: serde_json::Value = serde_json::from_str(&encoded)
                    .expect("native filesystem descriptor setup returned invalid JSON");
                assert_eq!(
                    result["kind"], "return",
                    "native public setup {global_name} failed: {result}"
                );
                state.fs_file_descriptor = Some(
                    result["value"]
                        .as_f64()
                        .expect("native filesystem setup must return a numeric descriptor"),
                );
            }
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
            NativeProbeSetup::SqliteMemoryDatabase {
                global_name,
                source_descriptor,
                source_descriptor_digest,
            } => {
                assert_eq!(global_name, "__exactSqliteOpen");
                assert_eq!(source_descriptor_digest, &tagged_value_digest(source_descriptor));
                assert_eq!(source_descriptor["kind"], "native-global-function");
                assert_eq!(source_descriptor["globalName"], global_name.as_str());
                assert_eq!(source_descriptor["arity"], 2);
                assert!(state.sqlite_database_handle.is_none());
                let encoded = engine
                    .eval_immediate(&setup_script(
                        global_name,
                        &[serde_json::json!(":memory:"), serde_json::Value::Null],
                    ))
                    .await
                    .expect("execute native in-memory SQLite setup")
                    .expect("native in-memory SQLite setup returned no result");
                let result: serde_json::Value = serde_json::from_str(&encoded)
                    .expect("native in-memory SQLite setup returned invalid JSON");
                assert_eq!(
                    result["kind"], "return",
                    "native public setup {global_name} failed: {result}"
                );
                state.sqlite_database_handle = Some(
                    result["value"]
                        .as_f64()
                        .expect("native in-memory SQLite setup must return a numeric handle"),
                );
            }
            NativeProbeSetup::SqliteMemoryStatement {
                global_name,
                source_descriptor,
                source_descriptor_digest,
            } => {
                assert_eq!(global_name, "__exactSqlitePrepare");
                assert_eq!(source_descriptor_digest, &tagged_value_digest(source_descriptor));
                assert_eq!(source_descriptor["kind"], "native-global-function");
                assert_eq!(source_descriptor["globalName"], global_name.as_str());
                assert_eq!(source_descriptor["arity"], 2);
                assert!(state.sqlite_statement_handle.is_none());
                let database_handle = state
                    .sqlite_database_handle
                    .expect("SQLite statement setup requires a database setup");
                let encoded = engine
                    .eval_immediate(&setup_script(
                        global_name,
                        &[
                            serde_json::json!(database_handle),
                            serde_json::json!("SELECT 1 AS value"),
                        ],
                    ))
                    .await
                    .expect("execute native in-memory SQLite statement setup")
                    .expect("native in-memory SQLite statement setup returned no result");
                let result: serde_json::Value = serde_json::from_str(&encoded)
                    .expect("native in-memory SQLite statement setup returned invalid JSON");
                assert_eq!(
                    result["kind"], "return",
                    "native public setup {global_name} failed: {result}"
                );
                state.sqlite_statement_handle = Some(
                    result["handle"]
                        .as_f64()
                        .expect("native SQLite statement setup must return a numeric handle"),
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
            NativeProbeArgument::HarnessFsFileDescriptor => serde_json::json!({
                "kind": "json-literal",
                "value": setup_state
                    .fs_file_descriptor
                    .expect("filesystem descriptor argument requires file setup"),
            }),
            NativeProbeArgument::HarnessLoopbackClientHandle => serde_json::json!({
                "kind": "json-literal",
                "value": setup_state
                    .tcp_loopback_client_handle
                    .expect("loopback client argument requires client setup"),
            }),
            NativeProbeArgument::HarnessSqliteDatabaseHandle => serde_json::json!({
                "kind": "json-literal",
                "value": setup_state
                    .sqlite_database_handle
                    .expect("SQLite database argument requires database setup"),
            }),
            NativeProbeArgument::HarnessSqliteStatementHandle => serde_json::json!({
                "kind": "json-literal",
                "value": setup_state
                    .sqlite_statement_handle
                    .expect("SQLite statement argument requires statement setup"),
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
    setup_state: &NativeSetupState,
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
    let cleanup_state = serde_json::json!({
        "sqliteDatabaseHandle": setup_state.sqlite_database_handle,
        "sqliteStatementHandle": setup_state.sqlite_statement_handle,
    });
    let script = format!(
        "JSON.stringify((function(){{var n={};var f=globalThis[n];if(typeof f!==\"function\")return {{kind:\"missing\",globalName:n}};var specs={};var cleanupState={};var producerResults=new Map();function invokeProducer(spec){{var producer=globalThis[spec.globalName];if(typeof producer!==\"function\")throw new Error(\"missing native argument producer: \"+spec.globalName);return Reflect.apply(producer,globalThis,spec.arguments.map(materialize));}}function materialize(spec){{if(spec.kind===\"json-literal\")return spec.value;if(spec.kind===\"harness-noop-callback\")return function(){{}};if(spec.kind===\"native-global-result\")return invokeProducer(spec);if(spec.kind===\"native-global-result-property\"){{var cacheKey=spec.sourceDescriptorDigest+\"\\n\"+JSON.stringify(spec.arguments);var result;if(producerResults.has(cacheKey))result=producerResults.get(cacheKey);else{{result=invokeProducer(spec);producerResults.set(cacheKey,result);}}if(result===null||(typeof result!==\"object\"&&typeof result!==\"function\")||!Object.prototype.hasOwnProperty.call(result,spec.property))throw new Error(\"native argument producer missing own property: \"+spec.property);return result[spec.property];}}throw new Error(\"unsupported native argument kind: \"+String(spec&&spec.kind));}}var args;try{{args=specs.map(materialize);}}catch(e){{return {{kind:\"argument-throw\",globalName:n,errorName:String(e&&e.name||\"Error\"),errorMessage:String(e&&e.message||e)}};}}try{{var value=Reflect.apply(f,globalThis,args);var valueType=value===null?\"null\":typeof value;var cleanup=\"none\";if(n===\"__exactTcpConnect\"&&typeof value===\"number\"&&typeof globalThis.__exactTcpClose===\"function\"){{globalThis.__exactTcpClose(value);cleanup=\"closed-tcp-handle\";}}else if(n===\"__exactUdpSocket\"&&typeof value===\"number\"&&typeof globalThis.__exactUdpClose===\"function\"){{globalThis.__exactUdpClose(value);cleanup=\"closed-udp-handle\";}}else if(n===\"__exactTcpClose\"&&typeof args[0]===\"number\"){{cleanup=\"consumed-tcp-handle\";}}else if((n===\"__exactTcpReset\"||n===\"__exactTcpShutdown\")&&typeof args[0]===\"number\"&&typeof globalThis.__exactTcpClose===\"function\"){{globalThis.__exactTcpClose(args[0]);cleanup=\"closed-tcp-handle\";}}else if(n===\"__exactSqliteOpen\"&&typeof value===\"number\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteClose(value);cleanup=\"closed-sqlite-db\";}}else if(n===\"__exactSqlitePrepare\"&&value&&typeof value.handle===\"number\"&&typeof args[0]===\"number\"&&typeof globalThis.__exactSqliteFinalize===\"function\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteFinalize(value.handle);globalThis.__exactSqliteClose(args[0]);cleanup=\"finalized-sqlite-statement-closed-db\";}}else if((n===\"__exactSqliteAll\"||n===\"__exactSqliteGet\"||n===\"__exactSqliteRun\"||n===\"__exactSqliteValues\")&&typeof args[0]===\"number\"&&typeof cleanupState.sqliteDatabaseHandle===\"number\"&&typeof globalThis.__exactSqliteFinalize===\"function\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteFinalize(args[0]);globalThis.__exactSqliteClose(cleanupState.sqliteDatabaseHandle);cleanup=\"finalized-sqlite-statement-closed-db\";}}else if(n===\"__exactSqliteExec\"&&typeof args[0]===\"number\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteClose(args[0]);cleanup=\"closed-sqlite-db\";}}else if(n===\"__exactSqliteClose\"&&typeof args[0]===\"number\"){{cleanup=\"consumed-sqlite-db\";}}else if(n===\"__exactSqliteInTransaction\"&&typeof args[0]===\"number\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteClose(args[0]);cleanup=\"closed-sqlite-db\";}}else if(n===\"__exactSqliteFinalize\"&&typeof cleanupState.sqliteDatabaseHandle===\"number\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteClose(cleanupState.sqliteDatabaseHandle);cleanup=\"consumed-sqlite-statement-closed-db\";}}else if(n===\"__exactSqliteExpandedSql\"&&typeof args[0]===\"number\"&&typeof cleanupState.sqliteDatabaseHandle===\"number\"&&typeof globalThis.__exactSqliteFinalize===\"function\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteFinalize(args[0]);globalThis.__exactSqliteClose(cleanupState.sqliteDatabaseHandle);cleanup=\"finalized-sqlite-statement-closed-db\";}}else if(n===\"setTimeout\"&&typeof globalThis.clearTimeout===\"function\"){{globalThis.clearTimeout(value);cleanup=\"cleared-timeout\";}}else if(n===\"setInterval\"&&typeof globalThis.clearInterval===\"function\"){{globalThis.clearInterval(value);cleanup=\"cleared-interval\";}}return {{kind:\"return\",globalName:n,valueType:valueType,cleanup:cleanup}};}}catch(e){{return {{kind:\"throw\",globalName:n,errorName:String(e&&e.name||\"Error\"),errorMessage:String(e&&e.message||e)}};}}}})())",
        serde_json::to_string(&invocation.global_name).expect("serialize native global"),
        serde_json::to_string(arguments).expect("serialize native arguments"),
        serde_json::to_string(&cleanup_state).expect("serialize native cleanup state")
    );
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // source-bound retained-state recipes must release the exact object they
    // produced before the runtime observation is accepted.
    let cleanup_marker = "else if(n===\"setTimeout\"";
    assert_eq!(
        script.matches(cleanup_marker).count(),
        1,
        "native public cleanup marker drift"
    );
    script.replacen(
        cleanup_marker,
        "else if(n===\"__exactFsClose\"&&typeof args[0]===\"number\"){cleanup=\"consumed-fs-file-descriptor\";}else if(n===\"__exactZlibCreate\"&&typeof value===\"number\"&&typeof globalThis.__exactZlibClose===\"function\"){globalThis.__exactZlibClose(value);cleanup=\"closed-zlib-stream\";}else if(n===\"__exactZlibClose\"&&typeof args[0]===\"number\"){cleanup=\"consumed-zlib-stream\";}else if((n===\"__exactZlibCheckOwner\"||n===\"__exactZlibParams\"||n===\"__exactZlibWrite\")&&typeof args[0]===\"number\"&&typeof globalThis.__exactZlibClose===\"function\"){globalThis.__exactZlibClose(args[0]);cleanup=\"closed-zlib-stream\";}else if(n===\"__exactTlsOwnerToken\"&&args[0]===\"new\"&&typeof value===\"number\"){globalThis.__exactTlsOwnerToken(\"close\",value);cleanup=\"closed-tls-owner-token\";}else if(n===\"__exactTlsEngineNew\"&&typeof value===\"number\"&&typeof globalThis.__exactTlsEngineClose===\"function\"){globalThis.__exactTlsEngineClose(value);cleanup=\"closed-tls-engine\";}else if(n===\"__exactTlsEngineClose\"&&typeof args[0]===\"number\"){cleanup=\"consumed-tls-engine\";}else if((n===\"__exactTlsEnginePeerCerts\"||n===\"__exactTlsEngineReadPlain\"||n===\"__exactTlsEngineReadTls\"||n===\"__exactTlsEngineShutdown\"||n===\"__exactTlsEngineStatus\"||n===\"__exactTlsEngineTransportEof\"||n===\"__exactTlsEngineWritePlain\"||n===\"__exactTlsEngineWriteTls\")&&typeof args[0]===\"number\"&&typeof globalThis.__exactTlsEngineClose===\"function\"){globalThis.__exactTlsEngineClose(args[0]);cleanup=\"closed-tls-engine\";}else if(n===\"setTimeout\"",
        1,
    )
}

const NATIVE_ASYNC_RESULT_SLOT: &str = "__ibexCapsecNativeAsyncResult";

fn native_async_invocation_script(
    invocation: &NativePublicInvocation,
    arguments: &[serde_json::Value],
) -> String {
    let completion = invocation
        .completion
        .as_ref()
        .expect("async native invocation requires a completion contract");
    assert_eq!(completion.kind, "event-loop-quiescence");
    assert_eq!(completion.timeout_milliseconds, 1_000);
    assert!(arguments.iter().all(|argument| argument["kind"] == "json-literal"));
    format!(
        "(function(){{var slot={};var n={};delete globalThis[slot];function record(value){{globalThis[slot]=JSON.stringify(value);}}function returned(value){{return {{kind:\"return\",globalName:n,valueType:value===null?\"null\":typeof value,resultString:typeof value===\"string\"?value:null,cleanup:n===\"__exactFsCloseAsync\"&&typeof args[0]===\"number\"?\"consumed-fs-file-descriptor\":\"none\"}};}}var f=globalThis[n];if(typeof f!==\"function\"){{record({{kind:\"missing\",globalName:n}});return \"completed\";}}var specs={};var args=specs.map(function(spec){{if(spec.kind!==\"json-literal\")throw new Error(\"async native fixtures accept only materialized JSON literals\");return spec.value;}});try{{var value=Reflect.apply(f,globalThis,args);if(value===null||typeof value.then!==\"function\"){{record(returned(value));return \"completed\";}}value.then(function(result){{record(returned(result));}},function(error){{record({{kind:\"throw\",globalName:n,errorName:String(error&&error.name||\"Error\"),errorMessage:String(error&&error.message||error)}});}});return \"scheduled\";}}catch(error){{record({{kind:\"throw\",globalName:n,errorName:String(error&&error.name||\"Error\"),errorMessage:String(error&&error.message||error)}});return \"completed\";}}}})()",
        serde_json::to_string(NATIVE_ASYNC_RESULT_SLOT).expect("serialize native async slot"),
        serde_json::to_string(&invocation.global_name).expect("serialize async native global"),
        serde_json::to_string(arguments).expect("serialize async native arguments"),
    )
}

fn remove_native_async_harness_fields(invocation_result: &mut serde_json::Value) {
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // resultString transports an owned cleanup path inside the harness; it is
    // not part of the exact public runtime-result evidence schema.
    if let Some(result) = invocation_result.as_object_mut() {
        result.remove("resultString");
    }
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
    if descriptor.member_kinds.iter().any(|kind| kind == "inherited") {
        assert_eq!(descriptor.value_shape, "data");
        assert!(descriptor.member_kinds.iter().any(|kind| kind == "static"));
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
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // an async dispatcher may observe its source-selected worker edge, but no
    // unrelated edge may be admitted by the authored recipe.
    let auxiliary_worker_terminal = if invocation.global_name == "__exactFsPathAsync" {
        match invocation.arguments.first() {
            Some(NativeProbeArgument::JsonLiteral { value })
                if value.as_str() == Some("readdir") =>
            {
                Some("native-op:__exactReaddir")
            }
            Some(NativeProbeArgument::JsonLiteral { value })
                if value.as_str() == Some("realpath") =>
            {
                Some("native-op:__exactRealpath")
            }
            Some(NativeProbeArgument::JsonLiteral { value })
                if matches!(value.as_str(), Some("mkdir" | "mkdtemp")) =>
            {
                Some("native-op:__exactMkdir")
            }
            _ => None,
        }
    } else {
        None
    };
    let mut expected_allowed_coverage_edge_ids = recipe.edge_ids.clone();
    if let Some(worker_terminal) = auxiliary_worker_terminal {
        let worker_edges = coverage_terminals
            .iter()
            .filter_map(|(edge_id, terminal)| {
                (terminal == worker_terminal).then_some(edge_id.clone())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            worker_edges.len(),
            1,
            "{}: async worker terminal must select one coverage edge",
            recipe.fixture_id
        );
        expected_allowed_coverage_edge_ids.extend(worker_edges);
    }
    expected_allowed_coverage_edge_ids.sort();
    expected_allowed_coverage_edge_ids.dedup();
    assert_eq!(
        invocation.allowed_coverage_edge_ids,
        expected_allowed_coverage_edge_ids
    );
    assert!(
        invocation
            .expected_action_ids
            .iter()
            .all(|action| recipe.action_ids.contains(action)),
        "{}: runtime-observed action expectation exceeds the semantic recipe",
        recipe.fixture_id
    );
    if invocation.expected_typed_decision_count > 0 {
        assert!(
            !invocation.expected_action_ids.is_empty(),
            "{}: typed runtime expectation has no action",
            recipe.fixture_id
        );
    }
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
            if invocation.kind == "global-property-read" {
                let descriptor: GlobalReadSourceDescriptor =
                    serde_json::from_value(invocation.source_descriptor.clone())
                        .expect("global read source descriptor must be typed");
                let result = invocation_result
                    .as_object()
                    .expect("global property read result must be an object");
                assert_eq!(result.len(), 5);
                for key in ["kind", "globalName", "valueType", "ownerDepths", "cleanup"] {
                    assert!(result.contains_key(key), "global read result lacks {key}");
                }
                assert!(invocation_result["valueType"].is_string());
                assert_eq!(invocation_result["cleanup"], "none");
                let owner_depths = invocation_result["ownerDepths"]
                    .as_array()
                    .expect("global read result has no owner depths");
                assert_eq!(owner_depths.len(), descriptor.access.path.len());
                assert!(owner_depths.iter().all(|depth| depth.as_u64().is_some()));
                let inherited = descriptor
                    .member_kinds
                    .iter()
                    .any(|kind| kind == "inherited");
                if inherited {
                    assert!(owner_depths
                        .last()
                        .and_then(serde_json::Value::as_u64)
                        .is_some_and(|depth| depth > 0));
                }
            }
            if let Some(expected_cleanup) = &invocation.expected_cleanup {
                assert_eq!(
                    invocation_result["cleanup"], expected_cleanup.as_str(),
                    "{}: native public invocation did not prove its authored cleanup",
                    recipe.fixture_id
                );
            }
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
                    .is_some_and(|message| message
                        .to_ascii_lowercase()
                        .contains("permission denied")),
                "{}: denied public native invocation threw the wrong error: {invocation_result}",
                recipe.fixture_id
            );
            serde_json::json!({
                "kind": "typed-permission-denial",
                "bodyEntered": true,
            })
        }
        "invalid-handle" => {
            // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
            // an owner-authenticated retained-object control may prove its
            // exact unknown-id refusal without claiming an effect decision.
            assert_eq!(
                invocation_result["kind"], "throw",
                "{}: retained-object refusal did not throw: {invocation_result}",
                recipe.fixture_id
            );
            assert_eq!(
                invocation_result["errorName"], "Error",
                "{}: retained-object refusal threw the wrong error: {invocation_result}",
                recipe.fixture_id
            );
            assert!(
                invocation_result["errorMessage"]
                    .as_str()
                    .is_some_and(|message| message.ends_with(": invalid handle")),
                "{}: retained-object refusal accepted the wrong failure: {invocation_result}",
                recipe.fixture_id
            );
            serde_json::json!({
                "kind": "retained-object-refusal",
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
        assert!(
            (recipe.classification == "non-capability" && recipe.scenario == "non-capability")
                || (recipe.classification == "effects"
                    && recipe.action_ids.is_empty()
                    && matches!(recipe.scenario.as_str(), "branch-selection" | "no-effect")),
            "{}: a zero-decision public invocation did not select a reviewed zero-effect branch",
            recipe.fixture_id
        );
        probe.surface_observed_key.clone()
    } else if let Some(worker_terminal) = auxiliary_worker_terminal {
        assert_eq!(
            observed_terminals,
            BTreeSet::from([worker_terminal.to_owned()]),
            "{}: async invocation did not remain on its source-selected worker",
            recipe.fixture_id
        );
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
    let fs_path_async_fixture = if invocation.global_name == "__exactFsPathAsync" {
        match (
            invocation.arguments.first(),
            invocation.arguments.get(1),
        ) {
            (
                Some(NativeProbeArgument::JsonLiteral { value: operation }),
                Some(NativeProbeArgument::JsonLiteral { value: path }),
            ) if matches!(operation.as_str(), Some("mkdir" | "mkdtemp")) => Some((
                operation.as_str().unwrap().to_owned(),
                path.as_str()
                    .expect("filesystem fixture path must be a string")
                    .to_owned(),
            )),
            _ => None,
        }
    } else {
        None
    };
    if let Some((operation, path)) = &fs_path_async_fixture {
        assert!(
            path.starts_with("target/ibex-capsec-fspathasync-"),
            "filesystem fixture cleanup path escaped its owned target prefix"
        );
        if operation == "mkdir" {
            let _ = std::fs::remove_dir(path);
        } else {
            std::fs::create_dir_all(path)
                .expect("create owned mkdtemp fixture parent");
        }
    }
    let fs_path_async_file_fixture = if invocation.global_name == "__exactFsPathAsync" {
        match (
            invocation.arguments.first(),
            invocation.arguments.get(1),
        ) {
            (
                Some(NativeProbeArgument::JsonLiteral { value: operation }),
                Some(NativeProbeArgument::JsonLiteral { value: path }),
            ) if matches!(
                operation.as_str(),
                Some("truncate" | "chmod" | "utime")
            ) => Some((
                operation.as_str().unwrap().to_owned(),
                path.as_str()
                    .expect("filesystem file fixture path must be a string")
                    .to_owned(),
            )),
            _ => None,
        }
    } else {
        None
    };
    if let Some((operation, path)) = &fs_path_async_file_fixture {
        assert_eq!(
            path,
            &format!("target/ibex-capsec-fspathasync-{operation}")
        );
        std::fs::write(path, b"ibex-capsec-retained-file")
            .expect("create owned retained-file fixture");
    }
    let session_id = format!("public-observation:{}", recipe.plan_digest);
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id),
        "public native observer has no installed host"
    );
    let result = if let Some(completion) = &invocation.completion {
        assert_eq!(completion.kind, "event-loop-quiescence");
        let scheduled = tokio::time::timeout(
            std::time::Duration::from_millis(completion.timeout_milliseconds),
            engine.eval(&native_async_invocation_script(invocation, &arguments)),
        )
        .await
        .expect("native public async invocation exceeded its completion bound")
        .expect("schedule native public async invocation in Hermes");
        assert!(
            matches!(scheduled.as_deref(), Some("scheduled" | "completed")),
            "native public async invocation returned an invalid scheduling marker: {scheduled:?}"
        );
        engine
            .eval_immediate(NATIVE_ASYNC_RESULT_SLOT)
            .await
    } else {
        engine
            .eval_immediate(&native_invocation_script(
                invocation,
                &arguments,
                &setup_state,
            ))
            .await
    };
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    let encoded = result
        .expect("execute native public invocation in Hermes")
        .expect("native public invocation returned no result");
    let mut invocation_result: serde_json::Value =
        serde_json::from_str(&encoded).expect("native public invocation returned invalid JSON");
    if let Some((operation, path)) = &fs_path_async_fixture {
        if invocation_result["kind"] == "return" {
            let created = if operation == "mkdir" {
                path.as_str()
            } else {
                invocation_result["resultString"]
                    .as_str()
                    .expect("mkdtemp public result must identify its created directory")
            };
            assert!(
                created.starts_with(path),
                "created filesystem fixture escaped its owned cleanup prefix"
            );
            std::fs::remove_dir(created)
                .expect("remove directory created by async filesystem fixture");
            invocation_result["cleanup"] =
                serde_json::Value::String("removed-created-directory".into());
        }
        if operation == "mkdtemp" {
            std::fs::remove_dir(path).expect("remove owned mkdtemp fixture parent");
        }
    }
    if let Some((operation, path)) = &fs_path_async_file_fixture {
        if invocation_result["kind"] == "return" {
            let metadata = std::fs::metadata(path)
                .expect("read retained-file fixture metadata");
            if operation == "truncate" {
                assert_eq!(
                    metadata.len(),
                    2,
                    "retained truncate fixture has the wrong final length"
                );
            }
            #[cfg(unix)]
            if operation == "chmod" {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    metadata.permissions().mode() & 0o777,
                    0o600,
                    "retained chmod fixture has the wrong final mode"
                );
            }
            if operation == "utime" {
                assert_eq!(
                    metadata
                        .modified()
                        .expect("read retained utime fixture timestamp")
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("retained utime fixture timestamp predates epoch")
                        .as_secs(),
                    2,
                    "retained utime fixture has the wrong final timestamp"
                );
            }
            invocation_result["cleanup"] =
                serde_json::Value::String("removed-owned-file".into());
        }
        std::fs::remove_file(path).expect("remove owned retained-file fixture");
    }
    remove_native_async_harness_fields(&mut invocation_result);
    let typed_decisions = observed_typed_values(&session_id, typed);
    let validation = validate_native_runtime_observation(
        recipe,
        probe,
        &invocation_result,
        legacy.len(),
        &typed_decisions,
        coverage_terminals,
    );
    let mut runtime_observation = serde_json::json!({
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
    if let Some(completion) = &invocation.completion {
        runtime_observation["invocation"]["completion"] = serde_json::json!({
            "kind": completion.kind,
            "status": "quiescent",
            "timeoutMilliseconds": completion.timeout_milliseconds,
        });
    }
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

fn take_host_sqlite_json(pointer: *mut std::ffi::c_char) -> serde_json::Value {
    assert!(!pointer.is_null(), "host SQLite operation returned no result");
    let text = unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_str()
        .expect("host SQLite result must be UTF-8");
    let value = capsec_semantics::strict_json::parse_strict(text)
        .expect("host SQLite result must be strict JSON");
    crate::host::abi::ex_host_free_string(pointer);
    value
}

async fn execute_host_abi_public_recipe(
    recipe: &Recipe,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let probe = recipe
        .public_surface_probe
        .as_ref()
        .expect("host ABI recipe must have a public probe");
    let invocation = probe
        .invocation
        .host_abi()
        .expect("host ABI executor received another invocation schema");
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "effects");
    assert!(matches!(recipe.scenario.as_str(), "branch-selection" | "no-effect"));
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert_eq!(probe.surface_observed_key, format!("host-abi:{}", invocation.function_name));
    assert_eq!(probe.surface_observed_key, recipe.terminal_observed_key);
    assert!(recipe.route.alternatives.iter().any(|alternative| {
        alternative.terminal_observed_key == probe.surface_observed_key
    }));
    assert_eq!(invocation.kind, "host-abi-function");
    assert_eq!(invocation.expected_result, "return");
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert_eq!(invocation.allowed_coverage_edge_ids, recipe.edge_ids);
    assert!(invocation.expected_action_ids.is_empty());
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_value_digest(&invocation.source_descriptor)
    );
    assert_eq!(invocation.source_descriptor["kind"], "host-abi-function");
    assert_eq!(
        invocation.source_descriptor["functionName"],
        invocation.function_name
    );
    assert_eq!(
        invocation.source_descriptor["sourceRefs"],
        serde_json::json!([format!("src/host/abi.rs#{}", invocation.function_name)])
    );
    assert_eq!(
        invocation.source_descriptor["sourceMetadata"]["definitions"][0]["language"],
        "rust"
    );
    assert_eq!(
        invocation.source_descriptor["selectedBranch"],
        invocation.operation["selectedBranch"]
    );
    assert_eq!(invocation.operation["kind"], "sqlite-memory");
    assert_eq!(invocation.operation["selectedBranch"]["id"], "memory");
    assert_eq!(
        invocation.operation["selectedBranch"]["when"][0]["equals"],
        "memory"
    );

    let session_id = format!("public-host-abi:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(
        &session_id
    ));
    let memory = std::ffi::CString::new(":memory:").unwrap();
    let select = std::ffi::CString::new("SELECT 1 AS value").unwrap();
    let create = std::ffi::CString::new("CREATE TABLE value(id INTEGER)").unwrap();
    let db = crate::host::abi::ex_host_sqlite_open(memory.as_ptr(), std::ptr::null());
    assert_ne!(db, 0, "host SQLite memory setup failed");
    let mut statement = 0_u64;
    let operation_result = match invocation.function_name.as_str() {
        "ex_host_sqlite_open" => serde_json::json!({"handle": db}),
        "ex_host_sqlite_prepare" => {
            let value = take_host_sqlite_json(crate::host::abi::ex_host_sqlite_prepare(
                db,
                select.as_ptr(),
            ));
            statement = value["handle"]
                .as_u64()
                .expect("host SQLite prepare returned no handle");
            value
        }
        name @ ("ex_host_sqlite_all" | "ex_host_sqlite_get" | "ex_host_sqlite_values") => {
            let prepared = take_host_sqlite_json(crate::host::abi::ex_host_sqlite_prepare(
                db,
                select.as_ptr(),
            ));
            statement = prepared["handle"]
                .as_u64()
                .expect("host SQLite query setup returned no handle");
            let pointer = match name {
                "ex_host_sqlite_all" => {
                    crate::host::abi::ex_host_sqlite_all(statement, std::ptr::null())
                }
                "ex_host_sqlite_get" => {
                    crate::host::abi::ex_host_sqlite_get(statement, std::ptr::null())
                }
                "ex_host_sqlite_values" => {
                    crate::host::abi::ex_host_sqlite_values(statement, std::ptr::null())
                }
                _ => unreachable!(),
            };
            take_host_sqlite_json(pointer)
        }
        "ex_host_sqlite_run" => {
            let prepared = take_host_sqlite_json(crate::host::abi::ex_host_sqlite_prepare(
                db,
                create.as_ptr(),
            ));
            statement = prepared["handle"]
                .as_u64()
                .expect("host SQLite run setup returned no handle");
            take_host_sqlite_json(crate::host::abi::ex_host_sqlite_run(
                statement,
                std::ptr::null(),
            ))
        }
        "ex_host_sqlite_exec" => take_host_sqlite_json(crate::host::abi::ex_host_sqlite_exec(
            db,
            create.as_ptr(),
            std::ptr::null(),
        )),
        other => panic!("unsupported conditional host ABI {other}"),
    };
    if statement != 0 {
        assert_eq!(crate::host::abi::ex_host_sqlite_finalize(statement), 0);
    }
    assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());
    assert!(operation_result.is_object());

    let invocation_result = serde_json::json!({
        "kind": "return",
        "functionName": invocation.function_name,
        "operation": "sqlite-memory",
        "cleanup": "released-sqlite-memory-state",
    });
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": "ibex/capsec-host-abi-invocation/1",
            "kind": invocation.kind,
            "surfaceObservedKey": probe.surface_observed_key,
            "functionName": invocation.function_name,
            "sourceDescriptorDigest": invocation.source_descriptor_digest,
            "result": invocation_result,
        },
        "legacyObservationCount": legacy.len(),
        "typedDecisions": [],
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected host ABI observation must be an object")
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
    serde_json::json!({
        "fixtureId": recipe.fixture_id,
        "outcome": "passed",
        "executor": "ibex-native-public-surface-harness",
        "evidence": evidence,
    })
}

async fn execute_module_runner_host_abi_public_recipe(
    recipe: &Recipe,
    engine_binary_digest: &str,
) -> serde_json::Value {
    use ibex_runtime::module_loader::runner_pipeline::{
        build_authenticated_source_graph_v1, load_prepared_source_graph_v1,
        publish_prepared_source_graph_v1, SourceModuleGraphBuildV1,
    };

    let probe = recipe
        .public_surface_probe
        .as_ref()
        .expect("module-runner host ABI recipe must have a public probe");
    let invocation = probe
        .invocation
        .host_abi()
        .expect("module-runner host ABI executor received another schema");
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "non-capability");
    assert_eq!(recipe.scenario, "non-capability");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert_eq!(probe.surface_observed_key, format!("host-abi:{}", invocation.function_name));
    assert_eq!(probe.surface_observed_key, recipe.terminal_observed_key);
    assert_eq!(invocation.kind, "host-abi-function");
    assert_eq!(invocation.operation["kind"], "module-runner-source-graph");
    assert_eq!(invocation.expected_result, "return");
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert_eq!(invocation.allowed_coverage_edge_ids, recipe.edge_ids);
    assert!(invocation.expected_action_ids.is_empty());
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_value_digest(&invocation.source_descriptor)
    );
    assert_eq!(invocation.source_descriptor["kind"], "host-abi-function");
    assert_eq!(invocation.source_descriptor["functionName"], invocation.function_name);
    assert_eq!(
        invocation.source_descriptor["sourceRefs"],
        serde_json::json!([format!(
            "src/engine/hermes_module_runner.cc#{}",
            invocation.function_name
        )])
    );
    assert_eq!(
        invocation.source_descriptor["sourceMetadata"]["definitions"][0]["language"],
        "c++"
    );

    let directory = tempfile::tempdir().expect("create module-runner public graph root");
    let project_root = std::fs::canonicalize(directory.path())
        .expect("canonicalize module-runner public graph root");
    let entry = project_root.join("entry.mjs");
    std::fs::write(
        &entry,
        "import { value as imported } from './dep.mjs';\n\
         export { other as forwarded } from './dep.mjs';\n\
         export * from './star.mjs';\n\
         export const local = imported;\n\
         export function loadDynamic() { return import('./dynamic.mjs'); }\n",
    )
    .expect("write module-runner public entry");
    std::fs::write(
        project_root.join("dep.mjs"),
        "export let value = 1; export const other = 2;\n",
    )
    .expect("write module-runner public dependency");
    std::fs::write(
        project_root.join("star.mjs"),
        "export const star = 3;\n",
    )
    .expect("write module-runner public star dependency");
    std::fs::write(
        project_root.join("dynamic.mjs"),
        "export const dynamicValue = 4;\n",
    )
    .expect("write module-runner public dynamic dependency");
    let commonjs_entry = project_root.join("commonjs-entry.cjs");
    std::fs::write(
        &commonjs_entry,
        "const peer = require('./commonjs-peer.cjs');\n\
         const esm = require('./commonjs-esm.mjs');\n\
         exports.total = peer.value + esm.value;\n\
         import('./dynamic.mjs');\n",
    )
    .expect("write module-runner public CommonJS entry");
    std::fs::write(
        project_root.join("commonjs-peer.cjs"),
        "exports.value = 2;\n",
    )
    .expect("write module-runner public CommonJS dependency");
    std::fs::write(
        project_root.join("commonjs-esm.mjs"),
        "export const value = 3;\n",
    )
    .expect("write module-runner public CommonJS ESM dependency");
    let asynchronous_entry = project_root.join("asynchronous-entry.mjs");
    std::fs::write(
        &asynchronous_entry,
        "await new Promise((resolve) => setTimeout(resolve, 0));\n\
         export const settled = true;\n",
    )
    .expect("write module-runner public asynchronous entry");

    let (host, snapshot_digest) = build_armed_test_host_custom(
        Some(&project_root),
        false,
        true,
        true,
        Vec::new(),
        None,
        |_| {},
    );
    assert_ne!(crate::host::abi::install_host(host), 0);
    let _reset = HostResetGuard;
    let producer_digest = capsec_semantics::model::Digest::new(engine_binary_digest.to_owned())
        .expect("loaded engine digest is a canonical digest");
    let build_graph = |entry: &std::path::Path, label: &str| {
        match build_authenticated_source_graph_v1(entry, producer_digest.clone(), label)
            .expect("build authenticated module-runner public graph")
        {
            SourceModuleGraphBuildV1::Native(graph) => graph,
            SourceModuleGraphBuildV1::LegacyRequired(requirement) => {
                panic!(
                    "module-runner public graph unexpectedly required legacy: {}",
                    requirement.reason
                )
            }
        }
    };
    let graph = build_graph(&entry, "capsec-module-runner-public-esm");
    let commonjs_graph = build_graph(
        &commonjs_entry,
        "capsec-module-runner-public-commonjs",
    );
    let asynchronous_graph = build_graph(
        &asynchronous_entry,
        "capsec-module-runner-public-asynchronous",
    );
    let deployment_digest = ibex_runtime::module_loader::artifact::digest_bytes(
        "ibex/capsec-module-runner-public-prepared/1",
        b"authenticated prepared graph",
    )
    .expect("digest module-runner public prepared graph");
    let prepared_cache = publish_prepared_source_graph_v1(
        &graph,
        &project_root,
        deployment_digest.clone(),
    )
    .expect("publish authenticated module-runner public prepared graph");
    let prepared_graph = load_prepared_source_graph_v1(
        &prepared_cache,
        &producer_digest,
        &deployment_digest,
    )
    .expect("load authenticated module-runner public prepared graph");
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create isolated module-runner host ABI engine");
    engine
        .load_runtime()
        .await
        .expect("load runtime before module-runner host ABI recipe");
    unsafe { ibex_test_begin_module_runner_abi_observation() };
    let session_id = format!("public-module-runner-host-abi:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(
        &session_id
    ));
    let runtime = engine
        .ensure_runtime()
        .await
        .expect("borrow loaded runtime for graph-context retain");
    runtime
        .with_runtime(|raw| -> anyhow::Result<()> {
            use ibex_runtime::engine::module_runner::{
                GraphEvaluationContext, NativeModuleRuntime,
            };
            use ibex_runtime::module_loader::identity::SourceId;

            let nonce = unsafe { ex_hermes_runtime_nonce(raw) };
            let raw = std::ptr::NonNull::new(raw.cast())
                .expect("loaded Hermes runtime pointer is non-null");
            let native = unsafe { NativeModuleRuntime::from_raw(raw, nonce)? };
            let context = native.create_graph_context(GraphEvaluationContext::new(
                SourceId::synthetic("capsec-module-runner-public", "retained-context")?,
                0,
                0,
                [0],
                1,
            )?)?;
            let retained = context.clone();
            drop(retained);
            drop(context);
            Ok(())
        })
        .expect("access loaded runtime for graph-context retain")
        .expect("retain a real native graph context");
    engine
        .run_authenticated_module_graph(&graph)
        .await
        .expect("execute authenticated module-runner public ESM graph");
    engine
        .run_authenticated_module_graph(&commonjs_graph)
        .await
        .expect("execute authenticated module-runner public CommonJS graph");
    engine
        .run_authenticated_module_graph(&asynchronous_graph)
        .await
        .expect("execute authenticated module-runner public asynchronous graph");
    engine
        .run_authenticated_module_graph(&prepared_graph)
        .await
        .expect("execute authenticated module-runner public prepared graph");
    let pointer = unsafe { ibex_test_take_module_runner_abi_observation() };
    assert!(!pointer.is_null(), "module-runner ABI observer returned no result");
    let observed_text = unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_str()
        .expect("module-runner ABI observations must be UTF-8")
        .to_owned();
    unsafe { ex_hermes_free_string(pointer) };
    let observed_function_names: Vec<String> = serde_json::from_value(
        capsec_semantics::strict_json::parse_strict(&observed_text)
            .expect("module-runner ABI observations must be strict JSON"),
    )
    .expect("module-runner ABI observations must be a string array");
    assert!(
        observed_function_names
            .iter()
            .any(|name| name == &invocation.function_name),
        "module-runner public graph did not enter {}: {:?}",
        invocation.function_name,
        observed_function_names
    );
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());

    let invocation_result = serde_json::json!({
        "kind": "return",
        "functionName": invocation.function_name,
        "operation": "module-runner-source-graph",
        "observedFunctionNames": observed_function_names,
        "cleanup": "released-module-graph",
    });
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": "ibex/capsec-host-abi-invocation/1",
            "kind": invocation.kind,
            "surfaceObservedKey": probe.surface_observed_key,
            "functionName": invocation.function_name,
            "sourceDescriptorDigest": invocation.source_descriptor_digest,
            "result": invocation_result,
        },
        "legacyObservationCount": legacy.len(),
        "typedDecisions": [],
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected module-runner ABI observation must be an object")
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
    serde_json::json!({
        "fixtureId": recipe.fixture_id,
        "outcome": "passed",
        "executor": "ibex-native-public-surface-harness",
        "evidence": evidence,
    })
}

#[derive(Clone)]
struct ModuleLoaderPublicPolicy {
    digest: capsec_semantics::model::Digest,
    generations: capsec_semantics::arming::SnapshotGenerations,
}

impl ibex_runtime::module_loader::security::GraphImportPolicy for ModuleLoaderPublicPolicy {
    fn snapshot_digest(&self) -> &capsec_semantics::model::Digest {
        &self.digest
    }

    fn snapshot_generations(&self) -> capsec_semantics::arming::SnapshotGenerations {
        self.generations
    }

    fn authenticates_module_edge(
        &self,
        _importer: &capsec_semantics::model::Principal,
        specifier: &str,
        _imported: &capsec_semantics::model::Principal,
        resolution_kind: &str,
        conditions: &[String],
        attributes: &BTreeMap<String, String>,
    ) -> bool {
        specifier == "dep"
            && resolution_kind == "esm-static"
            && conditions == ["import", "node"]
            && attributes.is_empty()
    }
}

fn module_loader_public_digest(label: &str) -> capsec_semantics::model::Digest {
    use sha2::Digest as _;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(label));
    capsec_semantics::model::Digest::new(format!("sha256-{encoded}"))
        .expect("module-loader public fixture digest")
}

fn module_loader_public_principal(name: &str) -> capsec_semantics::model::Principal {
    capsec_semantics::model::Principal::Package {
        name: capsec_semantics::model::NonEmptyString::new(name)
            .expect("module-loader public fixture package name"),
        integrity: module_loader_public_digest(name),
        locator: capsec_semantics::model::PackageLocator::new(format!("{name}@1.0.0"))
            .expect("module-loader public fixture locator"),
    }
}

// @ref LLP 0021#module-initialization-and-trusted-source-acquisition — prove
// the authenticated loader receipt path separately from ordinary host-effect
// DecisionSets; a successful access therefore observes no CapSec decision.
async fn execute_module_loader_public_recipe(
    recipe: &Recipe,
    engine_binary_digest: &str,
) -> serde_json::Value {
    use capsec_semantics::arming::{SnapshotGenerations};
    use capsec_semantics::model::{Generation, PathComponent, Stage};
    use ibex_runtime::module_loader::identity::{
        ConditionSet, ImportAttributes, ResolutionKind, SourceId,
    };
    use ibex_runtime::module_loader::security::{
        GraphAuthorityContext, GraphDecisionSet, GraphOperationKind, ModuleGraphAuthorizer,
    };

    let probe = recipe
        .public_surface_probe
        .as_ref()
        .expect("module-loader recipe must have a public probe");
    let invocation = probe
        .invocation
        .module_loader()
        .expect("module-loader executor received another invocation schema");
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "non-capability");
    assert_eq!(recipe.scenario, "non-capability");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert_eq!(probe.surface_observed_key, format!("loader:{}", invocation.surface_name));
    assert_eq!(probe.surface_observed_key, recipe.terminal_observed_key);
    assert!(recipe.route.alternatives.iter().any(|alternative| {
        alternative.terminal_observed_key == probe.surface_observed_key
    }));
    assert_eq!(invocation.kind, "module-loader-authority");
    assert_eq!(invocation.expected_result, "return");
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert_eq!(invocation.allowed_coverage_edge_ids, recipe.edge_ids);
    assert!(invocation.expected_action_ids.is_empty());
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_value_digest(&invocation.source_descriptor)
    );
    assert_eq!(invocation.source_descriptor["kind"], "module-loader-function");
    assert_eq!(invocation.source_descriptor["surfaceName"], invocation.surface_name);

    let expected = match invocation.surface_name.as_str() {
        "module-runner-edge-authorization" => ("authorize-edge", "authorize"),
        "module-runner-trusted-source-acquisition" => {
            ("source-acquisition", "authorize_then_access")
        }
        "module-runner-cache-access" => ("cache-read", "authorize_then_access"),
        "module-runner-prepared-carrier-access" => {
            ("prepared-carrier-read", "authorize_then_access")
        }
        other => panic!("unsupported module-loader public surface {other}"),
    };
    assert_eq!(invocation.operation["kind"], expected.0);
    assert_eq!(
        invocation.source_descriptor["sourceRefs"],
        serde_json::json!([format!("src/module_loader/security.rs#{}", expected.1)])
    );

    let generation = Generation::new(1).expect("module-loader public fixture generation");
    let policy = ModuleLoaderPublicPolicy {
        digest: module_loader_public_digest("module-loader-public-snapshot"),
        generations: SnapshotGenerations {
            policy: generation,
            negative: generation,
            dynamic: generation,
            handle: generation,
        },
    };
    let importer = module_loader_public_principal("app");
    let imported = module_loader_public_principal("dep");
    let requester = SourceId::file(
        importer.clone(),
        vec![PathComponent::utf8("entry.mjs").expect("fixture path component")],
    )
    .expect("module-loader public requester");
    let target = SourceId::file(
        imported,
        vec![PathComponent::utf8("index.mjs").expect("fixture path component")],
    )
    .expect("module-loader public target");
    let decision = || {
        GraphDecisionSet::new(
            GraphOperationKind::StaticImport,
            GraphAuthorityContext::new(
                requester.clone(),
                importer.clone(),
                importer.clone(),
                importer.clone(),
                vec![importer.clone()],
                Stage::Requested,
                7,
            )
            .expect("module-loader public authority context"),
            target.clone(),
            "dep",
            ResolutionKind::EsmStatic,
            ConditionSet::for_kind(ResolutionKind::EsmStatic),
            ImportAttributes::default(),
            None,
            None,
        )
        .expect("module-loader public decision")
    };
    let authorizer = ModuleGraphAuthorizer::new(&policy);
    let accessed = std::cell::Cell::new(false);
    let session_id = format!("public-module-loader:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(
        &session_id
    ));
    match expected.0 {
        "authorize-edge" => {
            authorizer
                .authorize(decision())
                .expect("authenticated module edge must authorize");
        }
        operation => {
            let access_kind = match operation {
                "source-acquisition" => GraphOperationKind::SourceAcquisition,
                "cache-read" => GraphOperationKind::CacheRead,
                "prepared-carrier-read" => GraphOperationKind::PreparedCarrierRead,
                _ => unreachable!(),
            };
            authorizer
                .authorize_then_access(
                    decision(),
                    access_kind,
                    module_loader_public_digest("module-loader-public-source"),
                    (access_kind == GraphOperationKind::PreparedCarrierRead)
                        .then(|| module_loader_public_digest("module-loader-public-carrier")),
                    || {
                        accessed.set(true);
                        Ok(())
                    },
                )
                .expect("authenticated module-loader access must execute");
            assert!(accessed.get(), "module-loader access closure did not run");
        }
    }
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());

    let invocation_result = serde_json::json!({
        "kind": "return",
        "surfaceName": invocation.surface_name,
        "operation": expected.0,
        "accessExecuted": accessed.get(),
        "cleanup": "none",
    });
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": "ibex/capsec-module-loader-invocation/1",
            "kind": invocation.kind,
            "surfaceObservedKey": probe.surface_observed_key,
            "surfaceName": invocation.surface_name,
            "sourceDescriptorDigest": invocation.source_descriptor_digest,
            "result": invocation_result,
        },
        "legacyObservationCount": legacy.len(),
        "typedDecisions": [],
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected module-loader observation must be an object")
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
    (probe.invocation.native().is_some()
        || probe.invocation.host_abi().is_some()
        || probe.invocation.module_loader().is_some())
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
        let probe = recipe
            .public_surface_probe
            .as_ref()
            .expect("native recipe index must contain a public invocation");
        if let Some(invocation) = probe.invocation.native() {
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
            let (_reset, snapshot_digest) = install_native_public_test_host(
                invocation,
                listener_port,
                recipe.scenario == "deny",
            );
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
        } else if probe.invocation.host_abi().is_some() {
            if probe.invocation.host_abi().unwrap().operation["kind"]
                == "module-runner-source-graph"
            {
                executions.push(
                    execute_module_runner_host_abi_public_recipe(
                        recipe,
                        &identity_before.binary_digest,
                    )
                    .await,
                );
            } else {
                let (host, snapshot_digest) = build_armed_test_host_custom(
                    None,
                    false,
                    false,
                    false,
                    Vec::new(),
                    None,
                    |_| {},
                );
                assert_ne!(crate::host::abi::install_host(host), 0);
                let _reset = HostResetGuard;
                let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
                    .expect("create isolated host-ABI public recipe engine");
                engine
                    .load_runtime()
                    .await
                    .expect("load runtime before host-ABI public recipe");
                executions.push(
                    execute_host_abi_public_recipe(recipe, &identity_before.binary_digest).await,
                );
            }
        } else {
            assert!(probe.invocation.module_loader().is_some());
            let (host, snapshot_digest) =
                build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |_| {});
            assert_ne!(crate::host::abi::install_host(host), 0);
            let _reset = HostResetGuard;
            let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
                .expect("create isolated module-loader public recipe engine");
            engine
                .load_runtime()
                .await
                .expect("load runtime before module-loader public recipe");
            executions.push(
                execute_module_loader_public_recipe(recipe, &identity_before.binary_digest).await,
            );
        }
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
