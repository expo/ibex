use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write as _;

const CALLBACK_INVOCATION_SCHEMA: &str = "ibex/capsec-callback-invariant-invocation/1";
const ENV_AUXILIARY_EDGE_ID: &str = "surface.native.op.exactgetenv.0k6bv7a";
const SNAPSHOT_AUXILIARY_EDGE_ID: &str = "surface.host.abi.ex.host.fs.read.file.042wgnk";
const CALLBACK_BATCH_COMMAND: [&str; 9] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--features",
    "capsec-conformance-observer",
    "capsec_public_callback_invariant_batch",
    "--",
    "--test-threads=1",
];

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
    edge_ids: Vec<String>,
    implementation_branch_ids: Vec<String>,
    enforcement_branch_ids: Vec<String>,
    action_ids: Vec<String>,
    terminal_observed_key: String,
    expected_observation: serde_json::Value,
    route: PublicRoute,
    status: String,
    public_surface_probe: Option<PublicSurfaceProbe>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicRoute {
    surface_observed_keys: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicSurfaceProbe {
    kind: String,
    surface_observed_key: String,
    command: Vec<String>,
    invocation: CallbackInvariantInvocation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CallbackInvariantInvocation {
    invocation_schema: String,
    kind: String,
    #[serde(default)]
    scenario: String,
    #[serde(default)]
    surface_kind: String,
    #[serde(default)]
    surface_name: String,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    expected_result: String,
    expected_typed_decision_count: usize,
    expected_typed_stages: Vec<String>,
    #[serde(default)]
    expected_typed_outcomes: Vec<String>,
    #[serde(default)]
    expected_typed_reasons: Vec<String>,
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

struct PackageFixture {
    _directory: tempfile::TempDir,
    root: std::path::PathBuf,
    package_root: std::path::PathBuf,
    project_file: std::path::PathBuf,
    principal_value: serde_json::Value,
    principal: capsec_semantics::model::Principal,
}

struct ScenarioExecution {
    result: serde_json::Value,
    typed_decisions: Vec<serde_json::Value>,
    legacy_observation_count: usize,
}

fn tagged_jcs_digest(value: &serde_json::Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("callback invariant evidence must have canonical JSON bytes");
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
    assert_eq!(tagged_jcs_digest(&projected), expected_digest);
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
        "recipe fixture ids must be a strictly sorted set"
    );
    catalog
}

fn checked_registry_rows() -> (
    BTreeMap<String, serde_json::Value>,
    BTreeMap<String, serde_json::Value>,
) {
    let implementation: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/generated/implementation-manifest.json"
    )))
    .expect("checked implementation manifest must be JSON");
    let coverage: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/registry/coverage-edges.json"
    )))
    .expect("checked coverage registry must be JSON");
    let branches = implementation["surfaces"]
        .as_array()
        .expect("implementation manifest has no surfaces")
        .iter()
        .map(|row| {
            (
                row["branchId"]
                    .as_str()
                    .expect("implementation row has no branch id")
                    .to_owned(),
                row.clone(),
            )
        })
        .collect();
    let edges = coverage["edges"]
        .as_array()
        .expect("coverage registry has no edges")
        .iter()
        .map(|edge| {
            (
                edge["id"]
                    .as_str()
                    .expect("coverage edge has no id")
                    .to_owned(),
                edge.clone(),
            )
        })
        .collect();
    (branches, edges)
}

fn expected_invariant(scenario: &str) -> (&'static str, Vec<&'static str>, Vec<&'static str>) {
    match scenario {
        "attribution-missing-deny" => (
            "callback-attribution-carrier",
            vec!["deny"],
            vec!["invalid-attribution"],
        ),
        "generation-recheck" => (
            "callback-attribution-carrier",
            vec!["allow", "deny"],
            vec!["dynamic-session", "missing-authority"],
        ),
        "principal-restore" => (
            "callback-attribution-carrier",
            vec!["allow", "allow"],
            vec!["static-floor", "ambient-root"],
        ),
        "snapshot-mismatch-deny" => (
            "callback-attribution-carrier",
            vec!["allow", "deny"],
            vec!["bearer-handle", "invalid-attribution"],
        ),
        "cannot-widen-authority" | "post-lockdown-invariant" => {
            ("authority-control-plane", Vec::new(), Vec::new())
        }
        other => panic!("unsupported callback invariant scenario {other}"),
    }
}

fn callback_recipes(catalog: &RecipeCatalog) -> Vec<&Recipe> {
    catalog
        .recipes
        .iter()
        .filter(|recipe| {
            recipe.status == "fully-executable"
                && recipe.public_surface_probe.as_ref().is_some_and(|probe| {
                    probe.invocation.invocation_schema == CALLBACK_INVOCATION_SCHEMA
                })
        })
        .collect()
}

fn validate_recipe_source_binding(
    recipe: &Recipe,
    branches: &BTreeMap<String, serde_json::Value>,
    edges: &BTreeMap<String, serde_json::Value>,
) {
    let probe = recipe
        .public_surface_probe
        .as_ref()
        .expect("callback invariant recipe has no public probe");
    let invocation = &probe.invocation;
    let descriptor = &invocation.source_descriptor;
    let (rationale, outcomes, reasons) = expected_invariant(&recipe.scenario);
    assert_eq!(recipe.classification, "non-capability");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(recipe.implementation_branch_ids.len(), 1);
    assert_eq!(recipe.enforcement_branch_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(CALLBACK_BATCH_COMMAND));
    assert_eq!(probe.surface_observed_key, recipe.terminal_observed_key);
    assert!(recipe
        .route
        .surface_observed_keys
        .contains(&probe.surface_observed_key));
    assert_eq!(invocation.invocation_schema, CALLBACK_INVOCATION_SCHEMA);
    assert_eq!(invocation.kind, "callback-security-invariant");
    assert_eq!(invocation.scenario, recipe.scenario);
    assert_eq!(invocation.expected_result, "invariant-passed");
    assert_eq!(invocation.expected_typed_decision_count, outcomes.len());
    let expected_stage = if recipe.scenario == "snapshot-mismatch-deny" {
        "commit"
    } else {
        "requested"
    };
    assert_eq!(
        invocation.expected_typed_stages,
        vec![expected_stage.to_owned(); outcomes.len()]
    );
    assert_eq!(
        invocation.expected_typed_outcomes,
        outcomes
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        invocation.expected_typed_reasons,
        reasons
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    );
    if outcomes.is_empty() {
        assert!(invocation.allowed_coverage_edge_ids.is_empty());
        assert!(invocation.expected_action_ids.is_empty());
    } else {
        let (edge_id, action) = if recipe.scenario == "snapshot-mismatch-deny" {
            (SNAPSHOT_AUXILIARY_EDGE_ID, "fs:read")
        } else {
            (ENV_AUXILIARY_EDGE_ID, "env:read")
        };
        assert_eq!(invocation.allowed_coverage_edge_ids, [edge_id]);
        assert_eq!(invocation.expected_action_ids, [action]);
    }
    assert_eq!(
        tagged_jcs_digest(descriptor),
        invocation.source_descriptor_digest
    );
    assert_eq!(descriptor["kind"], "callback-security-invariant");
    assert_eq!(descriptor["scenario"], recipe.scenario);
    assert_eq!(descriptor["rationaleId"], rationale);
    assert_eq!(descriptor["surfaceObservedKey"], probe.surface_observed_key);
    assert_eq!(descriptor["edgeId"], recipe.edge_ids[0]);
    assert_eq!(descriptor["branchId"], recipe.implementation_branch_ids[0]);
    let edge = edges
        .get(&recipe.edge_ids[0])
        .expect("callback invariant names unknown coverage edge");
    let branch = branches
        .get(&recipe.implementation_branch_ids[0])
        .expect("callback invariant names unknown implementation branch");
    assert_eq!(&descriptor["coverageEdge"], edge);
    assert_eq!(&descriptor["implementationBranch"], branch);
    assert_eq!(edge["classification"], "non-capability");
    assert_eq!(edge["rationaleId"], rationale);
    assert_eq!(edge["surface"]["kind"], invocation.surface_kind);
    assert_eq!(edge["surface"]["name"], invocation.surface_name);
    assert_eq!(
        probe.surface_observed_key,
        format!("{}:{}", invocation.surface_kind, invocation.surface_name)
    );
    assert_eq!(branch["edgeId"], recipe.edge_ids[0]);
    assert_eq!(branch["branchId"], recipe.implementation_branch_ids[0]);
    assert_eq!(
        branch["enforcementBranchId"],
        recipe.enforcement_branch_ids[0]
    );
    assert_eq!(
        descriptor["liveSurface"]["observedKey"],
        probe.surface_observed_key
    );
    assert_eq!(descriptor["liveSurface"]["kind"], invocation.surface_kind);
    assert_eq!(descriptor["liveSurface"]["name"], invocation.surface_name);
    let descriptor_refs = descriptor["sourceRefs"]
        .as_array()
        .expect("callback invariant descriptor has no source refs");
    assert!(!descriptor_refs.is_empty());
    assert_eq!(descriptor_refs, branch["sourceRefs"].as_array().unwrap());
    assert!(descriptor_refs.iter().any(|source_ref| {
        descriptor["liveSurface"]["sourceRefs"]
            .as_array()
            .unwrap()
            .contains(source_ref)
    }));
    assert_eq!(
        recipe.expected_observation["branchId"],
        recipe.implementation_branch_ids[0]
    );
}

fn invariant_selector() -> serde_json::Value {
    serde_json::json!({
        "cap": "env:read",
        "resource": {
            "kind": "environment-name",
            "target": "broker-base",
            "name": "IBEX_CALLBACK_INVARIANT"
        },
    })
}

fn snapshot_selector() -> serde_json::Value {
    serde_json::json!({
        "cap": "fs:read",
        "resource": {
            "kind": "path-exact",
            "path": {
                "root": "project",
                "components": [{"encoding": "utf8", "value": "callback-data.txt"}]
            }
        },
    })
}

fn root_principal_value() -> serde_json::Value {
    serde_json::json!({"kind": "root", "identity": "project-root"})
}

fn generations_value(generations: capsec_semantics::cache::GenerationSet) -> serde_json::Value {
    serde_json::to_value(generations).expect("typed generations must serialize")
}

fn package_components(path: &std::path::Path) -> Vec<serde_json::Value> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(serde_json::json!({
                "encoding": "utf8",
                "value": value.to_str().expect("package path must be UTF-8"),
            })),
            _ => None,
        })
        .collect()
}

fn object_identity(path: &std::path::Path) -> serde_json::Value {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path).expect("read callback package metadata");
        serde_json::json!({
            "platform": if cfg!(any(target_os = "macos", target_os = "ios")) {
                "apple"
            } else {
                "unix"
            },
            "volume": format!("dev:{}", metadata.dev()),
            "file": format!("ino:{}", metadata.ino()),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        serde_json::json!({
            "platform": "windows",
            "volume": "callback-fixture-volume",
            "file": "callback-fixture-file",
        })
    }
}

fn prepare_package_fixture() -> PackageFixture {
    let directory = tempfile::tempdir().expect("create callback package fixture");
    let root = std::fs::canonicalize(directory.path()).expect("canonicalize callback fixture root");
    let package_root = root.join("node_modules/image-lib");
    let project_file = root.join("callback-data.txt");
    std::fs::write(&project_file, b"callback invariant\n").expect("write callback project file");
    std::fs::create_dir_all(&package_root).expect("create callback package root");
    std::fs::write(
        package_root.join("package.json"),
        r#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
    )
    .expect("write callback package manifest");
    std::fs::write(
        package_root.join("index.js"),
        r#"module.exports = function(sink, operation, request) {
  var result;
  try { result = { value: __hostCall(operation, request) }; }
  catch (error) { result = { threw: String(error && error.message || error) }; }
  sink(result);
};
"#,
    )
    .expect("write callback package source");
    let integrity = crate::module_loader::package_tree_integrity(&package_root)
        .expect("digest callback package tree");
    let principal_value = serde_json::json!({
        "kind": "package",
        "name": "image-lib",
        "integrity": integrity,
        "locator": "image-lib@2.4.1",
    });
    let principal = serde_json::from_value(principal_value.clone())
        .expect("callback package principal must be valid");
    PackageFixture {
        _directory: directory,
        root,
        package_root,
        project_file,
        principal_value,
        principal,
    }
}

fn build_callback_host(
    package: Option<&PackageFixture>,
    package_floor: Option<&str>,
    package_ceiling: bool,
    run_nonce: Option<&str>,
) -> (crate::host::Host, String) {
    build_armed_test_host_control(
        package.map(|fixture| fixture.root.as_path()),
        false,
        false,
        false,
        Vec::new(),
        Vec::new(),
        false,
        0,
        None,
        |snapshot| {
            if let Some(run_nonce) = run_nonce {
                snapshot["runNonce"] = serde_json::Value::String(run_nonce.to_owned());
            }
            let Some(package) = package else {
                return;
            };
            snapshot["rootBindings"][0]["owner"] = package.principal_value.clone();
            snapshot["rootBindings"][0]["hostPath"] = serde_json::json!({
                "root": "absolute",
                "components": package_components(&package.package_root),
                "hostBound": true,
            });
            snapshot["rootBindings"][0]["object"] = object_identity(&package.package_root);
            snapshot["principals"][1]["principal"] = package.principal_value.clone();
            snapshot["principals"][1]["floor"] = match package_floor {
                Some("environment") => serde_json::json!([invariant_selector()]),
                Some("filesystem") => serde_json::json!([snapshot_selector()]),
                None => serde_json::json!([]),
                Some(other) => panic!("unknown callback package floor {other}"),
            };
            snapshot["principals"][1]["escalationCeiling"] = if package_ceiling {
                serde_json::json!([invariant_selector()])
            } else {
                serde_json::json!([])
            };
            snapshot["principals"][1]["imports"]["builtins"] = serde_json::json!([]);
            snapshot["packageGraph"]["nodes"][0]["principal"] = package.principal_value.clone();
            snapshot["packageGraph"]["importEdges"][0]["imported"] =
                package.principal_value.clone();
        },
    )
}

fn typed_request(
    session_id: &str,
    operation_id: &str,
    principal: serde_json::Value,
    constrained_principals: Vec<serde_json::Value>,
    presented_handle_ids: Vec<String>,
) -> serde_json::Value {
    let decision = serde_json::json!({
        "decisionSetSchema": "ibex/capsec-decision-set/1",
        "operationId": operation_id,
        "atomicityGroup": format!("{ENV_AUXILIARY_EDGE_ID}.decision"),
        "combination": "conjunction",
        "context": {
            "stage": "requested",
            "actor": principal,
            "constrainedPrincipals": constrained_principals,
            "presentedHandleIds": presented_handle_ids,
        },
        "effects": [{
            "cap": "env:read",
            "effectOwner": principal,
            "resource": {
                "kind": "environment-occurrence",
                "requested": {
                    "kind": "environment-name",
                    "target": "broker-base",
                    "name": "IBEX_CALLBACK_INVARIANT"
                },
                "valueOrigin": "broker-base",
            },
        }],
    });
    let gates = serde_json::json!([{
        "coverageEdgeId": ENV_AUXILIARY_EDGE_ID,
        "targetCell": "complete",
        "definitionAndEdgePredicatesSatisfied": true,
    }]);
    serde_json::json!({
        "terminalBranchId": session_id,
        "decisionSetJson": serde_json::to_string(&decision).unwrap(),
        "gatesJson": serde_json::to_string(&gates).unwrap(),
    })
}

fn snapshot_typed_request(
    session_id: &str,
    operation_id: &str,
    package: &PackageFixture,
    handle_id: &str,
) -> serde_json::Value {
    let principal = root_principal_value();
    let decision = serde_json::json!({
        "decisionSetSchema": "ibex/capsec-decision-set/1",
        "operationId": operation_id,
        "atomicityGroup": format!("{SNAPSHOT_AUXILIARY_EDGE_ID}.decision"),
        "combination": "conjunction",
        "context": {
            "stage": "commit",
            "actor": principal.clone(),
            "constrainedPrincipals": [principal.clone()],
            "presentedHandleIds": [handle_id],
        },
        "effects": [{
            "cap": "fs:read",
            "effectOwner": principal,
            "resource": {
                "kind": "path-occurrence",
                "requested": {
                    "root": "project",
                    "components": [{"encoding": "utf8", "value": "callback-data.txt"}],
                },
                "followMode": "follow-final",
                "objectState": "existing",
                "parentObject": object_identity(&package.root),
                "finalObject": object_identity(&package.project_file),
                "retainedHandle": format!("callback:{operation_id}"),
            },
        }],
    });
    let gates = serde_json::json!([{
        "coverageEdgeId": SNAPSHOT_AUXILIARY_EDGE_ID,
        "targetCell": "complete",
        "definitionAndEdgePredicatesSatisfied": true,
    }]);
    serde_json::json!({
        "terminalBranchId": session_id,
        "decisionSetJson": serde_json::to_string(&decision).unwrap(),
        "gatesJson": serde_json::to_string(&gates).unwrap(),
    })
}

fn decode_adapter_wrapper(encoded: &str) -> serde_json::Value {
    let wrapper: serde_json::Value =
        serde_json::from_str(encoded).expect("callback adapter wrapper must be JSON");
    assert!(
        wrapper["threw"].is_null(),
        "callback adapter threw: {wrapper}"
    );
    wrapper["value"].clone()
}

async fn invoke_root_callback(
    engine: &HermesEngine,
    request: &serde_json::Value,
) -> serde_json::Value {
    let script = format!(
        r#"globalThis.__capsecCallbackResult = null;
setTimeout(function(request) {{
  try {{ globalThis.__capsecCallbackResult = {{value: __hostCall('capsec.conformance.evaluate', request)}}; }}
  catch (error) {{ globalThis.__capsecCallbackResult = {{threw: String(error && error.message || error)}}; }}
}}, 0, {});"#,
        serde_json::to_string(request).unwrap()
    );
    engine
        .eval_immediate(&script)
        .await
        .expect("schedule root callback invariant");
    engine
        .drive_event_loop()
        .await
        .expect("drive root callback invariant");
    let encoded = engine
        .eval_immediate("JSON.stringify(globalThis.__capsecCallbackResult)")
        .await
        .expect("read root callback invariant")
        .expect("root callback invariant returned no result");
    decode_adapter_wrapper(&encoded)
}

async fn invoke_package_adapter(
    engine: &HermesEngine,
    request: &serde_json::Value,
    scheduled: bool,
) -> serde_json::Value {
    if scheduled {
        schedule_package_adapter(engine, request).await;
        return take_scheduled_package_adapter(engine).await;
    }
    let invocation = format!(
        r#"globalThis.__capsecCallbackResult = null;
require('image-lib')(function(result) {{ globalThis.__capsecCallbackResult = result; }}, 'capsec.conformance.evaluate', {});"#,
        serde_json::to_string(request).unwrap()
    );
    engine
        .eval_immediate(&invocation)
        .await
        .expect("invoke package callback invariant");
    read_package_adapter_result(engine).await
}

async fn schedule_package_adapter(engine: &HermesEngine, request: &serde_json::Value) {
    let invocation = format!(
        r#"globalThis.__capsecCallbackResult = null;
setTimeout(require('image-lib'), 0, function(result) {{ globalThis.__capsecCallbackResult = result; }}, 'capsec.conformance.evaluate', {});"#,
        serde_json::to_string(request).unwrap()
    );
    engine
        .eval_immediate(&invocation)
        .await
        .expect("schedule package callback invariant");
}

async fn take_scheduled_package_adapter(engine: &HermesEngine) -> serde_json::Value {
    engine
        .drive_event_loop()
        .await
        .expect("drive package callback invariant");
    read_package_adapter_result(engine).await
}

async fn read_package_adapter_result(engine: &HermesEngine) -> serde_json::Value {
    let encoded = engine
        .eval_immediate("JSON.stringify(globalThis.__capsecCallbackResult)")
        .await
        .expect("read package callback invariant")
        .expect("package callback invariant returned no result");
    decode_adapter_wrapper(&encoded)
}

fn parse_principal_id(value: &serde_json::Value) -> String {
    value["executionContext"]["principalId"]
        .as_str()
        .expect("adapter response has no actual principal id")
        .strip_prefix("u64:")
        .expect("actual principal id is not tagged")
        .to_owned()
}

fn typed_from_response(
    response: &serde_json::Value,
    session_id: &str,
    host: &crate::host::Host,
    expected_principal: &capsec_semantics::model::Principal,
    expected_outcome: &str,
    expected_reason: &str,
    expected_edge_id: &str,
    expected_action: &str,
    expected_stage: &str,
) -> serde_json::Value {
    assert_eq!(response["legacyObservations"], serde_json::json!([]));
    let principal_id = parse_principal_id(response);
    assert_eq!(
        host.typed_principal_for_module(&principal_id).as_ref(),
        Some(expected_principal),
        "adapter JSON actor was not bound to the actual Hermes principal"
    );
    let typed = response["typedObservations"]
        .as_array()
        .expect("adapter response has no typed observations");
    assert_eq!(typed.len(), 1);
    let mut decision = typed[0].clone();
    assert_eq!(decision["terminalBranchId"], session_id);
    decision.as_object_mut().unwrap().remove("terminalBranchId");
    assert_eq!(decision["decisionSet"]["context"]["stage"], expected_stage);
    assert_eq!(
        decision["decisionSet"]["effects"][0]["cap"],
        expected_action
    );
    assert_eq!(decision["gates"][0]["coverageEdgeId"], expected_edge_id);
    assert_eq!(decision["gates"][0]["targetCell"], "complete");
    assert_eq!(
        decision["gates"][0]["definitionAndEdgePredicatesSatisfied"],
        true
    );
    assert_eq!(
        decision["evidence"]["outcome"], expected_outcome,
        "unexpected callback invariant decision: {decision}"
    );
    assert_eq!(
        decision["evidence"]["evidence"][0]["reason"],
        expected_reason
    );
    decision
}

fn install_armed_host(host: &crate::host::Host) -> HostResetGuard {
    assert_ne!(
        crate::host::abi::install_host(host.clone()),
        0,
        "callback invariant Host context token allocation"
    );
    HostResetGuard
}

async fn armed_engine(digest: &str) -> HermesEngine {
    let engine = HermesEngine::new_with_armed_snapshot(Some(digest))
        .expect("create exact callback invariant engine");
    engine
        .load_runtime()
        .await
        .expect("load exact callback invariant runtime");
    engine
}

async fn execute_attribution_missing(recipe: &Recipe) -> ScenarioExecution {
    let (host, digest) = build_callback_host(None, None, false, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&digest).await;
    let session = format!("callback-attribution:{}", recipe.plan_digest);
    let request = typed_request(
        &session,
        &format!("missing-attribution:{}", recipe.plan_digest),
        root_principal_value(),
        Vec::new(),
        Vec::new(),
    );
    let response = invoke_root_callback(&engine, &request).await;
    let root: capsec_semantics::model::Principal =
        serde_json::from_value(root_principal_value()).unwrap();
    let typed = typed_from_response(
        &response,
        &session,
        &host,
        &root,
        "deny",
        "invalid-attribution",
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
        "requested",
    );
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "callbackExecuted": true,
                "actualPrincipal": root_principal_value(),
                "invalidAttributionDenied": true,
                "runtimeNonce": response["executionContext"]["runtimeNonce"],
            },
        }),
        typed_decisions: vec![typed],
        legacy_observation_count: 0,
    }
}

async fn execute_generation_recheck(
    recipe: &Recipe,
    package: &PackageFixture,
) -> ScenarioExecution {
    use capsec_semantics::model::{AuthoritySelector, NonEmptyString};

    let (host, digest) = build_callback_host(Some(package), None, true, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&digest).await;
    let selector: AuthoritySelector = serde_json::from_value(invariant_selector()).unwrap();
    let grant_id = NonEmptyString::new(format!(
        "callback-generation-{}",
        recipe.plan_digest.trim_start_matches("sha256-")
    ))
    .unwrap();
    assert!(host
        .grant_typed_dynamic(grant_id.clone(), package.principal.clone(), selector,)
        .expect("publish callback dynamic grant"));
    let granted_generations = host.typed_generations().unwrap();
    let allow_session = format!("callback-generation-allow:{}", recipe.plan_digest);
    let allow_request = typed_request(
        &allow_session,
        &format!("generation-before:{}", recipe.plan_digest),
        package.principal_value.clone(),
        vec![package.principal_value.clone()],
        Vec::new(),
    );
    let allow_response = invoke_package_adapter(&engine, &allow_request, false).await;
    let allow = typed_from_response(
        &allow_response,
        &allow_session,
        &host,
        &package.principal,
        "allow",
        "dynamic-session",
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
        "requested",
    );
    let deny_session = format!("callback-generation-deny:{}", recipe.plan_digest);
    let deny_request = typed_request(
        &deny_session,
        &format!("generation-after:{}", recipe.plan_digest),
        package.principal_value.clone(),
        vec![package.principal_value.clone()],
        Vec::new(),
    );
    schedule_package_adapter(&engine, &deny_request).await;
    assert!(host
        .revoke_typed_dynamic(&grant_id)
        .expect("revoke callback dynamic grant"));
    let revoked_generations = host.typed_generations().unwrap();
    assert!(revoked_generations.negative > granted_generations.negative);
    assert!(revoked_generations.dynamic > granted_generations.dynamic);
    let deny_response = take_scheduled_package_adapter(&engine).await;
    let deny = typed_from_response(
        &deny_response,
        &deny_session,
        &host,
        &package.principal,
        "deny",
        "missing-authority",
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
        "requested",
    );
    assert_eq!(
        allow["evidence"]["generations"],
        generations_value(granted_generations)
    );
    assert_eq!(
        deny["evidence"]["generations"],
        generations_value(revoked_generations)
    );
    assert_eq!(
        allow_response["executionContext"]["runtimeNonce"],
        deny_response["executionContext"]["runtimeNonce"]
    );
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "callbackExecuted": true,
                "actualPrincipal": package.principal_value,
                "generationsBefore": generations_value(granted_generations),
                "generationsAfter": generations_value(revoked_generations),
                "generationAdvanced": true,
                "scheduledDecisionRechecked": true,
                "runtimeNonce": deny_response["executionContext"]["runtimeNonce"],
            },
        }),
        typed_decisions: vec![allow, deny],
        legacy_observation_count: 0,
    }
}

async fn execute_principal_restore(recipe: &Recipe, package: &PackageFixture) -> ScenarioExecution {
    let (host, digest) = build_callback_host(Some(package), Some("environment"), false, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&digest).await;
    let package_session = format!("callback-package-principal:{}", recipe.plan_digest);
    let package_request = typed_request(
        &package_session,
        &format!("principal-package:{}", recipe.plan_digest),
        package.principal_value.clone(),
        vec![package.principal_value.clone()],
        Vec::new(),
    );
    let package_response = invoke_package_adapter(&engine, &package_request, true).await;
    let package_decision = typed_from_response(
        &package_response,
        &package_session,
        &host,
        &package.principal,
        "allow",
        "static-floor",
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
        "requested",
    );
    let root_value = root_principal_value();
    let root: capsec_semantics::model::Principal =
        serde_json::from_value(root_value.clone()).unwrap();
    let root_session = format!("callback-restored-root:{}", recipe.plan_digest);
    let root_request = typed_request(
        &root_session,
        &format!("principal-root:{}", recipe.plan_digest),
        root_value.clone(),
        vec![root_value.clone()],
        Vec::new(),
    );
    let root_script = format!(
        "JSON.stringify(__hostCall('capsec.conformance.evaluate', {}))",
        serde_json::to_string(&root_request).unwrap()
    );
    let root_encoded = engine
        .eval_immediate(&root_script)
        .await
        .expect("execute restored-root invariant")
        .expect("restored-root invariant returned no result");
    let root_response: serde_json::Value =
        serde_json::from_str(&root_encoded).expect("restored-root response must be JSON");
    let root_decision = typed_from_response(
        &root_response,
        &root_session,
        &host,
        &root,
        "allow",
        "ambient-root",
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
        "requested",
    );
    assert_ne!(
        package_response["executionContext"]["principalId"],
        root_response["executionContext"]["principalId"]
    );
    assert_eq!(
        package_response["executionContext"]["runtimeNonce"],
        root_response["executionContext"]["runtimeNonce"]
    );
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "callbackExecuted": true,
                "callbackPrincipal": package.principal_value,
                "restoredPrincipal": root_value,
                "principalRestored": true,
                "runtimeNonce": root_response["executionContext"]["runtimeNonce"],
            },
        }),
        typed_decisions: vec![package_decision, root_decision],
        legacy_observation_count: 0,
    }
}

async fn execute_snapshot_mismatch(recipe: &Recipe, package: &PackageFixture) -> ScenarioExecution {
    use capsec_semantics::model::AuthoritySelector;

    let (source_host, source_digest) = build_callback_host(
        Some(package),
        Some("filesystem"),
        false,
        Some("AQIDBAUGBwgJCgsMDQ4PEA"),
    );
    let selector: AuthoritySelector = serde_json::from_value(snapshot_selector()).unwrap();
    let root: capsec_semantics::model::Principal =
        serde_json::from_value(root_principal_value()).unwrap();
    let handle_id = source_host
        .mint_typed_handle(
            package.principal.clone(),
            std::slice::from_ref(&package.principal),
            root.clone(),
            selector,
            None,
            None,
        )
        .expect("mint source-snapshot bearer");
    let source_response = {
        let _reset = install_armed_host(&source_host);
        let engine = armed_engine(&source_digest).await;
        let session = format!("callback-source-snapshot:{}", recipe.plan_digest);
        let request = snapshot_typed_request(
            &session,
            &format!("snapshot-source:{}", recipe.plan_digest),
            package,
            handle_id.as_str(),
        );
        let response = invoke_root_callback(&engine, &request).await;
        let decision = typed_from_response(
            &response,
            &session,
            &source_host,
            &root,
            "allow",
            "bearer-handle",
            SNAPSHOT_AUXILIARY_EDGE_ID,
            "fs:read",
            "commit",
        );
        (response, decision)
    };
    let (target_host, target_digest) = build_callback_host(
        Some(package),
        Some("filesystem"),
        false,
        Some("AQIDBAUGBwgJCgsMDQ4PEQ"),
    );
    assert_ne!(source_digest, target_digest);
    let target_response = {
        let _reset = install_armed_host(&target_host);
        let engine = armed_engine(&target_digest).await;
        let session = format!("callback-target-snapshot:{}", recipe.plan_digest);
        let request = snapshot_typed_request(
            &session,
            &format!("snapshot-target:{}", recipe.plan_digest),
            package,
            handle_id.as_str(),
        );
        let response = invoke_root_callback(&engine, &request).await;
        let decision = typed_from_response(
            &response,
            &session,
            &target_host,
            &root,
            "deny",
            "invalid-attribution",
            SNAPSHOT_AUXILIARY_EDGE_ID,
            "fs:read",
            "commit",
        );
        (response, decision)
    };
    assert_eq!(
        source_response.1["evidence"]["identity"]["armedSnapshotDigest"],
        source_digest
    );
    assert_eq!(
        target_response.1["evidence"]["identity"]["armedSnapshotDigest"],
        target_digest
    );
    assert_ne!(
        source_response.0["executionContext"]["runtimeNonce"],
        target_response.0["executionContext"]["runtimeNonce"]
    );
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "callbackExecuted": true,
                "actualPrincipal": root_principal_value(),
                "sourceSnapshotDigest": source_digest,
                "targetSnapshotDigest": target_digest,
                "snapshotDigestsDiffer": true,
                "foreignBearerDenied": true,
                "sourceRuntimeNonce": source_response.0["executionContext"]["runtimeNonce"],
                "targetRuntimeNonce": target_response.0["executionContext"]["runtimeNonce"],
            },
        }),
        typed_decisions: vec![source_response.1, target_response.1],
        legacy_observation_count: 0,
    }
}

async fn execute_cannot_widen(recipe: &Recipe) -> ScenarioExecution {
    let (host, digest) = build_callback_host(None, None, false, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&digest).await;
    let before = host.typed_generations().unwrap();
    let request = serde_json::json!({
        "grantId": format!("cannot-widen-{}", recipe.plan_digest.trim_start_matches("sha256-")),
        "principal": root_principal_value(),
        "authority": invariant_selector(),
    });
    let script = format!(
        r#"JSON.stringify((function(request) {{
  try {{ return {{requestRefused: !Ibex.permissions.requestTyped(request), errorMessage: null}}; }}
  catch (error) {{ return {{requestRefused: true, errorMessage: String(error && error.message || error)}}; }}
}})({}))"#,
        serde_json::to_string(&request).unwrap()
    );
    let session = format!("callback-cannot-widen:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session));
    let encoded = engine
        .eval_immediate(&script)
        .await
        .expect("execute cannot-widen public bridge")
        .expect("cannot-widen bridge returned no result");
    let bridge: serde_json::Value =
        serde_json::from_str(&encoded).expect("cannot-widen result must be JSON");
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());
    assert_eq!(bridge["requestRefused"], true);
    assert!(bridge["errorMessage"]
        .as_str()
        .is_some_and(|message| message.contains("refused")));
    let after = host.typed_generations().unwrap();
    assert_eq!(after, before);
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "bridgeExecuted": true,
                "requestRefused": true,
                "generationsBefore": generations_value(before),
                "generationsAfter": generations_value(after),
                "generationsUnchanged": true,
            },
        }),
        typed_decisions: Vec::new(),
        legacy_observation_count: 0,
    }
}

async fn execute_post_lockdown(recipe: &Recipe) -> ScenarioExecution {
    let (host, digest) = build_callback_host(None, None, false, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&digest).await;
    let before = host.typed_generations().unwrap();
    let request = serde_json::json!({
        "grantId": format!("post-lockdown-{}", recipe.plan_digest.trim_start_matches("sha256-")),
        "principal": root_principal_value(),
        "authority": invariant_selector(),
    });
    let script = format!(
        r#"JSON.stringify((function(request) {{
  var descriptor = Object.getOwnPropertyDescriptor(globalThis, '__ibexLockedDown');
  var hatches = ['__exactSetActiveModuleId','__exactGrantCapability','__exactSetPendingPackageId','__exactRegisterPackage','__exactCheckImport','__exactSetCompartmentFor'];
  var hatchesAbsent = hatches.every(function(name) {{ return !(name in globalThis); }});
  var compartment = globalThis.__compartments['image-lib@2.4.1'];
  var compartmentWithholdsAuthority = compartment.Ibex === undefined && compartment.__exactTypedPermissionRequest === undefined;
  var prototypeMutationBlocked = false;
  try {{ Object.defineProperty(Object.prototype, '__capsecLockdownMutation', {{value: true}}); }} catch (_) {{}}
  prototypeMutationBlocked = Object.prototype.__capsecLockdownMutation !== true;
  var functionTamed = false;
  try {{ Function('return 1')(); }} catch (_) {{ functionTamed = true; }}
  var evalTamed = false;
  try {{ (0, eval)('1'); }} catch (_) {{ evalTamed = true; }}
  var authorityRequestRefused = false;
  try {{ authorityRequestRefused = !Ibex.permissions.requestTyped(request); }}
  catch (_) {{ authorityRequestRefused = true; }}
  return {{
    structuralLockdown: globalThis.__ibexLockedDown === true && descriptor && descriptor.writable === false && descriptor.configurable === false,
    intrinsicsFrozen: Object.isFrozen(Object.prototype) && Object.isFrozen(Function.prototype),
    evaluatorsTamed: functionTamed && evalTamed && Function.__ibexTamed === true && eval.__ibexTamed === true,
    hatchesAbsent: hatchesAbsent,
    compartmentWithholdsAuthority: compartmentWithholdsAuthority,
    prototypeMutationBlocked: prototypeMutationBlocked,
    authorityRequestRefused: authorityRequestRefused
  }};
}})({}))"#,
        serde_json::to_string(&request).unwrap()
    );
    let session = format!("callback-post-lockdown:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session));
    let encoded = engine
        .eval_immediate(&script)
        .await
        .expect("execute post-lockdown invariant")
        .expect("post-lockdown invariant returned no result");
    let checks: serde_json::Value =
        serde_json::from_str(&encoded).expect("post-lockdown result must be JSON");
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());
    for name in [
        "structuralLockdown",
        "intrinsicsFrozen",
        "evaluatorsTamed",
        "hatchesAbsent",
        "compartmentWithholdsAuthority",
        "prototypeMutationBlocked",
        "authorityRequestRefused",
    ] {
        assert_eq!(
            checks[name], true,
            "post-lockdown check {name} failed: {checks}"
        );
    }
    let after = host.typed_generations().unwrap();
    assert_eq!(after, before);
    let mut checks = checks;
    checks["bridgeExecuted"] = serde_json::Value::Bool(true);
    checks["generationsBefore"] = generations_value(before);
    checks["generationsAfter"] = generations_value(after);
    checks["generationsUnchanged"] = serde_json::Value::Bool(true);
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": checks,
        }),
        typed_decisions: Vec::new(),
        legacy_observation_count: 0,
    }
}

async fn execute_scenario(recipe: &Recipe, package: &PackageFixture) -> ScenarioExecution {
    match recipe.scenario.as_str() {
        "attribution-missing-deny" => execute_attribution_missing(recipe).await,
        "generation-recheck" => execute_generation_recheck(recipe, package).await,
        "principal-restore" => execute_principal_restore(recipe, package).await,
        "snapshot-mismatch-deny" => execute_snapshot_mismatch(recipe, package).await,
        "cannot-widen-authority" => execute_cannot_widen(recipe).await,
        "post-lockdown-invariant" => execute_post_lockdown(recipe).await,
        other => panic!("unsupported callback invariant scenario {other}"),
    }
}

fn build_execution(
    recipe: &Recipe,
    scenario: ScenarioExecution,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let probe = recipe.public_surface_probe.as_ref().unwrap();
    assert_eq!(
        scenario.typed_decisions.len(),
        probe.invocation.expected_typed_decision_count
    );
    assert_eq!(scenario.legacy_observation_count, 0);
    let observed_stages = scenario
        .typed_decisions
        .iter()
        .map(|decision| decision["decisionSet"]["context"]["stage"].clone())
        .collect::<Vec<_>>();
    let observed_outcomes = scenario
        .typed_decisions
        .iter()
        .map(|decision| decision["evidence"]["outcome"].clone())
        .collect::<Vec<_>>();
    let observed_reasons = scenario
        .typed_decisions
        .iter()
        .map(|decision| decision["evidence"]["evidence"][0]["reason"].clone())
        .collect::<Vec<_>>();
    assert_eq!(
        observed_stages,
        probe
            .invocation
            .expected_typed_stages
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        observed_outcomes,
        probe
            .invocation
            .expected_typed_outcomes
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        observed_reasons,
        probe
            .invocation
            .expected_typed_reasons
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>()
    );
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": probe.invocation.invocation_schema,
            "kind": probe.invocation.kind,
            "surfaceObservedKey": probe.surface_observed_key,
            "surfaceKind": probe.invocation.surface_kind,
            "surfaceName": probe.invocation.surface_name,
            "scenario": probe.invocation.scenario,
            "sourceDescriptorDigest": probe.invocation.source_descriptor_digest,
            "result": scenario.result,
        },
        "legacyObservationCount": scenario.legacy_observation_count,
        "typedDecisions": scenario.typed_decisions,
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected callback observation must be an object")
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
    let evidence_digest = tagged_jcs_digest(&evidence);
    evidence
        .as_object_mut()
        .unwrap()
        .insert("evidenceDigest".into(), evidence_digest.into());
    serde_json::json!({
        "fixtureId": recipe.fixture_id,
        "outcome": "passed",
        "executor": "ibex-callback-invariant-public-harness",
        "evidence": evidence,
    })
}

fn smoke_recipe(scenario: &str) -> Recipe {
    Recipe {
        fixture_id: format!("callback-smoke.{scenario}"),
        plan_digest: format!("smoke-{scenario}"),
        classification: "non-capability".into(),
        scenario: scenario.into(),
        edge_ids: Vec::new(),
        implementation_branch_ids: Vec::new(),
        enforcement_branch_ids: Vec::new(),
        action_ids: Vec::new(),
        terminal_observed_key: "callback:smoke".into(),
        expected_observation: serde_json::json!({}),
        route: PublicRoute {
            surface_observed_keys: Vec::new(),
        },
        status: "diagnostic".into(),
        public_surface_probe: None,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_callback_invariant_mechanisms_smoke() {
    let _lock = hermes_engine_test_lock().lock().await;
    let package = prepare_package_fixture();
    for scenario in [
        "attribution-missing-deny",
        "generation-recheck",
        "principal-restore",
        "snapshot-mismatch-deny",
        "cannot-widen-authority",
        "post-lockdown-invariant",
    ] {
        let recipe = smoke_recipe(scenario);
        let execution = execute_scenario(&recipe, &package).await;
        let (_, outcomes, _) = expected_invariant(scenario);
        assert_eq!(execution.result["outcome"], "passed");
        assert_eq!(execution.legacy_observation_count, 0);
        assert_eq!(execution.typed_decisions.len(), outcomes.len());
    }
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn capsec_public_callback_invariant_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping callback invariant batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT")
        .expect("callback invariant batch requires an owned evidence output path");
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipes = callback_recipes(&catalog);
    let mut by_scenario = BTreeMap::new();
    for recipe in &recipes {
        *by_scenario
            .entry(recipe.scenario.as_str())
            .or_insert(0usize) += 1;
    }
    assert_eq!(recipes.len(), 2_822);
    assert_eq!(by_scenario.get("attribution-missing-deny"), Some(&556));
    assert_eq!(by_scenario.get("generation-recheck"), Some(&556));
    assert_eq!(by_scenario.get("principal-restore"), Some(&556));
    assert_eq!(by_scenario.get("snapshot-mismatch-deny"), Some(&556));
    assert_eq!(by_scenario.get("cannot-widen-authority"), Some(&299));
    assert_eq!(by_scenario.get("post-lockdown-invariant"), Some(&299));
    let (branches, edges) = checked_registry_rows();
    for recipe in &recipes {
        validate_recipe_source_binding(recipe, &branches, &edges);
    }

    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before callback invariant recipes");
    let package = prepare_package_fixture();
    let mut executions = Vec::with_capacity(recipes.len());
    for recipe in recipes {
        let scenario = execute_scenario(recipe, &package).await;
        executions.push(build_execution(
            recipe,
            scenario,
            &identity_before.binary_digest,
        ));
    }
    executions.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after callback invariant recipes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after callback invariant recipes");
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
        .expect("create owned callback invariant evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize callback invariant evidence artifact");
    output
        .write_all(b"\n")
        .expect("finish callback invariant evidence artifact");
    output
        .sync_all()
        .expect("sync callback invariant evidence artifact");
}
