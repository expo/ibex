use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write as _;

const CALLBACK_INVOCATION_SCHEMA: &str = "ibex/capsec-callback-invariant-invocation/1";
const ENV_AUXILIARY_EDGE_ID: &str = "surface.native.op.exactgetenv.0k6bv7a";
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

fn expected_invariant(
    scenario: &str,
) -> (
    &'static str,
    Vec<&'static str>,
    Vec<&'static str>,
    Vec<&'static str>,
) {
    match scenario {
        "attribution-missing-deny" => (
            "callback-attribution-carrier",
            vec!["requested", "commit"],
            vec!["allow", "allow"],
            vec!["ambient-root", "ambient-root"],
        ),
        "generation-recheck" => (
            "callback-attribution-carrier",
            vec!["requested", "commit", "requested"],
            vec!["allow", "allow", "deny"],
            vec!["dynamic-session", "dynamic-session", "missing-authority"],
        ),
        "principal-restore" => (
            "callback-attribution-carrier",
            vec!["requested", "commit", "requested", "commit"],
            vec!["allow", "allow", "allow", "allow"],
            vec!["static-floor", "static-floor", "ambient-root", "ambient-root"],
        ),
        "snapshot-mismatch-deny" => (
            "callback-attribution-carrier",
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ),
        "cannot-widen-authority" | "post-lockdown-invariant" => {
            (
                "authority-control-plane",
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
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
    let (rationale, stages, outcomes, reasons) = expected_invariant(&recipe.scenario);
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
    assert_eq!(
        invocation.expected_typed_stages,
        stages
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
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
        assert_eq!(
            invocation.allowed_coverage_edge_ids,
            [ENV_AUXILIARY_EDGE_ID]
        );
        assert_eq!(invocation.expected_action_ids, ["env:read"]);
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
            "name": "PATH",
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
        r#"module.exports = function(sink, observer, env) {
  var sloppyThis = (function() { return this; })();
  var result = {
    context: observer(),
    globals: {
      processType: typeof process,
      ibexType: typeof Ibex,
      functionType: typeof Function,
      evalType: typeof eval,
      sloppyThisProcessType: sloppyThis == null ? 'nullish' : typeof sloppyThis.process
    }
  };
  try {
    result.value = typeof env.PATH === 'string';
  }
  catch (error) { result.threw = String(error && error.message || error); }
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

struct ObservedInvocation {
    result: serde_json::Value,
    typed_decisions: Vec<serde_json::Value>,
}

fn begin_observation(session_id: &str) {
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(session_id),
        "install callback conformance observation {session_id}"
    );
}

fn finish_observation(session_id: &str) -> Vec<serde_json::Value> {
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty(), "rev2 public path consulted the legacy plane");
    typed
        .into_iter()
        .map(|observation| {
            let mut decision = serde_json::to_value(observation)
                .expect("typed callback observation must serialize");
            assert_eq!(decision["terminalBranchId"], session_id);
            decision
                .as_object_mut()
                .expect("typed callback observation must be an object")
                .remove("terminalBranchId");
            decision
        })
        .collect()
}

fn assert_context_principal(
    result: &serde_json::Value,
    host: &crate::host::Host,
    expected_principal: &capsec_semantics::model::Principal,
) {
    let principal_id = result["context"]["principalId"]
        .as_str()
        .expect("context observer returned no principal id")
        .strip_prefix("u64:")
        .expect("context observer principal id is not tagged");
    assert_eq!(
        host.typed_principal_for_module(principal_id).as_ref(),
        Some(expected_principal),
        "public operation did not run under the observed Hermes principal"
    );
    assert!(result["context"]["runtimeNonce"]
        .as_str()
        .is_some_and(|value| value.strip_prefix("u64:").is_some_and(|raw| raw.parse::<u64>().is_ok())));
}

fn assert_package_global_withholding(result: &serde_json::Value) {
    assert_eq!(
        result["globals"],
        serde_json::json!({
            "processType": "undefined",
            "ibexType": "undefined",
            "functionType": "undefined",
            "evalType": "undefined",
            "sloppyThisProcessType": "undefined",
        }),
        "package callback escaped its armed compartment globals: {result}"
    );
}

fn typed_actor_reason(decision: &serde_json::Value) -> Option<&str> {
    let actor = &decision["decisionSet"]["context"]["actor"];
    decision["evidence"]["evidence"]
        .as_array()?
        .iter()
        .find(|entry| entry["principal"] == *actor)?["reason"]
        .as_str()
}

fn assert_typed_decisions(
    decisions: &[serde_json::Value],
    expected_principal: &capsec_semantics::model::Principal,
    expected_stages: &[&str],
    expected_outcomes: &[&str],
    expected_reasons: &[&str],
    expected_edge_id: &str,
    expected_action: &str,
) {
    assert_eq!(
        decisions.len(),
        expected_stages.len(),
        "unexpected typed decision count: {decisions:#?}"
    );
    assert_eq!(decisions.len(), expected_outcomes.len());
    assert_eq!(decisions.len(), expected_reasons.len());
    let expected_principal =
        serde_json::to_value(expected_principal).expect("expected principal must serialize");
    for (index, decision) in decisions.iter().enumerate() {
        assert_eq!(
            decision["decisionSet"]["context"]["actor"], expected_principal,
            "public decision actor drifted: {decision}"
        );
        assert_eq!(
            decision["decisionSet"]["context"]["stage"], expected_stages[index]
        );
        assert_eq!(decision["decisionSet"]["effects"][0]["cap"], expected_action);
        assert_eq!(decision["gates"][0]["coverageEdgeId"], expected_edge_id);
        assert_eq!(decision["gates"][0]["targetCell"], "complete");
        assert_eq!(
            decision["gates"][0]["definitionAndEdgePredicatesSatisfied"],
            true
        );
        assert_eq!(
            decision["evidence"]["outcome"], expected_outcomes[index],
            "unexpected callback invariant decision: {decision}"
        );
        assert_eq!(
            typed_actor_reason(decision),
            Some(expected_reasons[index]),
            "callback decision has no actor-bound reason: {decision}"
        );
    }
}

async fn read_callback_result(engine: &HermesEngine) -> serde_json::Value {
    let encoded = engine
        .eval_immediate("JSON.stringify(globalThis.__capsecCallbackResult)")
        .await
        .expect("read callback public-operation result")
        .expect("callback public operation returned no result");
    serde_json::from_str(&encoded).expect("callback public-operation result must be JSON")
}

async fn prewarm_package_public_operation(engine: &HermesEngine) {
    engine
        .eval_immediate("require('image-lib'); 'ready'")
        .await
        .expect("load callback package before observation");
}

async fn invoke_package_environment_read(
    engine: &HermesEngine,
    session_id: &str,
) -> ObservedInvocation {
    prewarm_package_public_operation(engine).await;
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install immediate package context observer");
    let invocation = format!(
        r#"globalThis.__capsecCallbackResult = null;
var observer = globalThis[{0}];
var removed = delete globalThis[{0}];
if (typeof observer !== 'function' || !removed || ({0} in globalThis)) throw new Error('CapSec context observer was project-reachable');
require('image-lib')(function(result) {{ globalThis.__capsecCallbackResult = result; }}, observer, process.env);"#,
        serde_json::to_string(&observer_name).unwrap()
    );
    begin_observation(session_id);
    engine
        .eval_immediate(&invocation)
        .await
        .expect("invoke package public environment read");
    let typed_decisions = finish_observation(session_id);
    let result = read_callback_result(engine).await;
    ObservedInvocation {
        result,
        typed_decisions,
    }
}

async fn schedule_package_environment_read(engine: &HermesEngine) {
    prewarm_package_public_operation(engine).await;
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install scheduled package context observer");
    let invocation = format!(
        r#"globalThis.__capsecCallbackResult = null;
var observer = globalThis[{0}];
var removed = delete globalThis[{0}];
if (typeof observer !== 'function' || !removed || ({0} in globalThis)) throw new Error('CapSec context observer was project-reachable');
setTimeout(require('image-lib'), 0, function(result) {{ globalThis.__capsecCallbackResult = result; }}, observer, process.env);"#,
        serde_json::to_string(&observer_name).unwrap()
    );
    engine
        .eval_immediate(&invocation)
        .await
        .expect("schedule package public environment read");
}

async fn take_scheduled_package_operation(
    engine: &HermesEngine,
    session_id: &str,
) -> ObservedInvocation {
    begin_observation(session_id);
    engine
        .drive_event_loop()
        .await
        .expect("drive package public operation");
    let typed_decisions = finish_observation(session_id);
    let result = read_callback_result(engine).await;
    ObservedInvocation {
        result,
        typed_decisions,
    }
}

async fn invoke_root_environment_read(
    engine: &HermesEngine,
    session_id: &str,
) -> ObservedInvocation {
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install root context observer");
    let script = format!(
        r#"JSON.stringify((function(name) {{
  var observer = globalThis[name];
  var removed = delete globalThis[name];
  if (typeof observer !== 'function' || !removed || (name in globalThis)) throw new Error('CapSec context observer was project-reachable');
  var result = {{context: observer()}};
  try {{ result.value = typeof process.env.PATH === 'string'; }}
  catch (error) {{ result.threw = String(error && error.message || error); }}
  return result;
}})({0}))"#,
        serde_json::to_string(&observer_name).unwrap()
    );
    begin_observation(session_id);
    let encoded = engine
        .eval_immediate(&script)
        .await
        .expect("invoke root public environment read")
        .expect("root public environment read returned no result");
    let typed_decisions = finish_observation(session_id);
    let result =
        serde_json::from_str(&encoded).expect("root public environment result must be JSON");
    ObservedInvocation {
        result,
        typed_decisions,
    }
}

async fn invoke_attribution_guard_callback(
    engine: &HermesEngine,
    session_id: &str,
    request: &serde_json::Value,
) -> ObservedInvocation {
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install attribution context observer");
    let script = format!(
        r#"globalThis.__capsecCallbackResult = null;
var observer = globalThis[{0}];
var removed = delete globalThis[{0}];
if (typeof observer !== 'function' || !removed || ({0} in globalThis)) throw new Error('CapSec context observer was project-reachable');
setTimeout(function(observer, request) {{
  var result = {{context: observer(), requestRefused: false, errorMessage: null}};
  try {{ result.requestRefused = !Ibex.permissions.requestTyped(request); }}
  catch (error) {{ result.requestRefused = true; result.errorMessage = String(error && error.message || error); }}
  try {{ result.value = typeof process.env.PATH === 'string'; }}
  catch (error) {{ result.threw = String(error && error.message || error); }}
  globalThis.__capsecCallbackResult = result;
}}, 0, observer, {1});"#,
        serde_json::to_string(&observer_name).unwrap(),
        serde_json::to_string(request).unwrap()
    );
    engine
        .eval_immediate(&script)
        .await
        .expect("schedule public attribution-guard callback");
    begin_observation(session_id);
    engine
        .drive_event_loop()
        .await
        .expect("drive public attribution-guard callback");
    let typed_decisions = finish_observation(session_id);
    let result = read_callback_result(engine).await;
    ObservedInvocation {
        result,
        typed_decisions,
    }
}

async fn invoke_root_handle_mint_callback(
    engine: &HermesEngine,
    session_id: &str,
    request: &serde_json::Value,
) -> ObservedInvocation {
    let observer_name = engine
        .install_capsec_context_test_observer()
        .await
        .expect("install handle callback context observer");
    let script = format!(
        r#"globalThis.__capsecCallbackResult = null;
var observer = globalThis[{0}];
var removed = delete globalThis[{0}];
if (typeof observer !== 'function' || !removed || ({0} in globalThis)) throw new Error('CapSec context observer was project-reachable');
setTimeout(function(observer, request) {{
  var result = {{context: observer()}};
  try {{ result.value = Ibex.authority.mintHandle(request); }}
  catch (error) {{ result.threw = String(error && error.message || error); }}
  globalThis.__capsecCallbackResult = result;
}}, 0, observer, {1});"#,
        serde_json::to_string(&observer_name).unwrap(),
        serde_json::to_string(request).unwrap()
    );
    engine
        .eval_immediate(&script)
        .await
        .expect("schedule public handle-mint callback");
    begin_observation(session_id);
    engine
        .drive_event_loop()
        .await
        .expect("drive public handle-mint callback");
    let typed_decisions = finish_observation(session_id);
    let result = read_callback_result(engine).await;
    ObservedInvocation {
        result,
        typed_decisions,
    }
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
    assert_eq!(
        engine
            .eval_immediate("typeof __hostCall + '/' + typeof __hostCallAsync")
            .await
            .expect("inspect generic host bridges")
            .as_deref(),
        Some("undefined/undefined"),
        "armed callback evidence must not reopen the generic host bridge"
    );
    engine
}

async fn execute_attribution_missing(recipe: &Recipe) -> ScenarioExecution {
    let (host, digest) = build_callback_host(None, None, false, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&digest).await;
    let before = host.typed_generations().unwrap();
    let session = format!("callback-attribution:{}", recipe.plan_digest);
    let request = serde_json::json!({
        "grantId": format!("missing-attribution-{}", recipe.plan_digest.trim_start_matches("sha256-")),
        "principal": {"kind": "root", "identity": "forged-callback-root"},
        "authority": invariant_selector(),
    });
    let invocation = invoke_attribution_guard_callback(&engine, &session, &request).await;
    let root: capsec_semantics::model::Principal =
        serde_json::from_value(root_principal_value()).unwrap();
    assert_context_principal(&invocation.result, &host, &root);
    assert_eq!(invocation.result["requestRefused"], true);
    assert!(invocation.result["errorMessage"]
        .as_str()
        .is_some_and(|message| message.contains("refused")));
    assert!(invocation.result["threw"].is_null());
    assert_typed_decisions(
        &invocation.typed_decisions,
        &root,
        &["requested", "commit"],
        &["allow", "allow"],
        &["ambient-root", "ambient-root"],
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
    );
    assert_eq!(host.typed_generations().unwrap(), before);
    ScenarioExecution {
        result: serde_json::json!({
            "kind": "callback-security-invariant",
            "scenario": recipe.scenario,
            "outcome": "passed",
            "checks": {
                "callbackExecuted": true,
                "actualPrincipal": root_principal_value(),
                "invalidAttributionDenied": true,
                "runtimeNonce": invocation.result["context"]["runtimeNonce"],
            },
        }),
        typed_decisions: invocation.typed_decisions,
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
        .grant_typed_dynamic(grant_id.clone(), package.principal.clone(), selector)
        .expect("publish callback dynamic environment grant"));
    let granted_generations = host.typed_generations().unwrap();
    let allow_session = format!("callback-generation-allow:{}", recipe.plan_digest);
    let allow = invoke_package_environment_read(&engine, &allow_session).await;
    assert_context_principal(&allow.result, &host, &package.principal);
    assert_package_global_withholding(&allow.result);
    assert!(
        allow.result["threw"].is_null(),
        "authorized package environment read threw: {}",
        allow.result
    );
    assert_typed_decisions(
        &allow.typed_decisions,
        &package.principal,
        &["requested", "commit"],
        &["allow", "allow"],
        &["dynamic-session", "dynamic-session"],
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
    );
    let deny_session = format!("callback-generation-deny:{}", recipe.plan_digest);
    schedule_package_environment_read(&engine).await;
    assert!(host
        .revoke_typed_dynamic(&grant_id)
        .expect("revoke callback dynamic environment grant"));
    let revoked_generations = host.typed_generations().unwrap();
    assert!(revoked_generations.negative > granted_generations.negative);
    assert!(revoked_generations.dynamic > granted_generations.dynamic);
    assert_eq!(revoked_generations.handle, granted_generations.handle);
    let deny = take_scheduled_package_operation(&engine, &deny_session).await;
    assert_context_principal(&deny.result, &host, &package.principal);
    assert!(deny.result["threw"].is_null());
    assert_typed_decisions(
        &deny.typed_decisions,
        &package.principal,
        &["requested"],
        &["deny"],
        &["missing-authority"],
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
    );
    for decision in &allow.typed_decisions {
        assert_eq!(
            decision["evidence"]["generations"],
            generations_value(granted_generations)
        );
    }
    assert_eq!(
        deny.typed_decisions[0]["evidence"]["generations"],
        generations_value(revoked_generations)
    );
    assert_eq!(
        allow.result["context"]["runtimeNonce"],
        deny.result["context"]["runtimeNonce"]
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
                "runtimeNonce": deny.result["context"]["runtimeNonce"],
            },
        }),
        typed_decisions: allow
            .typed_decisions
            .into_iter()
            .chain(deny.typed_decisions)
            .collect(),
        legacy_observation_count: 0,
    }
}

async fn execute_principal_restore(recipe: &Recipe, package: &PackageFixture) -> ScenarioExecution {
    let (host, digest) = build_callback_host(Some(package), Some("environment"), false, None);
    let _reset = install_armed_host(&host);
    let engine = armed_engine(&digest).await;
    let package_session = format!("callback-package-principal:{}", recipe.plan_digest);
    schedule_package_environment_read(&engine).await;
    let package_invocation = take_scheduled_package_operation(&engine, &package_session).await;
    assert_context_principal(&package_invocation.result, &host, &package.principal);
    assert_package_global_withholding(&package_invocation.result);
    assert!(package_invocation.result["threw"].is_null());
    assert_typed_decisions(
        &package_invocation.typed_decisions,
        &package.principal,
        &["requested", "commit"],
        &["allow", "allow"],
        &["static-floor", "static-floor"],
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
    );
    let root_value = root_principal_value();
    let root: capsec_semantics::model::Principal =
        serde_json::from_value(root_value.clone()).unwrap();
    let root_session = format!("callback-restored-root:{}", recipe.plan_digest);
    let root_invocation = invoke_root_environment_read(&engine, &root_session).await;
    assert_context_principal(&root_invocation.result, &host, &root);
    assert!(root_invocation.result["threw"].is_null());
    assert_typed_decisions(
        &root_invocation.typed_decisions,
        &root,
        &["requested", "commit"],
        &["allow", "allow"],
        &["ambient-root", "ambient-root"],
        ENV_AUXILIARY_EDGE_ID,
        "env:read",
    );
    assert_ne!(
        package_invocation.result["context"]["principalId"],
        root_invocation.result["context"]["principalId"]
    );
    assert_eq!(
        package_invocation.result["context"]["runtimeNonce"],
        root_invocation.result["context"]["runtimeNonce"]
    );
    let mut typed_decisions = package_invocation.typed_decisions;
    typed_decisions.extend(root_invocation.typed_decisions);
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
                "runtimeNonce": root_invocation.result["context"]["runtimeNonce"],
            },
        }),
        typed_decisions,
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
    let request = serde_json::json!({
        "actor": root_principal_value(),
        "holder": root_principal_value(),
        "authority": snapshot_selector(),
        "parentHandleId": handle_id.as_str(),
        "operationId": format!("snapshot-recheck-{}", recipe.plan_digest.trim_start_matches("sha256-")),
    });
    let source_invocation = {
        let _reset = install_armed_host(&source_host);
        let engine = armed_engine(&source_digest).await;
        let session = format!("callback-source-snapshot:{}", recipe.plan_digest);
        let invocation = invoke_root_handle_mint_callback(&engine, &session, &request).await;
        assert_context_principal(&invocation.result, &source_host, &root);
        assert!(invocation.result["threw"].is_null());
        assert!(invocation.result["value"]
            .as_str()
            .is_some_and(|value| !value.is_empty() && value != handle_id.as_str()));
        assert!(invocation.typed_decisions.is_empty());
        invocation
    };
    let (target_host, target_digest) = build_callback_host(
        Some(package),
        Some("filesystem"),
        false,
        Some("AQIDBAUGBwgJCgsMDQ4PEQ"),
    );
    assert_ne!(source_digest, target_digest);
    let target_invocation = {
        let _reset = install_armed_host(&target_host);
        let engine = armed_engine(&target_digest).await;
        let session = format!("callback-target-snapshot:{}", recipe.plan_digest);
        let invocation = invoke_root_handle_mint_callback(&engine, &session, &request).await;
        assert_context_principal(&invocation.result, &target_host, &root);
        assert!(invocation.result["threw"]
            .as_str()
            .is_some_and(|message| message.contains("parent handle is absent or revoked")));
        assert!(invocation.typed_decisions.is_empty());
        invocation
    };
    assert_ne!(
        source_invocation.result["context"]["runtimeNonce"],
        target_invocation.result["context"]["runtimeNonce"]
    );
    assert!(source_invocation.typed_decisions.is_empty());
    assert!(target_invocation.typed_decisions.is_empty());
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
                "sourceRuntimeNonce": source_invocation.result["context"]["runtimeNonce"],
                "targetRuntimeNonce": target_invocation.result["context"]["runtimeNonce"],
            },
        }),
        typed_decisions: Vec::new(),
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
  var hatches = ['__exactSetActiveModuleId','__exactGrantCapability','__exactSetPendingPackageId','__exactRegisterPackage','__exactCheckImport','__exactSetCompartmentFor','__exactDeepFreeze','__exactNativeFreeze'];
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
        .map(|decision| {
            serde_json::Value::String(
                typed_actor_reason(decision)
                    .expect("callback decision has no actor-bound reason")
                    .to_owned(),
            )
        })
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
        let (_, _, outcomes, _) = expected_invariant(scenario);
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
    assert_eq!(recipes.len(), 2_836);
    assert_eq!(by_scenario.get("attribution-missing-deny"), Some(&557));
    assert_eq!(by_scenario.get("generation-recheck"), Some(&557));
    assert_eq!(by_scenario.get("principal-restore"), Some(&557));
    assert_eq!(by_scenario.get("snapshot-mismatch-deny"), Some(&557));
    assert_eq!(by_scenario.get("cannot-widen-authority"), Some(&304));
    assert_eq!(by_scenario.get("post-lockdown-invariant"), Some(&304));
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
