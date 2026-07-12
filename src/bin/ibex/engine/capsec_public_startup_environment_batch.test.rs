// Loaded-engine conformance harness; excluded from production surface scans.
use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsString;
#[cfg(not(feature = "host-http-server"))]
use std::io::Write as _;

const STARTUP_ENVIRONMENT_INVOCATION_SCHEMA: &str =
    "ibex/capsec-startup-environment-invocation/1";
const ENV_AUXILIARY_EDGE_ID: &str = "surface.native.op.exactgetenv.0k6bv7a";
const STARTUP_ENVIRONMENT_BATCH_COMMAND: [&str; 9] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--features",
    "capsec-conformance-observer",
    "capsec_public_startup_environment_batch",
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
    status: String,
    public_surface_probe: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicSurfaceProbe {
    kind: String,
    surface_observed_key: String,
    command: Vec<String>,
    invocation: StartupEnvironmentInvocation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartupEnvironmentInvocation {
    invocation_schema: String,
    kind: String,
    scenario: String,
    surface_kind: String,
    surface_name: String,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    operation: StartupEnvironmentOperation,
    expected_result: String,
    expected_typed_decision_count: usize,
    expected_typed_stages: Vec<String>,
    expected_typed_outcomes: Vec<String>,
    expected_typed_reasons: Vec<String>,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
    expected_resource_names: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartupEnvironmentOperation {
    kind: String,
    module_specifier: Option<String>,
    preload_module_specifiers: Vec<String>,
    environment: StartupEnvironment,
    principal_mode: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartupEnvironment {
    name: String,
    presence: String,
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

struct EnvironmentRestore {
    name: String,
    value: Option<OsString>,
}

struct ExpectedSource {
    environment_name: &'static str,
    source_ref: &'static str,
    mechanism: &'static str,
    module_specifier: Option<&'static str>,
    preload_module_specifiers: &'static [&'static str],
}

const EXPECTED_SOURCES: [ExpectedSource; 3] = [
    ExpectedSource {
        environment_name: "NODE_DEBUG",
        source_ref: "src/builtins/http.js#process.env:NODE_DEBUG:read",
        mechanism: "builtin-module-load",
        module_specifier: Some("node:http"),
        preload_module_specifiers: &["node:util"],
    },
    ExpectedSource {
        environment_name: "EXACT_DEBUG_EMIT_LISTENER",
        source_ref: "src/builtins/events.js#process.env:EXACT_DEBUG_EMIT_LISTENER:read",
        mechanism: "event-emitter-emit",
        module_specifier: Some("node:events"),
        preload_module_specifiers: &["node:events"],
    },
    ExpectedSource {
        environment_name: "TZ",
        source_ref: "packages/ibex-runtime-js/src/node/process.ts#process.env:TZ:read",
        mechanism: "date-to-string",
        module_specifier: None,
        preload_module_specifiers: &[],
    },
];

fn expected_source(environment_name: &str) -> &'static ExpectedSource {
    EXPECTED_SOURCES
        .iter()
        .find(|source| source.environment_name == environment_name)
        .unwrap_or_else(|| panic!("unreviewed startup environment source {environment_name}"))
}

impl EnvironmentRestore {
    fn absent(name: &str) -> Self {
        let value = std::env::var_os(name);
        std::env::remove_var(name);
        Self {
            name: name.to_owned(),
            value,
        }
    }
}

impl Drop for EnvironmentRestore {
    fn drop(&mut self) {
        match &self.value {
            Some(value) => std::env::set_var(&self.name, value),
            None => std::env::remove_var(&self.name),
        }
    }
}

fn tagged_jcs_digest(value: &serde_json::Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("startup environment evidence must have canonical JSON bytes");
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

fn startup_environment_probe(recipe: &Recipe) -> Option<PublicSurfaceProbe> {
    let value = recipe.public_surface_probe.as_ref()?;
    if value["invocation"]["invocationSchema"] != STARTUP_ENVIRONMENT_INVOCATION_SCHEMA {
        return None;
    }
    Some(
        serde_json::from_value(value.clone())
            .expect("startup environment public probe must match its typed schema"),
    )
}

fn environment_selector(name: &str) -> serde_json::Value {
    // @ref LLP 0021#typed-resources-and-initial-vocabulary — bind each
    // startup source to one exact broker-base name, never an env wildcard.
    serde_json::json!({
        "cap": "env:read",
        "resource": {
            "kind": "environment-name",
            "target": "broker-base",
            "name": name,
        },
    })
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
        let metadata = std::fs::metadata(path).expect("read environment probe package metadata");
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
            "volume": "startup-environment-fixture-volume",
            "file": "startup-environment-fixture-file",
        })
    }
}

fn prepare_package_fixture(operation: &StartupEnvironmentOperation) -> PackageFixture {
    let directory = tempfile::tempdir().expect("create startup environment package fixture");
    let root = std::fs::canonicalize(directory.path())
        .expect("canonicalize startup environment fixture root");
    let package_root = root.join("node_modules/image-lib");
    std::fs::create_dir_all(&package_root).expect("create startup environment package root");
    std::fs::write(
        package_root.join("package.json"),
        r#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
    )
    .expect("write startup environment package manifest");
    let source = match operation.kind.as_str() {
        "builtin-module-load" => format!(
            "module.exports = function() {{ return require({}) !== null; }};\n",
            serde_json::to_string(
                operation
                    .module_specifier
                    .as_deref()
                    .expect("module-load environment probe requires a module"),
            )
            .expect("serialize environment probe module")
        ),
        "event-emitter-emit" => format!(
            "module.exports = function() {{ var EventEmitter = require({}).EventEmitter; var emitter = new EventEmitter(); emitter.on('ibex-capsec', function() {{}}); return emitter.emit('ibex-capsec'); }};\n",
            serde_json::to_string(
                operation
                    .module_specifier
                    .as_deref()
                    .expect("event environment probe requires a module"),
            )
            .expect("serialize event environment probe module")
        ),
        "date-to-string" => "module.exports = function() { return typeof new Date(0).toString() === 'string'; };\n".to_owned(),
        other => panic!("unsupported package startup environment mechanism {other}"),
    };
    std::fs::write(package_root.join("index.js"), source)
    .expect("write startup environment package source");
    let integrity = crate::module_loader::package_tree_integrity(&package_root)
        .expect("digest startup environment package tree");
    let principal_value = serde_json::json!({
        "kind": "package",
        "name": "image-lib",
        "integrity": integrity,
        "locator": "image-lib@2.4.1",
    });
    let principal = serde_json::from_value(principal_value.clone())
        .expect("startup environment package principal must be valid");
    PackageFixture {
        _directory: directory,
        root,
        package_root,
        principal_value,
        principal,
    }
}

fn build_environment_host(
    package: Option<&PackageFixture>,
    operation: &StartupEnvironmentOperation,
    environment_name: &str,
) -> (crate::host::Host, String) {
    let root_floor = vec![environment_selector(environment_name)];
    let mut builtin_imports = operation
        .module_specifier
        .iter()
        .chain(operation.preload_module_specifiers.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    builtin_imports.sort();
    build_armed_test_host_control(
        package.map(|fixture| fixture.root.as_path()),
        false,
        false,
        false,
        root_floor,
        Vec::new(),
        false,
        0,
        None,
        |snapshot| {
            snapshot["principals"][0]["imports"]["builtins"] =
                serde_json::to_value(&builtin_imports).unwrap();
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
            snapshot["principals"][1]["floor"] = serde_json::json!([]);
            snapshot["principals"][1]["denials"] =
                serde_json::json!([environment_selector(environment_name)]);
            snapshot["principals"][1]["escalationCeiling"] = serde_json::json!([]);
            snapshot["principals"][1]["imports"]["builtins"] =
                serde_json::to_value(&builtin_imports).unwrap();
            snapshot["packageGraph"]["nodes"][0]["principal"] =
                package.principal_value.clone();
            snapshot["packageGraph"]["importEdges"][0]["imported"] =
                package.principal_value.clone();
        },
    )
}

fn typed_decision_values(
    session_id: &str,
    decisions: Vec<ibex_runtime::host::ObservedTypedDecision>,
) -> Vec<serde_json::Value> {
    decisions
        .into_iter()
        .map(|decision| {
            assert_eq!(decision.terminal_branch_id, session_id);
            let mut value = serde_json::to_value(decision)
                .expect("typed startup environment decision must serialize");
            value
                .as_object_mut()
                .expect("typed startup environment decision must be an object")
                .remove("terminalBranchId");
            value
        })
        .collect()
}

fn actor_reason(decision: &serde_json::Value) -> Option<&str> {
    let actor = &decision["decisionSet"]["context"]["actor"];
    decision["evidence"]["evidence"]
        .as_array()?
        .iter()
        .find(|entry| entry["principal"] == *actor)?["reason"]
        .as_str()
}

fn validate_probe(recipe: &Recipe, probe: &PublicSurfaceProbe) {
    let invocation = &probe.invocation;
    let descriptor = &invocation.source_descriptor;
    let environment_name = invocation.operation.environment.name.as_str();
    let expected = expected_source(environment_name);
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "effects");
    assert!(matches!(
        recipe.scenario.as_str(),
        "allow" | "deny" | "branch-selection"
    ));
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(
        probe
            .command
            .iter()
            .map(String::as_str)
            .eq(STARTUP_ENVIRONMENT_BATCH_COMMAND)
    );
    assert_eq!(invocation.invocation_schema, STARTUP_ENVIRONMENT_INVOCATION_SCHEMA);
    assert_eq!(invocation.kind, "startup-environment-source");
    assert_eq!(invocation.scenario, recipe.scenario);
    assert_eq!(invocation.surface_kind, "startup");
    assert_eq!(invocation.surface_name, format!("env:{environment_name}"));
    assert_eq!(
        probe.surface_observed_key,
        format!("{}:{}", invocation.surface_kind, invocation.surface_name)
    );
    assert_eq!(probe.surface_observed_key, recipe.terminal_observed_key);
    assert_eq!(recipe.edge_ids, [descriptor["carrierEdgeId"].as_str().unwrap()]);
    assert_eq!(
        recipe.implementation_branch_ids,
        serde_json::from_value::<Vec<String>>(descriptor["implementationBranchIds"].clone())
            .unwrap()
    );
    assert_eq!(
        recipe.enforcement_branch_ids,
        serde_json::from_value::<Vec<String>>(descriptor["enforcementBranchIds"].clone())
            .unwrap()
    );
    assert_eq!(recipe.action_ids, ["env:read"]);
    assert_eq!(recipe.expected_observation["kind"], "enforcement-branch");
    assert_eq!(descriptor["kind"], "startup-environment-source");
    assert_eq!(descriptor["surfaceObservedKey"], probe.surface_observed_key);
    assert_eq!(descriptor["environmentName"], environment_name);
    assert_eq!(descriptor["sourceRef"], expected.source_ref);
    assert!(descriptor["liveSourceRefs"]
        .as_array()
        .unwrap()
        .contains(&descriptor["sourceRef"]));
    assert_eq!(descriptor["selectedBranch"]["id"], "absent");
    assert_eq!(
        descriptor["selectedBranch"]["when"],
        serde_json::json!([{
            "fact": format!("environment.startup.{}", environment_name.to_lowercase()),
            "equals": "absent",
        }])
    );
    assert_eq!(descriptor["executionMechanism"], expected.mechanism);
    assert_eq!(
        descriptor["moduleSpecifier"],
        serde_json::json!(expected.module_specifier)
    );
    assert_eq!(
        descriptor["preloadModuleSpecifiers"],
        serde_json::json!(expected.preload_module_specifiers)
    );
    assert_eq!(descriptor["auxiliaryDecisionEdgeId"], ENV_AUXILIARY_EDGE_ID);
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_jcs_digest(descriptor)
    );
    assert_eq!(invocation.operation.kind, expected.mechanism);
    assert_eq!(
        invocation.operation.module_specifier.as_deref(),
        expected.module_specifier
    );
    assert_eq!(
        invocation
            .operation
            .preload_module_specifiers
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected.preload_module_specifiers
    );
    assert_eq!(
        invocation.operation.environment,
        StartupEnvironment {
            name: environment_name.into(),
            presence: "absent".into(),
        }
    );
    assert_eq!(
        invocation.allowed_coverage_edge_ids,
        [ENV_AUXILIARY_EDGE_ID]
    );
    assert_eq!(invocation.expected_action_ids, ["env:read"]);
    assert_eq!(invocation.expected_resource_names, [environment_name]);
    assert_eq!(
        invocation.expected_typed_decision_count,
        invocation.expected_typed_stages.len()
    );
    assert_eq!(
        invocation.expected_typed_decision_count,
        invocation.expected_typed_outcomes.len()
    );
    assert_eq!(
        invocation.expected_typed_decision_count,
        invocation.expected_typed_reasons.len()
    );
}

fn validate_typed_decisions(
    recipe: &Recipe,
    invocation: &StartupEnvironmentInvocation,
    expected_principal: &capsec_semantics::model::Principal,
    decisions: &[serde_json::Value],
) {
    assert_eq!(
        decisions.len(),
        invocation.expected_typed_decision_count,
        "{} observed unexpected typed decisions: {decisions:#?}",
        recipe.fixture_id
    );
    let expected_principal =
        serde_json::to_value(expected_principal).expect("expected principal must serialize");
    let environment_name = invocation.operation.environment.name.as_str();
    let expected_constrained = if invocation.operation.principal_mode == "package-denied" {
        serde_json::json!([
            {"kind": "root", "identity": "project-root"},
            expected_principal,
        ])
    } else {
        serde_json::json!([expected_principal])
    };
    for (index, decision) in decisions.iter().enumerate() {
        let set = &decision["decisionSet"];
        assert_eq!(set["context"]["actor"], expected_principal);
        assert_eq!(set["context"]["constrainedPrincipals"], expected_constrained);
        assert_eq!(set["context"]["stage"], invocation.expected_typed_stages[index]);
        assert_eq!(set["atomicityGroup"], format!("{ENV_AUXILIARY_EDGE_ID}.decision"));
        assert_eq!(set["effects"].as_array().unwrap().len(), 1);
        assert_eq!(set["effects"][0]["cap"], "env:read");
        assert_eq!(set["effects"][0]["effectOwner"], expected_principal);
        assert_eq!(
            set["effects"][0]["resource"],
            serde_json::json!({
                "kind": "environment-occurrence",
                "requested": {
                    "kind": "environment-name",
                    "target": "broker-base",
                    "name": environment_name,
                },
                "valueOrigin": "broker-base",
            })
        );
        assert_eq!(decision["gates"].as_array().unwrap().len(), 1);
        assert_eq!(decision["gates"][0]["coverageEdgeId"], ENV_AUXILIARY_EDGE_ID);
        assert_eq!(decision["gates"][0]["targetCell"], "complete");
        assert_eq!(
            decision["gates"][0]["definitionAndEdgePredicatesSatisfied"],
            true
        );
        assert_eq!(
            decision["evidence"]["outcome"],
            invocation.expected_typed_outcomes[index]
        );
        assert_eq!(
            actor_reason(decision),
            Some(invocation.expected_typed_reasons[index].as_str())
        );
    }
}

async fn invoke_source(
    engine: &HermesEngine,
    invocation: &StartupEnvironmentInvocation,
    package: Option<&PackageFixture>,
    session_id: &str,
) -> (serde_json::Value, usize, Vec<serde_json::Value>) {
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // preloads are outside the observer; only the curated source operation is
    // allowed to contribute the promotion decision.
    // Preload only dependencies whose module initialization is a distinct
    // source occurrence. The observed operation still calls the real public
    // API after the session opens.
    for module_specifier in &invocation.operation.preload_module_specifiers {
        let script = format!(
            "require({}); 'dependency-ready'",
            serde_json::to_string(module_specifier).unwrap()
        );
        assert_eq!(
            engine
                .eval_immediate(&script)
                .await
                .expect("preload distinct startup environment dependency")
                .as_deref(),
            Some("dependency-ready")
        );
    }
    if package.is_some() {
        assert_eq!(
            engine
                .eval_immediate("require('image-lib'); 'ready'")
                .await
                .expect("preload startup environment package")
                .as_deref(),
            Some("ready")
        );
    }
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(session_id),
        "install startup environment observation {session_id}"
    );
    let root_expression = match invocation.operation.kind.as_str() {
        "builtin-module-load" => format!(
            "require({}) !== null",
            serde_json::to_string(
                invocation
                    .operation
                    .module_specifier
                    .as_deref()
                    .expect("module-load source requires a module"),
            )
            .unwrap()
        ),
        "event-emitter-emit" => format!(
            "(function() {{ var EventEmitter = require({}).EventEmitter; var emitter = new EventEmitter(); emitter.on('ibex-capsec', function() {{}}); return emitter.emit('ibex-capsec'); }})()",
            serde_json::to_string(
                invocation
                    .operation
                    .module_specifier
                    .as_deref()
                    .expect("event source requires a module"),
            )
            .unwrap()
        ),
        "date-to-string" => "typeof new Date(0).toString() === 'string'".to_owned(),
        other => panic!("unsupported root startup environment mechanism {other}"),
    };
    let expression = if package.is_some() {
        "require('image-lib')()".to_owned()
    } else {
        root_expression
    };
    let project_marker = serde_json::to_string(session_id).unwrap();
    let script = format!(
        "JSON.stringify((function(projectMarker){{try{{var value={expression};return {{kind:'return',value:value===true,projectMarker:projectMarker}};}}catch(error){{return {{kind:'throw',errorName:String(error&&error.name||'Error'),errorMessage:String(error&&error.message||error),projectMarker:projectMarker}};}}}})({project_marker}))"
    );
    let encoded = engine
        .eval_immediate(&script)
        .await
        .expect("execute startup environment public source")
        .expect("startup environment public source returned no result");
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    let result: serde_json::Value = serde_json::from_str(&encoded)
        .expect("startup environment public source returned invalid JSON");
    assert_eq!(result["projectMarker"], session_id);
    let typed = typed_decision_values(session_id, typed);
    match invocation.expected_result.as_str() {
        "return" => {
            assert_eq!(result["kind"], "return");
            assert_eq!(result["value"], true);
        }
        "permission-denied" => {
            assert_eq!(result["kind"], "throw");
            assert!(result["errorMessage"]
                .as_str()
                .is_some_and(|message| message.contains("Permission denied")));
        }
        other => panic!("unsupported startup environment result {other}"),
    }
    (result, legacy.len(), typed)
}

async fn execute_recipe(
    recipe: &Recipe,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let probe = startup_environment_probe(recipe)
        .expect("startup environment recipe has no typed public probe");
    validate_probe(recipe, &probe);
    let invocation = &probe.invocation;
    let package = (invocation.operation.principal_mode == "package-denied")
        .then(|| prepare_package_fixture(&invocation.operation));
    let expected_principal = package
        .as_ref()
        .map(|fixture| fixture.principal.clone())
        .unwrap_or_else(|| {
            serde_json::from_value(serde_json::json!({
                "kind": "root",
                "identity": "project-root",
            }))
            .expect("root startup environment principal must be valid")
        });
    assert_eq!(
        invocation.source_descriptor["principalMode"],
        invocation.operation.principal_mode
    );
    let _environment = EnvironmentRestore::absent(&invocation.operation.environment.name);
    assert!(std::env::var_os(&invocation.operation.environment.name).is_none());
    let (host, snapshot_digest) = build_environment_host(
        package.as_ref(),
        &invocation.operation,
        &invocation.operation.environment.name,
    );
    assert_ne!(crate::host::abi::install_host(host), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create exact startup environment probe engine");
    engine
        .load_runtime()
        .await
        .expect("load exact startup environment probe runtime");
    let session_id = format!("startup-environment-observation:{}", recipe.plan_digest);
    let (source_result, legacy_count, typed_decisions) = invoke_source(
        &engine,
        invocation,
        package.as_ref(),
        &session_id,
    )
    .await;
    assert_eq!(legacy_count, 0, "startup environment source consulted legacy policy");
    validate_typed_decisions(
        recipe,
        invocation,
        &expected_principal,
        &typed_decisions,
    );
    assert!(std::env::var_os(&invocation.operation.environment.name).is_none());

    let source_outcome = if invocation.expected_typed_outcomes == ["deny"] {
        "denied-as-absent"
    } else {
        "source-observed"
    };
    let project_code_executed = source_result["projectMarker"] == session_id;
    assert!(project_code_executed);
    let result = serde_json::json!({
        "kind": source_result["kind"],
        "surfaceKind": "startup",
        "surfaceName": invocation.surface_name,
        "mechanism": invocation.operation.kind,
        "moduleSpecifier": invocation.operation.module_specifier,
        "environmentName": invocation.operation.environment.name,
        "environmentPresence": invocation.operation.environment.presence,
        "principalMode": invocation.operation.principal_mode,
        "engineExecuted": true,
        "projectCodeExecuted": project_code_executed,
        "sourceOutcome": source_outcome,
        "errorName": source_result.get("errorName").cloned().unwrap_or(serde_json::Value::Null),
        "errorMessage": source_result.get("errorMessage").cloned().unwrap_or(serde_json::Value::Null),
    });
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": invocation.invocation_schema,
            "kind": invocation.kind,
            "surfaceObservedKey": probe.surface_observed_key,
            "surfaceKind": invocation.surface_kind,
            "surfaceName": invocation.surface_name,
            "scenario": invocation.scenario,
            "sourceDescriptorDigest": invocation.source_descriptor_digest,
            "result": result,
        },
        "legacyObservationCount": legacy_count,
        "typedDecisions": typed_decisions,
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected startup environment observation must be an object")
        .insert("result".into(), serde_json::Value::String("passed".into()));
    let mut evidence = serde_json::json!({
        "evidenceSchema": "ibex/capsec-public-surface-fixture-evidence/2",
        "fixtureId": recipe.fixture_id,
        "planDigest": recipe.plan_digest,
        "engineBinaryDigest": engine_binary_digest,
        "probe": probe,
        "terminalObservedKey": recipe.terminal_observed_key,
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
        "executor": "ibex-startup-environment-public-source-harness",
        "evidence": evidence,
    })
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_public_startup_environment_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!(
            "IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping startup environment public batch"
        );
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT")
        .expect("startup environment batch requires an owned evidence output path");
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipes = catalog
        .recipes
        .iter()
        .filter(|recipe| startup_environment_probe(recipe).is_some())
        .collect::<Vec<_>>();
    assert_eq!(
        recipes.len(),
        9,
        "expected three curated startup environment absent slices"
    );
    assert_eq!(
        recipes
            .iter()
            .map(|recipe| recipe.scenario.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["allow", "branch-selection", "deny"])
    );
    assert_eq!(
        recipes
            .iter()
            .map(|recipe| recipe.terminal_observed_key.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "startup:env:EXACT_DEBUG_EMIT_LISTENER",
            "startup:env:NODE_DEBUG",
            "startup:env:TZ",
        ])
    );

    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before startup environment recipes");
    let mut executions = Vec::with_capacity(recipes.len());
    for recipe in recipes {
        executions.push(execute_recipe(recipe, &identity_before.binary_digest).await);
    }
    executions.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after startup environment recipes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after startup environment recipes");
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
        .expect("create owned startup environment public evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize startup environment public evidence artifact");
    output
        .write_all(b"\n")
        .expect("finish startup environment public evidence artifact");
    output
        .sync_all()
        .expect("sync startup environment public evidence artifact");
}
