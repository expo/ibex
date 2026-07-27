// Loaded-engine conformance harness; excluded from production surface scans.
use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsString;
#[cfg(not(feature = "host-http-server"))]
use std::io::Write as _;

const STARTUP_ENVIRONMENT_INVOCATION_SCHEMA: &str = "ibex/capsec-startup-environment-invocation/1";
const PRINCIPAL_ENVIRONMENT_INVOCATION_SCHEMA: &str =
    "ibex/capsec-principal-environment-invocation/1";
const ENV_AUXILIARY_EDGE_ID: &str = "surface.native.op.exactgetenv.0k6bv7a";
const ENV_WRITE_AUXILIARY_EDGE_ID: &str = "surface.native.op.exactsetenv.1785yh6";
const PRINCIPAL_ENVIRONMENT_SURFACE: &str =
    "native-op:global:process.env.[[dynamic-table:principal-environment-overlay-properties]]";
const PRINCIPAL_ENVIRONMENT_CARRIER_EDGE_ID: &str =
    "surface.native.op.global.process.env.dynamic.table.principal.environment.overlay.propertie.0sncb00";
const PRINCIPAL_ENVIRONMENT_NAME: &str = "IBEX_CAPSEC_PUBLIC_ENV_PROPERTY";
const STARTUP_ENVIRONMENT_BATCH_COMMAND: [&str; 10] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--no-default-features",
    "--features",
    "standard,capsec-conformance-observer,openssl-crypto",
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
struct PrincipalEnvironmentProbe {
    kind: String,
    surface_observed_key: String,
    command: Vec<String>,
    invocation: PrincipalEnvironmentInvocation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrincipalEnvironmentInvocation {
    invocation_schema: String,
    kind: String,
    scenario: String,
    source_descriptor: serde_json::Value,
    source_descriptor_digest: String,
    operation: PrincipalEnvironmentOperation,
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
struct PrincipalEnvironmentOperation {
    kind: String,
    environment_name: String,
    value: Option<String>,
    principal_mode: String,
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
    observed_environment_names: Vec<String>,
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
    observed_environment_names: &'static [&'static str],
}

const EXPECTED_SOURCES: [ExpectedSource; 7] = [
    ExpectedSource {
        environment_name: "NODE_DEBUG",
        source_ref: "src/builtins/http.js#process.env:NODE_DEBUG:read",
        mechanism: "builtin-module-load",
        module_specifier: Some("node:http"),
        preload_module_specifiers: &["node:events", "node:stream", "node:util"],
        observed_environment_names: &["NODE_DEBUG"],
    },
    ExpectedSource {
        environment_name: "EXACT_DEBUG_EMIT_LISTENER",
        source_ref: "src/builtins/events.js#process.env:EXACT_DEBUG_EMIT_LISTENER:read",
        mechanism: "event-emitter-emit",
        module_specifier: Some("node:events"),
        preload_module_specifiers: &[],
        observed_environment_names: &["EXACT_DEBUG_EMIT_LISTENER"],
    },
    ExpectedSource {
        environment_name: "TZ",
        source_ref: "packages/ibex-runtime-js/src/node/process.ts#process.env:TZ:read",
        mechanism: "date-to-string",
        module_specifier: None,
        preload_module_specifiers: &[],
        observed_environment_names: &["TZ"],
    },
    ExpectedSource {
        environment_name: "EXACT_PIPELINE_DEBUG",
        source_ref: "src/builtins/stream.js#process.env:EXACT_PIPELINE_DEBUG:read",
        mechanism: "builtin-module-load",
        module_specifier: Some("node:stream"),
        preload_module_specifiers: &["node:events", "node:string_decoder", "node:util"],
        observed_environment_names: &["EXACT_PIPELINE_DEBUG", "EXACT_PIPELINE_STATE_DEBUG"],
    },
    ExpectedSource {
        environment_name: "EXACT_PIPELINE_STATE_DEBUG",
        source_ref: "src/builtins/stream.js#process.env:EXACT_PIPELINE_STATE_DEBUG:read",
        mechanism: "builtin-module-load",
        module_specifier: Some("node:stream"),
        preload_module_specifiers: &["node:events", "node:string_decoder", "node:util"],
        observed_environment_names: &["EXACT_PIPELINE_DEBUG", "EXACT_PIPELINE_STATE_DEBUG"],
    },
    ExpectedSource {
        environment_name: "COLUMNS",
        source_ref: "src/builtins/tty.js#process.env:COLUMNS:read",
        mechanism: "tty-refresh-size",
        module_specifier: Some("node:tty"),
        preload_module_specifiers: &["node:tty"],
        observed_environment_names: &["COLUMNS", "LINES"],
    },
    ExpectedSource {
        environment_name: "LINES",
        source_ref: "src/builtins/tty.js#process.env:LINES:read",
        mechanism: "tty-refresh-size",
        module_specifier: Some("node:tty"),
        preload_module_specifiers: &["node:tty"],
        observed_environment_names: &["COLUMNS", "LINES"],
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

fn principal_environment_probe(recipe: &Recipe) -> Option<PrincipalEnvironmentProbe> {
    let value = recipe.public_surface_probe.as_ref()?;
    if value["invocation"]["invocationSchema"] != PRINCIPAL_ENVIRONMENT_INVOCATION_SCHEMA {
        return None;
    }
    Some(
        serde_json::from_value(value.clone())
            .expect("principal environment public probe must match its typed schema"),
    )
}

fn environment_selector(name: &str) -> serde_json::Value {
    // @ref LLP 0022#7-capabilities-principals-and-affordance-parity — armed
    // process.env reads only the current principal's exact-name overlay;
    // startup-source classification does not reopen the broker base.
    serde_json::json!({
        "cap": "env:read",
        "resource": {
            "kind": "environment-name",
            "target": "principal-overlay",
            "name": name,
        },
    })
}

fn principal_environment_selector(action: &str, name: &str) -> serde_json::Value {
    serde_json::json!({
        "cap": action,
        "resource": {
            "kind": "environment-name",
            "target": "principal-overlay",
            "name": name,
        },
    })
}

fn package_components(path: &std::path::Path) -> serde_json::Value {
    serde_json::to_value(
        ibex_runtime::host::host_path_components(path)
            .expect("encode production-equivalent startup package path"),
    )
    .expect("serialize startup package path components")
}

fn object_identity(path: &std::path::Path) -> serde_json::Value {
    serde_json::to_value(
        ibex_runtime::host::object_identity_for_host_path(path)
            .expect("pin production-equivalent startup package root"),
    )
    .expect("serialize startup package object identity")
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
        "tty-refresh-size" => format!(
            "module.exports = function() {{ var WriteStream = require({}).WriteStream; var target = {{ columns: undefined, rows: undefined }}; WriteStream.prototype._refreshSize.call(target); return target.columns === undefined && target.rows === undefined; }};\n",
            serde_json::to_string(
                operation
                    .module_specifier
                    .as_deref()
                    .expect("tty environment probe requires a module"),
            )
            .expect("serialize tty environment probe module")
        ),
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

fn prepare_principal_environment_package(
    operation: &PrincipalEnvironmentOperation,
) -> PackageFixture {
    let directory = tempfile::tempdir().expect("create principal environment package fixture");
    let root = std::fs::canonicalize(directory.path())
        .expect("canonicalize principal environment fixture root");
    let package_root = root.join("node_modules/image-lib");
    std::fs::create_dir_all(&package_root).expect("create principal environment package root");
    std::fs::write(
        package_root.join("package.json"),
        r#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
    )
    .expect("write principal environment package manifest");
    let name = serde_json::to_string(&operation.environment_name)
        .expect("serialize principal environment name");
    let source = match operation.kind.as_str() {
        "read" => format!(
            "module.exports = function(environment) {{ return environment[{name}] === undefined; }};\n"
        ),
        "write" => format!(
            "module.exports = function(environment) {{ environment[{name}] = {}; return true; }};\n",
            serde_json::to_string(
                operation
                    .value
                    .as_deref()
                    .expect("principal environment write requires a value"),
            )
            .expect("serialize principal environment value")
        ),
        other => panic!("unsupported principal environment operation {other}"),
    };
    std::fs::write(package_root.join("index.js"), source)
        .expect("write principal environment package source");
    let integrity = crate::module_loader::package_tree_integrity(&package_root)
        .expect("digest principal environment package tree");
    let principal_value = serde_json::json!({
        "kind": "package",
        "name": "image-lib",
        "integrity": integrity,
        "locator": "image-lib@2.4.1",
    });
    let principal = serde_json::from_value(principal_value.clone())
        .expect("principal environment package principal must be valid");
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
    environment_names: &[String],
) -> (crate::host::Host, String) {
    let root_floor = environment_names
        .iter()
        .map(|name| environment_selector(name))
        .collect::<Vec<_>>();
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
            snapshot["principals"][1]["denials"] = serde_json::to_value(
                environment_names
                    .iter()
                    .map(|name| environment_selector(name))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            snapshot["principals"][1]["escalationCeiling"] = serde_json::json!([]);
            snapshot["principals"][1]["imports"]["builtins"] =
                serde_json::to_value(&builtin_imports).unwrap();
            snapshot["packageGraph"]["nodes"][0]["principal"] = package.principal_value.clone();
            snapshot["packageGraph"]["importEdges"][0]["imported"] =
                package.principal_value.clone();
        },
    )
}

fn build_principal_environment_host(
    package: Option<&PackageFixture>,
    operation: &PrincipalEnvironmentOperation,
) -> (crate::host::Host, String) {
    let action = match operation.kind.as_str() {
        "read" => "env:read",
        "write" => "env:write",
        other => panic!("unsupported principal environment operation {other}"),
    };
    let selector = principal_environment_selector(action, &operation.environment_name);
    build_armed_test_host_control(
        package.map(|fixture| fixture.root.as_path()),
        false,
        false,
        false,
        vec![selector.clone()],
        Vec::new(),
        false,
        0,
        None,
        |snapshot| {
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
            snapshot["principals"][1]["denials"] = serde_json::json!([selector]);
            snapshot["principals"][1]["escalationCeiling"] = serde_json::json!([]);
            snapshot["principals"][1]["imports"]["builtins"] = serde_json::json!([]);
            snapshot["packageGraph"]["nodes"][0]["principal"] = package.principal_value.clone();
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
        "allow"
            | "deny"
            | "malformed"
            | "missing-attribution"
            | "wrong-principal"
            | "branch-selection"
    ));
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(STARTUP_ENVIRONMENT_BATCH_COMMAND));
    assert_eq!(
        invocation.invocation_schema,
        STARTUP_ENVIRONMENT_INVOCATION_SCHEMA
    );
    assert_eq!(invocation.kind, "startup-environment-source");
    assert_eq!(invocation.scenario, recipe.scenario);
    assert_eq!(invocation.surface_kind, "startup");
    assert_eq!(invocation.surface_name, format!("env:{environment_name}"));
    assert_eq!(
        probe.surface_observed_key,
        format!("{}:{}", invocation.surface_kind, invocation.surface_name)
    );
    assert_eq!(probe.surface_observed_key, recipe.terminal_observed_key);
    assert_eq!(
        recipe.edge_ids,
        [descriptor["carrierEdgeId"].as_str().unwrap()]
    );
    assert_eq!(
        recipe.implementation_branch_ids,
        serde_json::from_value::<Vec<String>>(descriptor["implementationBranchIds"].clone())
            .unwrap()
    );
    assert_eq!(
        recipe.enforcement_branch_ids,
        serde_json::from_value::<Vec<String>>(descriptor["enforcementBranchIds"].clone()).unwrap()
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
        invocation
            .operation
            .observed_environment_names
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected.observed_environment_names
    );
    assert_eq!(
        descriptor["observedEnvironmentNames"],
        serde_json::json!(expected.observed_environment_names)
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
    assert_eq!(
        invocation
            .expected_resource_names
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected.observed_environment_names
    );
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

fn validate_principal_environment_probe(recipe: &Recipe, probe: &PrincipalEnvironmentProbe) {
    let invocation = &probe.invocation;
    let descriptor = &invocation.source_descriptor;
    let operation = &invocation.operation;
    let (action, auxiliary_observed_key, auxiliary_edge_id, bridge) = match operation.kind.as_str()
    {
        "read" => (
            "env:read",
            "native-op:__exactGetEnv",
            ENV_AUXILIARY_EDGE_ID,
            "__exactGetEnv",
        ),
        "write" => (
            "env:write",
            "native-op:__exactSetEnv",
            ENV_WRITE_AUXILIARY_EDGE_ID,
            "__exactSetEnv",
        ),
        other => panic!("unsupported principal environment operation {other}"),
    };
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "effects");
    assert!(matches!(
        recipe.scenario.as_str(),
        "allow"
            | "deny"
            | "malformed"
            | "missing-attribution"
            | "wrong-principal"
            | "branch-selection"
    ));
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(STARTUP_ENVIRONMENT_BATCH_COMMAND));
    assert_eq!(
        invocation.invocation_schema,
        PRINCIPAL_ENVIRONMENT_INVOCATION_SCHEMA
    );
    assert_eq!(invocation.kind, "principal-environment-property");
    assert_eq!(invocation.scenario, recipe.scenario);
    assert_eq!(probe.surface_observed_key, PRINCIPAL_ENVIRONMENT_SURFACE);
    assert_eq!(probe.surface_observed_key, recipe.terminal_observed_key);
    assert_eq!(recipe.edge_ids, [PRINCIPAL_ENVIRONMENT_CARRIER_EDGE_ID]);
    assert_eq!(recipe.action_ids, [action]);
    assert_eq!(recipe.expected_observation["kind"], "enforcement-branch");
    assert_eq!(descriptor["kind"], "principal-environment-property");
    assert_eq!(
        descriptor["surfaceObservedKey"],
        PRINCIPAL_ENVIRONMENT_SURFACE
    );
    assert_eq!(
        descriptor["carrierEdgeId"],
        PRINCIPAL_ENVIRONMENT_CARRIER_EDGE_ID
    );
    assert_eq!(
        recipe.implementation_branch_ids,
        serde_json::from_value::<Vec<String>>(descriptor["implementationBranchIds"].clone())
            .unwrap()
    );
    assert_eq!(
        recipe.enforcement_branch_ids,
        serde_json::from_value::<Vec<String>>(descriptor["enforcementBranchIds"].clone()).unwrap()
    );
    assert_eq!(descriptor["selectedBranch"]["id"], operation.kind);
    assert_eq!(
        descriptor["selectedBranch"]["when"],
        serde_json::json!([{
            "fact": "environment.property.operation",
            "equals": operation.kind,
        }])
    );
    assert_eq!(
        descriptor["sourceContract"]["schema"],
        "ibex/principal-environment-overlay-source-contract/1"
    );
    assert_eq!(descriptor["sourceContract"]["globalPath"], "process.env");
    assert_eq!(
        descriptor["sourceContract"]["binding"]["member"],
        "Process.prototype.env"
    );
    assert_eq!(
        descriptor["selectedProxyTrap"]["name"],
        if operation.kind == "read" {
            "get"
        } else {
            "set"
        }
    );
    assert!(descriptor["selectedProxyTrap"]["nativeBridges"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String(bridge.into())));
    assert_eq!(descriptor["auxiliaryObservedKey"], auxiliary_observed_key);
    assert_eq!(descriptor["auxiliaryDecisionEdgeId"], auxiliary_edge_id);
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_jcs_digest(descriptor)
    );
    assert_eq!(operation.environment_name, PRINCIPAL_ENVIRONMENT_NAME);
    assert_eq!(
        operation.value.as_deref(),
        (operation.kind == "write").then_some("ibex-capsec-value")
    );
    let denial = recipe.scenario == "deny";
    let expected_principal_mode = if denial {
        "package-denied"
    } else {
        "root-authorized"
    };
    assert_eq!(operation.principal_mode, expected_principal_mode);
    assert_eq!(descriptor["principalMode"], expected_principal_mode);
    assert_eq!(
        invocation.expected_result,
        if denial && operation.kind == "write" {
            "permission-denied"
        } else {
            "return"
        }
    );
    assert_eq!(invocation.allowed_coverage_edge_ids, [auxiliary_edge_id]);
    assert_eq!(invocation.expected_action_ids, [action]);
    assert_eq!(
        invocation.expected_resource_names,
        [PRINCIPAL_ENVIRONMENT_NAME]
    );
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

fn validate_principal_environment_decisions(
    recipe: &Recipe,
    invocation: &PrincipalEnvironmentInvocation,
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
    let package_mode = invocation.operation.principal_mode == "package-denied";
    let expected_constrained = if package_mode {
        serde_json::json!([
            {"kind": "root", "identity": "project-root"},
            expected_principal,
        ])
    } else {
        serde_json::json!([expected_principal])
    };
    let action = invocation.expected_action_ids[0].as_str();
    let edge_id = invocation.allowed_coverage_edge_ids[0].as_str();
    for (index, decision) in decisions.iter().enumerate() {
        let set = &decision["decisionSet"];
        assert_eq!(set["context"]["actor"], expected_principal);
        assert_eq!(
            set["context"]["constrainedPrincipals"],
            expected_constrained
        );
        assert_eq!(
            set["context"]["stage"],
            invocation.expected_typed_stages[index]
        );
        assert_eq!(set["atomicityGroup"], format!("{edge_id}.decision"));
        assert_eq!(set["effects"].as_array().unwrap().len(), 1);
        assert_eq!(set["effects"][0]["cap"], action);
        assert_eq!(set["effects"][0]["effectOwner"], expected_principal);
        assert_eq!(
            set["effects"][0]["resource"],
            serde_json::json!({
                "kind": "environment-occurrence",
                "requested": {
                    "kind": "environment-name",
                    "target": "principal-overlay",
                    "name": invocation.operation.environment_name,
                },
                "valueOrigin": "principal-overlay",
            })
        );
        assert_eq!(decision["gates"].as_array().unwrap().len(), 1);
        assert_eq!(decision["gates"][0]["coverageEdgeId"], edge_id);
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
    let expected_constrained = if invocation.operation.principal_mode == "package-denied" {
        serde_json::json!([
            {"kind": "root", "identity": "project-root"},
            expected_principal,
        ])
    } else {
        serde_json::json!([expected_principal])
    };
    let decisions_per_resource = if invocation.operation.principal_mode == "package-denied" {
        1
    } else {
        2
    };
    let expected_decision_resource_names = invocation
        .expected_resource_names
        .iter()
        .flat_map(|name| std::iter::repeat(name.as_str()).take(decisions_per_resource))
        .collect::<Vec<_>>();
    assert_eq!(expected_decision_resource_names.len(), decisions.len());
    for (index, decision) in decisions.iter().enumerate() {
        let set = &decision["decisionSet"];
        assert_eq!(set["context"]["actor"], expected_principal);
        assert_eq!(
            set["context"]["constrainedPrincipals"],
            expected_constrained
        );
        assert_eq!(
            set["context"]["stage"],
            invocation.expected_typed_stages[index]
        );
        assert_eq!(
            set["atomicityGroup"],
            format!("{ENV_AUXILIARY_EDGE_ID}.decision")
        );
        assert_eq!(set["effects"].as_array().unwrap().len(), 1);
        assert_eq!(set["effects"][0]["cap"], "env:read");
        assert_eq!(set["effects"][0]["effectOwner"], expected_principal);
        assert_eq!(
            set["effects"][0]["resource"],
            serde_json::json!({
                "kind": "environment-occurrence",
                "requested": {
                    "kind": "environment-name",
                    "target": "principal-overlay",
                    "name": expected_decision_resource_names[index],
                },
                "valueOrigin": "principal-overlay",
            })
        );
        assert_eq!(decision["gates"].as_array().unwrap().len(), 1);
        assert_eq!(
            decision["gates"][0]["coverageEdgeId"],
            ENV_AUXILIARY_EDGE_ID
        );
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
    host: &crate::host::Host,
    invocation: &StartupEnvironmentInvocation,
    package: Option<&PackageFixture>,
    session_id: &str,
) -> (serde_json::Value, usize, Vec<serde_json::Value>) {
    let mut evaluator = AuthenticatedStartupEvaluator::new(host);
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
            evaluator
                .eval_string(engine, &script)
                .await
                .expect("preload distinct startup environment dependency")
                .as_deref(),
            Some("dependency-ready")
        );
    }
    if package.is_some() {
        assert_eq!(
            evaluator
                .eval_string(engine, "require('image-lib'); 'ready'")
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
        "tty-refresh-size" => format!(
            "(function() {{ var WriteStream = require({}).WriteStream; var target = {{ columns: undefined, rows: undefined }}; WriteStream.prototype._refreshSize.call(target); return target.columns === undefined && target.rows === undefined; }})()",
            serde_json::to_string(
                invocation
                    .operation
                    .module_specifier
                    .as_deref()
                    .expect("tty environment source requires a module"),
            )
            .unwrap()
        ),
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
    let encoded = evaluator
        .eval_string(engine, &script)
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
    evaluator
        .finish(engine, "startup environment public source")
        .expect("finish authenticated startup environment publications");
    (result, legacy.len(), typed)
}

async fn execute_recipe(recipe: &Recipe, engine_binary_digest: &str) -> serde_json::Value {
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
    let _environments = invocation
        .expected_resource_names
        .iter()
        .map(|name| EnvironmentRestore::absent(name))
        .collect::<Vec<_>>();
    assert!(invocation
        .expected_resource_names
        .iter()
        .all(|name| std::env::var_os(name).is_none()));
    let (host, snapshot_digest) = build_environment_host(
        package.as_ref(),
        &invocation.operation,
        &invocation.expected_resource_names,
    );
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create exact startup environment probe engine");
    engine
        .load_runtime()
        .await
        .expect("load exact startup environment probe runtime");
    let session_id = format!("startup-environment-observation:{}", recipe.plan_digest);
    let (source_result, legacy_count, typed_decisions) =
        invoke_source(&engine, &host, invocation, package.as_ref(), &session_id).await;
    assert_eq!(
        legacy_count, 0,
        "startup environment source consulted legacy policy"
    );
    validate_typed_decisions(recipe, invocation, &expected_principal, &typed_decisions);
    assert!(invocation
        .expected_resource_names
        .iter()
        .all(|name| std::env::var_os(name).is_none()));

    let source_outcome = if invocation
        .expected_typed_outcomes
        .iter()
        .all(|outcome| outcome == "deny")
    {
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
        "observedEnvironmentNames": invocation.operation.observed_environment_names,
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

async fn invoke_principal_environment_property(
    engine: &HermesEngine,
    host: &crate::host::Host,
    invocation: &PrincipalEnvironmentInvocation,
    package: Option<&PackageFixture>,
    session_id: &str,
) -> (serde_json::Value, usize, Vec<serde_json::Value>) {
    let mut evaluator = AuthenticatedStartupEvaluator::new(host);
    if package.is_some() {
        assert_eq!(
            evaluator
                .eval_string(engine, "require('image-lib'); 'ready'")
                .await
                .expect("preload principal environment package")
                .as_deref(),
            Some("ready")
        );
    }
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(session_id),
        "install principal environment observation {session_id}"
    );
    let name = serde_json::to_string(&invocation.operation.environment_name).unwrap();
    let root_expression = match invocation.operation.kind.as_str() {
        "read" => format!("process.env[{name}] === undefined"),
        "write" => format!(
            "((process.env[{name}] = {}) === {})",
            serde_json::to_string(
                invocation
                    .operation
                    .value
                    .as_deref()
                    .expect("principal environment write requires a value"),
            )
            .unwrap(),
            serde_json::to_string(
                invocation
                    .operation
                    .value
                    .as_deref()
                    .expect("principal environment write requires a value"),
            )
            .unwrap(),
        ),
        other => panic!("unsupported principal environment operation {other}"),
    };
    let expression = if package.is_some() {
        "(function(environment) { return require('image-lib')(environment); })(process.env)"
            .to_owned()
    } else {
        root_expression
    };
    let project_marker = serde_json::to_string(session_id).unwrap();
    let script = format!(
        "JSON.stringify((function(projectMarker){{try{{var value={expression};return {{kind:'return',value:value===true,projectMarker:projectMarker}};}}catch(error){{return {{kind:'throw',errorName:String(error&&error.name||'Error'),errorMessage:String(error&&error.message||error),projectMarker:projectMarker}};}}}})({project_marker}))"
    );
    let encoded = evaluator
        .eval_string(engine, &script)
        .await
        .expect("execute principal environment public source")
        .expect("principal environment public source returned no result");
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    let result: serde_json::Value = serde_json::from_str(&encoded)
        .expect("principal environment public source returned invalid JSON");
    assert_eq!(result["projectMarker"], session_id);
    let typed = typed_decision_values(session_id, typed);
    match invocation.expected_result.as_str() {
        "return" => {
            assert_eq!(
                result["kind"], "return",
                "principal environment {} {} returned {result}",
                invocation.operation.kind, invocation.operation.principal_mode
            );
            assert_eq!(
                result["value"], true,
                "principal environment {} {} returned {result}",
                invocation.operation.kind, invocation.operation.principal_mode
            );
        }
        "permission-denied" => {
            assert_eq!(result["kind"], "throw");
            assert!(result["errorMessage"]
                .as_str()
                .is_some_and(|message| message.contains("Permission denied")));
        }
        other => panic!("unsupported principal environment result {other}"),
    }
    evaluator
        .finish(engine, "principal environment public source")
        .expect("finish authenticated principal environment publications");
    (result, legacy.len(), typed)
}

async fn execute_principal_environment_recipe(
    recipe: &Recipe,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let probe = principal_environment_probe(recipe)
        .expect("principal environment recipe has no typed public probe");
    validate_principal_environment_probe(recipe, &probe);
    let invocation = &probe.invocation;
    let package = (invocation.operation.principal_mode == "package-denied")
        .then(|| prepare_principal_environment_package(&invocation.operation));
    let expected_principal = package
        .as_ref()
        .map(|fixture| fixture.principal.clone())
        .unwrap_or_else(|| {
            serde_json::from_value(serde_json::json!({
                "kind": "root",
                "identity": "project-root",
            }))
            .expect("root principal environment principal must be valid")
        });
    let (host, snapshot_digest) =
        build_principal_environment_host(package.as_ref(), &invocation.operation);
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create exact principal environment probe engine");
    engine
        .load_runtime()
        .await
        .expect("load exact principal environment probe runtime");
    let session_id = format!("principal-environment-observation:{}", recipe.plan_digest);
    let (source_result, legacy_count, typed_decisions) = invoke_principal_environment_property(
        &engine,
        &host,
        invocation,
        package.as_ref(),
        &session_id,
    )
    .await;
    assert_eq!(
        legacy_count, 0,
        "principal environment source consulted legacy policy"
    );
    validate_principal_environment_decisions(
        recipe,
        invocation,
        &expected_principal,
        &typed_decisions,
    );

    let denial = invocation.expected_typed_outcomes == ["deny"];
    let source_outcome = if denial {
        if invocation.operation.kind == "read" {
            "denied-as-absent"
        } else {
            "permission-denied"
        }
    } else {
        "source-observed"
    };
    let project_code_executed = source_result["projectMarker"] == session_id;
    assert!(project_code_executed);
    let result = serde_json::json!({
        "kind": source_result["kind"],
        "surfaceKind": "native-op",
        "surfaceName": "global:process.env.[[dynamic-table:principal-environment-overlay-properties]]",
        "mechanism": "process-env-proxy",
        "operationKind": invocation.operation.kind,
        "environmentName": invocation.operation.environment_name,
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
        .expect("expected principal environment observation must be an object")
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
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping startup environment public batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT").ok();
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipes = catalog
        .recipes
        .iter()
        .filter(|recipe| startup_environment_probe(recipe).is_some())
        .collect::<Vec<_>>();
    let principal_environment_recipes = catalog
        .recipes
        .iter()
        .filter(|recipe| principal_environment_probe(recipe).is_some())
        .collect::<Vec<_>>();
    assert_eq!(
        recipes.len(),
        42,
        "expected the complete matrix for seven startup environment absent slices"
    );
    assert_eq!(
        principal_environment_recipes.len(),
        12,
        "expected the complete read and write principal environment matrix"
    );
    assert_eq!(
        principal_environment_recipes
            .iter()
            .map(|recipe| recipe.scenario.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "allow",
            "branch-selection",
            "deny",
            "malformed",
            "missing-attribution",
            "wrong-principal",
        ])
    );
    assert!(principal_environment_recipes
        .iter()
        .all(|recipe| recipe.terminal_observed_key == PRINCIPAL_ENVIRONMENT_SURFACE));
    assert_eq!(
        recipes
            .iter()
            .map(|recipe| recipe.scenario.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "allow",
            "branch-selection",
            "deny",
            "malformed",
            "missing-attribution",
            "wrong-principal",
        ])
    );
    assert_eq!(
        recipes
            .iter()
            .map(|recipe| recipe.terminal_observed_key.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "startup:env:COLUMNS",
            "startup:env:EXACT_DEBUG_EMIT_LISTENER",
            "startup:env:EXACT_PIPELINE_DEBUG",
            "startup:env:EXACT_PIPELINE_STATE_DEBUG",
            "startup:env:LINES",
            "startup:env:NODE_DEBUG",
            "startup:env:TZ",
        ])
    );

    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before startup environment recipes");
    let portable = super::capsec_portable_public_batch::PortablePublicBatchContext::begin(
        "ibex-startup-environment-public-source-harness",
    );
    assert_ne!(
        output_path.is_some(),
        portable.is_some(),
        "startup environment batch requires exactly one legacy output or portable plan"
    );
    let mut executions = Vec::with_capacity(recipes.len() + principal_environment_recipes.len());
    for recipe in recipes {
        executions.push(execute_recipe(recipe, &identity_before.binary_digest).await);
    }
    for recipe in principal_environment_recipes {
        executions.push(
            execute_principal_environment_recipe(recipe, &identity_before.binary_digest).await,
        );
    }
    executions.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after startup environment recipes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after startup environment recipes");
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
        .open(output_path.expect("legacy startup environment batch has no output path"))
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

const OVERLAY_SHARED_NAME: &str = "IBEX_CAPSEC_OVERLAY_SHARED";
const OVERLAY_WRITE_ONLY_NAME: &str = "IBEX_CAPSEC_OVERLAY_WRITE_ONLY";
const OVERLAY_READ_ONLY_NAME: &str = "IBEX_CAPSEC_OVERLAY_READ_ONLY";
const OVERLAY_ASYNC_NAME: &str = "IBEX_CAPSEC_OVERLAY_ASYNC";

struct OverlayPackage {
    root: std::path::PathBuf,
    principal_value: serde_json::Value,
    principal: capsec_semantics::model::Principal,
}

struct TwoPackageOverlayFixture {
    _directory: tempfile::TempDir,
    root: std::path::PathBuf,
    alpha: OverlayPackage,
    beta: OverlayPackage,
}

fn prepare_overlay_package(
    project_root: &std::path::Path,
    name: &str,
    version: &str,
    label: &str,
) -> OverlayPackage {
    let root = project_root.join("node_modules").join(name);
    std::fs::create_dir_all(&root).expect("create principal-overlay package root");
    std::fs::write(
        root.join("package.json"),
        serde_json::json!({
            "name": name,
            "version": version,
            "main": "index.js",
        })
        .to_string(),
    )
    .expect("write principal-overlay package manifest");
    let source = r#"var requiredProcess = require('process');

function capture(thunk) {
  try { return { ok: true, value: thunk() }; }
  catch (error) {
    return { ok: false, error: String(error && error.message || error) };
  }
}

function read(name) {
  var value = process.env[name];
  return { present: value !== undefined, value: value === undefined ? null : value };
}

module.exports = {
  metadata: function() {
    return {
      label: '__PACKAGE_LABEL__',
      processType: typeof process,
      requiredProcessEnvIdentity: requiredProcess.env === process.env,
      rawSetterType: typeof __exactSetEnv,
      globalRawSetterType: typeof globalThis.__exactSetEnv,
      rawSetterInGlobal: '__exactSetEnv' in globalThis,
      rawSetterOwnGlobal: Object.prototype.hasOwnProperty.call(globalThis, '__exactSetEnv')
    };
  },
  read: read,
  keys: function() { return Object.keys(process.env).sort(); },
  set: function(name, value) {
    return capture(function() { process.env[name] = value; return true; });
  },
  remove: function(name) {
    return capture(function() { return delete process.env[name]; });
  },
  scheduleAsync: function(name, value, sink) {
    Promise.resolve().then(function() {
      process.env[name] = value;
      return read(name);
    }).then(function(result) {
      sink({ ok: true, result: result, keys: Object.keys(process.env).sort() });
    }, function(error) {
      sink({ ok: false, error: String(error && error.message || error) });
    });
    return true;
  }
};
"#
    .replace("__PACKAGE_LABEL__", label);
    std::fs::write(root.join("index.js"), source).expect("write principal-overlay package source");
    let integrity = crate::module_loader::package_tree_integrity(&root)
        .expect("digest principal-overlay package tree");
    let locator = format!("{name}@{version}");
    let principal_value = serde_json::json!({
        "kind": "package",
        "name": name,
        "integrity": integrity,
        "locator": locator,
    });
    let principal = serde_json::from_value(principal_value.clone())
        .expect("principal-overlay package principal must be valid");
    OverlayPackage {
        root,
        principal_value,
        principal,
    }
}

fn prepare_two_package_overlay_fixture() -> TwoPackageOverlayFixture {
    let directory = tempfile::tempdir().expect("create principal-overlay fixture");
    let root = std::fs::canonicalize(directory.path())
        .expect("canonicalize principal-overlay fixture root");
    std::fs::create_dir_all(root.join("node_modules"))
        .expect("create principal-overlay node_modules");
    let alpha = prepare_overlay_package(&root, "env-alpha", "1.0.0", "alpha");
    let beta = prepare_overlay_package(&root, "env-beta", "1.0.0", "beta");
    TwoPackageOverlayFixture {
        _directory: directory,
        root,
        alpha,
        beta,
    }
}

fn overlay_selector(action: &str, name: &str) -> serde_json::Value {
    serde_json::json!({
        "cap": action,
        "resource": {
            "kind": "environment-name",
            "target": "principal-overlay",
            "name": name,
        },
    })
}

fn sorted_overlay_selectors(
    selectors: impl IntoIterator<Item = serde_json::Value>,
) -> serde_json::Value {
    let mut selectors = selectors.into_iter().collect::<Vec<_>>();
    selectors.sort_by(|left, right| {
        capsec_semantics::canonical::to_jcs_bytes(left)
            .unwrap()
            .cmp(&capsec_semantics::canonical::to_jcs_bytes(right).unwrap())
    });
    selectors.dedup();
    serde_json::Value::Array(selectors)
}

fn build_two_package_overlay_host(
    fixture: &TwoPackageOverlayFixture,
) -> (crate::host::Host, String) {
    let all_names = [
        OVERLAY_SHARED_NAME,
        OVERLAY_WRITE_ONLY_NAME,
        OVERLAY_READ_ONLY_NAME,
        OVERLAY_ASYNC_NAME,
    ];
    let root_floor = all_names.into_iter().flat_map(|name| {
        [
            overlay_selector("env:read", name),
            overlay_selector("env:write", name),
        ]
    });
    build_armed_test_host_control(
        Some(&fixture.root),
        false,
        false,
        false,
        root_floor.collect(),
        Vec::new(),
        false,
        0,
        None,
        |snapshot| {
            // Calls enter package Domains from root-authored test code, so the
            // root deputy receives the union while each package row remains
            // independently least-authority.
            // @ref LLP 0013#mechanism-2
            let alpha_locator = fixture.alpha.principal_value["locator"].clone();
            let beta_locator = fixture.beta.principal_value["locator"].clone();
            snapshot["principals"][0]["imports"]["packages"] =
                serde_json::json!([alpha_locator, beta_locator]);

            let mut alpha_row = snapshot["principals"][1].clone();
            alpha_row["principal"] = fixture.alpha.principal_value.clone();
            alpha_row["floor"] = sorted_overlay_selectors([
                overlay_selector("env:read", OVERLAY_SHARED_NAME),
                overlay_selector("env:write", OVERLAY_SHARED_NAME),
                overlay_selector("env:write", OVERLAY_WRITE_ONLY_NAME),
                overlay_selector("env:read", OVERLAY_READ_ONLY_NAME),
                overlay_selector("env:read", OVERLAY_ASYNC_NAME),
                overlay_selector("env:write", OVERLAY_ASYNC_NAME),
            ]);
            alpha_row["denials"] = serde_json::json!([]);
            alpha_row["escalationCeiling"] = serde_json::json!([]);
            alpha_row["imports"] = serde_json::json!({
                "builtins": ["process"],
                "packages": [],
            });
            alpha_row["endowments"] = serde_json::json!(["process"]);

            let mut beta_row = alpha_row.clone();
            beta_row["principal"] = fixture.beta.principal_value.clone();
            beta_row["floor"] = sorted_overlay_selectors([
                overlay_selector("env:read", OVERLAY_SHARED_NAME),
                overlay_selector("env:write", OVERLAY_SHARED_NAME),
                overlay_selector("env:read", OVERLAY_ASYNC_NAME),
            ]);
            snapshot["principals"][1] = alpha_row;
            snapshot["principals"]
                .as_array_mut()
                .unwrap()
                .push(beta_row);

            snapshot["rootBindings"][0]["owner"] = fixture.alpha.principal_value.clone();
            snapshot["rootBindings"][0]["hostPath"] = serde_json::json!({
                "root": "absolute",
                "components": package_components(&fixture.alpha.root),
                "hostBound": true,
            });
            snapshot["rootBindings"][0]["object"] = object_identity(&fixture.alpha.root);
            let mut beta_binding = snapshot["rootBindings"][0].clone();
            beta_binding["owner"] = fixture.beta.principal_value.clone();
            beta_binding["hostPath"] = serde_json::json!({
                "root": "absolute",
                "components": package_components(&fixture.beta.root),
                "hostBound": true,
            });
            beta_binding["object"] = object_identity(&fixture.beta.root);
            snapshot["rootBindings"]
                .as_array_mut()
                .unwrap()
                .push(beta_binding);

            let root = snapshot["rootIdentity"].clone();
            snapshot["packageGraph"]["nodes"] = serde_json::json!([
                {"principal": fixture.alpha.principal_value},
                {"principal": fixture.beta.principal_value},
            ]);
            snapshot["packageGraph"]["importEdges"] = serde_json::json!([
                {"importer": root, "imported": fixture.alpha.principal_value},
                {"importer": snapshot["rootIdentity"], "imported": fixture.beta.principal_value},
            ]);
            snapshot["packageGraph"]["digest"] =
                serde_json::json!(capsec_semantics::digest::compute_domain_digest(
                    "ibex:capsec:package-graph:1",
                    &snapshot["packageGraph"],
                    &["digest".to_owned()],
                )
                .expect("digest principal-overlay package graph"));
        },
    )
}

/// Test-only authenticated source stream shared by the curated startup-source
/// and principal-overlay probes. Armed project code enters through the same
/// closed submission adapter as production REPL source; the test never
/// reopens Hermes' sealed bare evaluator.
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
/// @ref LLP 0025#11-delegated-obligations — the harness consumes every
/// authenticated work-unit, timer, and cancellation publication before the
/// supervised engine is discarded.
struct AuthenticatedStartupEvaluator {
    session: ibex_runtime::engine::evaluation::ArmedSessionToken,
    sequence: ibex_runtime::engine::evaluation::SubmissionSequence,
    publications: AuthenticatedPublicationTracker,
}

impl AuthenticatedStartupEvaluator {
    fn new(host: &crate::host::Host) -> Self {
        let session = host
            .mint_armed_session_token()
            .expect("mint authenticated startup session");
        let sequence = ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())
            .expect("create authenticated startup submission sequence");
        Self {
            session,
            sequence,
            publications: AuthenticatedPublicationTracker::default(),
        }
    }

    async fn eval_string(
        &mut self,
        engine: &HermesEngine,
        source: &str,
    ) -> anyhow::Result<Option<String>> {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};

        let context = "authenticated startup source";
        self.publications.drain(engine, context)?;
        let request = self
            .sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })?
            .authorize_inline()
            .bind_bytes(source.as_bytes().to_vec())
            .into_request()?;
        let ordinal = request.submission_ordinal();
        let evaluation = engine
            .evaluate_authenticated(&self.session, request)
            .await
            .with_context(|| {
                format!(
                    "evaluate authenticated startup submission {ordinal} ({})",
                    source.chars().take(80).collect::<String>()
                )
            });
        let publications = self.publications.drain(engine, context);
        let evaluation = evaluation?;
        publications?;
        match evaluation {
            AuthenticatedEvaluation::Empty => Ok(None),
            AuthenticatedEvaluation::Value { display, receipt } => {
                let release = engine
                    .release_undisplayed_value(
                        receipt.expect("startup value must retain a receipt"),
                    )
                    .await
                    .context("release authenticated startup value");
                let publications = self
                    .publications
                    .drain(engine, "authenticated startup value release");
                release?;
                publications?;
                anyhow::ensure!(
                    display.kind == AuthenticatedDisplayKind::String,
                    "authenticated startup evaluation returned {:?}, expected a string",
                    display.kind
                );
                Ok(Some(serde_json::from_str(&display.text)?))
            }
            AuthenticatedEvaluation::Throw(thrown) => {
                anyhow::bail!("authenticated startup source threw: {thrown:?}")
            }
            AuthenticatedEvaluation::Cancelled => {
                anyhow::bail!("authenticated startup source was cancelled")
            }
            AuthenticatedEvaluation::Lifecycle(code) => {
                anyhow::bail!("authenticated startup source exited with lifecycle code {code}")
            }
        }
    }

    async fn drive_event_loop(
        &mut self,
        engine: &HermesEngine,
        context: &str,
    ) -> anyhow::Result<()> {
        self.publications.drain(engine, context)?;
        let drive = engine
            .drive_event_loop()
            .await
            .with_context(|| format!("drive {context} to quiescence"));
        let publications = self.publications.drain(engine, context);
        drive?;
        publications?;
        Ok(())
    }

    fn finish(&mut self, engine: &HermesEngine, context: &str) -> anyhow::Result<()> {
        self.publications.drain(engine, context)?;
        self.publications.require_no_due_schedules(context)
    }
}

async fn eval_overlay_json(
    evaluator: &mut AuthenticatedStartupEvaluator,
    engine: &HermesEngine,
    expression: &str,
) -> serde_json::Value {
    let encoded = evaluator
        .eval_string(engine, &format!("JSON.stringify({expression})"))
        .await
        .expect("execute authenticated principal-overlay expression")
        .expect("principal-overlay expression returned no value");
    serde_json::from_str(&encoded).expect("principal-overlay expression returned invalid JSON")
}

fn assert_overlay_decision_stages(
    decisions: &[serde_json::Value],
    actor: &capsec_semantics::model::Principal,
    variant: &str,
    action: &str,
    name: &str,
    outcome: &str,
    expected_stages: &[&str],
) {
    let actor = serde_json::to_value(actor).expect("serialize overlay decision actor");
    let prefix = format!("environment-{variant}:");
    let expected_stage_set = expected_stages.iter().copied().collect::<BTreeSet<_>>();
    let mut stages = decisions
        .iter()
        .filter(|decision| {
            decision["decisionSet"]["context"]["actor"] == actor
                && decision["decisionSet"]["operationId"]
                    .as_str()
                    .is_some_and(|operation| operation.starts_with(&prefix))
                && decision["decisionSet"]["effects"][0]["cap"] == action
                && decision["decisionSet"]["effects"][0]["resource"]["requested"]["name"] == name
        })
        .map(|decision| {
            assert_eq!(
                decision["evidence"]["outcome"], outcome,
                "matching overlay operation carried an opposite outcome: {decision}"
            );
            assert_eq!(
                decision["decisionSet"]["effects"][0]["resource"]["requested"]["target"],
                "principal-overlay"
            );
            assert_eq!(
                decision["decisionSet"]["effects"][0]["resource"]["valueOrigin"],
                "principal-overlay"
            );
            assert!(decision["decisionSet"]["context"]["constrainedPrincipals"]
                .as_array()
                .is_some_and(|principals| principals.contains(&actor)));
            let stage = decision["decisionSet"]["context"]["stage"]
                .as_str()
                .expect("overlay decision stage must be a string");
            assert!(
                expected_stage_set.contains(stage),
                "matching overlay operation carried unexpected stage {stage}: {decision}"
            );
            stage.to_owned()
        })
        .collect::<Vec<_>>();
    stages.sort();
    stages.dedup();
    let mut expected = expected_stages
        .iter()
        .map(|stage| (*stage).to_owned())
        .collect::<Vec<_>>();
    expected.sort();
    expected.dedup();
    assert_eq!(
        stages, expected,
        "unexpected {outcome} stages for {actor:?} {variant} {action} {name}: {decisions:#?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn loaded_hermes_isolates_principal_environment_overlays() {
    let _lock = hermes_engine_test_lock().lock().await;
    let fixture = prepare_two_package_overlay_fixture();
    let (host, snapshot_digest) = build_two_package_overlay_host(&fixture);
    // One Host owns one authenticated session token and monotonic submission
    // sequence, so a fresh runtime needs a fresh Host whose first ordinal is 1.
    // Reuse the exact immutable snapshot object to hold every policy, graph,
    // and run-nonce input constant while proving that native overlay state does
    // not survive the runtime boundary.
    // @ref LLP 0024#1-the-in-memory-source-api — each runtime receives one
    // serialized authenticated submission stream.
    let second_engine_host = unsafe {
        crate::host::Host::new_armed_for_test(
            crate::host::HostConfig {
                mode: crate::host::SecurityMode::Enforce,
                ..Default::default()
            },
            host.armed_snapshot()
                .expect("principal-overlay Host must retain its armed snapshot")
                .clone(),
        )
    }
    .expect("create a fresh Host over the same principal-overlay snapshot");
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;

    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest loaded Hermes before principal-overlay test");
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create armed principal-overlay engine");
    engine
        .load_runtime()
        .await
        .expect("load armed principal-overlay runtime");
    let mut overlay = AuthenticatedStartupEvaluator::new(&host);
    assert_eq!(
        overlay
            .eval_string(
                &engine,
                "(function(){require('env-alpha');require('env-beta');return 'ready';})()",
            )
            .await
            .expect("preload principal-overlay packages")
            .as_deref(),
        Some("ready")
    );

    let observation = "loaded-hermes-principal-environment-overlays";
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(observation),
        "install principal-overlay observation"
    );
    let sync = eval_overlay_json(
        &mut overlay,
        &engine,
        &format!(
            r#"(function() {{
  var alpha = require('env-alpha');
  var beta = require('env-beta');
  var result = {{
    alphaMetadata: alpha.metadata(),
    betaMetadata: beta.metadata(),
    betaBefore: beta.read({shared:?}),
    alphaSetShared: alpha.set({shared:?}, 'alpha-value'),
    alphaAfterAlpha: alpha.read({shared:?}),
    betaAfterAlpha: beta.read({shared:?}),
    betaSetShared: beta.set({shared:?}, 'beta-value'),
    alphaAfterBeta: alpha.read({shared:?}),
    betaAfterBeta: beta.read({shared:?}),
    alphaSetWriteOnly: alpha.set({write_only:?}, 'write-only-value'),
    alphaReadWriteOnly: alpha.read({write_only:?}),
    alphaKeysAfterWriteOnly: alpha.keys(),
    alphaReadOnlyBefore: alpha.read({read_only:?}),
    alphaSetReadOnly: alpha.set({read_only:?}, 'forbidden-value'),
    alphaDeleteReadOnly: alpha.remove({read_only:?}),
    alphaReadOnlyAfter: alpha.read({read_only:?})
  }};
  return result;
}})()"#,
            shared = OVERLAY_SHARED_NAME,
            write_only = OVERLAY_WRITE_ONLY_NAME,
            read_only = OVERLAY_READ_ONLY_NAME,
        ),
    )
    .await;

    for metadata in [&sync["alphaMetadata"], &sync["betaMetadata"]] {
        assert_eq!(metadata["processType"], "object", "{metadata}");
        assert_eq!(metadata["requiredProcessEnvIdentity"], true, "{metadata}");
        assert_eq!(metadata["rawSetterType"], "undefined", "{metadata}");
        assert_eq!(metadata["globalRawSetterType"], "undefined", "{metadata}");
        assert_eq!(metadata["rawSetterInGlobal"], false, "{metadata}");
        assert_eq!(metadata["rawSetterOwnGlobal"], false, "{metadata}");
    }
    assert_eq!(sync["alphaMetadata"]["label"], "alpha");
    assert_eq!(sync["betaMetadata"]["label"], "beta");
    assert_eq!(
        sync["betaBefore"],
        serde_json::json!({"present": false, "value": null})
    );
    assert_eq!(
        sync["alphaSetShared"],
        serde_json::json!({"ok": true, "value": true})
    );
    assert_eq!(
        sync["alphaAfterAlpha"],
        serde_json::json!({"present": true, "value": "alpha-value"})
    );
    assert_eq!(
        sync["betaAfterAlpha"],
        serde_json::json!({"present": false, "value": null})
    );
    assert_eq!(
        sync["betaSetShared"],
        serde_json::json!({"ok": true, "value": true})
    );
    assert_eq!(
        sync["alphaAfterBeta"],
        serde_json::json!({"present": true, "value": "alpha-value"})
    );
    assert_eq!(
        sync["betaAfterBeta"],
        serde_json::json!({"present": true, "value": "beta-value"})
    );
    assert_eq!(
        sync["alphaSetWriteOnly"],
        serde_json::json!({"ok": true, "value": true})
    );
    assert_eq!(
        sync["alphaReadWriteOnly"],
        serde_json::json!({"present": false, "value": null})
    );
    assert_eq!(
        sync["alphaKeysAfterWriteOnly"],
        serde_json::json!([OVERLAY_SHARED_NAME])
    );
    assert_eq!(
        sync["alphaReadOnlyBefore"],
        serde_json::json!({"present": false, "value": null})
    );
    assert_eq!(sync["alphaSetReadOnly"]["ok"], false, "{sync}");
    assert!(sync["alphaSetReadOnly"]["error"]
        .as_str()
        .is_some_and(|error| error.contains("env:write authority required")));
    assert_eq!(sync["alphaDeleteReadOnly"]["ok"], false, "{sync}");
    assert!(sync["alphaDeleteReadOnly"]["error"]
        .as_str()
        .is_some_and(|error| error.contains("env:write authority required")));
    assert_eq!(
        sync["alphaReadOnlyAfter"],
        serde_json::json!({"present": false, "value": null})
    );

    assert_eq!(
        overlay
            .eval_string(
                &engine,
                &format!(
                    r#"globalThis.__overlayAsyncResult = null;
require('env-alpha').scheduleAsync({:?}, 'async-alpha', function(result) {{
  globalThis.__overlayAsyncResult = result;
}});
'scheduled'"#,
                    OVERLAY_ASYNC_NAME,
                ),
            )
            .await
            .expect("schedule package-owned environment mutation")
            .as_deref(),
        Some("scheduled")
    );
    overlay
        .drive_event_loop(&engine, "package-owned environment mutation")
        .await
        .expect("drive package-owned environment mutation");
    let async_result =
        eval_overlay_json(&mut overlay, &engine, "globalThis.__overlayAsyncResult").await;
    assert_eq!(
        async_result,
        serde_json::json!({
            "ok": true,
            "result": {"present": true, "value": "async-alpha"},
            "keys": [OVERLAY_ASYNC_NAME, OVERLAY_SHARED_NAME],
        })
    );
    let after_async = eval_overlay_json(
        &mut overlay,
        &engine,
        &format!(
            r#"(function() {{
  var alpha = require('env-alpha');
  var beta = require('env-beta');
  return {{
    alphaAsync: alpha.read({async_name:?}),
    betaAsync: beta.read({async_name:?}),
    alphaKeys: alpha.keys(),
    betaKeys: beta.keys()
  }};
}})()"#,
            async_name = OVERLAY_ASYNC_NAME,
        ),
    )
    .await;
    assert_eq!(
        after_async["alphaAsync"],
        serde_json::json!({"present": true, "value": "async-alpha"})
    );
    assert_eq!(
        after_async["betaAsync"],
        serde_json::json!({"present": false, "value": null})
    );
    assert_eq!(
        after_async["alphaKeys"],
        serde_json::json!([OVERLAY_ASYNC_NAME, OVERLAY_SHARED_NAME])
    );
    assert_eq!(
        after_async["betaKeys"],
        serde_json::json!([OVERLAY_SHARED_NAME])
    );

    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(
        legacy.is_empty(),
        "principal-overlay path consulted legacy policy"
    );
    let decisions = typed_decision_values(observation, typed);
    assert_overlay_decision_stages(
        &decisions,
        &fixture.alpha.principal,
        "write",
        "env:write",
        OVERLAY_SHARED_NAME,
        "allow",
        &["requested", "commit"],
    );
    assert_overlay_decision_stages(
        &decisions,
        &fixture.beta.principal,
        "write",
        "env:write",
        OVERLAY_SHARED_NAME,
        "allow",
        &["requested", "commit"],
    );
    assert_overlay_decision_stages(
        &decisions,
        &fixture.alpha.principal,
        "write",
        "env:write",
        OVERLAY_WRITE_ONLY_NAME,
        "allow",
        &["requested", "commit"],
    );
    assert_overlay_decision_stages(
        &decisions,
        &fixture.alpha.principal,
        "read",
        "env:read",
        OVERLAY_WRITE_ONLY_NAME,
        "deny",
        &["requested"],
    );
    assert_overlay_decision_stages(
        &decisions,
        &fixture.alpha.principal,
        "read",
        "env:read",
        OVERLAY_READ_ONLY_NAME,
        "allow",
        &["requested", "commit"],
    );
    assert_overlay_decision_stages(
        &decisions,
        &fixture.alpha.principal,
        "write",
        "env:write",
        OVERLAY_READ_ONLY_NAME,
        "deny",
        &["requested"],
    );
    assert_overlay_decision_stages(
        &decisions,
        &fixture.alpha.principal,
        "enumerate",
        "env:read",
        OVERLAY_SHARED_NAME,
        "allow",
        &["requested", "commit"],
    );
    assert_overlay_decision_stages(
        &decisions,
        &fixture.alpha.principal,
        "enumerate",
        "env:read",
        OVERLAY_WRITE_ONLY_NAME,
        "deny",
        &["requested"],
    );
    assert_overlay_decision_stages(
        &decisions,
        &fixture.alpha.principal,
        "write",
        "env:write",
        OVERLAY_ASYNC_NAME,
        "allow",
        &["requested", "commit"],
    );
    assert_overlay_decision_stages(
        &decisions,
        &fixture.alpha.principal,
        "read",
        "env:read",
        OVERLAY_ASYNC_NAME,
        "allow",
        &["requested", "commit"],
    );

    overlay
        .finish(&engine, "principal-overlay first runtime")
        .expect("finish first principal-overlay runtime publications");
    drop(overlay);
    drop(engine);
    assert_ne!(
        crate::host::abi::install_host(second_engine_host.clone()),
        0,
        "install the fresh Host over the same immutable snapshot"
    );
    let fresh = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create second armed principal-overlay engine");
    fresh
        .load_runtime()
        .await
        .expect("load second armed principal-overlay runtime");
    let mut fresh_overlay = AuthenticatedStartupEvaluator::new(&second_engine_host);
    let cleared = eval_overlay_json(
        &mut fresh_overlay,
        &fresh,
        &format!(
            r#"(function() {{
  var alpha = require('env-alpha');
  var beta = require('env-beta');
  return {{
    alphaShared: alpha.read({shared:?}),
    betaShared: beta.read({shared:?}),
    alphaAsync: alpha.read({async_name:?}),
    betaAsync: beta.read({async_name:?}),
    alphaKeys: alpha.keys(),
    betaKeys: beta.keys(),
    identity: alpha.metadata().requiredProcessEnvIdentity,
    rawSetterType: alpha.metadata().rawSetterType
  }};
}})()"#,
            shared = OVERLAY_SHARED_NAME,
            async_name = OVERLAY_ASYNC_NAME,
        ),
    )
    .await;
    for field in ["alphaShared", "betaShared", "alphaAsync", "betaAsync"] {
        assert_eq!(
            cleared[field],
            serde_json::json!({"present": false, "value": null})
        );
    }
    assert_eq!(cleared["alphaKeys"], serde_json::json!([]));
    assert_eq!(cleared["betaKeys"], serde_json::json!([]));
    assert_eq!(cleared["identity"], true);
    assert_eq!(cleared["rawSetterType"], "undefined");
    fresh_overlay
        .finish(&fresh, "principal-overlay fresh runtime")
        .expect("finish fresh principal-overlay runtime publications");

    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest loaded Hermes after principal-overlay test");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify loaded Hermes after principal-overlay test");
}
