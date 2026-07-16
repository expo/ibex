use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
#[cfg(not(feature = "host-http-server"))]
use std::io::Write as _;

// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — each
// startup claim creates a fresh armed runtime from the mapped Hermes artifact,
// checks its source-bound postcondition, then proves project code can execute.

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
    action_ids: Vec<String>,
    terminal_observed_key: String,
    expected_observation: serde_json::Value,
    public_surface_probe: Option<serde_json::Value>,
    status: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartupProbe {
    kind: String,
    surface_observed_key: String,
    command: Vec<String>,
    invocation: StartupInvocation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartupInvocation {
    invocation_schema: String,
    kind: String,
    surface_kind: String,
    surface_name: String,
    source_descriptor: StartupSourceDescriptor,
    source_descriptor_digest: String,
    operation: StartupOperation,
    expected_result: String,
    expected_typed_decision_count: usize,
    expected_typed_stages: Vec<String>,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartupSourceDescriptor {
    kind: String,
    surface_name: String,
    postcondition: String,
    required_facts: Vec<String>,
    source_refs: Vec<String>,
    source_metadata: serde_json::Value,
    environment: Option<StartupEnvironment>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct StartupEnvironment {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartupOperation {
    kind: String,
    postcondition: String,
    required_facts: Vec<String>,
    environment: Option<StartupEnvironment>,
}

struct ExpectedStartupStage {
    surface_name: &'static str,
    postcondition: &'static str,
    source_ref: &'static str,
    required_facts: &'static [&'static str],
    environment: Option<(&'static str, &'static str)>,
}

const STARTUP_BATCH_COMMAND: [&str; 9] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--features",
    "capsec-conformance-observer",
    "capsec_public_startup_batch",
    "--",
    "--test-threads=1",
];

const STARTUP_STAGES: [ExpectedStartupStage; 10] = [
    ExpectedStartupStage {
        surface_name: "runtime-create",
        postcondition: "runtime-created",
        source_ref: "src/engine/hermes_runtime.cc#ex_hermes_create_armed",
        required_facts: &["engine-can-evaluate"],
        environment: None,
    },
    ExpectedStartupStage {
        surface_name: "globals-install",
        postcondition: "globals-installed",
        source_ref: "src/engine/hermes_runtime.cc#installGlobals",
        required_facts: &["console-installed", "timers-installed"],
        environment: None,
    },
    ExpectedStartupStage {
        surface_name: "module-loader-install",
        postcondition: "module-loader-installed",
        source_ref: "src/engine/hermes_bootstrap.cc#installModuleLoader",
        required_facts: &["module-loader-installed"],
        environment: None,
    },
    ExpectedStartupStage {
        surface_name: "shared-runtime-install",
        postcondition: "shared-runtime-installed",
        source_ref: "src/engine/hermes_bootstrap.cc#installSharedRuntimeBundle",
        required_facts: &["shared-runtime-loaded"],
        environment: None,
    },
    ExpectedStartupStage {
        surface_name: "capability-hardening-seal",
        postcondition: "capability-hatches-sealed",
        source_ref: "src/engine/hermes_runtime.cc#kCapabilityHardeningJS",
        required_facts: &["capability-hatches-absent"],
        environment: None,
    },
    ExpectedStartupStage {
        surface_name: "eager-native-seal",
        postcondition: "lazy-installers-sealed",
        source_ref: "src/engine/hermes_runtime.cc#kEagerInstallSealJS",
        required_facts: &["lazy-installers-absent"],
        environment: None,
    },
    ExpectedStartupStage {
        surface_name: "lockdown-install",
        postcondition: "lockdown-installed",
        source_ref: "src/engine/hermes_runtime.cc#lockdownJS",
        required_facts: &[
            "lockdown-flag-pinned",
            "eval-tamed",
            "object-prototype-frozen",
        ],
        environment: None,
    },
    ExpectedStartupStage {
        surface_name: "freeze-seal",
        postcondition: "freeze-hatches-sealed",
        source_ref: "src/engine/hermes_runtime.cc#kFreezeSealJS",
        required_facts: &["freeze-hatches-absent"],
        environment: None,
    },
    ExpectedStartupStage {
        surface_name: "compartment-registry-install",
        postcondition: "compartment-registry-installed",
        source_ref: "src/engine/hermes_runtime.cc#kCompartmentRegistryJS",
        required_facts: &["compartment-registry-pinned"],
        environment: None,
    },
    ExpectedStartupStage {
        surface_name: "web-streams-install",
        postcondition: "web-streams-installed",
        source_ref: "src/engine/hermes_bootstrap.cc#installWebStreamsPolyfill",
        required_facts: &["web-stream-constructors-installed"],
        environment: Some(("EX_WEB_STREAMS_POLYFILL", "1")),
    },
];

fn expected_stage(surface_name: &str) -> &'static ExpectedStartupStage {
    STARTUP_STAGES
        .iter()
        .find(|stage| stage.surface_name == surface_name)
        .unwrap_or_else(|| panic!("unreviewed startup surface {surface_name}"))
}

fn tagged_jcs_digest(value: &serde_json::Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("startup evidence must have canonical JSON bytes");
    let digest = sha2::Sha256::digest(bytes);
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

fn tagged_value_digest<T: Serialize>(value: &T) -> String {
    tagged_jcs_digest(&serde_json::to_value(value).expect("startup value must serialize"))
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

fn coverage_terminals() -> BTreeMap<String, (String, String)> {
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
            let id = edge["id"].as_str().expect("coverage edge has no id");
            let kind = edge["surface"]["kind"]
                .as_str()
                .expect("coverage edge has no surface kind");
            let name = edge["surface"]["name"]
                .as_str()
                .expect("coverage edge has no surface name");
            (id.to_owned(), (kind.to_owned(), name.to_owned()))
        })
        .collect()
}

fn startup_probe(recipe: &Recipe) -> Option<StartupProbe> {
    let value = recipe.public_surface_probe.as_ref()?;
    if value["invocation"]["invocationSchema"]
        != "ibex/capsec-startup-surface-invocation/1"
    {
        return None;
    }
    Some(
        serde_json::from_value(value.clone())
            .expect("startup public probe must match its typed schema"),
    )
}

#[cfg(test)]
struct StartupEnvironmentRestore(Vec<(String, Option<OsString>)>);

#[cfg(test)]
impl StartupEnvironmentRestore {
    fn configure(environment: Option<&StartupEnvironment>) -> Self {
        let mut names = ibex_runtime::capsec_registry_generated::CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        names.extend([
            "IBEX_POLICY",
            "EXACT_POLICY",
            "EX_WEB_STREAMS_POLYFILL",
        ]);
        let values = names
            .iter()
            .map(|name| ((*name).to_owned(), std::env::var_os(name)))
            .collect::<Vec<_>>();
        for name in names {
            std::env::remove_var(name);
        }
        if let Some(environment) = environment {
            std::env::set_var(&environment.name, &environment.value);
        }
        Self(values)
    }
}

#[cfg(test)]
impl Drop for StartupEnvironmentRestore {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

fn startup_postcondition_script(postcondition: &str, marker: &str) -> String {
    let facts = match postcondition {
        "runtime-created" => r#"{"engine-can-evaluate": true}"#,
        "globals-installed" => r#"{
          "console-installed": typeof globalThis.console === "object" &&
            typeof globalThis.console.log === "function",
          "timers-installed": typeof globalThis.setTimeout === "function" &&
            typeof globalThis.clearTimeout === "function" &&
            typeof globalThis.setInterval === "function" &&
            typeof globalThis.clearInterval === "function"
        }"#,
        "module-loader-installed" => r#"{
          "module-loader-installed": typeof globalThis.require === "function" &&
            typeof globalThis.require.resolve === "function"
        }"#,
        "shared-runtime-installed" => r#"{
          "shared-runtime-loaded": globalThis.__exactRuntimeLoaded === true
        }"#,
        "capability-hatches-sealed" => r#"{
          "capability-hatches-absent": [
            "__exactSetActiveModuleId", "__exactGrantCapability",
            "__exactSetPendingPackageId", "__exactRegisterPackage",
            "__exactCheckImport", "__exactSetCompartmentFor",
            "__exactResolveManifestBuiltinInternal"
          ].every(function (name) { return typeof globalThis[name] === "undefined"; }) &&
            (!globalThis.Exact ||
              typeof globalThis.Exact.setModuleCapabilities === "undefined")
        }"#,
        "lazy-installers-sealed" => r#"{
          "lazy-installers-absent": [
            "__exactEnsureFs", "__exactEnsureHttp", "__exactEnsureSqlite",
            "__exactEnsureDns", "__exactEnsureChildProcess", "__exactEnsureNet",
            "__exactEnsureStreamEnhance", "__exactEnsureWebCrypto",
            "__exactEnsureWebStorage", "__exactEnsureFormData"
          ].every(function (name) { return typeof globalThis[name] === "undefined"; })
        }"#,
        "lockdown-installed" => r#"(function () {
          var descriptor = Object.getOwnPropertyDescriptor(
            globalThis, "__ibexLockedDown"
          );
          return {
            "lockdown-flag-pinned": descriptor !== undefined &&
              descriptor.value === true && descriptor.writable === false &&
              descriptor.configurable === false,
            "eval-tamed": typeof globalThis.eval === "function" &&
              globalThis.eval.__ibexTamed === true,
            "object-prototype-frozen": Object.isFrozen(Object.prototype)
          };
        })()"#,
        "freeze-hatches-sealed" => r#"{
          "freeze-hatches-absent":
            typeof globalThis.__exactDeepFreeze === "undefined" &&
            typeof globalThis.__exactNativeFreeze === "undefined"
        }"#,
        "compartment-registry-installed" => r#"(function () {
          var descriptor = Object.getOwnPropertyDescriptor(
            globalThis, "__compartments"
          );
          var registry = descriptor && descriptor.value;
          return {
            "compartment-registry-pinned": descriptor !== undefined &&
              descriptor.writable === false && descriptor.configurable === false &&
              registry !== null && typeof registry === "object" &&
              registry["ibex-startup-probe-a"] !==
                registry["ibex-startup-probe-b"] &&
              registry["ibex-startup-probe-a"].process === undefined
          };
        })()"#,
        "web-streams-installed" => r#"{
          "web-stream-constructors-installed":
            typeof globalThis.ReadableStream === "function" &&
            typeof globalThis.WritableStream === "function" &&
            typeof globalThis.TransformStream === "function"
        }"#,
        other => panic!("unreviewed startup postcondition {other}"),
    };
    let marker = serde_json::to_string(marker).expect("serialize startup project marker");
    format!(
        r#"JSON.stringify((function (marker) {{
          globalThis.__IBEX_CAPSEC_STARTUP_PROJECT_MARKER__ = marker;
          var observedFacts = {facts};
          var projectCodeExecuted =
            globalThis.__IBEX_CAPSEC_STARTUP_PROJECT_MARKER__ === marker;
          try {{ delete globalThis.__IBEX_CAPSEC_STARTUP_PROJECT_MARKER__; }} catch (e) {{}}
          return {{
            observedFacts: observedFacts,
            projectCodeExecuted: projectCodeExecuted
          }};
        }})({marker}))"#
    )
}

fn assert_exact_fact_set(
    observed: &BTreeMap<String, bool>,
    expected: &ExpectedStartupStage,
) {
    assert_eq!(
        observed.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        expected.required_facts.iter().copied().collect(),
        "startup probe returned the wrong fact set"
    );
    assert!(
        expected
            .required_facts
            .iter()
            .all(|fact| observed.get(*fact) == Some(&true)),
        "startup postcondition was not satisfied: {observed:?}"
    );
}

async fn execute_startup_recipe(
    recipe: &Recipe,
    coverage: &BTreeMap<String, (String, String)>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let probe = startup_probe(recipe).expect("startup recipe has no typed probe");
    let invocation = &probe.invocation;
    let expected = expected_stage(&invocation.surface_name);
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "non-capability");
    assert_eq!(recipe.scenario, "non-capability");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(
        probe
            .command
            .iter()
            .map(String::as_str)
            .eq(STARTUP_BATCH_COMMAND)
    );
    assert_eq!(
        invocation.invocation_schema,
        "ibex/capsec-startup-surface-invocation/1"
    );
    assert_eq!(invocation.kind, "startup-loaded-engine");
    assert_eq!(invocation.surface_kind, "startup");
    assert_eq!(invocation.surface_name, expected.surface_name);
    assert_eq!(invocation.expected_result, "return");
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert!(invocation.allowed_coverage_edge_ids.is_empty());
    assert!(invocation.expected_action_ids.is_empty());
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_value_digest(&invocation.source_descriptor)
    );
    let descriptor = &invocation.source_descriptor;
    assert_eq!(descriptor.kind, "startup-loaded-engine-postcondition");
    assert_eq!(descriptor.surface_name, expected.surface_name);
    assert_eq!(descriptor.postcondition, expected.postcondition);
    assert_eq!(
        descriptor
            .required_facts
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected.required_facts
    );
    assert_eq!(descriptor.source_refs, [expected.source_ref]);
    assert!(descriptor.source_metadata.is_null());
    let expected_environment = expected.environment.map(|(name, value)| StartupEnvironment {
        name: name.to_owned(),
        value: value.to_owned(),
    });
    assert_eq!(descriptor.environment, expected_environment);
    assert_eq!(invocation.operation.kind, "loaded-engine-startup");
    assert_eq!(invocation.operation.postcondition, expected.postcondition);
    assert_eq!(
        invocation
            .operation
            .required_facts
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        expected.required_facts
    );
    assert_eq!(invocation.operation.environment, expected_environment);
    let (surface_kind, surface_name) = coverage
        .get(&recipe.edge_ids[0])
        .expect("startup recipe names an unknown coverage edge");
    assert_eq!(surface_kind, "startup");
    assert_eq!(surface_name, expected.surface_name);
    let terminal_observed_key = format!("{surface_kind}:{surface_name}");
    assert_eq!(terminal_observed_key, recipe.terminal_observed_key);
    assert_eq!(terminal_observed_key, probe.surface_observed_key);

    let _environment = StartupEnvironmentRestore::configure(
        invocation.operation.environment.as_ref(),
    );
    let (host, snapshot_digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |_| {});
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let session_id = format!("startup-observation:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(
        &session_id
    ));
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create exact startup probe engine");
    engine
        .load_runtime()
        .await
        .expect("load exact startup probe runtime");
    let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
    let encoded = evaluator
        .eval_string(
            &engine,
            &startup_postcondition_script(
            expected.postcondition,
            &recipe.plan_digest,
            ),
        )
        .await;
    let observed: serde_json::Value =
        serde_json::from_str(&encoded).expect("startup postcondition result must be JSON");
    let observed_facts: BTreeMap<String, bool> =
        serde_json::from_value(observed["observedFacts"].clone())
            .expect("startup observed facts must be booleans");
    assert_exact_fact_set(&observed_facts, expected);
    assert_eq!(observed["projectCodeExecuted"], true);
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());

    let result = serde_json::json!({
        "kind": "return",
        "surfaceKind": "startup",
        "surfaceName": expected.surface_name,
        "mechanism": "loaded-engine-startup",
        "postcondition": expected.postcondition,
        "engineExecuted": true,
        "projectCodeExecuted": true,
        "observedFacts": observed_facts,
    });
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": invocation.invocation_schema,
            "kind": invocation.kind,
            "surfaceObservedKey": terminal_observed_key,
            "surfaceKind": "startup",
            "surfaceName": expected.surface_name,
            "sourceDescriptorDigest": invocation.source_descriptor_digest,
            "result": result,
        },
        "legacyObservationCount": legacy.len(),
        "typedDecisions": [],
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected startup observation must be an object")
        .insert("result".into(), serde_json::Value::String("passed".into()));
    let mut evidence = serde_json::json!({
        "evidenceSchema": "ibex/capsec-public-surface-fixture-evidence/2",
        "fixtureId": recipe.fixture_id,
        "planDigest": recipe.plan_digest,
        "engineBinaryDigest": engine_binary_digest,
        "probe": probe,
        "terminalObservedKey": terminal_observed_key,
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
        "executor": "ibex-startup-public-surface-harness",
        "evidence": evidence,
    })
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_public_startup_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping startup public batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT")
        .expect("startup public batch requires an owned evidence output path");
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipe_indexes = catalog
        .recipes
        .iter()
        .enumerate()
        .filter_map(|(index, recipe)| startup_probe(recipe).map(|_| index))
        .collect::<Vec<_>>();
    assert_eq!(recipe_indexes.len(), STARTUP_STAGES.len());
    assert_eq!(
        recipe_indexes
            .iter()
            .map(|index| {
                startup_probe(&catalog.recipes[*index])
                    .unwrap()
                    .invocation
                    .surface_name
            })
            .collect::<BTreeSet<_>>(),
        STARTUP_STAGES
            .iter()
            .map(|stage| stage.surface_name.to_owned())
            .collect()
    );

    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before startup public recipes");
    let coverage = coverage_terminals();
    let mut executions = Vec::with_capacity(recipe_indexes.len());
    for index in recipe_indexes {
        executions.push(
            execute_startup_recipe(
                &catalog.recipes[index],
                &coverage,
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
    let identity_after = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes after startup public recipes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after startup public recipes");
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
        .expect("create owned startup public evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize startup public evidence artifact");
    output
        .write_all(b"\n")
        .expect("finish startup public evidence artifact");
    output
        .sync_all()
        .expect("sync startup public evidence artifact");
}
