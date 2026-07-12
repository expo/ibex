use super::*;
use base64::Engine as _;
use clap::Parser as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
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
    edge_ids: Vec<String>,
    action_ids: Vec<String>,
    terminal_observed_key: String,
    expected_observation: serde_json::Value,
    public_surface_probe: Option<serde_json::Value>,
    status: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClosedSurfaceProbe {
    kind: String,
    surface_observed_key: String,
    command: Vec<String>,
    invocation: ClosedSurfaceInvocation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClosedSurfaceInvocation {
    invocation_schema: String,
    kind: String,
    surface_kind: String,
    surface_name: String,
    source_descriptor: ClosedSourceDescriptor,
    source_descriptor_digest: String,
    operation: ClosedOperation,
    expected_result: String,
    expected_typed_decision_count: usize,
    expected_typed_stages: Vec<String>,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClosedSourceDescriptor {
    kind: String,
    environment_name: String,
    source_refs: Vec<String>,
    source_metadata: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum ClosedOperation {
    StartupEnvironment {
        #[serde(rename = "environmentName")]
        environment_name: String,
    },
}

impl ClosedOperation {
    fn kind(&self) -> &'static str {
        match self {
            Self::StartupEnvironment { .. } => "startup-environment",
        }
    }

    fn environment_name(&self) -> &str {
        match self {
            Self::StartupEnvironment { environment_name } => environment_name,
        }
    }
}

const CLOSED_BATCH_COMMAND: [&str; 9] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--features",
    "capsec-conformance-observer",
    "capsec_public_closed_recipe_batch",
    "--",
    "--test-threads=1",
];

fn tagged_jcs_digest(value: &serde_json::Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("closed-surface evidence must have canonical JSON bytes");
    let digest = sha2::Sha256::digest(bytes);
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

fn tagged_value_digest<T: Serialize>(value: &T) -> String {
    tagged_jcs_digest(&serde_json::to_value(value).expect("closed-surface value must serialize"))
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

fn closed_surface_probe(recipe: &Recipe) -> Option<ClosedSurfaceProbe> {
    let value = recipe.public_surface_probe.as_ref()?;
    if value["invocation"]["invocationSchema"]
        != "ibex/capsec-closed-surface-invocation/1"
    {
        return None;
    }
    Some(
        serde_json::from_value(value.clone())
            .expect("closed public probe must match its typed schema"),
    )
}

struct ClosedEnvironmentRestore(Vec<(String, Option<OsString>)>);

impl ClosedEnvironmentRestore {
    fn clear() -> Self {
        let values = ibex_runtime::capsec_registry_generated::CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES
            .iter()
            .map(|name| ((*name).to_owned(), std::env::var_os(name)))
            .collect::<Vec<_>>();
        for name in ibex_runtime::capsec_registry_generated::CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES {
            std::env::remove_var(name);
        }
        Self(values)
    }
}

impl Drop for ClosedEnvironmentRestore {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

async fn attest_exact_engine() {
    let (host, snapshot_digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |_| {});
    assert_ne!(crate::host::abi::install_host(host), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create exact closed-surface attestation engine");
    engine
        .load_runtime()
        .await
        .expect("load exact closed-surface attestation runtime");
    assert_eq!(
        engine
            .eval_immediate("'IBEX_CAPSEC_CLOSED_BATCH_ENGINE_EXECUTED'")
            .await
            .expect("execute closed-surface engine marker")
            .as_deref(),
        Some("IBEX_CAPSEC_CLOSED_BATCH_ENGINE_EXECUTED")
    );
}

async fn execute_closed_startup_environment(
    recipe: &Recipe,
    probe: &ClosedSurfaceProbe,
    coverage: &BTreeMap<String, (String, String)>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let invocation = &probe.invocation;
    let environment_name = invocation.operation.environment_name();
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "closed");
    assert_eq!(recipe.scenario, "closed");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(
        probe
            .command
            .iter()
            .map(String::as_str)
            .eq(CLOSED_BATCH_COMMAND)
    );
    assert_eq!(invocation.invocation_schema, "ibex/capsec-closed-surface-invocation/1");
    assert_eq!(invocation.kind, "closed-surface");
    assert_eq!(invocation.surface_kind, "startup");
    assert_eq!(invocation.surface_name, format!("env:{environment_name}"));
    assert_eq!(invocation.expected_result, "closed");
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert!(invocation.allowed_coverage_edge_ids.is_empty());
    assert!(invocation.expected_action_ids.is_empty());
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_value_digest(&invocation.source_descriptor)
    );
    let descriptor = &invocation.source_descriptor;
    assert_eq!(descriptor.kind, "closed-startup-environment");
    assert_eq!(descriptor.environment_name, environment_name);
    assert!(!descriptor.source_refs.is_empty());
    assert_eq!(
        descriptor.source_metadata["evidenceType"],
        "static-runtime-environment-control"
    );
    assert_eq!(
        descriptor.source_metadata["authoredNames"],
        serde_json::json!([environment_name])
    );
    assert!(
        ibex_runtime::capsec_registry_generated::CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES
            .contains(&environment_name),
        "closed startup recipe is not in the generated production reject set"
    );
    let (surface_kind, surface_name) = coverage
        .get(&recipe.edge_ids[0])
        .expect("closed recipe names an unknown coverage edge");
    assert_eq!(surface_kind, &invocation.surface_kind);
    assert_eq!(surface_name, &invocation.surface_name);
    let terminal_observed_key = format!("{surface_kind}:{surface_name}");
    assert_eq!(terminal_observed_key, recipe.terminal_observed_key);
    assert_eq!(terminal_observed_key, probe.surface_observed_key);

    crate::host::abi::install_host(crate::host::Host::strict());
    let session_id = format!("public-observation:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(
        &session_id
    ));
    std::env::set_var(environment_name, "");
    let missing_root = std::env::temp_dir().join(format!(
        "ibex-capsec-closed-missing-{}",
        recipe.plan_digest.trim_start_matches("sha256-")
    ));
    let cli = crate::cli::Cli::parse_from([
        OsString::from("ibex"),
        OsString::from("--capsec-armed-snapshot"),
        missing_root.join("snapshot.json").into_os_string(),
        OsString::from("--capsec-arming-identity"),
        missing_root.join("identity.json").into_os_string(),
        missing_root.join("project-code.js").into_os_string(),
    ]);
    let error = crate::run(cli)
        .await
        .expect_err("closed startup environment reached the production entry")
        .to_string();
    std::env::remove_var(environment_name);
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(
        error.contains("production capability startup rejects closed environment controls")
            && error.contains(environment_name),
        "closed startup control produced the wrong error: {error}"
    );
    assert!(
        !error.contains("failed to read") && !error.contains("project-code"),
        "closed startup control reached artifact I/O or project code: {error}"
    );
    assert!(legacy.is_empty());
    assert!(typed.is_empty());

    let result = serde_json::json!({
        "kind": "closed",
        "surfaceKind": surface_kind,
        "surfaceName": surface_name,
        "mechanism": invocation.operation.kind(),
        "errorName": "ClosedSurface",
        "errorMessage": error,
        "engineExecuted": false,
        "projectCodeExecuted": false,
    });
    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": invocation.invocation_schema,
            "kind": invocation.kind,
            "surfaceObservedKey": terminal_observed_key,
            "surfaceKind": surface_kind,
            "surfaceName": surface_name,
            "sourceDescriptorDigest": invocation.source_descriptor_digest,
            "result": result,
        },
        "legacyObservationCount": legacy.len(),
        "typedDecisions": [],
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected closed observation must be an object")
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
        "executor": "ibex-closed-public-surface-harness",
        "evidence": evidence,
    })
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_public_closed_recipe_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping closed public batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT")
        .expect("closed public batch requires an owned evidence output path");
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let recipe_indexes = catalog
        .recipes
        .iter()
        .enumerate()
        .filter_map(|(index, recipe)| closed_surface_probe(recipe).map(|_| index))
        .collect::<Vec<_>>();
    assert_eq!(
        recipe_indexes.len(),
        ibex_runtime::capsec_registry_generated::CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES.len(),
        "expected every generated closed startup environment control"
    );
    assert_eq!(recipe_indexes.len(), 19);
    let _lock = hermes_engine_test_lock().lock().await;
    let _environment_restore = ClosedEnvironmentRestore::clear();
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before closed public recipes");
    attest_exact_engine().await;
    let coverage = coverage_terminals();
    let mut executions = Vec::with_capacity(recipe_indexes.len());
    for index in recipe_indexes {
        let recipe = &catalog.recipes[index];
        let probe = closed_surface_probe(recipe).unwrap();
        executions.push(
            execute_closed_startup_environment(
                recipe,
                &probe,
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
        .expect("attest exact loaded Hermes after closed public recipes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after closed public recipes");
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
        .expect("create owned closed public evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize closed public evidence artifact");
    output
        .write_all(b"\n")
        .expect("finish closed public evidence artifact");
    output
        .sync_all()
        .expect("sync closed public evidence artifact");
}
