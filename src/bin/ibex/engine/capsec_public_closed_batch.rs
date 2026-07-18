use super::*;
use base64::Engine as _;
use clap::{CommandFactory as _, Parser as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
#[cfg(not(feature = "host-http-server"))]
use std::io::Write as _;

extern "C" {
    fn ex_hermes_module_unpin_generation(
        runtime: *mut HermesRuntimeOpaque,
        runtime_nonce: u64,
        graph_generation: u64,
    ) -> i32;
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    environment_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    surface_observed_key: Option<String>,
    source_refs: Vec<String>,
    source_metadata: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    control_descriptor: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    global_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    member_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    engine_identity_review_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lockdown_taming_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    loader_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extension: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    export_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    module_specifiers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    function_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected_source_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_triple: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CliArgumentVector {
    spelling: String,
    args: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum ClosedOperation {
    StartupEnvironment {
        #[serde(rename = "environmentName")]
        environment_name: String,
    },
    CliControl {
        #[serde(rename = "argumentVectors")]
        argument_vectors: Vec<CliArgumentVector>,
        #[serde(rename = "expectedRejectionFragments")]
        expected_rejection_fragments: Vec<String>,
        #[serde(rename = "projectCodePlaceholder")]
        project_code_placeholder: String,
        #[serde(rename = "evaluationMarker")]
        evaluation_marker: String,
    },
    TamedEvaluator {
        #[serde(rename = "globalName")]
        global_name: String,
        #[serde(rename = "accessMode")]
        access_mode: String,
    },
    LoaderExecutableFile {
        #[serde(flatten)]
        _rejected_descriptor: BTreeMap<String, serde_json::Value>,
    },
    ExactUnendowedOperation {
        #[serde(rename = "contextKind")]
        context_kind: String,
        #[serde(rename = "operationManifestDigest")]
        operation_manifest_digest: String,
        #[serde(rename = "endowedOperationIds")]
        endowed_operation_ids: Vec<u32>,
        #[serde(rename = "selectedOperationId")]
        selected_operation_id: u32,
        #[serde(rename = "expectedError")]
        expected_error: String,
    },
    ModuleRunnerNamespace {
        #[serde(rename = "expectedError")]
        expected_error: String,
    },
    TerminalBuiltinImport {
        #[serde(rename = "terminalBuiltinRoot")]
        terminal_builtin_root: String,
        #[serde(rename = "moduleSpecifiers")]
        module_specifiers: Vec<String>,
        #[serde(rename = "expectedRejectionFragment")]
        expected_rejection_fragment: String,
    },
    DebuggerAbiDisabled {
        #[serde(rename = "functionName")]
        function_name: String,
        #[serde(rename = "expectedCallResult")]
        expected_call_result: String,
        #[serde(rename = "expectedError")]
        expected_error: String,
    },
    SharedRuntimeGlobalAbsence {
        #[serde(rename = "globalName")]
        global_name: String,
        #[serde(rename = "memberName")]
        member_name: Option<String>,
        #[serde(rename = "expectedError")]
        expected_error: String,
    },
}

impl ClosedOperation {
    fn kind(&self) -> &'static str {
        match self {
            Self::StartupEnvironment { .. } => "startup-environment",
            Self::CliControl { .. } => "cli-control",
            Self::TamedEvaluator { .. } => "tamed-evaluator",
            Self::LoaderExecutableFile { .. } => "loader-executable-file",
            Self::ExactUnendowedOperation { .. } => "exact-unendowed-operation",
            Self::ModuleRunnerNamespace { .. } => "module-runner-namespace",
            Self::TerminalBuiltinImport { .. } => "terminal-builtin-import",
            Self::DebuggerAbiDisabled { .. } => "debugger-abi-disabled",
            Self::SharedRuntimeGlobalAbsence { .. } => "shared-runtime-global-absence",
        }
    }

    fn environment_name(&self) -> Option<&str> {
        match self {
            Self::StartupEnvironment { environment_name } => Some(environment_name),
            Self::CliControl { .. }
            | Self::TamedEvaluator { .. }
            | Self::LoaderExecutableFile { .. }
            | Self::ExactUnendowedOperation { .. }
            | Self::ModuleRunnerNamespace { .. }
            | Self::TerminalBuiltinImport { .. }
            | Self::DebuggerAbiDisabled { .. } => None,
            Self::SharedRuntimeGlobalAbsence { .. } => None,
        }
    }
}

const CLOSED_BATCH_COMMAND: [&str; 9] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--features",
    "capsec-conformance-observer,openssl-crypto",
    "capsec_public_closed_recipe_batch",
    "--",
    "--test-threads=1",
];
const EXACT_OPERATION_MANIFEST_DIGEST: &str = "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA";
const EXACT_APP_OPERATION_IDS: [u32; 2] = [7, 11];
const EXACT_UNENDOWED_OPERATION_ID: u32 = 8;
const EXACT_UNENDOWED_ERROR: &str = "exact.invokeHostAsync operation is not endowed";

/// Test-only armed engine facade for closed terminal-builtin imports. Even a
/// refusal probe must enter through an authenticated submission and consume
/// the runtime's bounded work-unit publication stream.
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
/// @ref LLP 0025#11-delegated-obligations — OBL-UNIT-PUBLICATION requires every authenticated unit to reach its controller.
struct AuthenticatedClosedEngine {
    host: crate::host::Host,
    engine: HermesEngine,
    publications: AuthenticatedPublicationTracker,
}

impl std::ops::Deref for AuthenticatedClosedEngine {
    type Target = HermesEngine;

    fn deref(&self) -> &Self::Target {
        &self.engine
    }
}

impl AuthenticatedClosedEngine {
    async fn eval_immediate(&mut self, source: &str) -> anyhow::Result<Option<String>> {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};

        self.drain_publications("before authenticated closed-builtin evaluation")?;
        let session = self.host.mint_armed_session_token()?;
        let mut sequence =
            ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())?;
        let request = sequence
            .mint_repl(LogicalPath {
                root: LogicalRoot::Project,
                components: Vec::new(),
                host_bound: None,
            })?
            .authorize_inline()
            .bind_bytes(source.as_bytes().to_vec())
            .into_request()?;
        let ordinal = request.submission_ordinal();
        let evaluation = self
            .engine
            .evaluate_authenticated(&session, request)
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "authenticated closed-builtin submission {ordinal} failed: {error:#}"
                )
            });
        let publications =
            self.drain_publications("after authenticated closed-builtin evaluation");
        let evaluation = match (evaluation, publications) {
            (Err(evaluation_error), Err(publication_error)) => anyhow::bail!(
                "authenticated closed-builtin submission {ordinal} failed ({evaluation_error:#}) and its publication stream failed ({publication_error:#})"
            ),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
            (Ok(evaluation), Ok(())) => evaluation,
        };
        match evaluation {
            AuthenticatedEvaluation::Empty => Ok(None),
            AuthenticatedEvaluation::Value { display, receipt } => {
                let release = match receipt {
                    Some(receipt) => self.engine.release_undisplayed_value(receipt).await,
                    None => Err(anyhow::anyhow!(
                        "authenticated closed-builtin submission {ordinal} lost its value receipt"
                    )),
                };
                let publications = self
                    .drain_publications("after authenticated closed-builtin value release");
                match (release, publications) {
                    (Err(release_error), Err(publication_error)) => anyhow::bail!(
                        "authenticated closed-builtin submission {ordinal} failed to release its value ({release_error:#}) and its publication stream ({publication_error:#})"
                    ),
                    (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
                    (Ok(()), Ok(())) => {}
                }
                match display.kind {
                    AuthenticatedDisplayKind::Undefined => Ok(None),
                    AuthenticatedDisplayKind::String => serde_json::from_str(&display.text)
                        .map(Some)
                        .map_err(|error| {
                            anyhow::anyhow!(
                                "authenticated closed-builtin submission {ordinal} returned an invalid string display: {error}"
                            )
                        }),
                    _ => Ok(Some(display.text)),
                }
            }
            AuthenticatedEvaluation::Throw(thrown) => anyhow::bail!(
                "authenticated closed-builtin submission {ordinal} threw: {thrown:?}"
            ),
            AuthenticatedEvaluation::Cancelled => anyhow::bail!(
                "authenticated closed-builtin submission {ordinal} was cancelled"
            ),
            AuthenticatedEvaluation::Lifecycle(code) => anyhow::bail!(
                "authenticated closed-builtin submission {ordinal} exited with lifecycle code {code}"
            ),
        }
    }

    fn drain_publications(&mut self, context: &str) -> anyhow::Result<()> {
        self.publications.drain(&self.engine, context)
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        let publications =
            self.drain_publications("authenticated closed-builtin engine finish");
        let due = self
            .publications
            .require_no_due_schedules("authenticated closed-builtin engine finish");
        match (publications, due) {
            (Err(publication_error), Err(due_error)) => anyhow::bail!(
                "authenticated closed-builtin engine publication stream failed ({publication_error:#}) and retained due schedules ({due_error:#})"
            ),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

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
    if value["invocation"]["invocationSchema"] != "ibex/capsec-closed-surface-invocation/1" {
        return None;
    }
    Some(
        serde_json::from_value(value.clone())
            .expect("closed public probe must match its typed schema"),
    )
}

#[cfg(test)]
struct ClosedEnvironmentRestore(Vec<(String, Option<OsString>)>);

#[cfg(test)]
impl ClosedEnvironmentRestore {
    fn clear() -> Self {
        let mut names =
            ibex_runtime::capsec_registry_generated::CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
        names.extend(["IBEX_POLICY", "EXACT_POLICY"]);
        let values = names
            .iter()
            .map(|name| ((*name).to_owned(), std::env::var_os(name)))
            .collect::<Vec<_>>();
        for name in names {
            std::env::remove_var(name);
        }
        Self(values)
    }
}

#[cfg(test)]
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
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create exact closed-surface attestation engine");
    engine
        .load_runtime()
        .await
        .expect("load exact closed-surface attestation runtime");
    let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
    assert_eq!(
        evaluator
            .eval_string(&engine, "'IBEX_CAPSEC_CLOSED_BATCH_ENGINE_EXECUTED'")
            .await,
        "IBEX_CAPSEC_CLOSED_BATCH_ENGINE_EXECUTED"
    );
}

#[cfg(test)]
async fn execute_closed_startup_environment(
    recipe: &Recipe,
    probe: &ClosedSurfaceProbe,
    coverage: &BTreeMap<String, (String, String)>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let invocation = &probe.invocation;
    let environment_name = invocation
        .operation
        .environment_name()
        .expect("startup environment probe has the wrong operation");
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "closed");
    assert_eq!(recipe.scenario, "closed");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(CLOSED_BATCH_COMMAND));
    assert_eq!(
        invocation.invocation_schema,
        "ibex/capsec-closed-surface-invocation/1"
    );
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
    assert_eq!(
        descriptor.environment_name.as_deref(),
        Some(environment_name)
    );
    assert!(descriptor.surface_observed_key.is_none());
    assert!(descriptor.control_descriptor.is_none());
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
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id));
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

#[cfg(test)]
async fn execute_closed_tamed_evaluator(
    recipe: &Recipe,
    probe: &ClosedSurfaceProbe,
    coverage: &BTreeMap<String, (String, String)>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let invocation = &probe.invocation;
    let ClosedOperation::TamedEvaluator {
        global_name,
        access_mode,
    } = &invocation.operation
    else {
        panic!("tamed evaluator probe has the wrong operation")
    };
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "closed");
    assert_eq!(recipe.scenario, "closed");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(CLOSED_BATCH_COMMAND));
    assert_eq!(
        invocation.invocation_schema,
        "ibex/capsec-closed-surface-invocation/1"
    );
    assert_eq!(invocation.kind, "closed-surface");
    assert_eq!(invocation.surface_kind, "native-op");
    assert_eq!(invocation.surface_name, format!("global:{global_name}"));
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
    assert_eq!(descriptor.kind, "closed-tamed-evaluator");
    assert_eq!(
        descriptor.global_name.as_deref(),
        Some(global_name.as_str())
    );
    assert_eq!(
        descriptor.access_mode.as_deref(),
        Some(access_mode.as_str())
    );
    assert_eq!(
        descriptor.surface_observed_key.as_deref(),
        Some(probe.surface_observed_key.as_str())
    );
    assert!(descriptor.environment_name.is_none());
    assert!(descriptor.control_descriptor.is_none());
    assert!(!descriptor.source_refs.is_empty());
    assert!(descriptor
        .engine_identity_review_id
        .as_deref()
        .is_some_and(|value| value.starts_with("hermes-evaluators.")));
    assert!(descriptor
        .lockdown_taming_digest
        .as_deref()
        .is_some_and(|value| value.starts_with("sha256-") && value.len() == 71));
    assert_eq!(
        descriptor.source_metadata["evidenceType"],
        "hermes-evaluator-reachability"
    );
    assert_eq!(
        descriptor.source_metadata["exportName"],
        global_name.as_str()
    );
    assert_eq!(descriptor.source_metadata["tamingEvidence"], "lockdownJS");
    assert_eq!(
        descriptor.source_metadata["engineIdentityReviewId"],
        descriptor.engine_identity_review_id.as_deref().unwrap()
    );
    assert_eq!(
        descriptor.source_metadata["lockdownTamingDigest"],
        descriptor.lockdown_taming_digest.as_deref().unwrap()
    );
    assert!(matches!(
        (global_name.as_str(), access_mode.as_str()),
        ("eval", "global-eval")
            | ("Function", "global-function")
            | ("AsyncFunction", "async-function-constructor")
            | ("GeneratorFunction", "generator-function-constructor")
    ));
    let (surface_kind, surface_name) = coverage
        .get(&recipe.edge_ids[0])
        .expect("closed evaluator recipe names an unknown coverage edge");
    assert_eq!(surface_kind, &invocation.surface_kind);
    assert_eq!(surface_name, &invocation.surface_name);
    let terminal_observed_key = format!("{surface_kind}:{surface_name}");
    assert_eq!(terminal_observed_key, recipe.terminal_observed_key);
    assert_eq!(terminal_observed_key, probe.surface_observed_key);

    let expression = match access_mode.as_str() {
        "global-eval" => "globalThis.eval",
        "global-function" => "globalThis.Function",
        "async-function-constructor" => "Object.getPrototypeOf(async function(){}).constructor",
        "generator-function-constructor" => "Object.getPrototypeOf(function*(){}).constructor",
        other => panic!("unsupported tamed evaluator access mode {other}"),
    };
    let (host, snapshot_digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |_| {});
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create exact tamed-evaluator engine");
    engine
        .load_runtime()
        .await
        .expect("load exact tamed-evaluator runtime");
    let session_id = format!("closed-evaluator:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id));
    let script = format!(
        "JSON.stringify((function(){{var evaluator={expression};try{{Reflect.apply(evaluator,globalThis,['return 7']);return {{kind:'return',tamed:evaluator&&evaluator.__ibexTamed===true}};}}catch(error){{return {{kind:'throw',tamed:evaluator&&evaluator.__ibexTamed===true,errorName:String(error&&error.name||'Error'),errorMessage:String(error&&error.message||error)}};}}}})())"
    );
    let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
    let encoded = evaluator.eval_string(&engine, &script).await;
    let result: serde_json::Value =
        serde_json::from_str(&encoded).expect("tamed evaluator result must be JSON");
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());
    assert_eq!(result["kind"], "throw");
    assert_eq!(result["tamed"], true);
    assert_eq!(result["errorName"], "TypeError");
    assert!(result["errorMessage"]
        .as_str()
        .is_some_and(|message| message.contains("disabled under lockdown")));

    let result = serde_json::json!({
        "kind": "closed",
        "surfaceKind": surface_kind,
        "surfaceName": surface_name,
        "mechanism": invocation.operation.kind(),
        "errorName": "ClosedSurface",
        "errorMessage": result["errorMessage"],
        "engineExecuted": true,
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
        .expect("expected closed evaluator observation must be an object")
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

#[cfg(test)]
async fn execute_closed_exact_unendowed_operation(
    recipe: &Recipe,
    probe: &ClosedSurfaceProbe,
    coverage: &BTreeMap<String, (String, String)>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let invocation = &probe.invocation;
    let ClosedOperation::ExactUnendowedOperation {
        context_kind,
        operation_manifest_digest,
        endowed_operation_ids,
        selected_operation_id,
        expected_error,
    } = &invocation.operation
    else {
        panic!("Exact unendowed probe has the wrong closed operation")
    };
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "closed");
    assert_eq!(recipe.scenario, "closed");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(CLOSED_BATCH_COMMAND));
    assert_eq!(
        invocation.invocation_schema,
        "ibex/capsec-closed-surface-invocation/1"
    );
    assert_eq!(invocation.kind, "closed-surface");
    assert_eq!(invocation.surface_kind, "native-op");
    assert_eq!(invocation.surface_name, "global:exact.invokeHostAsync");
    assert_eq!(invocation.expected_result, "closed");
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert!(invocation.allowed_coverage_edge_ids.is_empty());
    assert!(invocation.expected_action_ids.is_empty());
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_value_digest(&invocation.source_descriptor)
    );
    assert_eq!(context_kind, "app");
    assert_eq!(operation_manifest_digest, EXACT_OPERATION_MANIFEST_DIGEST);
    assert_eq!(endowed_operation_ids, &EXACT_APP_OPERATION_IDS);
    assert_eq!(*selected_operation_id, EXACT_UNENDOWED_OPERATION_ID);
    assert!(!endowed_operation_ids.contains(selected_operation_id));
    assert_eq!(expected_error, EXACT_UNENDOWED_ERROR);

    let descriptor = &invocation.source_descriptor;
    assert_eq!(descriptor.kind, "closed-exact-unendowed-operation");
    assert_eq!(
        descriptor.surface_observed_key.as_deref(),
        Some(probe.surface_observed_key.as_str())
    );
    assert_eq!(descriptor.global_name.as_deref(), Some("exact"));
    assert_eq!(descriptor.member_name.as_deref(), Some("invokeHostAsync"));
    assert_eq!(
        descriptor.source_refs,
        ["src/engine/hermes_runtime.cc#jsi-global:exact.invokeHostAsync"]
    );
    assert_eq!(descriptor.source_metadata["surfaceType"], "global-api");
    assert_eq!(descriptor.source_metadata["sourceKey"], "native_jsi_global");
    assert_eq!(descriptor.source_metadata["globalName"], "exact");
    assert_eq!(descriptor.source_metadata["memberName"], "invokeHostAsync");
    assert_eq!(
        descriptor.source_metadata["memberKinds"],
        serde_json::json!(["native-object-member"])
    );
    let (surface_kind, surface_name) = coverage
        .get(&recipe.edge_ids[0])
        .expect("closed Exact recipe names an unknown coverage edge");
    assert_eq!(surface_kind, &invocation.surface_kind);
    assert_eq!(surface_name, &invocation.surface_name);
    let terminal_observed_key = format!("{surface_kind}:{surface_name}");
    assert_eq!(terminal_observed_key, recipe.terminal_observed_key);
    assert_eq!(terminal_observed_key, probe.surface_observed_key);

    let (host, snapshot_digest) = build_armed_exact_test_host();
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    EXACT_ABI_PROBE_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
    EXACT_ABI_PROBE_OPERATION.store(0, std::sync::atomic::Ordering::SeqCst);
    EXACT_ABI_PROBE_PAYLOAD_LEN.store(0, std::sync::atomic::Ordering::SeqCst);
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create exact closed-operation engine");
    engine
        .load_runtime()
        .await
        .expect("load exact closed-operation runtime");
    let session_id = format!("closed-exact-operation:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id));
    let manifest_digest = std::ffi::CString::new(operation_manifest_digest.as_str()).unwrap();
    let runtime = engine
        .ensure_runtime()
        .await
        .expect("load exact closed-operation runtime handle");
    runtime
        .with_runtime(|raw| unsafe {
            assert_eq!(
                ex_hermes_set_exact_host_call_async(
                    raw,
                    1,
                    endowed_operation_ids.as_ptr(),
                    endowed_operation_ids.len(),
                    manifest_digest.as_ptr(),
                    abi_probe_exact_host_call,
                    std::ptr::null_mut(),
                ),
                0,
                "install authenticated Exact app endowment"
            );
        })
        .expect("invoke Exact setter on the runtime owner thread");
    let script = format!(
        r#"JSON.stringify((function(operation) {{
  var descriptor = Object.getOwnPropertyDescriptor(exact, 'invokeHostAsync');
  var errorName = null;
  var errorMessage = null;
  try {{ exact.invokeHostAsync(operation, new Uint8Array()); }}
  catch (error) {{
    errorName = String(error && error.name || 'Error');
    errorMessage = String(error && error.message || error);
  }}
  return {{
    errorName: errorName,
    errorMessage: errorMessage,
    methodInstalled: typeof exact.invokeHostAsync === 'function',
    immutable: descriptor && descriptor.writable === false && descriptor.configurable === false,
    genericBridgeAbsent: typeof __hostCall === 'undefined' && typeof __hostCallAsync === 'undefined'
  }};
}})({selected_operation_id}))"#
    );
    let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);
    let encoded = evaluator.eval_string(&engine, &script).await;
    let observed: serde_json::Value =
        serde_json::from_str(&encoded).expect("unendowed Exact result must be JSON");
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert_eq!(observed["errorMessage"], expected_error.as_str());
    assert!(observed["errorName"].as_str().is_some());
    assert_eq!(observed["methodInstalled"], true);
    assert_eq!(observed["immutable"], true);
    assert_eq!(observed["genericBridgeAbsent"], true);
    assert_eq!(
        EXACT_ABI_PROBE_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "unendowed operation reached the trusted embedder callback"
    );
    assert!(legacy.is_empty());
    assert!(typed.is_empty());

    let result = serde_json::json!({
        "kind": "closed",
        "surfaceKind": surface_kind,
        "surfaceName": surface_name,
        "mechanism": invocation.operation.kind(),
        "errorName": "ClosedSurface",
        "errorMessage": observed["errorMessage"],
        "engineExecuted": true,
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
        .expect("expected closed Exact observation must be an object")
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

pub(super) async fn execute_exact_fixture_runtime_observation(
    recipe_value: &serde_json::Value,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let recipe: Recipe = serde_json::from_value(recipe_value.clone())
        .expect("closed Exact fixture recipe must match the executable recipe schema");
    let probe = closed_surface_probe(&recipe)
        .expect("closed Exact fixture recipe has no closed-surface probe");
    assert!(matches!(
        probe.invocation.operation,
        ClosedOperation::ExactUnendowedOperation { .. }
    ));
    let execution = execute_closed_exact_unendowed_operation(
        &recipe,
        &probe,
        &coverage_terminals(),
        engine_binary_digest,
    )
    .await;
    execution["evidence"]["runtimeObservation"].clone()
}

fn reviewed_terminal_builtin(source_key: &str) -> Option<(&'static str, &'static [&'static str])> {
    Some(match source_key {
        "node_async_hooks" => ("async_hooks", &["async_hooks", "node:async_hooks"]),
        "node_inspector" => (
            "inspector",
            &[
                "inspector",
                "inspector/promises",
                "node:inspector",
                "node:inspector/promises",
            ],
        ),
        "node_vm" => ("vm", &["node:vm", "vm"]),
        "node_wasi" => ("wasi", &["node:wasi", "wasi"]),
        "node_worker_threads" => ("worker_threads", &["node:worker_threads", "worker_threads"]),
        _ => return None,
    })
}

#[cfg(test)]
async fn execute_closed_terminal_builtin_import(
    engine: &mut AuthenticatedClosedEngine,
    recipe: &Recipe,
    probe: &ClosedSurfaceProbe,
    coverage: &BTreeMap<String, (String, String)>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let invocation = &probe.invocation;
    let ClosedOperation::TerminalBuiltinImport {
        terminal_builtin_root,
        module_specifiers,
        expected_rejection_fragment,
    } = &invocation.operation
    else {
        panic!("terminal builtin probe has the wrong operation")
    };
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "closed");
    assert_eq!(recipe.scenario, "closed");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(CLOSED_BATCH_COMMAND));
    assert_eq!(
        invocation.invocation_schema,
        "ibex/capsec-closed-surface-invocation/1"
    );
    assert_eq!(invocation.kind, "closed-surface");
    assert_eq!(invocation.surface_kind, "builtin");
    assert_eq!(invocation.expected_result, "closed");
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert!(invocation.allowed_coverage_edge_ids.is_empty());
    assert!(invocation.expected_action_ids.is_empty());
    assert_eq!(expected_rejection_fragment, "Import denied:");
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_value_digest(&invocation.source_descriptor)
    );

    let descriptor = &invocation.source_descriptor;
    assert_eq!(descriptor.kind, "closed-terminal-builtin");
    assert_eq!(
        descriptor.surface_observed_key.as_deref(),
        Some(probe.surface_observed_key.as_str())
    );
    assert_eq!(
        descriptor.module_specifiers.as_ref(),
        Some(module_specifiers)
    );
    assert_eq!(descriptor.source_refs.len(), 1);
    let source_key = descriptor
        .source_key
        .as_deref()
        .expect("terminal builtin descriptor has no source key");
    let (reviewed_root, reviewed_specifiers) =
        reviewed_terminal_builtin(source_key).expect("unreviewed terminal builtin source");
    assert_eq!(terminal_builtin_root, reviewed_root);
    assert_eq!(
        module_specifiers,
        &reviewed_specifiers
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(descriptor.source_metadata["sourceKey"], source_key);
    assert_eq!(descriptor.source_metadata["importReachability"], "public");
    if let Some(export_name) = descriptor.export_name.as_deref() {
        assert_eq!(descriptor.source_metadata["surfaceType"], "export");
        assert_eq!(descriptor.source_metadata["exportName"], export_name);
        assert_eq!(
            descriptor.source_metadata["publicModuleSpecifiers"],
            serde_json::json!(module_specifiers)
        );
        assert_eq!(
            invocation.surface_name,
            format!("export:{source_key}:{export_name}")
        );
    } else {
        assert!(descriptor.source_metadata.get("surfaceType").is_none());
        assert_eq!(descriptor.source_metadata["moduleBuiltin"], true);
        assert_eq!(descriptor.source_metadata["bundleExternal"], true);
        assert!(
            reviewed_specifiers.contains(&invocation.surface_name.as_str()),
            "unreviewed terminal builtin alias {}",
            invocation.surface_name
        );
    }
    let (surface_kind, surface_name) = coverage
        .get(&recipe.edge_ids[0])
        .expect("closed terminal builtin recipe names an unknown coverage edge");
    assert_eq!(surface_kind, &invocation.surface_kind);
    assert_eq!(surface_name, &invocation.surface_name);
    let terminal_observed_key = format!("{surface_kind}:{surface_name}");
    assert_eq!(terminal_observed_key, recipe.terminal_observed_key);
    assert_eq!(terminal_observed_key, probe.surface_observed_key);

    let session_id = format!("public-observation:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id));
    let script = format!(
        r#"JSON.stringify((function(specifiers) {{
  return specifiers.map(function(specifier) {{
    var errorName = null;
    var errorMessage = null;
    try {{ require(specifier); }}
    catch (error) {{
      errorName = String(error && error.name || 'Error');
      errorMessage = String(error && error.message || error);
    }}
    return {{specifier: specifier, errorName: errorName, errorMessage: errorMessage}};
  }});
}})({}))"#,
        serde_json::to_string(module_specifiers).unwrap()
    );
    let encoded = engine
        .eval_immediate(&script)
        .await
        .expect("execute terminal builtin public imports")
        .expect("terminal builtin imports returned no result");
    let observed: Vec<serde_json::Value> =
        serde_json::from_str(&encoded).expect("terminal builtin result must be JSON");
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert_eq!(observed.len(), module_specifiers.len());
    let mut errors = Vec::with_capacity(observed.len());
    for (row, specifier) in observed.iter().zip(module_specifiers) {
        assert_eq!(row["specifier"].as_str(), Some(specifier.as_str()));
        assert_eq!(row["errorName"], "Error");
        let error = row["errorMessage"]
            .as_str()
            .expect("terminal builtin import unexpectedly succeeded");
        assert!(
            error.contains(expected_rejection_fragment) && error.contains(specifier),
            "terminal builtin returned the wrong refusal for {specifier}: {error}"
        );
        errors.push(format!("{specifier}: {error}"));
    }
    assert!(legacy.is_empty());
    assert!(typed.is_empty());

    let result = serde_json::json!({
        "kind": "closed",
        "surfaceKind": surface_kind,
        "surfaceName": surface_name,
        "mechanism": invocation.operation.kind(),
        "errorName": "ClosedSurface",
        "errorMessage": errors.join("\n"),
        "engineExecuted": true,
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
        "legacyObservationCount": 0,
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

fn reviewed_debugger_abi(function_name: &str) -> Option<(&'static str, &'static str)> {
    Some(match function_name {
        "ex_hermes_debugger_enable" => ("enable", "integer-zero"),
        "ex_hermes_debugger_eval" => ("eval", "null-pointer"),
        "ex_hermes_debugger_get_script_source" => ("get-script-source", "null-pointer"),
        "ex_hermes_debugger_get_scripts" => ("get-scripts", "null-pointer"),
        "ex_hermes_debugger_next_event" => ("next-event", "null-pointer"),
        "ex_hermes_debugger_pause" => ("pause", "no-event"),
        "ex_hermes_debugger_remove_breakpoint" => ("remove-breakpoint", "no-event"),
        "ex_hermes_debugger_resume" => ("resume", "no-event"),
        "ex_hermes_debugger_set_breakpoint" => ("set-breakpoint", "null-pointer"),
        _ => return None,
    })
}

#[cfg(test)]
unsafe fn assert_null_debugger_string(value: *mut std::os::raw::c_char, function_name: &str) {
    if !value.is_null() {
        unsafe { ex_hermes_free_string(value) };
        panic!("{function_name} returned debugger data on the no-debugger exact target");
    }
}

#[cfg(test)]
async fn execute_closed_debugger_abi(
    engine: &mut AuthenticatedClosedEngine,
    recipe: &Recipe,
    probe: &ClosedSurfaceProbe,
    coverage: &BTreeMap<String, (String, String)>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let invocation = &probe.invocation;
    let ClosedOperation::DebuggerAbiDisabled {
        function_name,
        expected_call_result,
        expected_error,
    } = &invocation.operation
    else {
        panic!("debugger ABI probe has the wrong operation")
    };
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "closed");
    assert_eq!(recipe.scenario, "closed");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(CLOSED_BATCH_COMMAND));
    assert_eq!(
        invocation.invocation_schema,
        "ibex/capsec-closed-surface-invocation/1"
    );
    assert_eq!(invocation.kind, "closed-surface");
    assert!(matches!(
        invocation.surface_kind.as_str(),
        "host-abi" | "native-op"
    ));
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
    let (operation_slug, reviewed_call_result) =
        reviewed_debugger_abi(function_name).expect("unreviewed debugger ABI function");
    assert_eq!(expected_call_result, reviewed_call_result);
    assert_eq!(descriptor.kind, "closed-debugger-abi");
    assert_eq!(
        descriptor.surface_observed_key.as_deref(),
        Some(probe.surface_observed_key.as_str())
    );
    assert_eq!(
        descriptor.function_name.as_deref(),
        Some(function_name.as_str())
    );
    assert_eq!(
        descriptor.target_triple.as_deref(),
        Some("aarch64-apple-darwin")
    );
    let default_source_ref = format!("src/engine/hermes_runtime_debugger.cc#{function_name}");
    let windows_source_ref =
        format!("src/engine/hermes_runtime_platform_windows.cc#{function_name}");
    assert_eq!(
        descriptor.selected_source_ref.as_deref(),
        Some(default_source_ref.as_str())
    );
    assert_eq!(
        descriptor.source_refs,
        [default_source_ref.clone(), windows_source_ref.clone()]
    );
    if invocation.surface_kind == "host-abi" {
        assert_eq!(invocation.surface_name.as_str(), function_name.as_str());
        let alternatives = serde_json::json!([
            {
                "id": "default",
                "kind": "alternative",
                "sourceRefs": [default_source_ref.clone()],
                "stubDisposition": "not-structurally-proven",
                "targetVariant": "default",
            },
            {
                "id": "windows",
                "kind": "alternative",
                "sourceRefs": [windows_source_ref.clone()],
                "stubDisposition": "not-structurally-proven",
                "targetVariant": "windows",
            },
        ]);
        let metadata = descriptor
            .source_metadata
            .as_object()
            .expect("debugger Host ABI source metadata must be an object");
        assert_eq!(metadata.len(), 5);
        assert_eq!(metadata["alternatives"], alternatives);
        assert_eq!(metadata["branches"], metadata["alternatives"]);
        assert_eq!(
            metadata["provenanceLimitation"],
            "ABI definitions are source-structural evidence; supported/unsupported target semantics require fixtures."
        );
        let definitions = metadata["definitions"]
            .as_array()
            .expect("debugger Host ABI metadata has no definitions");
        let output_contracts = metadata["outputContracts"]
            .as_array()
            .expect("debugger Host ABI metadata has no output contracts");
        assert_eq!(definitions.len(), 2);
        assert_eq!(output_contracts.len(), 2);
        for (index, (target_variant, source_ref)) in [
            ("default", default_source_ref.as_str()),
            ("windows", windows_source_ref.as_str()),
        ]
        .into_iter()
        .enumerate()
        {
            let definition = definitions[index]
                .as_object()
                .expect("debugger Host ABI definition must be an object");
            assert_eq!(definition.len(), 6);
            assert_eq!(definition["language"], "c++");
            assert_eq!(definition["sourceRef"], source_ref);
            assert_eq!(definition["targetVariant"], target_variant);
            assert_eq!(definition["unsafe"], false);
            assert_eq!(definition["weak"], false);
            assert_eq!(definition["outputContract"], output_contracts[index]);
            let contract = output_contracts[index]
                .as_object()
                .expect("debugger Host ABI output contract must be an object");
            assert_eq!(contract["schema"], "ibex/host-abi-output-contract/1");
            assert_eq!(contract["language"], "c++");
            assert_eq!(contract["functionName"], function_name.as_str());
            assert_eq!(contract["sourceRef"], source_ref);
            assert_eq!(contract["status"], "resolved");
            assert!(contract["bufferLengthPairs"].is_array());
            assert!(contract["outputChannels"].is_array());
            assert!(contract["parameters"].is_array());
            assert!(contract["return"].is_object());
            assert_eq!(contract["unresolved"], serde_json::json!([]));
        }
    } else {
        assert_eq!(
            invocation.surface_name,
            format!("inspector.debugger-{operation_slug}")
        );
        assert!(descriptor.source_metadata.is_null());
    }
    assert_eq!(
        expected_error,
        &format!("debugger ABI {function_name} is unavailable in the no-debugger exact target")
    );
    let (surface_kind, surface_name) = coverage
        .get(&recipe.edge_ids[0])
        .expect("closed debugger ABI recipe names an unknown coverage edge");
    assert_eq!(surface_kind, &invocation.surface_kind);
    assert_eq!(surface_name, &invocation.surface_name);
    let terminal_observed_key = format!("{surface_kind}:{surface_name}");
    assert_eq!(terminal_observed_key, recipe.terminal_observed_key);
    assert_eq!(terminal_observed_key, probe.surface_observed_key);

    let session_id = format!("public-observation:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id));
    assert_eq!(
        engine
            .eval_immediate("'IBEX_CAPSEC_DEBUGGER_ABI_READY'")
            .await
            .expect("evaluate debugger ABI precondition marker")
            .as_deref(),
        Some("IBEX_CAPSEC_DEBUGGER_ABI_READY")
    );
    let runtime = engine
        .ensure_runtime()
        .await
        .expect("load debugger ABI runtime handle");
    let enable_result = runtime
        .with_runtime(|raw| unsafe { ex_hermes_debugger_enable(raw) })
        .expect("probe debugger enablement on the runtime owner thread");
    assert_eq!(
        enable_result, 0,
        "exact target unexpectedly enabled debugger"
    );
    runtime
        .with_runtime(|raw| unsafe {
            match function_name.as_str() {
                "ex_hermes_debugger_enable" => {}
                "ex_hermes_debugger_eval" => {
                    let expression = std::ffi::CString::new(
                        "globalThis.__IBEX_CAPSEC_DEBUGGER_EVAL_EXECUTED__ = true",
                    )
                    .unwrap();
                    assert_null_debugger_string(
                        ex_hermes_debugger_eval(raw, expression.as_ptr(), 0),
                        function_name,
                    );
                }
                "ex_hermes_debugger_get_script_source" => {
                    assert_null_debugger_string(
                        ex_hermes_debugger_get_script_source(raw, 0),
                        function_name,
                    );
                }
                "ex_hermes_debugger_get_scripts" => {
                    assert_null_debugger_string(ex_hermes_debugger_get_scripts(raw), function_name);
                }
                "ex_hermes_debugger_next_event" => {
                    assert_null_debugger_string(ex_hermes_debugger_next_event(raw), function_name);
                }
                "ex_hermes_debugger_pause" => ex_hermes_debugger_pause(raw),
                "ex_hermes_debugger_remove_breakpoint" => {
                    ex_hermes_debugger_remove_breakpoint(raw, 0)
                }
                "ex_hermes_debugger_resume" => ex_hermes_debugger_resume(raw, 0),
                "ex_hermes_debugger_set_breakpoint" => {
                    assert_null_debugger_string(
                        ex_hermes_debugger_set_breakpoint(raw, 0, 0, 0, std::ptr::null()),
                        function_name,
                    );
                }
                _ => unreachable!(),
            }
            assert_null_debugger_string(
                ex_hermes_debugger_next_event(raw),
                "ex_hermes_debugger_next_event after closed call",
            );
        })
        .expect("invoke debugger ABI on the runtime owner thread");
    assert_eq!(
        engine
            .eval_immediate(
                "typeof globalThis.__IBEX_CAPSEC_DEBUGGER_EVAL_EXECUTED__ === 'undefined' ? 'closed' : 'executed'",
            )
            .await
            .expect("evaluate debugger ABI postcondition marker")
            .as_deref(),
        Some("closed")
    );
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());

    let result = serde_json::json!({
        "kind": "closed",
        "surfaceKind": surface_kind,
        "surfaceName": surface_name,
        "mechanism": invocation.operation.kind(),
        "errorName": "ClosedSurface",
        "errorMessage": expected_error,
        "engineExecuted": true,
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
        "legacyObservationCount": 0,
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

fn reviewed_shared_runtime_absent_surface(surface_name: &str) -> bool {
    matches!(
        surface_name,
        "__exactAllowNativesSyntax"
            | "__exactCompatEval"
            | "__exactDebugModuleSource"
            | "__exactDebugModuleSources"
            | "__exactDebugModuleSources.length"
            | "__exactInstallAsyncIpcListenerPatch"
            | "__exactInstallProcessIpcBootstrap"
            | "__exactNativeWrapState"
            | "__exactNativeWrapState.Pipe"
            | "__exactNativeWrapState.TCP"
            | "__exactNativeWrapState.TCPConnectWrap"
            | "__exactNativeWrapState.UV_EINVAL"
            | "__exactNativeWrapState.byFd"
            | "__exactNativeWrapState.pipeConstants"
            | "__exactNativeWrapState.tcpConstants"
            | "__exactStreamWrapState"
            | "__exactSyncTrackedIpcListenersAfterDispatch"
            | "global:Bun.gc"
            | "global:Cache"
            | "global:Cache.add"
            | "global:Cache.addAll"
            | "global:Cache.delete"
            | "global:Cache.keys"
            | "global:Cache.match"
            | "global:Cache.matchAll"
            | "global:Cache.put"
            | "global:CacheStorage"
            | "global:CacheStorage.delete"
            | "global:CacheStorage.has"
            | "global:CacheStorage.keys"
            | "global:CacheStorage.match"
            | "global:CacheStorage.open"
            | "global:Exact.gc"
    )
}

#[cfg(test)]
async fn execute_closed_shared_runtime_global_absence(
    engine: &mut AuthenticatedClosedEngine,
    recipe: &Recipe,
    probe: &ClosedSurfaceProbe,
    coverage: &BTreeMap<String, (String, String)>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let invocation = &probe.invocation;
    let ClosedOperation::SharedRuntimeGlobalAbsence {
        global_name,
        member_name,
        expected_error,
    } = &invocation.operation
    else {
        panic!("shared-runtime global absence probe has the wrong operation")
    };
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "closed");
    assert_eq!(recipe.scenario, "closed");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(CLOSED_BATCH_COMMAND));
    assert_eq!(
        invocation.invocation_schema,
        "ibex/capsec-closed-surface-invocation/1"
    );
    assert_eq!(invocation.kind, "closed-surface");
    assert_eq!(invocation.surface_kind, "native-op");
    assert!(reviewed_shared_runtime_absent_surface(
        &invocation.surface_name
    ));
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
    assert_eq!(descriptor.kind, "closed-shared-runtime-global-absence");
    assert_eq!(
        descriptor.surface_observed_key.as_deref(),
        Some(probe.surface_observed_key.as_str())
    );
    assert_eq!(
        descriptor.global_name.as_deref(),
        Some(global_name.as_str())
    );
    assert_eq!(descriptor.member_name.as_ref(), member_name.as_ref());
    assert_eq!(
        descriptor.target_triple.as_deref(),
        Some("aarch64-apple-darwin")
    );
    assert!(!descriptor.source_refs.is_empty());
    let metadata = &descriptor.source_metadata;
    assert_eq!(metadata["surfaceType"], "global-api");
    assert_eq!(metadata["globalName"], global_name.as_str());
    assert_eq!(metadata["memberName"], serde_json::json!(member_name));
    let export_name = member_name.as_ref().map_or_else(
        || global_name.clone(),
        |member| format!("{global_name}.{member}"),
    );
    assert_eq!(metadata["exportName"], export_name);
    let branches = metadata["installationBranches"]
        .as_array()
        .expect("shared-runtime global source must name installation branches");
    assert_eq!(branches.len(), 1);
    assert_eq!(branches[0]["route"], "legacy-bootstrap");
    assert_eq!(branches[0]["targetVariant"], "default");
    assert_eq!(
        branches[0]["sourceRefs"],
        serde_json::json!(descriptor.source_refs)
    );
    assert_eq!(
        expected_error,
        &format!("armed shared runtime does not expose {export_name}")
    );
    let (surface_kind, surface_name) = coverage
        .get(&recipe.edge_ids[0])
        .expect("closed shared-runtime global recipe names an unknown coverage edge");
    assert_eq!(surface_kind, &invocation.surface_kind);
    assert_eq!(surface_name, &invocation.surface_name);
    let terminal_observed_key = format!("{surface_kind}:{surface_name}");
    assert_eq!(terminal_observed_key, recipe.terminal_observed_key);
    assert_eq!(terminal_observed_key, probe.surface_observed_key);

    let session_id = format!("public-observation:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id));
    let global_json = serde_json::to_string(global_name).unwrap();
    let script = if let Some(member_name) = member_name {
        let member_json = serde_json::to_string(member_name).unwrap();
        format!(
            "(function(){{var root=Object.getOwnPropertyDescriptor(globalThis,{global_json});if(!root)return 'absent';if(!Object.prototype.hasOwnProperty.call(root,'value'))return 'present';var value=root.value;if((typeof value!=='object'&&typeof value!=='function')||value===null)return 'absent';return Object.getOwnPropertyDescriptor(value,{member_json})===undefined?'absent':'present';}})()"
        )
    } else {
        format!(
            "Object.getOwnPropertyDescriptor(globalThis,{global_json})===undefined?'absent':'present'"
        )
    };
    assert_eq!(
        engine
            .eval_immediate(&script)
            .await
            .expect("inspect armed shared-runtime global")
            .as_deref(),
        Some("absent")
    );
    assert_eq!(
        engine
            .eval_immediate("'IBEX_CAPSEC_SHARED_RUNTIME_GLOBALS_HEALTHY'")
            .await
            .expect("evaluate shared-runtime global postcondition marker")
            .as_deref(),
        Some("IBEX_CAPSEC_SHARED_RUNTIME_GLOBALS_HEALTHY")
    );
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());

    let result = serde_json::json!({
        "kind": "closed",
        "surfaceKind": surface_kind,
        "surfaceName": surface_name,
        "mechanism": invocation.operation.kind(),
        "errorName": "ClosedSurface",
        "errorMessage": expected_error,
        "engineExecuted": true,
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
        "legacyObservationCount": 0,
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

fn clap_command_at_path<'a>(root: &'a clap::Command, path: &str) -> &'a clap::Command {
    let mut components = path.split(' ');
    assert_eq!(components.next(), Some(root.get_name()));
    let mut command = root;
    for component in components {
        command = command
            .get_subcommands()
            .find(|candidate| candidate.get_name() == component)
            .unwrap_or_else(|| panic!("reviewed Clap command path {path} is absent"));
    }
    command
}

fn clap_option_spellings(argument: &clap::Arg) -> Vec<String> {
    let mut spellings = std::collections::BTreeSet::new();
    if let Some(long) = argument.get_long() {
        spellings.insert(format!("--{long}"));
    }
    if let Some(short) = argument.get_short() {
        spellings.insert(format!("-{short}"));
    }
    for alias in argument.get_all_aliases().unwrap_or_default() {
        spellings.insert(format!("--{alias}"));
    }
    for alias in argument.get_all_short_aliases().unwrap_or_default() {
        spellings.insert(format!("-{alias}"));
    }
    spellings.into_iter().collect()
}

fn clap_action_name(action: &clap::ArgAction) -> &'static str {
    match action {
        clap::ArgAction::Set => "Set",
        clap::ArgAction::Append => "Append",
        clap::ArgAction::SetTrue => "SetTrue",
        clap::ArgAction::SetFalse => "SetFalse",
        clap::ArgAction::Count => "Count",
        other => panic!("closed CLI descriptor uses unsupported action {other:?}"),
    }
}

fn string_values(values: &[impl AsRef<std::ffi::OsStr>]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_ref().to_string_lossy().into_owned())
        .collect()
}

fn assert_clap_value_shape(argument: &clap::Arg, shape: &serde_json::Value) {
    let arity = argument.get_num_args().unwrap_or_default();
    assert_eq!(shape["action"], clap_action_name(argument.get_action()));
    assert_eq!(shape["required"], argument.is_required_set());
    assert_eq!(shape["minValues"], arity.min_values());
    if arity.max_values() == usize::MAX {
        assert!(shape["maxValues"].is_null());
    } else {
        assert_eq!(shape["maxValues"], arity.max_values());
    }
    let value_names = argument
        .get_value_names()
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    assert_eq!(shape["valueNames"], serde_json::json!(value_names));
    assert_eq!(
        shape["defaultValues"],
        serde_json::json!(string_values(argument.get_default_values()))
    );
    let possible_values = argument
        .get_possible_values()
        .into_iter()
        .map(|value| value.get_name().to_owned())
        .collect::<Vec<_>>();
    let expected_possible_values = shape["possibleValues"]
        .as_array()
        .expect("reviewed value shape has no possible-values array")
        .iter()
        .map(|value| {
            value["value"]
                .as_str()
                .expect("reviewed possible value has no name")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(expected_possible_values, possible_values);
}

fn reviewed_parser_kind(command_path: &str, argument: &clap::Arg) -> Option<&'static str> {
    let arity = argument.get_num_args().unwrap_or_default();
    if arity.max_values() == 0 || !argument.get_possible_values().is_empty() {
        return None;
    }
    let debug = format!("{:?}", argument.get_value_parser());
    match debug.as_str() {
        "ValueParser::string" => Some("utf8-string"),
        _ if debug.starts_with("ValueParser::other(")
            && argument.get_id().as_str() == "inspect_port"
            && matches!(command_path, "ibex" | "ibex run") =>
        {
            Some("unsigned-integer-u16")
        }
        other => panic!(
            "unreviewed parser for {} on {command_path}: {other}",
            argument.get_id()
        ),
    }
}

fn assert_cli_source_facet(
    source_metadata: &serde_json::Value,
    control: &serde_json::Value,
    argument: Option<&clap::Arg>,
) {
    let evidence_type = source_metadata["evidenceType"].as_str();
    let Some(argument) = argument else {
        assert!(
            evidence_type == Some("cli-command-route")
                || evidence_type == Some("cli-positional-route")
                || evidence_type.is_none(),
            "command fixture has unexpected source facet {source_metadata}"
        );
        if evidence_type.is_none() {
            assert_eq!(source_metadata["commandClass"], "visibleCommands");
        }
        return;
    };
    let value_shape = if control["kind"] == "clap-positional" {
        &control["positionalMetadata"]["valueShape"]
    } else {
        &control["valueShape"]
    };
    match evidence_type.expect("closed CLI source facet has no evidence type") {
        "cli-option-route" => {
            assert_eq!(source_metadata["commandPath"], control["commandPath"]);
            assert_eq!(source_metadata["id"], control["argumentId"]);
            assert_eq!(source_metadata["valueShape"], control["valueShape"]);
        }
        "cli-option-name" => {
            assert!(control["optionSpellings"]
                .as_array()
                .unwrap()
                .contains(&source_metadata["name"]));
            let name = source_metadata["name"].as_str().unwrap();
            let primary = argument
                .get_long()
                .is_some_and(|long| name == format!("--{long}"))
                || argument
                    .get_short()
                    .is_some_and(|short| name == format!("-{short}"));
            let visible_alias = argument
                .get_visible_aliases()
                .unwrap_or_default()
                .iter()
                .any(|alias| name == format!("--{alias}"))
                || argument
                    .get_visible_short_aliases()
                    .unwrap_or_default()
                    .iter()
                    .any(|alias| name == format!("-{alias}"));
            let route_kind = if primary {
                "primary"
            } else if visible_alias {
                "visible-alias"
            } else {
                "hidden-alias"
            };
            assert_eq!(source_metadata["routeKind"], route_kind);
        }
        "cli-value-action" => {
            assert_eq!(
                source_metadata["action"],
                clap_action_name(argument.get_action())
            )
        }
        "cli-value-arity" => {
            let arity = argument.get_num_args().unwrap_or_default();
            assert_eq!(source_metadata["minValues"], arity.min_values());
            assert_eq!(source_metadata["maxValues"], arity.max_values());
        }
        "cli-default-missing-value" => assert!(value_shape["defaultMissingValues"]
            .as_array()
            .unwrap()
            .contains(&source_metadata["value"])),
        "cli-default-value" => assert!(value_shape["defaultValues"]
            .as_array()
            .unwrap()
            .contains(&source_metadata["value"])),
        "cli-value-name" => assert!(value_shape["valueNames"]
            .as_array()
            .unwrap()
            .contains(&source_metadata["valueName"])),
        "cli-enum-value" => assert!(argument
            .get_possible_values()
            .iter()
            .any(|value| value.get_name() == source_metadata["value"].as_str().unwrap())),
        "cli-non-enumerated-parser" => {
            assert_eq!(source_metadata["commandPath"], control["commandPath"]);
            assert_eq!(source_metadata["argumentId"], control["argumentId"]);
            assert_eq!(source_metadata["parserKind"], control["parserKind"]);
        }
        "cli-positional-route" => {
            assert_eq!(source_metadata["commandPath"], control["commandPath"]);
            assert_eq!(source_metadata["id"], argument.get_id().as_str());
            assert_eq!(source_metadata["index"], argument.get_index().unwrap());
        }
        other => panic!("unsupported closed CLI source facet {other}"),
    }
}

fn assert_clap_control_descriptor(descriptor: &ClosedSourceDescriptor) {
    let control = descriptor
        .control_descriptor
        .as_ref()
        .expect("closed CLI source has no control descriptor");
    let command_path = control["commandPath"]
        .as_str()
        .expect("closed CLI control has no command path");
    let mut root = crate::cli::Cli::command();
    root.build();
    let command = clap_command_at_path(&root, command_path);
    match control["kind"].as_str().unwrap() {
        "clap-option" => {
            let argument_id = control["argumentId"].as_str().unwrap();
            let argument = command
                .get_arguments()
                .find(|argument| argument.get_id().as_str() == argument_id)
                .expect("reviewed closed CLI option is absent");
            assert!(!argument.is_positional());
            assert_eq!(
                control["optionSpellings"],
                serde_json::json!(clap_option_spellings(argument))
            );
            assert_eq!(control["hidden"], argument.is_hide_set());
            assert_clap_value_shape(argument, &control["valueShape"]);
            assert_eq!(
                control["parserKind"],
                serde_json::json!(reviewed_parser_kind(command_path, argument))
            );
            assert_cli_source_facet(&descriptor.source_metadata, control, Some(argument));
        }
        "clap-positional" => {
            let positional = control["positionalMetadata"]
                .as_object()
                .expect("closed positional descriptor has no metadata");
            let argument_id = positional["id"].as_str().unwrap();
            let argument = command
                .get_positionals()
                .find(|argument| argument.get_id().as_str() == argument_id)
                .expect("reviewed closed CLI positional is absent");
            assert_eq!(positional["index"], argument.get_index().unwrap());
            assert_clap_value_shape(argument, &positional["valueShape"]);
            assert_cli_source_facet(&descriptor.source_metadata, control, Some(argument));
        }
        "clap-command" => {
            if let Some(metadata) = control["commandMetadata"].as_object() {
                assert_eq!(metadata["path"], command_path);
                assert_eq!(
                    metadata
                        .get("hidden")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                    command.is_hide_set()
                );
            }
            assert_cli_source_facet(&descriptor.source_metadata, control, None);
        }
        other => panic!("unsupported closed CLI control descriptor {other}"),
    }
}

fn assert_cli_control_selected(
    cli: &crate::cli::Cli,
    descriptor: &ClosedSourceDescriptor,
    evaluation_marker: &str,
    project_code: &std::path::Path,
) {
    let control = descriptor.control_descriptor.as_ref().unwrap();
    let command_path = control["commandPath"].as_str().unwrap();
    match control["kind"].as_str().unwrap() {
        "clap-option" => {
            let argument_id = control["argumentId"].as_str().unwrap();
            if command_path == "ibex run" {
                let Some(crate::cli::Commands::Run {
                    file,
                    inspect,
                    inspect_wait,
                    inspect_open,
                    inspect_pause,
                    inspect_port,
                    inspect_host,
                    ..
                }) = cli.command.as_ref()
                else {
                    panic!("closed run option did not select the run command")
                };
                assert_eq!(file, project_code.to_str().unwrap());
                match argument_id {
                    "inspect" => assert!(*inspect),
                    "inspect_wait" => assert!(*inspect_wait),
                    "inspect_open" => assert!(*inspect_open),
                    "inspect_pause" => assert!(*inspect_pause),
                    "inspect_port" => assert_eq!(*inspect_port, Some(9230)),
                    "inspect_host" => assert_eq!(inspect_host.as_deref(), Some("127.0.0.1")),
                    other => panic!("unsupported closed run option {other}"),
                }
                return;
            }
            match argument_id {
                "allow_all" => assert!(cli.allow_all),
                "allow_env_endowments" => assert!(cli.allow_env_endowments),
                "capsec" => match descriptor.source_metadata["value"].as_str().unwrap() {
                    "audit" => assert_eq!(cli.capsec, crate::cli::CapSecMode::Audit),
                    "permissive" => assert_eq!(cli.capsec, crate::cli::CapSecMode::Permissive),
                    other => panic!("unsupported closed CapSec mode {other}"),
                },
                "capsec_allow_advisory" => assert!(cli.capsec_allow_advisory),
                "eval_code" => assert_eq!(cli.eval_code.as_deref(), Some(evaluation_marker)),
                "expose_internals" => assert!(cli.expose_internals),
                "inspect" => assert!(cli.inspect),
                "inspect_wait" => assert!(cli.inspect_wait),
                "inspect_open" => assert!(cli.inspect_open),
                "inspect_pause" => assert!(cli.inspect_pause),
                "inspect_port" => assert_eq!(cli.inspect_port, Some(9230)),
                "inspect_host" => assert_eq!(cli.inspect_host.as_deref(), Some("127.0.0.1")),
                "print_eval" => assert_eq!(cli.print_eval.as_deref(), Some(evaluation_marker)),
                other => panic!("unsupported closed root option {other}"),
            }
            assert_eq!(cli.file.as_deref(), Some(project_code.to_str().unwrap()));
        }
        "clap-command" | "clap-positional" => match command_path {
            "ibex eval" => match cli.command.as_ref() {
                Some(crate::cli::Commands::Eval { code }) => {
                    assert_eq!(code, evaluation_marker)
                }
                other => panic!("closed eval command selected {other:?}"),
            },
            "ibex repl" => assert!(matches!(
                cli.command.as_ref(),
                Some(crate::cli::Commands::Repl)
            )),
            "ibex debug" | "ibex debug modules" => assert!(matches!(
                cli.command.as_ref(),
                Some(crate::cli::Commands::Debug {
                    command: crate::cli::DebugCommands::Modules
                })
            )),
            other => panic!("unsupported closed command {other}"),
        },
        other => panic!("unsupported selected closed CLI control {other}"),
    }
}

async fn execute_closed_module_runner_namespace(
    recipe: &Recipe,
    probe: &ClosedSurfaceProbe,
    coverage: &BTreeMap<String, (String, String)>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    use ibex_runtime::engine::module_runner::{NativeModuleRuntime, NativeSynchronousGraph};
    use ibex_runtime::module_loader::runner_pipeline::{
        build_authenticated_source_graph_v1, SourceModuleGraphBuildV1,
    };
    use ibex_runtime::module_loader::security::ModuleGraphAuthorizer;

    let invocation = &probe.invocation;
    let ClosedOperation::ModuleRunnerNamespace { expected_error } = &invocation.operation else {
        panic!("module-runner namespace probe has the wrong operation")
    };
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "closed");
    assert_eq!(recipe.scenario, "closed");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(CLOSED_BATCH_COMMAND));
    assert_eq!(invocation.kind, "closed-surface");
    assert_eq!(invocation.surface_kind, "host-abi");
    assert_eq!(
        invocation.surface_name,
        "ex_hermes_module_record_namespace_json"
    );
    assert_eq!(invocation.expected_result, "closed");
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert!(invocation.allowed_coverage_edge_ids.is_empty());
    assert!(invocation.expected_action_ids.is_empty());
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_value_digest(&invocation.source_descriptor)
    );
    assert_eq!(
        expected_error,
        "native ModuleRecord namespace read refused (-1): module namespace inspection is closed under armed startup"
    );
    let descriptor = &invocation.source_descriptor;
    assert_eq!(descriptor.kind, "closed-module-runner-namespace");
    assert_eq!(
        descriptor.surface_observed_key.as_deref(),
        Some(probe.surface_observed_key.as_str())
    );
    assert_eq!(
        descriptor.source_refs,
        ["src/engine/hermes_module_runner.cc#ex_hermes_module_record_namespace_json"]
    );
    assert_eq!(
        descriptor.source_metadata["definitions"][0]["language"],
        "c++"
    );
    let (surface_kind, surface_name) = coverage
        .get(&recipe.edge_ids[0])
        .expect("closed module-runner recipe names an unknown coverage edge");
    assert_eq!(surface_kind, &invocation.surface_kind);
    assert_eq!(surface_name, &invocation.surface_name);
    let terminal_observed_key = format!("{surface_kind}:{surface_name}");
    assert_eq!(terminal_observed_key, recipe.terminal_observed_key);
    assert_eq!(terminal_observed_key, probe.surface_observed_key);

    let directory = tempfile::tempdir().expect("create closed module-runner project root");
    let project_root = std::fs::canonicalize(directory.path())
        .expect("canonicalize closed module-runner project root");
    let entry = project_root.join("entry.mjs");
    std::fs::write(&entry, "export const value = 42;\n").expect("write closed module-runner entry");
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
        .expect("loaded engine digest is canonical");
    let graph = match build_authenticated_source_graph_v1(
        &entry,
        producer_digest,
        "capsec-closed-module-runner-namespace",
    )
    .expect("build authenticated closed module-runner graph")
    {
        SourceModuleGraphBuildV1::Native(graph) => graph,
        SourceModuleGraphBuildV1::LegacyRequired(requirement) => panic!(
            "closed module-runner graph unexpectedly required legacy: {}",
            requirement.reason
        ),
    };
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create armed closed module-runner engine");
    engine
        .load_runtime()
        .await
        .expect("load armed closed module-runner runtime");
    unsafe { ibex_test_begin_module_runner_abi_observation() };
    let session_id = format!("closed-module-runner-namespace:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id));
    let runtime = engine
        .ensure_runtime()
        .await
        .expect("borrow armed closed module-runner runtime");
    let error = runtime
        .with_runtime(|raw| -> anyhow::Result<String> {
            let nonce = unsafe { ex_hermes_runtime_nonce(raw) };
            let pin_status = unsafe { ex_hermes_module_pin_generation(raw, nonce, 1) };
            anyhow::ensure!(
                pin_status == 0,
                "module generation pin refused ({pin_status})"
            );
            let result = (|| -> anyhow::Result<String> {
                let raw = std::ptr::NonNull::new(raw.cast())
                    .expect("loaded Hermes runtime pointer is non-null");
                let native = unsafe { NativeModuleRuntime::from_raw(raw, nonce)? };
                let plan = graph.plan()?;
                let (configs, authority_contexts) = graph.native_execution_inputs(1)?;
                let authorizer = ModuleGraphAuthorizer::new(graph.snapshot());
                let linked = NativeSynchronousGraph::link_authorized(
                    &native,
                    &plan,
                    graph.entry(),
                    configs,
                    &authorizer,
                    &authority_contexts,
                )?;
                let error = linked
                    .namespace_json(graph.entry())
                    .expect_err("armed runtime exposed module namespace inspection")
                    .to_string();
                drop(linked);
                drop(native);
                Ok(error)
            })();
            let unpin_status = unsafe { ex_hermes_module_unpin_generation(raw, nonce, 1) };
            anyhow::ensure!(
                unpin_status == 0,
                "module generation unpin refused ({unpin_status})"
            );
            result
        })
        .expect("access armed closed module-runner runtime")
        .expect("exercise armed module namespace closure");
    assert_eq!(&error, expected_error);
    let pointer = unsafe { ibex_test_take_module_runner_abi_observation() };
    assert!(
        !pointer.is_null(),
        "module-runner ABI observer returned no result"
    );
    let observed_text = unsafe { std::ffi::CStr::from_ptr(pointer) }
        .to_str()
        .expect("module-runner ABI observations must be UTF-8")
        .to_owned();
    unsafe { ex_hermes_free_string(pointer) };
    let observed: Vec<String> = serde_json::from_value(
        capsec_semantics::strict_json::parse_strict(&observed_text)
            .expect("module-runner ABI observations must be strict JSON"),
    )
    .expect("module-runner ABI observations must be a string array");
    assert!(observed
        .iter()
        .any(|name| name == "ex_hermes_module_record_namespace_json"));
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());

    let result = serde_json::json!({
        "kind": "closed",
        "surfaceKind": surface_kind,
        "surfaceName": surface_name,
        "mechanism": invocation.operation.kind(),
        "errorName": "ClosedSurface",
        "errorMessage": error,
        "engineExecuted": true,
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
        .expect("expected closed module-runner observation must be an object")
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

async fn execute_closed_cli_control(
    recipe: &Recipe,
    probe: &ClosedSurfaceProbe,
    coverage: &BTreeMap<String, (String, String)>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let invocation = &probe.invocation;
    let ClosedOperation::CliControl {
        argument_vectors,
        expected_rejection_fragments,
        project_code_placeholder,
        evaluation_marker,
    } = &invocation.operation
    else {
        panic!("CLI probe has the wrong closed operation")
    };
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.classification, "closed");
    assert_eq!(recipe.scenario, "closed");
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert!(probe
        .command
        .iter()
        .map(String::as_str)
        .eq(CLOSED_BATCH_COMMAND));
    assert_eq!(
        invocation.invocation_schema,
        "ibex/capsec-closed-surface-invocation/1"
    );
    assert_eq!(invocation.kind, "closed-surface");
    assert_eq!(invocation.surface_kind, "cli");
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
    assert_eq!(descriptor.kind, "closed-cli-control");
    assert_eq!(
        descriptor.surface_observed_key.as_deref(),
        Some(probe.surface_observed_key.as_str())
    );
    assert!(descriptor.environment_name.is_none());
    assert!(!descriptor.source_refs.is_empty());
    assert!(descriptor.source_metadata.is_object());
    assert_clap_control_descriptor(descriptor);
    let (surface_kind, surface_name) = coverage
        .get(&recipe.edge_ids[0])
        .expect("closed CLI recipe names an unknown coverage edge");
    assert_eq!(surface_kind, &invocation.surface_kind);
    assert_eq!(surface_name, &invocation.surface_name);
    let terminal_observed_key = format!("{surface_kind}:{surface_name}");
    assert_eq!(terminal_observed_key, recipe.terminal_observed_key);
    assert_eq!(terminal_observed_key, probe.surface_observed_key);
    assert!(!argument_vectors.is_empty());
    assert!(!expected_rejection_fragments.is_empty());

    let missing_root = std::env::temp_dir().join(format!(
        "ibex-capsec-closed-cli-missing-{}",
        recipe.plan_digest.trim_start_matches("sha256-")
    ));
    assert!(!missing_root.exists());
    let project_code = missing_root.join("project-code.js");
    let mut errors = std::collections::BTreeSet::new();
    for vector in argument_vectors {
        assert!(!vector.spelling.is_empty());
        assert!(!vector.args.is_empty());
        let mut argv = vec![
            OsString::from("ibex"),
            OsString::from("--capsec-armed-snapshot"),
            missing_root.join("snapshot.json").into_os_string(),
            OsString::from("--capsec-arming-identity"),
            missing_root.join("identity.json").into_os_string(),
        ];
        argv.extend(vector.args.iter().map(|argument| {
            if argument == project_code_placeholder {
                project_code.clone().into_os_string()
            } else {
                OsString::from(argument)
            }
        }));
        let cli = crate::cli::Cli::try_parse_from(argv).unwrap_or_else(|error| {
            panic!(
                "reviewed closed CLI vector {} did not parse: {error}",
                vector.spelling
            )
        });
        let control = descriptor.control_descriptor.as_ref().unwrap();
        match control["kind"].as_str().unwrap() {
            "clap-option" => {
                assert!(control["optionSpellings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|spelling| spelling.as_str() == Some(vector.spelling.as_str())));
                assert!(vector
                    .args
                    .iter()
                    .any(|argument| argument == &vector.spelling));
                if descriptor.source_metadata["evidenceType"] == "cli-option-name" {
                    assert_eq!(
                        descriptor.source_metadata["name"].as_str(),
                        Some(vector.spelling.as_str())
                    );
                }
            }
            "clap-command" | "clap-positional" => {
                assert_eq!(vector.spelling, control["commandPath"].as_str().unwrap())
            }
            other => panic!("unsupported closed CLI vector kind {other}"),
        }
        assert_cli_control_selected(&cli, descriptor, evaluation_marker, &project_code);
        crate::host::abi::install_host(crate::host::Host::strict());
        let session_id = format!(
            "public-observation:{}:{}",
            recipe.plan_digest, vector.spelling
        );
        assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id));
        let error = crate::run(cli)
            .await
            .expect_err("closed CLI control reached production execution");
        let error = format!("{error:#}");
        let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert!(typed.is_empty());
        assert!(
            expected_rejection_fragments
                .iter()
                .all(|fragment| error.contains(fragment)),
            "closed CLI control produced the wrong rejection: {error}"
        );
        assert!(
            !error.contains("failed to read")
                && !error.contains(&project_code.to_string_lossy().to_string())
                && !error.contains(evaluation_marker),
            "closed CLI control reached artifact, engine, or project input: {error}"
        );
        errors.insert(error);
    }
    assert!(!project_code.exists());
    let error_message = errors.into_iter().collect::<Vec<_>>().join(" | ");
    let result = serde_json::json!({
        "kind": "closed",
        "surfaceKind": surface_kind,
        "surfaceName": surface_name,
        "mechanism": invocation.operation.kind(),
        "errorName": "ClosedSurface",
        "errorMessage": error_message,
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
        "legacyObservationCount": 0,
        "typedDecisions": [],
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected closed CLI observation must be an object")
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

#[cfg(test)]
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
    let startup_count = recipe_indexes
        .iter()
        .filter(|index| {
            matches!(
                &closed_surface_probe(&catalog.recipes[**index])
                    .unwrap()
                    .invocation
                    .operation,
                ClosedOperation::StartupEnvironment { .. }
            )
        })
        .count();
    let cli_count = recipe_indexes
        .iter()
        .filter(|index| {
            matches!(
                &closed_surface_probe(&catalog.recipes[**index])
                    .unwrap()
                    .invocation
                    .operation,
                ClosedOperation::CliControl { .. }
            )
        })
        .count();
    let evaluator_count = recipe_indexes
        .iter()
        .filter(|index| {
            matches!(
                &closed_surface_probe(&catalog.recipes[**index])
                    .unwrap()
                    .invocation
                    .operation,
                ClosedOperation::TamedEvaluator { .. }
            )
        })
        .count();
    let loader_count = recipe_indexes
        .iter()
        .filter(|index| {
            matches!(
                &closed_surface_probe(&catalog.recipes[**index])
                    .unwrap()
                    .invocation
                    .operation,
                ClosedOperation::LoaderExecutableFile { .. }
            )
        })
        .count();
    let exact_unendowed_count = recipe_indexes
        .iter()
        .filter(|index| {
            matches!(
                &closed_surface_probe(&catalog.recipes[**index])
                    .unwrap()
                    .invocation
                    .operation,
                ClosedOperation::ExactUnendowedOperation { .. }
            )
        })
        .count();
    let module_runner_namespace_count = recipe_indexes
        .iter()
        .filter(|index| {
            matches!(
                &closed_surface_probe(&catalog.recipes[**index])
                    .unwrap()
                    .invocation
                    .operation,
                ClosedOperation::ModuleRunnerNamespace { .. }
            )
        })
        .count();
    let terminal_builtin_count = recipe_indexes
        .iter()
        .filter(|index| {
            matches!(
                &closed_surface_probe(&catalog.recipes[**index])
                    .unwrap()
                    .invocation
                    .operation,
                ClosedOperation::TerminalBuiltinImport { .. }
            )
        })
        .count();
    let debugger_abi_count = recipe_indexes
        .iter()
        .filter(|index| {
            matches!(
                &closed_surface_probe(&catalog.recipes[**index])
                    .unwrap()
                    .invocation
                    .operation,
                ClosedOperation::DebuggerAbiDisabled { .. }
            )
        })
        .count();
    let shared_runtime_global_absence_count = recipe_indexes
        .iter()
        .filter(|index| {
            matches!(
                &closed_surface_probe(&catalog.recipes[**index])
                    .unwrap()
                    .invocation
                    .operation,
                ClosedOperation::SharedRuntimeGlobalAbsence { .. }
            )
        })
        .count();
    assert_eq!(
        recipe_indexes.len(),
        startup_count
            + cli_count
            + evaluator_count
            + loader_count
            + exact_unendowed_count
            + module_runner_namespace_count
            + terminal_builtin_count
            + debugger_abi_count
            + shared_runtime_global_absence_count,
        "every closed recipe must have an accounted execution family"
    );
    assert_eq!(
        startup_count,
        ibex_runtime::capsec_registry_generated::CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES.len(),
        "expected every generated closed startup environment control"
    );
    assert_eq!(startup_count, 20);
    assert_eq!(cli_count, 114, "expected every rejecting closed CLI facet");
    assert_eq!(
        evaluator_count, 4,
        "expected every reviewed lockdown-tamed evaluator"
    );
    assert_eq!(
        loader_count, 0,
        "authenticated VFS imports cannot claim the legacy loader facets"
    );
    assert_eq!(
        exact_unendowed_count, 1,
        "expected the authenticated Exact app endowment closure fixture"
    );
    assert_eq!(
        module_runner_namespace_count, 1,
        "expected the armed module namespace inspection closure fixture"
    );
    assert_eq!(
        terminal_builtin_count, 106,
        "expected every source facet of the five terminal builtin modules"
    );
    assert_eq!(
        debugger_abi_count, 18,
        "expected every debugger ABI and native-operation facet on Apple"
    );
    assert_eq!(
        shared_runtime_global_absence_count, 33,
        "expected every reviewed legacy-only global path to be absent"
    );
    let _lock = hermes_engine_test_lock().lock().await;
    let _environment_restore = ClosedEnvironmentRestore::clear();
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before closed public recipes");
    attest_exact_engine().await;
    let coverage = coverage_terminals();
    let mut executions = Vec::with_capacity(recipe_indexes.len());
    if terminal_builtin_count > 0 {
        let terminal_indexes = recipe_indexes
            .iter()
            .copied()
            .filter(|index| {
                matches!(
                    &closed_surface_probe(&catalog.recipes[*index])
                        .unwrap()
                        .invocation
                        .operation,
                    ClosedOperation::TerminalBuiltinImport { .. }
                )
            })
            .collect::<Vec<_>>();
        let terminal_imports = terminal_indexes
            .iter()
            .flat_map(|index| {
                let probe = closed_surface_probe(&catalog.recipes[*index]).unwrap();
                let ClosedOperation::TerminalBuiltinImport {
                    module_specifiers, ..
                } = probe.invocation.operation
                else {
                    unreachable!()
                };
                module_specifiers
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let (host, snapshot_digest) =
            build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |snapshot| {
                snapshot["principals"][0]["imports"]["builtins"] =
                    serde_json::json!(terminal_imports);
            });
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
            .expect("create exact terminal builtin closure engine");
        engine
            .load_runtime()
            .await
            .expect("load exact terminal builtin closure runtime");
        let mut engine = AuthenticatedClosedEngine {
            host,
            engine,
            publications: AuthenticatedPublicationTracker::default(),
        };
        for index in terminal_indexes {
            let recipe = &catalog.recipes[index];
            let probe = closed_surface_probe(recipe).unwrap();
            executions.push(
                execute_closed_terminal_builtin_import(
                    &mut engine,
                    recipe,
                    &probe,
                    &coverage,
                    &identity_before.binary_digest,
                )
                .await,
            );
        }
        engine
            .finish()
            .expect("finish authenticated closed-builtin publications");
    }
    if debugger_abi_count > 0 {
        let debugger_indexes = recipe_indexes
            .iter()
            .copied()
            .filter(|index| {
                matches!(
                    &closed_surface_probe(&catalog.recipes[*index])
                        .unwrap()
                        .invocation
                        .operation,
                    ClosedOperation::DebuggerAbiDisabled { .. }
                )
            })
            .collect::<Vec<_>>();
        let (host, snapshot_digest) =
            build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |_| {});
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
            .expect("create exact no-debugger ABI closure engine");
        engine
            .load_runtime()
            .await
            .expect("load exact no-debugger ABI closure runtime");
        let mut engine = AuthenticatedClosedEngine {
            host,
            engine,
            publications: AuthenticatedPublicationTracker::default(),
        };
        for index in debugger_indexes {
            let recipe = &catalog.recipes[index];
            let probe = closed_surface_probe(recipe).unwrap();
            executions.push(
                execute_closed_debugger_abi(
                    &mut engine,
                    recipe,
                    &probe,
                    &coverage,
                    &identity_before.binary_digest,
                )
                .await,
            );
        }
        engine
            .finish()
            .expect("finish authenticated debugger-closure publications");
    }
    if shared_runtime_global_absence_count > 0 {
        let absence_indexes = recipe_indexes
            .iter()
            .copied()
            .filter(|index| {
                matches!(
                    &closed_surface_probe(&catalog.recipes[*index])
                        .unwrap()
                        .invocation
                        .operation,
                    ClosedOperation::SharedRuntimeGlobalAbsence { .. }
                )
            })
            .collect::<Vec<_>>();
        let (host, snapshot_digest) =
            build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |_| {});
        assert_ne!(crate::host::abi::install_host(host.clone()), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
            .expect("create exact shared-runtime global absence engine");
        engine
            .load_runtime()
            .await
            .expect("load exact shared-runtime global absence runtime");
        let mut engine = AuthenticatedClosedEngine {
            host,
            engine,
            publications: AuthenticatedPublicationTracker::default(),
        };
        for index in absence_indexes {
            let recipe = &catalog.recipes[index];
            let probe = closed_surface_probe(recipe).unwrap();
            executions.push(
                execute_closed_shared_runtime_global_absence(
                    &mut engine,
                    recipe,
                    &probe,
                    &coverage,
                    &identity_before.binary_digest,
                )
                .await,
            );
        }
        engine
            .finish()
            .expect("finish authenticated shared-runtime-closure publications");
    }
    for index in recipe_indexes {
        let recipe = &catalog.recipes[index];
        let probe = closed_surface_probe(recipe).unwrap();
        if matches!(
            &probe.invocation.operation,
            ClosedOperation::TerminalBuiltinImport { .. }
                | ClosedOperation::DebuggerAbiDisabled { .. }
                | ClosedOperation::SharedRuntimeGlobalAbsence { .. }
        ) {
            continue;
        }
        executions.push(match &probe.invocation.operation {
            ClosedOperation::StartupEnvironment { .. } => {
                execute_closed_startup_environment(
                    recipe,
                    &probe,
                    &coverage,
                    &identity_before.binary_digest,
                )
                .await
            }
            ClosedOperation::CliControl { .. } => {
                execute_closed_cli_control(
                    recipe,
                    &probe,
                    &coverage,
                    &identity_before.binary_digest,
                )
                .await
            }
            ClosedOperation::TamedEvaluator { .. } => {
                execute_closed_tamed_evaluator(
                    recipe,
                    &probe,
                    &coverage,
                    &identity_before.binary_digest,
                )
                .await
            }
            ClosedOperation::LoaderExecutableFile { .. } => {
                panic!("authenticated VFS imports cannot prove the legacy loader facet")
            }
            ClosedOperation::ExactUnendowedOperation { .. } => {
                execute_closed_exact_unendowed_operation(
                    recipe,
                    &probe,
                    &coverage,
                    &identity_before.binary_digest,
                )
                .await
            }
            ClosedOperation::ModuleRunnerNamespace { .. } => {
                execute_closed_module_runner_namespace(
                    recipe,
                    &probe,
                    &coverage,
                    &identity_before.binary_digest,
                )
                .await
            }
            ClosedOperation::TerminalBuiltinImport { .. } => unreachable!(),
            ClosedOperation::DebuggerAbiDisabled { .. } => unreachable!(),
            ClosedOperation::SharedRuntimeGlobalAbsence { .. } => unreachable!(),
        });
    }
    executions.sort_by(|left, right| left["fixtureId"].as_str().cmp(&right["fixtureId"].as_str()));
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
