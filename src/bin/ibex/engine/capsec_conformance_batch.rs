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
        details: Box<NativePublicInvocation>,
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
            Self::NativeGlobal { details } => Some(details.as_ref()),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_access: Option<NativePublicAccess>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_access_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_deny_message_fragment: Option<String>,
    arguments: Vec<NativeProbeArgument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion: Option<NativeProbeCompletion>,
    #[serde(default)]
    required_floor: Vec<serde_json::Value>,
    /// Setup-infrastructure authority (e.g. the overlay-seeding env:write for
    /// the enumeration probe): granted in every scenario, never denied — the
    /// deny scenario refuses exactly the operation's declared capability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    required_setup_floor: Vec<serde_json::Value>,
    setup: Vec<NativeProbeSetup>,
    expected_result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_string_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_cleanup: Option<String>,
    expected_typed_stages: Vec<String>,
    /// Per-decision typed outcomes, pinned from the observed run, for
    /// denial-return surfaces whose public result is an ordinary return even
    /// though the typed decision was refused (the `existsSync` shape: the
    /// typed denied decision, not an exception, is the denial evidence).
    /// Omitted everywhere else, where the outcome follows `expected_result`.
    /// @ref LLP 0037#denial-return-evidence-existssync
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    expected_typed_outcomes: Vec<String>,
    expected_typed_decision_count: usize,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativePublicAccess {
    kind: String,
    observed_key: String,
    install_id: String,
    path: Vec<String>,
    source_refs: Vec<String>,
    private_terminal: NativePrivateTerminal,
    expected_deny_message_fragment: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativePrivateTerminal {
    observed_key: String,
    install_id: String,
    private_consumer: String,
    live_expectation: String,
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
    HarnessUint8ArrayList {
        #[serde(rename = "byteLengths")]
        byte_lengths: Vec<usize>,
    },
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
    FsWriteFile {
        #[serde(rename = "globalName")]
        global_name: String,
        path: String,
        #[serde(rename = "sourceDescriptor")]
        source_descriptor: serde_json::Value,
        #[serde(rename = "sourceDescriptorDigest")]
        source_descriptor_digest: String,
    },
    SqliteFile {
        path: String,
    },
    SqliteFileDatabase {
        #[serde(rename = "globalName")]
        global_name: String,
        path: String,
        options: serde_json::Value,
        #[serde(rename = "sourceDescriptor")]
        source_descriptor: serde_json::Value,
        #[serde(rename = "sourceDescriptorDigest")]
        source_descriptor_digest: String,
    },
    SqliteFileStatement {
        #[serde(rename = "globalName")]
        global_name: String,
        sql: String,
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
fn native_sqlite_file_setup_is_real_and_bounded() {
    let path = "target/ibex-capsec-sqlite-open-read.sqlite";
    let mut cleanup = NativePublicFixtureCleanup::default();
    cleanup
        .files
        .extend(native_sqlite_owned_paths(path).map(Into::into));
    create_native_sqlite_file_fixture(path);

    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("reopen SQLite setup read-only");
    let value: String = connection
        .query_row("SELECT value FROM ibex_capsec_probe", [], |row| row.get(0))
        .expect("read seeded SQLite setup row");
    assert_eq!(value, "file-backed");
    drop(connection);

    let escaped = std::panic::catch_unwind(|| {
        create_native_sqlite_file_fixture("target/ibex-capsec-sqlite-escaped.sqlite")
    });
    assert!(escaped.is_err(), "SQLite setup accepted an unowned path");
}

#[tokio::test(flavor = "current_thread")]
async fn retained_sqlite_setup_creates_a_real_file_backed_native_handle() {
    let _lock = hermes_engine_test_lock().lock().await;
    let path = ".ibex-capsec-sqlite-retained-test.sqlite";
    let selector = serde_json::json!({
        "cap": "fs:read",
        "resource": {
            "kind": "path-exact",
            "path": {
                "root": "project",
                "components": [
                    { "encoding": "utf8", "value": ".ibex-capsec-sqlite-retained-test.sqlite" }
                ]
            }
        }
    });
    let open_source = serde_json::json!({
        "kind": "native-global-function",
        "globalName": "__exactSqliteOpen",
        "arity": 2,
        "sourceRef": "src/engine/hermes_runtime_sqlite.cc#jsi-global:__exactSqliteOpen",
    });
    let prepare_source = serde_json::json!({
        "kind": "native-global-function",
        "globalName": "__exactSqlitePrepare",
        "arity": 2,
        "sourceRef": "src/engine/hermes_runtime_sqlite.cc#jsi-global:__exactSqlitePrepare",
    });
    let invocation = NativePublicInvocation {
        kind: "native-global-function".into(),
        global_name: "__exactSqliteExec".into(),
        source_descriptor: serde_json::json!({
            "kind": "native-global-function",
            "globalName": "__exactSqliteExec",
            "arity": 2,
            "sourceRef": "src/engine/hermes_runtime_sqlite.cc#jsi-global:__exactSqliteExec",
        }),
        source_descriptor_digest: "unused-by-setup-test".into(),
        public_access: None,
        public_access_digest: None,
        expected_deny_message_fragment: None,
        arguments: vec![],
        completion: None,
        required_floor: vec![selector.clone()],
        required_setup_floor: vec![selector],
        setup: vec![
            NativeProbeSetup::SqliteFileDatabase {
                global_name: "__exactSqliteOpen".into(),
                path: path.into(),
                options: serde_json::json!({ "readonly": true }),
                source_descriptor_digest: tagged_value_digest(&open_source),
                source_descriptor: open_source,
            },
            NativeProbeSetup::SqliteFileStatement {
                global_name: "__exactSqlitePrepare".into(),
                sql: "SELECT value FROM ibex_capsec_probe".into(),
                source_descriptor_digest: tagged_value_digest(&prepare_source),
                source_descriptor: prepare_source,
            },
        ],
        expected_result: "return".into(),
        expected_string_value: None,
        expected_cleanup: None,
        expected_typed_stages: vec![],
        expected_typed_outcomes: vec![],
        expected_typed_decision_count: 0,
        allowed_coverage_edge_ids: vec![],
        expected_action_ids: vec![],
    };
    let mut cleanup = NativePublicFixtureCleanup::default();
    cleanup
        .files
        .extend(native_sqlite_owned_paths(path).map(Into::into));
    for owned_path in native_sqlite_owned_paths(path) {
        if let Err(error) = std::fs::remove_file(&owned_path) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "clear retained SQLite test fixture {owned_path}: {error}"
            );
        }
    }
    assert!(
        !std::path::Path::new(path).exists(),
        "retained SQLite test path must be absent before the runtime open"
    );
    let (host, _reset, snapshot_digest, probe_principals) =
        install_native_public_test_host(&invocation, None, false);
    assert_eq!(probe_principals.as_deref(), Some(&[0, 1][..]));
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create retained SQLite setup engine");
    engine
        .load_runtime()
        .await
        .expect("load retained SQLite setup engine");
    let mut engine = AuthenticatedNativeEngine {
        host,
        engine,
        publications: AuthenticatedPublicationTracker::default(),
        probe_principals,
    };
    let absent = engine
        .eval_immediate(&setup_script(
            "__exactSqliteOpen",
            &[
                serde_json::json!(path),
                serde_json::json!({ "readonly": true }),
            ],
        ))
        .await
        .expect("attempt absent file-backed SQLite open")
        .expect("absent file-backed SQLite open returned no result");
    let absent: serde_json::Value =
        serde_json::from_str(&absent).expect("absent SQLite result must be JSON");
    assert_eq!(
        absent["kind"], "throw",
        "read-only SQLite open unexpectedly succeeded before its file existed: {absent}"
    );
    let setup = run_native_setup(&mut engine, &invocation, None).await;
    let handle = setup
        .sqlite_database_handle
        .expect("file-backed setup did not return a native SQLite handle");
    let statement = setup
        .sqlite_statement_handle
        .expect("file-backed setup did not return a native SQLite statement");
    assert_eq!(setup.sqlite_file_path.as_deref(), Some(path));
    let read = engine
        .eval_immediate(&format!(
            "JSON.stringify((function(){{try{{var result=globalThis.__exactSqliteGet({},null);return {{kind:\"return\",row:result.row}};}}catch(e){{return {{kind:\"throw\",errorMessage:String(e&&e.message||e)}};}}}})())",
            serde_json::to_string(&statement).expect("serialize SQLite statement handle")
        ))
        .await
        .expect("read seeded row through native SQLite statement")
        .expect("native SQLite get returned no result");
    let read: serde_json::Value =
        serde_json::from_str(&read).expect("native SQLite get result must be JSON");
    assert_eq!(read["kind"], "return", "native SQLite get failed: {read}");
    assert_eq!(
        read["row"]["value"], "file-backed",
        "returned native handle did not read the seeded on-disk row"
    );
    let closed = engine
        .eval_immediate(&format!(
            "JSON.stringify((function(){{try{{globalThis.__exactSqliteFinalize({});globalThis.__exactSqliteClose({});return {{kind:\"return\"}};}}catch(e){{return {{kind:\"throw\",errorMessage:String(e&&e.message||e)}};}}}})())",
            serde_json::to_string(&statement).expect("serialize SQLite statement handle"),
            serde_json::to_string(&handle).expect("serialize SQLite database handle")
        ))
        .await
        .expect("close real file-backed SQLite setup handles")
        .expect("SQLite cleanup returned no result");
    let closed: serde_json::Value = serde_json::from_str(&closed).unwrap();
    assert_eq!(closed["kind"], "return");
    engine.finish().expect("finish retained SQLite setup engine");
}

#[test]
fn native_sqlite_file_setup_binding_is_exact() {
    let invocation = |global_name: &str, argument: serde_json::Value| NativePublicInvocation {
        kind: "native-global-function".into(),
        global_name: global_name.into(),
        source_descriptor: serde_json::json!({}),
        source_descriptor_digest: "sha256-test".into(),
        public_access: None,
        public_access_digest: None,
        expected_deny_message_fragment: None,
        arguments: vec![NativeProbeArgument::JsonLiteral { value: argument }],
        completion: None,
        required_floor: Vec::new(),
        required_setup_floor: Vec::new(),
        setup: Vec::new(),
        expected_result: "return".into(),
        expected_string_value: None,
        expected_cleanup: None,
        expected_typed_stages: Vec::new(),
        expected_typed_outcomes: Vec::new(),
        expected_typed_decision_count: 0,
        allowed_coverage_edge_ids: Vec::new(),
        expected_action_ids: Vec::new(),
    };
    let path = "target/ibex-capsec-sqlite-open-read.sqlite";
    assert!(native_sqlite_file_setup_is_bound(
        &invocation("__exactSqliteOpen", serde_json::json!(path)),
        path,
    ));
    assert!(!native_sqlite_file_setup_is_bound(
        &invocation("__exactSqliteExec", serde_json::json!(path)),
        path,
    ));
    assert!(!native_sqlite_file_setup_is_bound(
        &invocation(
            "__exactSqliteOpen",
            serde_json::json!("target/another.sqlite"),
        ),
        path,
    ));
    assert!(!native_sqlite_file_setup_is_bound(
        &invocation("__exactSqliteOpen", serde_json::Value::Null),
        path,
    ));
}

#[test]
fn native_public_probe_serialization_preserves_omitted_optional_fields() {
    let invocation = NativePublicInvocation {
        kind: "native-global-function".into(),
        global_name: "__exactGetCwd".into(),
        source_descriptor: serde_json::json!({}),
        source_descriptor_digest: "sha256-test".into(),
        public_access: None,
        public_access_digest: None,
        expected_deny_message_fragment: None,
        arguments: Vec::new(),
        completion: None,
        required_floor: Vec::new(),
        required_setup_floor: Vec::new(),
        setup: Vec::new(),
        expected_result: "return".into(),
        expected_string_value: None,
        expected_cleanup: None,
        expected_typed_stages: Vec::new(),
        expected_typed_outcomes: Vec::new(),
        expected_typed_decision_count: 0,
        allowed_coverage_edge_ids: Vec::new(),
        expected_action_ids: Vec::new(),
    };

    let serialized = serde_json::to_value(invocation).expect("serialize native public probe");
    assert!(serialized.get("completion").is_none());
    assert!(serialized.get("expectedStringValue").is_none());
    assert!(serialized.get("expectedCleanup").is_none());
}

#[test]
fn native_async_worker_terminal_account_is_exact() {
    assert_eq!(
        NATIVE_ASYNC_WORKER_TERMINALS,
        [
            ("access", "native-op:__exactAccess"),
            ("mkdir", "native-op:__exactMkdir"),
            ("readdir", "native-op:__exactReaddir"),
            ("readlink", "native-op:__exactReadlink"),
            ("realpath", "native-op:__exactRealpath"),
            ("statfs", "native-op:__exactStatfs"),
            ("truncate", "native-op:__exactTruncate"),
        ]
    );
    let invocation = |global_name: &str, operation: serde_json::Value| NativePublicInvocation {
        kind: "native-global-function".into(),
        global_name: global_name.into(),
        source_descriptor: serde_json::json!({}),
        source_descriptor_digest: "sha256-test".into(),
        public_access: None,
        public_access_digest: None,
        expected_deny_message_fragment: None,
        arguments: vec![NativeProbeArgument::JsonLiteral { value: operation }],
        completion: None,
        required_floor: Vec::new(),
        required_setup_floor: Vec::new(),
        setup: Vec::new(),
        expected_result: "return".into(),
        expected_string_value: None,
        expected_cleanup: None,
        expected_typed_stages: Vec::new(),
        expected_typed_outcomes: Vec::new(),
        expected_typed_decision_count: 0,
        allowed_coverage_edge_ids: Vec::new(),
        expected_action_ids: Vec::new(),
    };

    for (operation, terminal) in NATIVE_ASYNC_WORKER_TERMINALS {
        assert_eq!(
            native_async_worker_terminal(&invocation(
                "__exactFsPathAsync",
                serde_json::Value::String(operation.into()),
            )),
            Some(terminal)
        );
    }
    assert_eq!(
        native_async_worker_terminal(&invocation(
            "__exactFsPathAsync",
            serde_json::Value::String("mkdtemp".into()),
        )),
        None
    );
    assert_eq!(
        native_async_worker_terminal(&invocation(
            "__exactMkdir",
            serde_json::Value::String("mkdir".into()),
        )),
        None
    );
    assert_eq!(
        native_async_worker_terminal(&invocation("__exactFsPathAsync", serde_json::Value::Null,)),
        None
    );
}

#[test]
fn native_incidental_traversal_allowance_is_exact_and_fail_closed() {
    let invocation = |global_name: &str, operation: Option<&str>| NativePublicInvocation {
        kind: "native-global-function".into(),
        global_name: global_name.into(),
        source_descriptor: serde_json::json!({}),
        source_descriptor_digest: "sha256-test".into(),
        public_access: None,
        public_access_digest: None,
        expected_deny_message_fragment: None,
        arguments: operation
            .map(|operation| NativeProbeArgument::JsonLiteral {
                value: serde_json::json!(operation),
            })
            .into_iter()
            .collect(),
        completion: None,
        required_floor: Vec::new(),
        required_setup_floor: Vec::new(),
        setup: Vec::new(),
        expected_result: "return".into(),
        expected_string_value: None,
        expected_cleanup: None,
        expected_typed_stages: Vec::new(),
        expected_typed_outcomes: Vec::new(),
        expected_typed_decision_count: 0,
        allowed_coverage_edge_ids: Vec::new(),
        expected_action_ids: vec!["fs:read".into()],
    };
    let declared_and_traversal = BTreeSet::from(["fs:list".into(), "fs:read".into()]);
    let missing_declared = BTreeSet::from(["fs:list".into()]);
    let unrelated_surplus =
        BTreeSet::from(["fs:list".into(), "fs:read".into(), "network:connect".into()]);

    let direct = invocation("__exactReadlink", None);
    assert_eq!(
        reviewed_native_open_traversal_prefix(&direct),
        Some("fs-readlink:")
    );
    assert!(native_observed_actions_are_reviewed(
        &direct,
        &declared_and_traversal
    ));
    assert!(!native_observed_actions_are_reviewed(
        &direct,
        &missing_declared
    ));
    assert!(!native_observed_actions_are_reviewed(
        &direct,
        &unrelated_surplus
    ));

    let asynchronous = invocation("__exactFsPathAsync", Some("readlink"));
    assert_eq!(
        reviewed_native_open_traversal_prefix(&asynchronous),
        Some("fs-readlink:")
    );
    assert!(native_observed_actions_are_reviewed(
        &asynchronous,
        &declared_and_traversal
    ));

    let wrong_branch = invocation("__exactFsPathAsync", Some("readdir"));
    assert_eq!(reviewed_native_open_traversal_prefix(&wrong_branch), None);
    assert!(!native_observed_actions_are_reviewed(
        &wrong_branch,
        &declared_and_traversal
    ));

    let mut write_file = invocation(
        "__exactFsWriteFileAsync",
        Some("target/ibex-capsec-fswritefileasync-path"),
    );
    write_file.expected_action_ids = vec!["fs:write".into()];
    let declared_write_and_traversal = BTreeSet::from(["fs:list".into(), "fs:write".into()]);
    assert_eq!(
        native_async_write_file_fixture_path(&write_file),
        Some("target/ibex-capsec-fswritefileasync-path")
    );
    assert_eq!(
        reviewed_native_open_traversal_prefix(&write_file),
        Some("fs-write-file-async:")
    );
    assert!(native_observed_actions_are_reviewed(
        &write_file,
        &declared_write_and_traversal
    ));
    let mut wrong_write_path = invocation(
        "__exactFsWriteFileAsync",
        Some("target/not-owned-by-this-fixture"),
    );
    wrong_write_path.expected_action_ids = vec!["fs:write".into()];
    assert_eq!(
        native_async_write_file_fixture_path(&wrong_write_path),
        None
    );
    assert_eq!(
        reviewed_native_open_traversal_prefix(&wrong_write_path),
        None
    );
    let mut wrong_write_action = invocation(
        "__exactFsWriteFileAsync",
        Some("target/ibex-capsec-fswritefileasync-path"),
    );
    wrong_write_action.expected_action_ids = vec!["fs:list".into()];
    assert_eq!(
        reviewed_native_open_traversal_prefix(&wrong_write_action),
        None
    );

    let traversal_decision = |stage: &str, operation_id: &str| {
        serde_json::json!({
            "decisionSet": {
                "context": { "stage": stage },
                "operationId": operation_id,
            },
        })
    };
    let list_effects = vec![serde_json::json!({ "cap": "fs:list" })];
    assert!(native_decision_is_reviewed_open_traversal(
        &direct,
        &traversal_decision("discovery", "fs-readlink:/project/CLAUDE.md"),
        &list_effects,
        false,
    ));
    assert!(!native_decision_is_reviewed_open_traversal(
        &direct,
        &traversal_decision("commit", "fs-readlink:/project/CLAUDE.md"),
        &list_effects,
        false,
    ));
    assert!(!native_decision_is_reviewed_open_traversal(
        &direct,
        &traversal_decision("discovery", "fs-readdir:/project"),
        &list_effects,
        false,
    ));
    assert!(!native_decision_is_reviewed_open_traversal(
        &direct,
        &traversal_decision("discovery", "fs-readlink:/project/CLAUDE.md"),
        &list_effects,
        true,
    ));
    assert!(native_decision_is_reviewed_open_traversal(
        &write_file,
        &traversal_decision(
            "repeat",
            "fs-write-file-async:/project/target/ibex-capsec-fswritefileasync-path",
        ),
        &list_effects,
        false,
    ));
    assert!(!native_decision_is_reviewed_open_traversal(
        &write_file,
        &traversal_decision(
            "commit",
            "fs-write-file-async:/project/target/ibex-capsec-fswritefileasync-path",
        ),
        &list_effects,
        false,
    ));
}

#[test]
fn native_which_early_denial_action_prefix_is_exact_and_fail_closed() {
    let invocation = |global_name: &str,
                      argument: &str,
                      expected_result: &str,
                      expected_stages: &[&str],
                      expected_count: usize,
                      expected_actions: &[&str]| NativePublicInvocation {
        kind: "native-global-function".into(),
        global_name: global_name.into(),
        source_descriptor: serde_json::json!({}),
        source_descriptor_digest: "sha256-test".into(),
        public_access: None,
        public_access_digest: None,
        expected_deny_message_fragment: None,
        arguments: vec![NativeProbeArgument::JsonLiteral {
            value: serde_json::json!(argument),
        }],
        completion: None,
        required_floor: Vec::new(),
        required_setup_floor: Vec::new(),
        setup: Vec::new(),
        expected_result: expected_result.into(),
        expected_string_value: None,
        expected_cleanup: None,
        expected_typed_stages: expected_stages
            .iter()
            .map(|stage| (*stage).into())
            .collect(),
        expected_typed_outcomes: Vec::new(),
        expected_typed_decision_count: expected_count,
        allowed_coverage_edge_ids: Vec::new(),
        expected_action_ids: expected_actions
            .iter()
            .map(|action| (*action).into())
            .collect(),
    };
    let observed_prefix = BTreeSet::from(["env:read".to_owned()]);
    let exact = invocation(
        "__exactWhich",
        "ref-check",
        "permission-denied",
        &["requested"],
        1,
        &["env:read", "fs:list"],
    );
    assert!(reviewed_native_early_denial_action_prefix(
        &exact,
        &observed_prefix
    ));
    assert!(native_observed_actions_are_reviewed(
        &exact,
        &observed_prefix
    ));

    for nearby in [
        invocation(
            "__exactWhichExtra",
            "ref-check",
            "permission-denied",
            &["requested"],
            1,
            &["env:read", "fs:list"],
        ),
        invocation(
            "__exactWhich",
            "/project/ref-check",
            "permission-denied",
            &["requested"],
            1,
            &["env:read", "fs:list"],
        ),
        invocation(
            "__exactWhich",
            "ref-check",
            "return",
            &["requested"],
            1,
            &["env:read", "fs:list"],
        ),
        invocation(
            "__exactWhich",
            "ref-check",
            "permission-denied",
            &["requested", "commit"],
            2,
            &["env:read", "fs:list"],
        ),
        invocation(
            "__exactWhich",
            "ref-check",
            "permission-denied",
            &["requested"],
            1,
            &["env:read"],
        ),
    ] {
        assert!(!reviewed_native_early_denial_action_prefix(
            &nearby,
            &observed_prefix
        ));
        assert!(!native_observed_actions_are_reviewed(
            &nearby,
            &observed_prefix
        ));
    }

    for wrong_observed in [
        BTreeSet::new(),
        BTreeSet::from(["fs:list".to_owned()]),
        BTreeSet::from(["env:read".to_owned(), "fs:list".to_owned()]),
        BTreeSet::from(["env:read".to_owned(), "network:connect".to_owned()]),
    ] {
        assert!(!reviewed_native_early_denial_action_prefix(
            &exact,
            &wrong_observed
        ));
        assert!(!native_observed_actions_are_reviewed(
            &exact,
            &wrong_observed
        ));
    }
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

#[test]
fn native_async_argument_producer_is_exact_and_fail_closed() {
    let supported = serde_json::json!({
        "kind": "native-global-result",
        "globalName": "__exactStringToUtf8Bytes",
        "arguments": [{
            "kind": "json-literal",
            "value": "ibex-capsec-async-write-file"
        }]
    });
    assert!(native_async_argument_is_supported(&supported));

    let mut wrong_producer = supported.clone();
    wrong_producer["globalName"] = serde_json::json!("__exactUtf8BytesToString");
    assert!(!native_async_argument_is_supported(&wrong_producer));

    let mut wrong_argument = supported.clone();
    wrong_argument["arguments"][0]["value"] = serde_json::json!("different-bytes");
    assert!(!native_async_argument_is_supported(&wrong_argument));

    let mut extra_argument = supported;
    extra_argument["arguments"] = serde_json::json!([
        {"kind": "json-literal", "value": "ibex-capsec-async-write-file"},
        {"kind": "json-literal", "value": "extra"}
    ]);
    assert!(!native_async_argument_is_supported(&extra_argument));
    assert!(!native_async_argument_is_supported(
        &serde_json::json!({"kind": "native-global-result-property"})
    ));
}

#[test]
fn native_async_write_file_fixture_lifecycle_is_exact_and_fail_closed() {
    let path = NATIVE_ASYNC_WRITE_FILE_FIXTURE_PATH;
    let mut cleanup = NativePublicFixtureCleanup::default();
    prepare_native_async_write_file_fixture(path, &mut cleanup);
    assert_eq!(cleanup.files, [std::path::PathBuf::from(path)]);
    assert!(!std::path::Path::new(path).exists());

    std::fs::write(path, b"wrong-bytes").expect("write wrong async write-file fixture bytes");
    let mut returned = serde_json::json!({ "kind": "return" });
    let wrong_bytes = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        finalize_native_async_write_file_fixture(path, &mut returned);
    }));
    assert!(
        wrong_bytes.is_err(),
        "async write-file accepted wrong bytes"
    );

    std::fs::write(path, NATIVE_ASYNC_WRITE_FILE_FIXTURE_BYTES)
        .expect("write exact async write-file fixture bytes");
    finalize_native_async_write_file_fixture(path, &mut returned);
    assert_eq!(returned["cleanup"], "removed-owned-file");
    assert!(!std::path::Path::new(path).exists());

    std::fs::write(path, NATIVE_ASYNC_WRITE_FILE_FIXTURE_BYTES)
        .expect("write forbidden denied async write-file fixture state");
    let mut denied = serde_json::json!({ "kind": "throw" });
    let denied_state = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        finalize_native_async_write_file_fixture(path, &mut denied);
    }));
    assert!(
        denied_state.is_err(),
        "denied async write-file accepted changed physical state"
    );
    std::fs::remove_file(path).expect("remove forbidden denied async write-file fixture state");
    finalize_native_async_write_file_fixture(path, &mut denied);
    assert!(denied.get("cleanup").is_none());

    let escaped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prepare_native_async_write_file_fixture("target/not-owned-by-this-fixture", &mut cleanup);
    }));
    assert!(
        escaped.is_err(),
        "async write-file cleanup accepted an unowned path"
    );
}

#[test]
fn native_filesystem_denial_message_allowance_is_exact_and_fail_closed() {
    assert!(native_filesystem_denial_message_is_reviewed(
        "__exactFsStatAsync"
    ));
    assert!(!native_filesystem_denial_message_is_reviewed(
        "__exactFsStatAsyncExtra"
    ));
    assert!(!native_filesystem_denial_message_is_reviewed(
        "__exactFsLstatAsync"
    ));
    assert!(native_filesystem_denial_message_is_reviewed("__exactWhich"));
    assert!(!native_filesystem_denial_message_is_reviewed(
        "__exactWhichExtra"
    ));
}

#[test]
fn native_closed_filesystem_mutation_account_is_exact_and_fail_closed() {
    let invocation =
        |global_name: &str, arguments: Vec<serde_json::Value>| NativePublicInvocation {
            kind: "native-global-function".into(),
            global_name: global_name.into(),
            source_descriptor: serde_json::json!({}),
            source_descriptor_digest: "sha256-test".into(),
            public_access: None,
            public_access_digest: None,
            expected_deny_message_fragment: Some("EPERM: operation not permitted".into()),
            arguments: arguments
                .into_iter()
                .map(|value| NativeProbeArgument::JsonLiteral { value })
                .collect(),
            completion: (global_name != "__exactMkdir").then_some(NativeProbeCompletion {
                kind: "event-loop-quiescence".into(),
                timeout_milliseconds: 1_000,
            }),
            required_floor: Vec::new(),
            required_setup_floor: Vec::new(),
            setup: Vec::new(),
            expected_result: "permission-denied".into(),
            expected_string_value: None,
            expected_cleanup: None,
            expected_typed_stages: Vec::new(),
            expected_typed_outcomes: Vec::new(),
            expected_typed_decision_count: 0,
            allowed_coverage_edge_ids: Vec::new(),
            expected_action_ids: Vec::new(),
        };
    let exact_cases = [
        (
            "__exactMkdir",
            serde_json::json!(["target/ibex-capsec-mkdir-recursive-closed", true, -1]),
        ),
        (
            "__exactFsFdAsync",
            serde_json::json!(["fchmod", 42, 0o600, 0]),
        ),
        ("__exactFsFdAsync", serde_json::json!(["fchown", 42, 0, 0])),
        ("__exactFsFdAsync", serde_json::json!(["futimes", 42, 0, 0])),
        (
            "__exactFsPathAsync",
            serde_json::json!(["chown", "target/ibex-capsec-closed-chown", null, 0, 0, 0]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!([
                "copyfile",
                "target/ibex-capsec-closed-copyfile-source",
                "target/ibex-capsec-closed-copyfile-destination",
                0,
                0,
                0
            ]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!([
                "copyfile_excl",
                "target/ibex-capsec-closed-copyfile-excl-source",
                "target/ibex-capsec-closed-copyfile-excl-destination",
                0,
                0,
                0
            ]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!([
                "lchmod",
                "target/ibex-capsec-closed-lchmod",
                null,
                0o600,
                0,
                0
            ]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!(["lchown", "target/ibex-capsec-closed-lchown", null, 0, 0, 0]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!([
                "link",
                "target/ibex-capsec-closed-link-source",
                "target/ibex-capsec-closed-link-destination",
                0,
                0,
                0
            ]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!(["lutime", "target/ibex-capsec-closed-lutime", null, 0, 0, 0]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!([
                "mkdir",
                "target/ibex-capsec-fspathasync-closed-mkdir-recursive",
                null,
                1,
                -1,
                0
            ]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!([
                "mkdtemp",
                "target/ibex-capsec-closed-mkdtemp-",
                null,
                0,
                0,
                0
            ]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!([
                "rename",
                "target/ibex-capsec-closed-rename-source",
                "target/ibex-capsec-closed-rename-destination",
                0,
                0,
                0
            ]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!(["rmdir", "target/ibex-capsec-closed-rmdir", null, 0, 0, 0]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!([
                "symlink",
                "closed-symlink-target",
                "target/ibex-capsec-closed-symlink",
                0,
                0,
                0
            ]),
        ),
        (
            "__exactFsPathAsync",
            serde_json::json!(["unlink", "target/ibex-capsec-closed-unlink", null, 0, 0, 0]),
        ),
    ];
    for (global_name, arguments) in exact_cases {
        let operation = if global_name == "__exactMkdir" {
            "mkdir".to_owned()
        } else {
            arguments[0]
                .as_str()
                .expect("closed mutation operation")
                .to_owned()
        };
        let exact_invocation = invocation(
            global_name,
            arguments
                .as_array()
                .expect("closed mutation arguments")
                .clone(),
        );
        assert!(native_closed_filesystem_mutation_is_reviewed(
            "closed",
            "branch-selection",
            &exact_invocation,
        ));
        assert!(native_closed_filesystem_mutation_result_is_reviewed(
            "closed",
            "branch-selection",
            &exact_invocation,
            &serde_json::json!({
                "kind": "throw",
                "globalName": global_name,
                "errorName": "Error",
                "errorMessage": format!("EPERM: operation not permitted, {operation}"),
            }),
        ));
    }

    let exact = || {
        invocation(
            "__exactFsFdAsync",
            serde_json::json!(["fchmod", 42, 0o600, 0])
                .as_array()
                .unwrap()
                .clone(),
        )
    };
    assert!(!native_closed_filesystem_mutation_is_reviewed(
        "effects",
        "branch-selection",
        &exact(),
    ));
    assert!(!native_closed_filesystem_mutation_is_reviewed(
        "closed",
        "closed",
        &exact(),
    ));
    let mut nearby = exact();
    nearby.global_name = "__exactFsFdAsyncExtra".into();
    assert!(!native_closed_filesystem_mutation_is_reviewed(
        "closed",
        "branch-selection",
        &nearby,
    ));
    let mut nearby = exact();
    nearby.expected_deny_message_fragment = Some("Permission denied".into());
    assert!(!native_closed_filesystem_mutation_is_reviewed(
        "closed",
        "branch-selection",
        &nearby,
    ));
    let mut nearby = exact();
    nearby.expected_action_ids.push("fs:write".into());
    assert!(!native_closed_filesystem_mutation_is_reviewed(
        "closed",
        "branch-selection",
        &nearby,
    ));
    let mut nearby = exact();
    nearby.expected_typed_decision_count = 1;
    assert!(!native_closed_filesystem_mutation_is_reviewed(
        "closed",
        "branch-selection",
        &nearby,
    ));
    let wrong_descriptor = invocation(
        "__exactFsFdAsync",
        serde_json::json!(["fchmod", 43, 0o600, 0])
            .as_array()
            .unwrap()
            .clone(),
    );
    assert!(!native_closed_filesystem_mutation_is_reviewed(
        "closed",
        "branch-selection",
        &wrong_descriptor,
    ));
    let wrong_path = invocation(
        "__exactFsPathAsync",
        serde_json::json!(["unlink", "target/not-reviewed", null, 0, 0, 0])
            .as_array()
            .unwrap()
            .clone(),
    );
    assert!(!native_closed_filesystem_mutation_is_reviewed(
        "closed",
        "branch-selection",
        &wrong_path,
    ));
    let wrong_recursive_path = invocation(
        "__exactMkdir",
        serde_json::json!(["target/ibex-capsec-mkdir-recursive-nearby", true, -1])
            .as_array()
            .unwrap()
            .clone(),
    );
    assert!(!native_closed_filesystem_mutation_is_reviewed(
        "closed",
        "branch-selection",
        &wrong_recursive_path,
    ));
    assert!(!native_closed_filesystem_mutation_result_is_reviewed(
        "closed",
        "branch-selection",
        &exact(),
        &serde_json::json!({
            "kind": "throw",
            "globalName": "__exactFsFdAsync",
            "errorName": "Error",
            "errorMessage": "EPERM: operation not permitted, fchown",
        }),
    ));
}

#[test]
fn native_which_string_result_account_is_exact_and_fail_closed() {
    let slash_arguments = [NativeProbeArgument::JsonLiteral {
        value: serde_json::json!("/project/ref-check"),
    }];
    let bare_arguments = [NativeProbeArgument::JsonLiteral {
        value: serde_json::json!("ref-check"),
    }];
    let exact_result = serde_json::json!({
        "kind": "return",
        "globalName": "__exactWhich",
        "valueType": "string",
        "cleanup": "none",
        "stringValue": "/project/ref-check",
    });
    assert!(native_string_result_matches_reviewed_expectation(
        "__exactWhich",
        &slash_arguments,
        "/project/ref-check",
        &exact_result,
    ));
    assert!(native_string_result_matches_reviewed_expectation(
        "__exactWhich",
        &bare_arguments,
        "/project/ref-check",
        &exact_result,
    ));

    let mut wrong_result = exact_result.clone();
    wrong_result["stringValue"] = serde_json::json!("/backing/project/ref-check");
    assert!(!native_string_result_matches_reviewed_expectation(
        "__exactWhich",
        &slash_arguments,
        "/project/ref-check",
        &wrong_result,
    ));
    assert!(!native_string_result_matches_reviewed_expectation(
        "__exactWhichExtra",
        &slash_arguments,
        "/project/ref-check",
        &exact_result,
    ));
    assert!(!native_string_result_matches_reviewed_expectation(
        "__exactWhich",
        &slash_arguments,
        "/project/other",
        &exact_result,
    ));
    let wrong_arguments = [NativeProbeArgument::JsonLiteral {
        value: serde_json::json!("other-command"),
    }];
    assert!(!native_string_result_matches_reviewed_expectation(
        "__exactWhich",
        &wrong_arguments,
        "/project/ref-check",
        &exact_result,
    ));
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

    // The adapter cases are a diagnostic execution of the registry's fixed
    // model vectors, not public JavaScript or filesystem observations. Their
    // synthetic path occurrences intentionally use the contract fixture's
    // `unix` / `dev-1` volume. Install a separate unclaimed Host for that
    // direct adapter after the real loaded engine has authenticated its VFS;
    // the engine keeps its exact claimed Host context and the adapter keeps
    // the authored decision-set bytes unchanged.
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
    let (adapter_host, _adapter_snapshot_digest) = build_armed_test_host_control(
        None,
        false,
        false,
        false,
        required_floor(&catalog),
        Vec::new(),
        false,
        0,
        None,
        |snapshot| {
            snapshot["rootBindings"][1]["object"] = serde_json::json!({
                "platform": "unix",
                "volume": "dev-1",
                "file": "inode-10",
            });
        },
    );
    assert_ne!(
        crate::host::abi::install_host(adapter_host),
        0,
        "install exact typed-adapter Host"
    );
    let _adapter_reset = HostResetGuard;

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

fn native_uses_retained_handle_authority(invocation: &NativePublicInvocation) -> bool {
    !invocation.required_setup_floor.is_empty()
        && invocation.setup.iter().any(|setup| {
            matches!(
                setup,
                NativeProbeSetup::FsReadFile { .. }
                    | NativeProbeSetup::FsWriteFile { .. }
                    | NativeProbeSetup::SqliteFileDatabase { .. }
                    | NativeProbeSetup::SqliteFileStatement { .. }
            )
        })
}

fn install_native_public_test_host(
    invocation: &NativePublicInvocation,
    listener_port: Option<u16>,
    deny: bool,
) -> (crate::host::Host, HostResetGuard, String, Option<Vec<u64>>) {
    let deniable_floor = if invocation.required_floor.is_empty() {
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
        !deny || !deniable_floor.is_empty(),
        "an explicit native public denial requires an exact selector"
    );
    // The setup floor is harness infrastructure authority: always granted,
    // never denied, so a deny scenario refuses exactly the operation's
    // declared capability while authored setup still succeeds.
    assert!(
        invocation.required_setup_floor.is_empty() || !invocation.setup.is_empty(),
        "a native public setup floor without a setup step grants unused authority"
    );
    let retained_handle_setup = native_uses_retained_handle_authority(invocation);
    if retained_handle_setup {
        assert_eq!(
            invocation.required_setup_floor, invocation.required_floor,
            "a retained-handle setup floor must exactly match the probe floor"
        );
        assert!(
            listener_port.is_none(),
            "retained-handle setup does not admit a dynamic listener selector"
        );
    }
    let denials = if deny {
        deniable_floor.clone()
    } else {
        Vec::new()
    };
    let floor: Vec<serde_json::Value> = if retained_handle_setup {
        invocation.required_setup_floor.clone()
    } else {
        deniable_floor
            .iter()
            .chain(invocation.required_setup_floor.iter())
            .cloned()
            .collect()
    };
    let uses_project_path = floor.iter().chain(deniable_floor.iter()).any(|selector| {
        matches!(
            selector["resource"]["kind"].as_str(),
            Some("path-exact" | "path-tree")
        ) && selector["resource"]["path"]["root"] == "project"
    });
    let package_floor = deniable_floor.clone();
    let mutate = move |value: &mut serde_json::Value| {
        if retained_handle_setup {
            // Principal 0 owns the real handle and receives only setup
            // authority. Principal 1 constrains the probe and alone carries
            // the denial. The evaluator intersects both principals, so setup
            // authority cannot satisfy or erase the probe-time decision.
            // @ref LLP 0021#decision-staging-and-principal-semantics
            // @ref LLP 0049#6-phase-2--the-authoring-campaign-parallel-with-phase-1
            value["principals"][0]["denials"] = serde_json::json!([]);
            value["principals"][1]["floor"] = serde_json::Value::Array(package_floor);
            value["principals"][1]["denials"] = serde_json::Value::Array(denials);
            value["principals"][1]["escalationCeiling"] = serde_json::json!([]);
        } else if !denials.is_empty() {
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
        crate::host::abi::install_host(host.clone()),
        0,
        "native public test Host context token allocation"
    );
    let probe_principals = retained_handle_setup.then(|| {
        let snapshot = host
            .armed_snapshot()
            .expect("retained-handle Host must carry an armed snapshot");
        let package: capsec_semantics::model::Principal = serde_json::from_value(
            snapshot.document()["principals"][1]["principal"].clone(),
        )
        .expect("retained-handle probe principal must deserialize");
        assert!(package.is_package());
        let package_id = u64::from(
            host.conformance_observer_principal_id(&package)
                .expect("retained-handle probe principal must be indexed"),
        );
        assert_ne!(package_id, 0, "probe principal cannot alias the root owner");
        vec![0, package_id]
    });
    (host, HostResetGuard, digest, probe_principals)
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
    fs_file_path: Option<String>,
    tcp_loopback_client_handle: Option<f64>,
    sqlite_database_handle: Option<f64>,
    sqlite_statement_handle: Option<f64>,
    sqlite_file_path: Option<String>,
}

fn native_sqlite_file_path_is_owned(path: &str) -> bool {
    matches!(
        path,
        "target/ibex-capsec-sqlite-open-read.sqlite"
            | "target/ibex-capsec-sqlite-open-read-write.sqlite"
            | ".ibex-capsec-sqlite-retained-all.sqlite"
            | ".ibex-capsec-sqlite-retained-exec-read.sqlite"
            | ".ibex-capsec-sqlite-retained-exec-read-write.sqlite"
            | ".ibex-capsec-sqlite-retained-get.sqlite"
            | ".ibex-capsec-sqlite-retained-prepare.sqlite"
            | ".ibex-capsec-sqlite-retained-run-read.sqlite"
            | ".ibex-capsec-sqlite-retained-run-read-write.sqlite"
            | ".ibex-capsec-sqlite-retained-values.sqlite"
            | ".ibex-capsec-sqlite-retained-test.sqlite"
    )
}

fn native_sqlite_owned_paths(path: &str) -> [String; 4] {
    assert!(
        native_sqlite_file_path_is_owned(path),
        "SQLite setup escaped its exact harness-owned paths"
    );
    [
        path.to_owned(),
        format!("{path}-journal"),
        format!("{path}-shm"),
        format!("{path}-wal"),
    ]
}

fn create_native_sqlite_file_fixture(path: &str) {
    assert!(
        native_sqlite_file_path_is_owned(path),
        "SQLite setup escaped its exact harness-owned paths"
    );
    for owned_path in native_sqlite_owned_paths(path) {
        if let Err(error) = std::fs::remove_file(&owned_path) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "clear stale SQLite setup fixture {owned_path}: {error}"
            );
        }
    }
    let connection = rusqlite::Connection::open(path).expect("create on-disk SQLite setup");
    connection
        .execute_batch(
            "CREATE TABLE ibex_capsec_probe (value TEXT NOT NULL);\n\
             INSERT INTO ibex_capsec_probe (value) VALUES ('file-backed');",
        )
        .expect("seed on-disk SQLite setup");
    drop(connection);
}

fn native_sqlite_file_setup_is_bound(invocation: &NativePublicInvocation, path: &str) -> bool {
    invocation.global_name == "__exactSqliteOpen"
        && matches!(
            invocation.arguments.first(),
            Some(NativeProbeArgument::JsonLiteral { value })
                if value.as_str() == Some(path)
        )
}

/// Test-only armed engine facade for source-derived native-global probes.
/// Setup and observed invocation source are separate submissions, but both
/// consume the installed Host's single authenticated session ordinal stream
/// and the engine's bounded native publication stream.
/// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
/// @ref LLP 0025#11-delegated-obligations — OBL-UNIT-PUBLICATION requires
/// every authenticated unit to reach a controller with paired identities.
struct AuthenticatedNativeEngine {
    host: crate::host::Host,
    engine: HermesEngine,
    publications: AuthenticatedPublicationTracker,
    probe_principals: Option<Vec<u64>>,
}

impl AuthenticatedNativeEngine {
    async fn eval_immediate(&mut self, source: &str) -> anyhow::Result<Option<String>> {
        self.eval_immediate_with_scope(source, false).await
    }

    async fn eval_probe_immediate(&mut self, source: &str) -> anyhow::Result<Option<String>> {
        self.eval_immediate_with_scope(source, true).await
    }

    async fn eval_immediate_with_scope(
        &mut self,
        source: &str,
        probe_scope: bool,
    ) -> anyhow::Result<Option<String>> {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};

        self.drain_publications("before authenticated native-public evaluation")?;
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
        let evaluation = if probe_scope {
            if let Some(principals) = &self.probe_principals {
                self.engine
                    .evaluate_authenticated_with_constrained_principals(
                        &session,
                        request,
                        principals,
                    )
                    .await
            } else {
                self.engine.evaluate_authenticated(&session, request).await
            }
        } else {
            self.engine.evaluate_authenticated(&session, request).await
        }
        .map_err(|error| {
            anyhow::anyhow!(
                "authenticated native-public submission {ordinal} failed: {error:#}"
            )
        });
        let publications = self.drain_publications("after authenticated native-public evaluation");
        let evaluation = match (evaluation, publications) {
            (Err(evaluation_error), Err(publication_error)) => anyhow::bail!(
                "authenticated native-public submission {ordinal} failed ({evaluation_error:#}) and its publication stream failed ({publication_error:#})"
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
                        "authenticated native-public submission {ordinal} lost its value receipt"
                    )),
                };
                let publications =
                    self.drain_publications("after authenticated native-public value release");
                match (release, publications) {
                    (Err(release_error), Err(publication_error)) => anyhow::bail!(
                        "authenticated native-public submission {ordinal} failed to release its value ({release_error:#}) and its publication stream failed ({publication_error:#})"
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
                                "authenticated native-public submission {ordinal} returned an invalid string display: {error}"
                            )
                        }),
                    _ => Ok(Some(display.text)),
                }
            }
            AuthenticatedEvaluation::Throw(thrown) => {
                anyhow::bail!("authenticated native-public submission {ordinal} threw: {thrown:?}")
            }
            AuthenticatedEvaluation::Cancelled => {
                anyhow::bail!("authenticated native-public submission {ordinal} was cancelled")
            }
            AuthenticatedEvaluation::Lifecycle(code) => anyhow::bail!(
                "authenticated native-public submission {ordinal} exited with lifecycle code {code}"
            ),
        }
    }

    fn drain_publications(&mut self, context: &str) -> anyhow::Result<()> {
        self.publications.drain(&self.engine, context)
    }

    async fn drive_event_loop_to_quiescence(&mut self) -> anyhow::Result<()> {
        self.drain_publications("before authenticated native-public event-loop drive")?;
        let drive = self.engine.drive_event_loop().await;
        let publications =
            self.drain_publications("after authenticated native-public event-loop drive");
        match (drive, publications) {
            (Err(drive_error), Err(publication_error)) => anyhow::bail!(
                "authenticated native-public event-loop drive failed ({drive_error:#}) and its publication stream failed ({publication_error:#})"
            ),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
            (Ok(()), Ok(())) => {}
        }
        self.publications
            .require_no_due_schedules("authenticated native-public event-loop drive")
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        let publications = self.drain_publications("authenticated native-public engine finish");
        let due = self
            .publications
            .require_no_due_schedules("authenticated native-public engine finish");
        match (publications, due) {
            (Err(publication_error), Err(due_error)) => anyhow::bail!(
                "authenticated native-public engine publication stream failed ({publication_error:#}) and retained due schedules ({due_error:#})"
            ),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

async fn run_native_setup(
    engine: &mut AuthenticatedNativeEngine,
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
                assert_eq!(
                    source_descriptor_digest,
                    &tagged_value_digest(source_descriptor)
                );
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
            NativeProbeSetup::FsWriteFile {
                global_name,
                path,
                source_descriptor,
                source_descriptor_digest,
            } => {
                // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
                // retained write controls receive a harness-owned file and
                // descriptor before their decision observation begins.
                assert_eq!(global_name, "__exactFsOpen");
                assert_eq!(
                    source_descriptor_digest,
                    &tagged_value_digest(source_descriptor)
                );
                assert_eq!(source_descriptor["kind"], "native-global-function");
                assert_eq!(source_descriptor["globalName"], global_name.as_str());
                assert_eq!(source_descriptor["arity"], 4);
                assert!(state.fs_file_descriptor.is_none());
                assert!(state.fs_file_path.is_none());
                assert!(
                    matches!(
                        path.as_str(),
                        "target/ibex-capsec-fsync"
                            | "target/ibex-capsec-fdatasync"
                            | "target/ibex-capsec-fswrite"
                            | "target/ibex-capsec-fswrite-async"
                            | "target/ibex-capsec-fswritev-async"
                            | "target/ibex-capsec-ftruncate"
                            | "target/ibex-capsec-fdasync-durability"
                    ),
                    "retained write setup escaped its exact owned paths"
                );
                let _ = std::fs::remove_file(path);
                std::fs::write(path, b"ibex-capsec-retained-sync")
                    .expect("create retained write setup fixture");
                let encoded = engine
                    .eval_immediate(&setup_script(
                        global_name,
                        &[serde_json::json!(path), serde_json::json!("a")],
                    ))
                    .await
                    .expect("execute native writable descriptor setup")
                    .expect("native writable descriptor setup returned no result");
                let result: serde_json::Value = serde_json::from_str(&encoded)
                    .expect("native writable descriptor setup returned invalid JSON");
                assert_eq!(
                    result["kind"], "return",
                    "native public setup {global_name} failed: {result}"
                );
                state.fs_file_descriptor = Some(
                    result["value"]
                        .as_f64()
                        .expect("native writable setup must return a numeric descriptor"),
                );
                state.fs_file_path = Some(path.clone());
            }
            NativeProbeSetup::SqliteFile { path } => {
                // The fixture is a genuine on-disk database, while the
                // observed __exactSqliteOpen remains solely responsible for
                // the typed VFS walk and checked-fd SQLite open under test.
                // @ref LLP 0049#6-phase-2--the-authoring-campaign-parallel-with-phase-1
                assert!(
                    native_sqlite_file_setup_is_bound(invocation, path),
                    "SQLite setup is not bound to the observed open path"
                );
                assert!(state.sqlite_file_path.is_none());
                create_native_sqlite_file_fixture(path);
                state.sqlite_file_path = Some(path.clone());
            }
            NativeProbeSetup::SqliteFileDatabase {
                global_name,
                path,
                options,
                source_descriptor,
                source_descriptor_digest,
            } => {
                // Seed bytes with rusqlite, but create the retained handle by
                // calling the loaded __exactSqliteOpen implementation. That
                // crosses the armed VFS, checked-fd ABI, and Hermes SQLite
                // registry and therefore records the real runtime nonce and
                // principal-0 owner.
                // @ref LLP 0021#handles-dynamic-authority-and-generations
                // @ref LLP 0049#3-construction-rules
                assert_eq!(global_name, "__exactSqliteOpen");
                assert_eq!(
                    source_descriptor_digest,
                    &tagged_value_digest(source_descriptor)
                );
                assert_eq!(source_descriptor["kind"], "native-global-function");
                assert_eq!(source_descriptor["globalName"], global_name.as_str());
                assert_eq!(source_descriptor["arity"], 2);
                assert!(native_sqlite_file_path_is_owned(path));
                assert!(
                    options == &serde_json::json!({ "readonly": true })
                        || options
                            == &serde_json::json!({ "create": false, "readwrite": true }),
                    "file-backed SQLite setup options escaped reviewed read/read-write shapes"
                );
                assert!(state.sqlite_database_handle.is_none());
                assert!(state.sqlite_file_path.is_none());
                create_native_sqlite_file_fixture(path);
                let encoded = engine
                    .eval_immediate(&setup_script(
                        global_name,
                        &[serde_json::json!(path), options.clone()],
                    ))
                    .await
                    .expect("execute file-backed SQLite database setup")
                    .expect("file-backed SQLite database setup returned no result");
                let result: serde_json::Value = serde_json::from_str(&encoded)
                    .expect("file-backed SQLite database setup returned invalid JSON");
                assert_eq!(
                    result["kind"], "return",
                    "native public setup {global_name} failed: {result}"
                );
                state.sqlite_database_handle = Some(
                    result["value"]
                        .as_f64()
                        .expect("file-backed SQLite setup must return a numeric handle"),
                );
                state.sqlite_file_path = Some(path.clone());
            }
            NativeProbeSetup::SqliteFileStatement {
                global_name,
                sql,
                source_descriptor,
                source_descriptor_digest,
            } => {
                assert_eq!(global_name, "__exactSqlitePrepare");
                assert_eq!(
                    source_descriptor_digest,
                    &tagged_value_digest(source_descriptor)
                );
                assert_eq!(source_descriptor["kind"], "native-global-function");
                assert_eq!(source_descriptor["globalName"], global_name.as_str());
                assert_eq!(source_descriptor["arity"], 2);
                assert!(matches!(
                    sql.as_str(),
                    "SELECT value FROM ibex_capsec_probe"
                        | "UPDATE ibex_capsec_probe SET value = 'file-backed-updated'"
                ));
                assert!(state.sqlite_statement_handle.is_none());
                assert!(state.sqlite_file_path.is_some());
                let database_handle = state
                    .sqlite_database_handle
                    .expect("file-backed SQLite statement requires a database setup");
                let encoded = engine
                    .eval_immediate(&setup_script(
                        global_name,
                        &[serde_json::json!(database_handle), serde_json::json!(sql)],
                    ))
                    .await
                    .expect("execute file-backed SQLite statement setup")
                    .expect("file-backed SQLite statement setup returned no result");
                let result: serde_json::Value = serde_json::from_str(&encoded)
                    .expect("file-backed SQLite statement setup returned invalid JSON");
                assert_eq!(
                    result["kind"], "return",
                    "native public setup {global_name} failed: {result}"
                );
                state.sqlite_statement_handle = Some(
                    result["handle"]
                        .as_f64()
                        .expect("file-backed SQLite statement setup must return a numeric handle"),
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
                assert_eq!(
                    source_descriptor_digest,
                    &tagged_value_digest(source_descriptor)
                );
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
                assert_eq!(
                    source_descriptor_digest,
                    &tagged_value_digest(source_descriptor)
                );
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
                assert_eq!(
                    source_descriptor_digest,
                    &tagged_value_digest(source_descriptor)
                );
                assert_eq!(source_descriptor["kind"], "native-global-function");
                assert_eq!(source_descriptor["globalName"], global_name.as_str());
                assert_eq!(source_descriptor["arity"], 4);
                assert!(state.tcp_loopback_client_handle.is_none());
                let port =
                    listener_port.expect("loopback client setup requires an owned listener port");
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
            NativeProbeArgument::HarnessUint8ArrayList { byte_lengths } => {
                assert!(
                    byte_lengths.len() <= 1024
                        && byte_lengths
                            .iter()
                            .all(|length| *length <= u32::MAX as usize)
                        && byte_lengths
                            .iter()
                            .try_fold(0_u64, |sum, length| { sum.checked_add(*length as u64) })
                            .is_some_and(|sum| sum <= u32::MAX as u64),
                    "typed-array list fixture must remain bounded"
                );
                serde_json::json!({
                    "kind": "harness-uint8-array-list",
                    "byteLengths": byte_lengths,
                })
            }
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
    let callable_binding = if let Some(access) = &invocation.public_access {
        format!(
            "var accessPath={};var receiver=globalThis;for(var accessIndex=0;accessIndex+1<accessPath.length;accessIndex++){{if(receiver===null||(typeof receiver!==\"object\"&&typeof receiver!==\"function\")){{receiver=undefined;break;}}receiver=receiver[accessPath[accessIndex]];}}var f=receiver===null||receiver===undefined?undefined:receiver[accessPath[accessPath.length-1]];var thisValue=receiver;",
            serde_json::to_string(&access.path).expect("serialize native public facade path")
        )
    } else {
        "var f=globalThis[n];var thisValue=globalThis;".to_owned()
    };
    let cleanup_state = serde_json::json!({
        "sqliteDatabaseHandle": setup_state.sqlite_database_handle,
        "sqliteStatementHandle": setup_state.sqlite_statement_handle,
    });
    let script = format!(
        "JSON.stringify((function(){{var n={};var f=globalThis[n];if(typeof f!==\"function\")return {{kind:\"missing\",globalName:n}};var specs={};var cleanupState={};var captureString={};var producerResults=new Map();function invokeProducer(spec){{var producer=globalThis[spec.globalName];if(typeof producer!==\"function\")throw new Error(\"missing native argument producer: \"+spec.globalName);return Reflect.apply(producer,globalThis,spec.arguments.map(materialize));}}function materialize(spec){{if(spec.kind===\"json-literal\")return spec.value;if(spec.kind===\"harness-noop-callback\")return function(){{}};if(spec.kind===\"harness-uint8-array-list\")return spec.byteLengths.map(function(length){{return new Uint8Array(length);}});if(spec.kind===\"native-global-result\")return invokeProducer(spec);if(spec.kind===\"native-global-result-property\"){{var cacheKey=spec.sourceDescriptorDigest+\"\\n\"+JSON.stringify(spec.arguments);var result;if(producerResults.has(cacheKey))result=producerResults.get(cacheKey);else{{result=invokeProducer(spec);producerResults.set(cacheKey,result);}}if(result===null||(typeof result!==\"object\"&&typeof result!==\"function\")||!Object.prototype.hasOwnProperty.call(result,spec.property))throw new Error(\"native argument producer missing own property: \"+spec.property);return result[spec.property];}}throw new Error(\"unsupported native argument kind: \"+String(spec&&spec.kind));}}var args;try{{args=specs.map(materialize);}}catch(e){{return {{kind:\"argument-throw\",globalName:n,errorName:String(e&&e.name||\"Error\"),errorMessage:String(e&&e.message||e)}};}}try{{var value=Reflect.apply(f,globalThis,args);var valueType=value===null?\"null\":typeof value;var cleanup=\"none\";if(n===\"__exactTcpConnect\"&&typeof value===\"number\"&&typeof globalThis.__exactTcpClose===\"function\"){{globalThis.__exactTcpClose(value);cleanup=\"closed-tcp-handle\";}}else if(n===\"__exactUdpSocket\"&&typeof value===\"number\"&&typeof globalThis.__exactUdpClose===\"function\"){{globalThis.__exactUdpClose(value);cleanup=\"closed-udp-handle\";}}else if(n===\"__exactTcpClose\"&&typeof args[0]===\"number\"){{cleanup=\"consumed-tcp-handle\";}}else if((n===\"__exactTcpReset\"||n===\"__exactTcpShutdown\")&&typeof args[0]===\"number\"&&typeof globalThis.__exactTcpClose===\"function\"){{globalThis.__exactTcpClose(args[0]);cleanup=\"closed-tcp-handle\";}}else if(n===\"__exactSqliteOpen\"&&typeof value===\"number\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteClose(value);cleanup=\"closed-sqlite-db\";}}else if(n===\"__exactSqlitePrepare\"&&value&&typeof value.handle===\"number\"&&typeof args[0]===\"number\"&&typeof globalThis.__exactSqliteFinalize===\"function\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteFinalize(value.handle);globalThis.__exactSqliteClose(args[0]);cleanup=\"finalized-sqlite-statement-closed-db\";}}else if((n===\"__exactSqliteAll\"||n===\"__exactSqliteGet\"||n===\"__exactSqliteRun\"||n===\"__exactSqliteValues\")&&typeof args[0]===\"number\"&&typeof cleanupState.sqliteDatabaseHandle===\"number\"&&typeof globalThis.__exactSqliteFinalize===\"function\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteFinalize(args[0]);globalThis.__exactSqliteClose(cleanupState.sqliteDatabaseHandle);cleanup=\"finalized-sqlite-statement-closed-db\";}}else if(n===\"__exactSqliteExec\"&&typeof args[0]===\"number\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteClose(args[0]);cleanup=\"closed-sqlite-db\";}}else if(n===\"__exactSqliteClose\"&&typeof args[0]===\"number\"){{cleanup=\"consumed-sqlite-db\";}}else if(n===\"__exactSqliteInTransaction\"&&typeof args[0]===\"number\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteClose(args[0]);cleanup=\"closed-sqlite-db\";}}else if(n===\"__exactSqliteFinalize\"&&typeof cleanupState.sqliteDatabaseHandle===\"number\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteClose(cleanupState.sqliteDatabaseHandle);cleanup=\"consumed-sqlite-statement-closed-db\";}}else if(n===\"__exactSqliteExpandedSql\"&&typeof args[0]===\"number\"&&typeof cleanupState.sqliteDatabaseHandle===\"number\"&&typeof globalThis.__exactSqliteFinalize===\"function\"&&typeof globalThis.__exactSqliteClose===\"function\"){{globalThis.__exactSqliteFinalize(args[0]);globalThis.__exactSqliteClose(cleanupState.sqliteDatabaseHandle);cleanup=\"finalized-sqlite-statement-closed-db\";}}else if(n===\"setTimeout\"&&typeof globalThis.clearTimeout===\"function\"){{globalThis.clearTimeout(value);cleanup=\"cleared-timeout\";}}else if(n===\"setInterval\"&&typeof globalThis.clearInterval===\"function\"){{globalThis.clearInterval(value);cleanup=\"cleared-interval\";}}var out={{kind:\"return\",globalName:n,valueType:valueType,cleanup:cleanup}};if(captureString){{out.stringValue=typeof value===\"string\"?value:null;}}if(n===\"__exactGetAllEnv\"&&value!==null&&typeof value===\"object\"){{var envNames=Object.keys(value).sort();out.valuePropertyCount=envNames.length;out.enumeratedNames=envNames;out.enumeratedValues=envNames.map(function(envName){{return String(value[envName]);}});}}return out;}}catch(e){{return {{kind:\"throw\",globalName:n,errorName:String(e&&e.name||\"Error\"),errorMessage:String(e&&e.message||e)}};}}}})())",
        serde_json::to_string(&invocation.global_name).expect("serialize native global"),
        serde_json::to_string(arguments).expect("serialize native arguments"),
        serde_json::to_string(&cleanup_state).expect("serialize native cleanup state"),
        serde_json::to_string(&invocation.expected_string_value.is_some())
            .expect("serialize native string-capture requirement")
    );
    let callable_marker = "var f=globalThis[n];";
    assert_eq!(
        script.matches(callable_marker).count(),
        1,
        "native public callable binding marker drift"
    );
    let script = script.replacen(callable_marker, &callable_binding, 1);
    let receiver_marker = "Reflect.apply(f,globalThis,args)";
    assert_eq!(
        script.matches(receiver_marker).count(),
        1,
        "native public receiver marker drift"
    );
    let script = script.replacen(receiver_marker, "Reflect.apply(f,thisValue,args)", 1);
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
        "else if(n===\"__exactFsOpen\"&&typeof value===\"number\"&&typeof globalThis.__exactFsClose===\"function\"){globalThis.__exactFsClose(value);cleanup=\"closed-fs-file-descriptor\";}else if(n===\"__exactFsClose\"&&typeof args[0]===\"number\"){cleanup=\"consumed-fs-file-descriptor\";}else if(n===\"__exactZlibCreate\"&&typeof value===\"number\"&&typeof globalThis.__exactZlibClose===\"function\"){globalThis.__exactZlibClose(value);cleanup=\"closed-zlib-stream\";}else if(n===\"__exactZlibClose\"&&typeof args[0]===\"number\"){cleanup=\"consumed-zlib-stream\";}else if((n===\"__exactZlibCheckOwner\"||n===\"__exactZlibParams\"||n===\"__exactZlibWrite\")&&typeof args[0]===\"number\"&&typeof globalThis.__exactZlibClose===\"function\"){globalThis.__exactZlibClose(args[0]);cleanup=\"closed-zlib-stream\";}else if(n===\"__exactTlsOwnerToken\"&&args[0]===\"new\"&&typeof value===\"number\"){globalThis.__exactTlsOwnerToken(\"close\",value);cleanup=\"closed-tls-owner-token\";}else if(n===\"__exactTlsEngineNew\"&&typeof value===\"number\"&&typeof globalThis.__exactTlsEngineClose===\"function\"){globalThis.__exactTlsEngineClose(value);cleanup=\"closed-tls-engine\";}else if(n===\"__exactTlsEngineClose\"&&typeof args[0]===\"number\"){cleanup=\"consumed-tls-engine\";}else if((n===\"__exactTlsEnginePeerCerts\"||n===\"__exactTlsEngineReadPlain\"||n===\"__exactTlsEngineReadTls\"||n===\"__exactTlsEngineShutdown\"||n===\"__exactTlsEngineStatus\"||n===\"__exactTlsEngineTransportEof\"||n===\"__exactTlsEngineWritePlain\"||n===\"__exactTlsEngineWriteTls\")&&typeof args[0]===\"number\"&&typeof globalThis.__exactTlsEngineClose===\"function\"){globalThis.__exactTlsEngineClose(args[0]);cleanup=\"closed-tls-engine\";}else if(n===\"setTimeout\"",
        1,
    )
}

const NATIVE_ASYNC_RESULT_SLOT: &str = "__ibexCapsecNativeAsyncResult";

fn native_async_result_take_script() -> String {
    format!(
        "(function(){{var slot={};var owns=Object.prototype.hasOwnProperty;if(!owns.call(globalThis,slot))throw new Error(\"native async result slot is absent\");var value=globalThis[slot];if(!Reflect.deleteProperty(globalThis,slot)||owns.call(globalThis,slot))throw new Error(\"native async result slot could not be removed\");if(typeof value!==\"string\")throw new Error(\"native async result did not settle\");return value;}})()",
        serde_json::to_string(NATIVE_ASYNC_RESULT_SLOT).expect("serialize native async result slot")
    )
}

fn native_async_argument_is_supported(argument: &serde_json::Value) -> bool {
    match argument["kind"].as_str() {
        Some("json-literal" | "harness-uint8-array-list") => true,
        Some("native-global-result") => {
            argument["globalName"] == "__exactStringToUtf8Bytes"
                && argument["arguments"].as_array().is_some_and(|arguments| {
                    arguments.as_slice()
                        == [serde_json::json!({
                            "kind": "json-literal",
                            "value": "ibex-capsec-async-write-file"
                        })]
                })
        }
        _ => false,
    }
}

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
    assert!(arguments.iter().all(native_async_argument_is_supported));
    format!(
        "(function(){{var slot={};var n={};var owns=Object.prototype.hasOwnProperty;if(owns.call(globalThis,slot)&&(!Reflect.deleteProperty(globalThis,slot)||owns.call(globalThis,slot)))throw new Error(\"stale native async result slot could not be removed\");Object.defineProperty(globalThis,slot,{{value:null,writable:true,enumerable:false,configurable:true}});if(!owns.call(globalThis,slot)||globalThis[slot]!==null)throw new Error(\"native async result slot was not installed\");function record(value){{if(!owns.call(globalThis,slot))throw new Error(\"native async result slot was removed while pending\");globalThis[slot]=JSON.stringify(value);}}function returned(value){{var cleanup=n===\"__exactFsCloseAsync\"&&typeof args[0]===\"number\"?\"consumed-fs-file-descriptor\":\"none\";if(n===\"__exactFsOpenAsync\"&&typeof value===\"number\"&&typeof globalThis.__exactFsClose===\"function\"){{globalThis.__exactFsClose(value);cleanup=\"closed-fs-file-descriptor\";}}return {{kind:\"return\",globalName:n,valueType:value===null?\"null\":typeof value,resultString:typeof value===\"string\"?value:null,cleanup:cleanup}};}}var f=globalThis[n];if(typeof f!==\"function\"){{record({{kind:\"missing\",globalName:n}});return \"completed\";}}var specs={};function materialize(spec){{if(spec.kind===\"json-literal\")return spec.value;if(spec.kind===\"harness-uint8-array-list\")return spec.byteLengths.map(function(length){{return new Uint8Array(length);}});if(spec.kind===\"native-global-result\"){{var producer=globalThis[spec.globalName];if(typeof producer!==\"function\")throw new Error(\"missing native argument producer: \"+spec.globalName);return Reflect.apply(producer,globalThis,spec.arguments.map(materialize));}}throw new Error(\"unsupported async native fixture argument: \"+String(spec&&spec.kind));}}var args;try{{args=specs.map(materialize);}}catch(error){{record({{kind:\"argument-throw\",globalName:n,errorName:String(error&&error.name||\"Error\"),errorMessage:String(error&&error.message||error)}});return \"completed\";}}try{{var value=Reflect.apply(f,globalThis,args);if(value===null||typeof value.then!==\"function\"){{record(returned(value));return \"completed\";}}value.then(function(result){{record(returned(result));}},function(error){{record({{kind:\"throw\",globalName:n,errorName:String(error&&error.name||\"Error\"),errorMessage:String(error&&error.message||error)}});}});return \"scheduled\";}}catch(error){{record({{kind:\"throw\",globalName:n,errorName:String(error&&error.name||\"Error\"),errorMessage:String(error&&error.message||error)}});return \"completed\";}}}})()",
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

// Keep the carrier-to-worker account closed: each admitted operation must be
// source-selected by __exactFsPathAsync and proven by a break-test below.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
const NATIVE_ASYNC_WORKER_TERMINALS: [(&str, &str); 7] = [
    ("access", "native-op:__exactAccess"),
    ("mkdir", "native-op:__exactMkdir"),
    ("readdir", "native-op:__exactReaddir"),
    ("readlink", "native-op:__exactReadlink"),
    ("realpath", "native-op:__exactRealpath"),
    ("statfs", "native-op:__exactStatfs"),
    ("truncate", "native-op:__exactTruncate"),
];

fn native_async_worker_terminal(invocation: &NativePublicInvocation) -> Option<&'static str> {
    if invocation.global_name != "__exactFsPathAsync" {
        return None;
    }
    let operation = match invocation.arguments.first() {
        Some(NativeProbeArgument::JsonLiteral { value }) => value.as_str()?,
        _ => return None,
    };
    NATIVE_ASYNC_WORKER_TERMINALS
        .iter()
        .find_map(|(candidate, terminal)| (*candidate == operation).then_some(*terminal))
}

fn reviewed_native_open_traversal_prefix(
    invocation: &NativePublicInvocation,
) -> Option<&'static str> {
    if invocation.kind != "native-global-function" {
        return None;
    }
    match invocation.global_name.as_str() {
        "__exactReadlink" if invocation.expected_action_ids.as_slice() == ["fs:read"] => {
            Some("fs-readlink:")
        }
        "__exactFsPathAsync"
            if invocation.expected_action_ids.as_slice() == ["fs:read"]
                && matches!(
                    invocation.arguments.first(),
                    Some(NativeProbeArgument::JsonLiteral { value })
                        if value.as_str() == Some("readlink")
                ) =>
        {
            Some("fs-readlink:")
        }
        "__exactFsWriteFileAsync"
            if invocation.expected_action_ids.as_slice() == ["fs:write"]
                && native_async_write_file_fixture_path(invocation).is_some() =>
        {
            Some("fs-write-file-async:")
        }
        _ => None,
    }
}

const NATIVE_ASYNC_WRITE_FILE_FIXTURE_PATH: &str = "target/ibex-capsec-fswritefileasync-path";
const NATIVE_ASYNC_WRITE_FILE_FIXTURE_BYTES: &[u8] = b"ibex-capsec-async-write-file";

fn native_async_write_file_fixture_path(invocation: &NativePublicInvocation) -> Option<&str> {
    if invocation.global_name != "__exactFsWriteFileAsync" {
        return None;
    }
    match invocation.arguments.first() {
        Some(NativeProbeArgument::JsonLiteral { value })
            if value.as_str() == Some(NATIVE_ASYNC_WRITE_FILE_FIXTURE_PATH) =>
        {
            value.as_str()
        }
        _ => None,
    }
}

fn native_observed_actions_are_reviewed(
    invocation: &NativePublicInvocation,
    observed_actions: &BTreeSet<String>,
) -> bool {
    if native_requires_reviewed_early_denial_action_prefix(invocation) {
        return reviewed_native_early_denial_action_prefix(invocation, observed_actions);
    }
    let declared_actions = invocation
        .expected_action_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    declared_actions.is_subset(observed_actions)
        && observed_actions.difference(&declared_actions).all(|extra| {
            extra == "fs:list" && reviewed_native_open_traversal_prefix(invocation).is_some()
        })
}

fn native_requires_reviewed_early_denial_action_prefix(
    invocation: &NativePublicInvocation,
) -> bool {
    invocation.global_name == "__exactWhich"
        && matches!(
            invocation.arguments.as_slice(),
            [NativeProbeArgument::JsonLiteral { value }]
                if value.as_str() == Some("ref-check")
        )
        && invocation.expected_result == "permission-denied"
}

fn reviewed_native_early_denial_action_prefix(
    invocation: &NativePublicInvocation,
    observed_actions: &BTreeSet<String>,
) -> bool {
    // @ref LLP 0037#d3--observed-typed-sequences-are-pinned-from-a-run-never-authored-by-hand
    // A denied bare `which` stops after the PATH lookup, before filesystem
    // discovery. Admit only the exact engine-observed prefix; all nearby
    // globals, arguments, outcomes, sequences, and action sets fail closed.
    native_requires_reviewed_early_denial_action_prefix(invocation)
        && invocation.expected_typed_stages.as_slice() == ["requested"]
        && invocation.expected_typed_decision_count == 1
        && invocation.expected_action_ids.as_slice() == ["env:read", "fs:list"]
        && observed_actions == &BTreeSet::from(["env:read".to_owned()])
}

fn native_decision_is_reviewed_open_traversal(
    invocation: &NativePublicInvocation,
    decision: &serde_json::Value,
    effects: &[serde_json::Value],
    public_denial: bool,
) -> bool {
    let Some(operation_prefix) = reviewed_native_open_traversal_prefix(invocation) else {
        return false;
    };
    !public_denial
        && !effects.is_empty()
        && effects.iter().all(|effect| effect["cap"] == "fs:list")
        && matches!(
            decision["decisionSet"]["context"]["stage"].as_str(),
            Some("requested" | "discovery" | "repeat")
        )
        && decision["decisionSet"]["operationId"]
            .as_str()
            .is_some_and(|operation_id| operation_id.starts_with(operation_prefix))
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
    assert!(matches!(
        descriptor.value_shape.as_str(),
        "accessor" | "data"
    ));
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
                    character == '_' || character == '$' || character.is_ascii_alphanumeric()
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
    if descriptor
        .member_kinds
        .iter()
        .any(|kind| kind == "inherited")
    {
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

fn validate_private_native_facade(
    recipe: &Recipe,
    probe: &PublicSurfaceProbe,
    invocation: &NativePublicInvocation,
) {
    let access = invocation
        .public_access
        .as_ref()
        .expect("private native facade has no authored public access path");
    let access_digest = tagged_value_digest(access);
    assert_eq!(
        invocation.public_access_digest.as_deref(),
        Some(access_digest.as_str()),
        "{}: private native facade access digest drift",
        recipe.fixture_id
    );
    assert_eq!(invocation.global_name, "__exactGetCwd");
    assert_eq!(probe.surface_observed_key, "native-op:__exactGetCwd");
    assert!(invocation.expected_deny_message_fragment.is_none());
    assert_eq!(access.kind, "captured-private-global-function");
    assert_eq!(access.observed_key, "native-op:global:process.cwd");
    assert_eq!(access.path, ["process", "cwd"]);
    let public_disposition = root_global_disposition_by_install_id(&access.install_id)
        .expect("private cwd facade install ID is absent or duplicated");
    assert_eq!(
        public_disposition["observedKey"].as_str(),
        Some(access.observed_key.as_str())
    );
    assert_eq!(
        public_disposition["branch"]["activation"].as_str(),
        Some("always")
    );
    assert_eq!(
        public_disposition["disposition"].as_str(),
        Some("converted")
    );
    assert_eq!(
        public_disposition["liveExpectation"].as_str(),
        Some("reachable")
    );
    assert_eq!(
        public_disposition["property"],
        serde_json::json!({
            "root": {"kind": "string", "value": "process"},
            "path": [{"kind": "string", "value": "cwd"}],
        })
    );
    assert_eq!(
        public_disposition["branch"]["sourceRefs"],
        serde_json::to_value(&access.source_refs).unwrap()
    );
    assert_eq!(
        access.private_terminal.observed_key,
        probe.surface_observed_key
    );
    let private_disposition =
        root_global_disposition_by_install_id(&access.private_terminal.install_id)
            .expect("private cwd terminal install ID is absent or duplicated");
    assert_eq!(
        private_disposition["observedKey"].as_str(),
        Some(access.private_terminal.observed_key.as_str())
    );
    assert_eq!(
        private_disposition["branch"]["activation"].as_str(),
        Some("always")
    );
    assert_eq!(private_disposition["disposition"].as_str(), Some("private"));
    assert_eq!(
        private_disposition["property"],
        serde_json::json!({
            "root": {"kind": "string", "value": "__exactGetCwd"},
            "path": [],
        })
    );
    assert_eq!(
        access.private_terminal.private_consumer,
        "trusted-path-process-builtins"
    );
    assert_eq!(
        private_disposition["privateConsumer"].as_str(),
        Some(access.private_terminal.private_consumer.as_str())
    );
    assert_eq!(access.private_terminal.live_expectation, "absent");
    assert_eq!(
        private_disposition["liveExpectation"].as_str(),
        Some(access.private_terminal.live_expectation.as_str())
    );
    assert_eq!(
        access.expected_deny_message_fragment,
        "filesystem policy denied"
    );
}

fn root_global_disposition_by_install_id(install_id: &str) -> Option<&'static serde_json::Value> {
    static MANIFEST: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    let manifest = MANIFEST.get_or_init(|| {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/generated/root-global-disposition-manifest.json"
        )))
        .expect("parse checked root-global disposition manifest")
    });
    let rows = manifest["rows"]
        .as_array()
        .expect("root-global disposition manifest rows");
    let mut matches = rows
        .iter()
        .filter(|row| row["installId"].as_str() == Some(install_id));
    let disposition = matches.next()?;
    matches.next().is_none().then_some(disposition)
}

fn uses_ambient_project_prefix_authority(
    invocation: &NativePublicInvocation,
    effects: &[serde_json::Value],
) -> bool {
    !effects.is_empty()
        && effects.iter().all(|effect| {
            if effect["cap"] != "fs:list"
                || effect["resource"]["kind"] != "path-occurrence"
                || effect["resource"]["requested"]["root"] != "project"
            {
                return false;
            }
            let Some(requested_components) =
                effect["resource"]["requested"]["components"].as_array()
            else {
                return false;
            };
            invocation.required_floor.iter().any(|selector| {
                if selector["cap"] != "fs:list"
                    || !matches!(
                        selector["resource"]["kind"].as_str(),
                        Some("path-exact" | "path-tree")
                    )
                    || selector["resource"]["path"]["root"] != "project"
                {
                    return false;
                }
                let Some(floor_components) = selector["resource"]["path"]["components"].as_array()
                else {
                    return false;
                };
                requested_components.len() < floor_components.len()
                    && requested_components
                        .iter()
                        .zip(floor_components)
                        .all(|(requested, floor)| requested == floor)
            })
        })
}

fn native_filesystem_denial_message_is_reviewed(global_name: &str) -> bool {
    matches!(
        global_name,
        "__exactAccess"
            | "__exactOpendir"
            | "__exactAppendFile"
            | "__exactFsOpen"
            | "__exactFsOpenAsync"
            | "__exactFsFstatSync"
            | "__exactFsPathAsync"
            | "__exactFsReadFileAsync"
            | "__exactFsStatAsync"
            | "__exactFsWriteFileAsync"
            | "__exactLstat"
            | "__exactMkdir"
            | "__exactReadFile"
            | "__exactReaddir"
            | "__exactRealpath"
            | "__exactReadlink"
            | "__exactSqliteOpen"
            | "__exactStat"
            | "__exactStatfs"
            | "__exactTruncate"
            | "__exactWhich"
            | "__exactWriteFile"
    )
}

fn native_closed_filesystem_mutation_is_reviewed(
    classification: &str,
    scenario: &str,
    invocation: &NativePublicInvocation,
) -> bool {
    // @ref LLP 0023#41-the-v1-mutation-surface-small-object-bound-and-completely-specified —
    // these loaded native branches refuse with EPERM before path lookup or
    // descriptor validation, and therefore must emit no capability decision.
    if classification != "closed"
        || scenario != "branch-selection"
        || invocation.kind != "native-global-function"
        || invocation.expected_result != "permission-denied"
        || invocation.expected_deny_message_fragment.as_deref()
            != Some("EPERM: operation not permitted")
        || !invocation.required_floor.is_empty()
        || !invocation.required_setup_floor.is_empty()
        || !invocation.setup.is_empty()
        || !invocation.expected_typed_stages.is_empty()
        || !invocation.expected_typed_outcomes.is_empty()
        || invocation.expected_typed_decision_count != 0
        || !invocation.expected_action_ids.is_empty()
        || if invocation.global_name == "__exactMkdir" {
            invocation.completion.is_some()
        } else {
            invocation.completion.as_ref().is_none_or(|completion| {
                completion.kind != "event-loop-quiescence"
                    || completion.timeout_milliseconds != 1_000
            })
        }
    {
        return false;
    }
    let Some(arguments) = invocation
        .arguments
        .iter()
        .map(|argument| match argument {
            NativeProbeArgument::JsonLiteral { value } => Some(value.clone()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if invocation.global_name == "__exactMkdir" {
        return arguments
            == vec![
                serde_json::json!("target/ibex-capsec-mkdir-recursive-closed"),
                serde_json::json!(true),
                serde_json::json!(-1),
            ];
    }
    if invocation.global_name == "__exactFsFdAsync" {
        return matches!(
            arguments.as_slice(),
            [operation, descriptor, first, second]
                if descriptor == &serde_json::json!(42)
                    && second == &serde_json::json!(0)
                    && matches!(
                        operation.as_str(),
                        Some("fchmod" | "fchown" | "futimes")
                    )
                    && match operation.as_str() {
                        Some("fchmod") => first == &serde_json::json!(0o600),
                        Some("fchown" | "futimes") => first == &serde_json::json!(0),
                        _ => false,
                    }
        );
    }
    if invocation.global_name != "__exactFsPathAsync" || arguments.len() != 6 {
        return false;
    }
    let expected = match arguments[0].as_str() {
        Some("chown") => {
            serde_json::json!(["chown", "target/ibex-capsec-closed-chown", null, 0, 0, 0])
        }
        Some("copyfile") => serde_json::json!([
            "copyfile",
            "target/ibex-capsec-closed-copyfile-source",
            "target/ibex-capsec-closed-copyfile-destination",
            0,
            0,
            0
        ]),
        Some("copyfile_excl") => serde_json::json!([
            "copyfile_excl",
            "target/ibex-capsec-closed-copyfile-excl-source",
            "target/ibex-capsec-closed-copyfile-excl-destination",
            0,
            0,
            0
        ]),
        Some("lchmod") => serde_json::json!([
            "lchmod",
            "target/ibex-capsec-closed-lchmod",
            null,
            0o600,
            0,
            0
        ]),
        Some("lchown") => {
            serde_json::json!(["lchown", "target/ibex-capsec-closed-lchown", null, 0, 0, 0])
        }
        Some("link") => serde_json::json!([
            "link",
            "target/ibex-capsec-closed-link-source",
            "target/ibex-capsec-closed-link-destination",
            0,
            0,
            0
        ]),
        Some("lutime") => {
            serde_json::json!(["lutime", "target/ibex-capsec-closed-lutime", null, 0, 0, 0])
        }
        Some("mkdir") => serde_json::json!([
            "mkdir",
            "target/ibex-capsec-fspathasync-closed-mkdir-recursive",
            null,
            1,
            -1,
            0
        ]),
        Some("mkdtemp") => serde_json::json!([
            "mkdtemp",
            "target/ibex-capsec-closed-mkdtemp-",
            null,
            0,
            0,
            0
        ]),
        Some("rename") => serde_json::json!([
            "rename",
            "target/ibex-capsec-closed-rename-source",
            "target/ibex-capsec-closed-rename-destination",
            0,
            0,
            0
        ]),
        Some("rmdir") => {
            serde_json::json!(["rmdir", "target/ibex-capsec-closed-rmdir", null, 0, 0, 0])
        }
        Some("symlink") => serde_json::json!([
            "symlink",
            "closed-symlink-target",
            "target/ibex-capsec-closed-symlink",
            0,
            0,
            0
        ]),
        Some("unlink") => {
            serde_json::json!(["unlink", "target/ibex-capsec-closed-unlink", null, 0, 0, 0])
        }
        _ => return false,
    };
    expected
        .as_array()
        .is_some_and(|expected| expected == &arguments)
}

fn native_closed_filesystem_mutation_result_is_reviewed(
    classification: &str,
    scenario: &str,
    invocation: &NativePublicInvocation,
    invocation_result: &serde_json::Value,
) -> bool {
    if !native_closed_filesystem_mutation_is_reviewed(classification, scenario, invocation) {
        return false;
    }
    let operation = if invocation.global_name == "__exactMkdir" {
        "mkdir"
    } else {
        let Some(operation) = invocation
            .arguments
            .first()
            .and_then(|argument| match argument {
                NativeProbeArgument::JsonLiteral { value } => value.as_str(),
                _ => None,
            })
        else {
            return false;
        };
        operation
    };
    let Some(result) = invocation_result.as_object() else {
        return false;
    };
    result.len() == 4
        && ["kind", "globalName", "errorName", "errorMessage"]
            .iter()
            .all(|key| result.contains_key(*key))
        && invocation_result["kind"] == "throw"
        && invocation_result["globalName"] == invocation.global_name
        && invocation_result["errorName"] == "Error"
        && invocation_result["errorMessage"]
            == format!("EPERM: operation not permitted, {operation}")
}

fn native_string_result_matches_reviewed_expectation(
    global_name: &str,
    arguments: &[NativeProbeArgument],
    expected_string_value: &str,
    invocation_result: &serde_json::Value,
) -> bool {
    let [NativeProbeArgument::JsonLiteral { value }] = arguments else {
        return false;
    };
    let Some(argument) = value.as_str() else {
        return false;
    };
    let reviewed_lookup = matches!(
        (argument, expected_string_value),
        ("/project/ref-check", "/project/ref-check") | ("ref-check", "/project/ref-check")
    );
    let Some(result) = invocation_result.as_object() else {
        return false;
    };
    global_name == "__exactWhich"
        && expected_string_value == "/project/ref-check"
        && reviewed_lookup
        && result.len() == 5
        && ["kind", "globalName", "valueType", "cleanup", "stringValue"]
            .iter()
            .all(|key| result.contains_key(*key))
        && invocation_result["kind"] == "return"
        && invocation_result["globalName"] == global_name
        && invocation_result["valueType"] == "string"
        && invocation_result["cleanup"] == "none"
        && invocation_result["stringValue"] == expected_string_value
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
        "native-global-function" | "private-native-facade-function" | "global-property-read"
    ));
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_value_digest(&invocation.source_descriptor),
        "{}: source-derived native descriptor digest drift",
        recipe.fixture_id
    );
    if invocation.kind == "global-property-read" {
        assert!(invocation.public_access.is_none());
        assert!(invocation.public_access_digest.is_none());
        assert!(invocation.expected_deny_message_fragment.is_none());
        validate_global_read_descriptor(recipe, probe, invocation);
    } else {
        let expected_observed_key = if invocation.global_name.starts_with('_') {
            format!("native-op:{}", invocation.global_name)
        } else {
            format!("native-op:global:{}", invocation.global_name)
        };
        assert_eq!(probe.surface_observed_key, expected_observed_key);
        if invocation.kind == "private-native-facade-function" {
            validate_private_native_facade(recipe, probe, invocation);
        } else {
            assert!(invocation.public_access.is_none());
            assert!(invocation.public_access_digest.is_none());
            if let Some(fragment) = invocation.expected_deny_message_fragment.as_deref() {
                if fragment == "EPERM: operation not permitted" {
                    assert!(native_closed_filesystem_mutation_is_reviewed(
                        &recipe.classification,
                        &recipe.scenario,
                        invocation,
                    ));
                } else {
                    assert_eq!(fragment, "filesystem policy denied");
                    // Direct armed list terminals refuse through
                    // openArmedListTarget / throwFsAsyncResult with this exact
                    // EACCES message. Keep the accepted public-global set closed.
                    // @ref LLP 0049#3-construction-rules — reviewed evidence sets stay closed
                    assert!(native_filesystem_denial_message_is_reviewed(
                        invocation.global_name.as_str()
                    ));
                }
            }
        }
    }
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report —
    // an async dispatcher or retained-object operation may observe its
    // source-selected worker, cleanup, or object-gate edge, but no unrelated
    // edge may be admitted by the authored recipe. FsPathAsync remains bound
    // to the closed source-selected worker map above; in particular,
    // mkdtemp cannot inherit mkdir's worker evidence.
    let windows_source = invocation.source_descriptor["sourceRef"]
        .as_str()
        .is_some_and(|source_ref| source_ref.contains("_windows.cc#"));
    let target_absence = recipe.expected_observation["kind"] == "target-absence";
    let retained_descriptor_setup = invocation.setup.iter().any(|setup| {
        matches!(
            setup,
            NativeProbeSetup::FsReadFile { .. } | NativeProbeSetup::FsWriteFile { .. }
        )
    });
    let closed_filesystem_mutation = native_closed_filesystem_mutation_is_reviewed(
        &recipe.classification,
        &recipe.scenario,
        invocation,
    );
    // These exact branches refuse in __exactFsPathAsync before dispatch. In
    // particular, recursive mkdir must not inherit __exactMkdir's worker edge
    // merely because its operation selector is "mkdir".
    let auxiliary_allowed_terminal = if closed_filesystem_mutation {
        None
    } else if !target_absence
        && ((retained_descriptor_setup
            && matches!(
                invocation.global_name.as_str(),
                "__exactFsFdAsync"
                    | "__exactFsRead"
                    | "__exactFsReadv"
                    | "__exactFsReadAsync"
                    | "__exactFsReadvAsync"
                    | "__exactFsReadFileAsync"
                    | "__exactFsFstatSync"
                    | "__exactFsFtruncateSync"
                    | "__exactFsFchmodSync"
                    | "__exactFsFutimesSync"
                    | "__exactFsWrite"
            ))
            || (!windows_source && invocation.global_name == "__exactFsOpenAsync"))
    {
        Some("native-op:__exactFsOpen")
    } else {
        native_async_worker_terminal(invocation)
    };
    // POSIX synchronous retained reads reauthorize through the source-owned
    // open receipt. Descriptor readFileAsync retains that edge and also emits
    // its operation-specific worker edge; scalar/vector async reads emit only
    // their dedicated worker surface. Windows routes carry operation-specific
    // identities throughout. An admitted setup edge is therefore not
    // automatically the selected terminal.
    // @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
    let source_selected_auxiliary_terminals = if closed_filesystem_mutation {
        None
    } else if !target_absence
        && !windows_source
        && retained_descriptor_setup
        && invocation.global_name == "__exactFsReadFileAsync"
    {
        Some(BTreeSet::from([
            "native-op:__exactFsOpen".to_owned(),
            "native-op:__exactFsReadFileAsync".to_owned(),
        ]))
    } else if !target_absence
        && !windows_source
        && matches!(
            invocation.global_name.as_str(),
            "__exactFsOpenAsync"
                | "__exactFsFdAsync"
                | "__exactFsFstatSync"
                | "__exactFsFtruncateSync"
                | "__exactFsFchmodSync"
                | "__exactFsFutimesSync"
                | "__exactFsRead"
                | "__exactFsReadv"
                | "__exactFsWrite"
        )
    {
        Some(BTreeSet::from(["native-op:__exactFsOpen".to_owned()]))
    } else {
        native_async_worker_terminal(invocation)
            .map(|terminal| BTreeSet::from([terminal.to_owned()]))
    };
    let mut expected_allowed_coverage_edge_ids = recipe.edge_ids.clone();
    if let Some(worker_terminal) = auxiliary_allowed_terminal {
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
                    invocation_result["cleanup"],
                    expected_cleanup.as_str(),
                    "{}: native public invocation did not prove its authored cleanup",
                    recipe.fixture_id
                );
            }
            if let Some(expected_string_value) = &invocation.expected_string_value {
                assert!(
                    native_string_result_matches_reviewed_expectation(
                        &invocation.global_name,
                        &invocation.arguments,
                        expected_string_value,
                        invocation_result,
                    ),
                    "{}: native public invocation did not return its exact authored string",
                    recipe.fixture_id
                );
            }
            if invocation.global_name == "__exactGetAllEnv" {
                assert_eq!(invocation_result["valueType"], "object");
                if invocation.expected_typed_decision_count == 0 {
                    // Empty logical branch: the armed base is empty and no
                    // overlay name was seeded, so enumeration must disclose
                    // nothing and observe no typed decision.
                    assert_eq!(
                        invocation_result["valuePropertyCount"], 0,
                        "{}: armed whole-environment enumeration was not empty",
                        recipe.fixture_id
                    );
                } else {
                    // Nonempty logical branch: setup seeded exactly one
                    // principal-overlay name through __exactSetEnv. Allowed
                    // scenarios must disclose exactly that name and value;
                    // denial must skip the seeded name and disclose nothing
                    // (the typed denied decision is the denial evidence).
                    let (seeded_name, seeded_value) = match invocation.setup.as_slice() {
                        [NativeProbeSetup::InvokeNativeGlobal {
                            global_name,
                            arguments,
                        }] if global_name == "__exactSetEnv" && arguments.len() == 2 => (
                            arguments[0]
                                .as_str()
                                .expect("seeded environment name must be a string"),
                            arguments[1]
                                .as_str()
                                .expect("seeded environment value must be a string"),
                        ),
                        _ => panic!(
                            "{}: nonempty environment enumeration requires the single __exactSetEnv seeding setup",
                            recipe.fixture_id
                        ),
                    };
                    if recipe.scenario == "deny" {
                        assert_eq!(
                            invocation_result["valuePropertyCount"], 0,
                            "{}: denied enumeration must skip the seeded name and disclose nothing",
                            recipe.fixture_id
                        );
                    } else {
                        assert_eq!(
                            invocation_result["valuePropertyCount"], 1,
                            "{}: allowed enumeration must disclose exactly the seeded overlay name",
                            recipe.fixture_id
                        );
                        assert_eq!(
                            invocation_result["enumeratedNames"],
                            serde_json::json!([seeded_name]),
                            "{}: enumeration disclosed a name other than the seeded overlay name",
                            recipe.fixture_id
                        );
                        assert_eq!(
                            invocation_result["enumeratedValues"],
                            serde_json::json!([seeded_value]),
                            "{}: enumeration disclosed a value other than the seeded overlay value",
                            recipe.fixture_id
                        );
                    }
                }
                assert_eq!(invocation_result["cleanup"], "none");
            }
            if invocation.global_name == "__exactGetAllEnv" {
                serde_json::json!({
                    "kind": if invocation.expected_typed_decision_count == 0 {
                        "armed-empty-environment-enumeration"
                    } else {
                        "armed-seeded-environment-enumeration"
                    },
                    "bodyEntered": true,
                    "propertyCount": invocation_result["valuePropertyCount"].clone(),
                })
            } else {
                serde_json::json!({
                    "kind": if invocation.kind == "global-property-read" {
                        "global-property-read"
                    } else {
                        "native-return"
                    },
                    "bodyEntered": true,
                })
            }
        }
        "permission-denied" => {
            assert_eq!(
                invocation_result["kind"], "throw",
                "{}: denied public native invocation did not throw: {invocation_result}",
                recipe.fixture_id
            );
            let expected_fragment = invocation
                .expected_deny_message_fragment
                .as_deref()
                .or_else(|| {
                    invocation
                        .public_access
                        .as_ref()
                        .map(|access| access.expected_deny_message_fragment.as_str())
                })
                .unwrap_or("Permission denied");
            assert!(
                invocation_result["errorMessage"]
                    .as_str()
                    .is_some_and(|message| {
                        if expected_fragment == "Permission denied" {
                            message.to_ascii_lowercase().contains("permission denied")
                        } else {
                            message.contains(expected_fragment)
                        }
                    }),
                "{}: denied public native invocation threw the wrong error: {invocation_result}",
                recipe.fixture_id
            );
            if native_closed_filesystem_mutation_is_reviewed(
                &recipe.classification,
                &recipe.scenario,
                invocation,
            ) {
                assert!(
                    native_closed_filesystem_mutation_result_is_reviewed(
                        &recipe.classification,
                        &recipe.scenario,
                        invocation,
                        invocation_result,
                    ),
                    "{}: closed native filesystem mutation returned the wrong exact EPERM account: {invocation_result}",
                    recipe.fixture_id
                );
            }
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
    assert!(
        invocation.expected_typed_outcomes.is_empty()
            || invocation.expected_typed_outcomes.len() == invocation.expected_typed_decision_count,
        "{}: pinned typed outcomes must cover every expected decision",
        recipe.fixture_id
    );
    let mut observed_actions = BTreeSet::new();
    let mut observed_terminals = BTreeSet::new();
    for (decision_index, decision) in typed_decisions.iter().enumerate() {
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
        let expected_outcome = invocation
            .expected_typed_outcomes
            .get(decision_index)
            .map(String::as_str)
            .unwrap_or(if invocation.expected_result == "permission-denied" {
                "deny"
            } else {
                "allow"
            });
        assert_eq!(
            outcome, expected_outcome,
            "{}: observed typed outcome disagrees with the public recipe at decision {decision_index}",
            recipe.fixture_id
        );
        let authority_evidence = decision["evidence"]["evidence"]
            .as_array()
            .expect("observed typed decision has no authority evidence");
        // A denial-return surface refuses the typed decision without throwing,
        // so the authority stratum follows the per-decision outcome, not the
        // public result. @ref LLP 0037#denial-return-evidence-existssync
        let public_denial = expected_outcome == "deny";
        let has_surplus_effect = effects.iter().any(|effect| {
            effect["cap"].as_str().is_some_and(|action_id| {
                !invocation
                    .expected_action_ids
                    .iter()
                    .any(|expected| expected == action_id)
            })
        });
        let reviewed_open_traversal = native_decision_is_reviewed_open_traversal(
            invocation,
            decision,
            effects,
            public_denial,
        );
        if has_surplus_effect {
            assert!(
                reviewed_open_traversal,
                "{}: surplus native effect did not come from a reviewed traversal-stage fs:list operation: expected {:?}, observed {:?}",
                recipe.fixture_id,
                invocation.expected_action_ids,
                effects
            );
        }
        let ambient_project_prefix = !public_denial
            && (uses_ambient_project_prefix_authority(invocation, effects)
                || reviewed_open_traversal);
        let (expected_stratum, expected_source_prefix) = if public_denial {
            ("principal-denial", Some("principal.000000.denial."))
        } else if ambient_project_prefix {
            ("ambient-root", None)
        } else {
            ("static-floor", Some("principal.000000.floor."))
        };
        if native_uses_retained_handle_authority(invocation) {
            let expected_package = serde_json::json!({
                "kind": "package",
                "name": "image-lib",
                "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
                "locator": "image-lib@2.4.1",
            });
            if public_denial {
                assert_eq!(
                    authority_evidence.len(),
                    1,
                    "{}: retained-handle denial must name only the decisive package denial: {authority_evidence:?}",
                    recipe.fixture_id
                );
                let authority = &authority_evidence[0];
                assert_eq!(authority["principal"], expected_package);
                assert_eq!(authority["stratum"], "principal-denial");
                assert_eq!(authority["reason"], "principal-denial");
                assert!(
                    authority["sourceId"]
                        .as_str()
                        .is_some_and(|source| source.starts_with("principal.000001.denial.")),
                    "{}: retained-handle denial escaped the probe principal: {authority}",
                    recipe.fixture_id
                );
                assert!(
                    authority["effectIndex"]
                        .as_u64()
                        .is_some_and(|index| index < effects.len() as u64),
                    "{}: retained-handle denial named an invalid effect: {authority}",
                    recipe.fixture_id
                );
            } else {
                assert!(!ambient_project_prefix);
                assert_eq!(
                    authority_evidence.len(),
                    effects.len() * 2,
                    "{}: retained-handle allow must prove both owner and probe authority for every effect: {authority_evidence:?}",
                    recipe.fixture_id
                );
                let expected_root = serde_json::json!({
                    "kind": "root",
                    "identity": "project-root",
                });
                let mut authority_rows = BTreeSet::new();
                for authority in authority_evidence {
                    let effect_index = authority["effectIndex"]
                        .as_u64()
                        .and_then(|index| usize::try_from(index).ok())
                        .filter(|index| *index < effects.len())
                        .unwrap_or_else(|| {
                            panic!(
                                "{}: retained-handle authority row has an invalid effect index: {authority}",
                                recipe.fixture_id
                            )
                        });
                    let (principal_index, expected_source_prefix) =
                        if authority["principal"] == expected_root {
                            (0_usize, "principal.000000.floor.")
                        } else {
                            assert_eq!(authority["principal"], expected_package);
                            (1_usize, "principal.000001.floor.")
                        };
                    assert!(
                        authority_rows.insert((effect_index, principal_index)),
                        "{}: retained-handle authority duplicated effect/principal row ({effect_index}, {principal_index})",
                        recipe.fixture_id
                    );
                    assert_eq!(authority["stratum"], "static-floor");
                    assert_eq!(authority["reason"], "static-floor");
                    assert!(
                        authority["sourceId"]
                            .as_str()
                            .is_some_and(|source| source.starts_with(expected_source_prefix)),
                        "{}: retained-handle allow used the wrong authority source: {authority}",
                        recipe.fixture_id
                    );
                }
                assert_eq!(authority_rows.len(), effects.len() * 2);
            }
            continue;
        }
        assert_eq!(
            authority_evidence.len(),
            effects.len(),
            "{}: public native decision must have one decisive authority row per effect: {authority_evidence:?}",
            recipe.fixture_id
        );
        let mut authority_effect_indexes = BTreeSet::new();
        for authority in authority_evidence {
            let effect_index = authority["effectIndex"]
                .as_u64()
                .and_then(|index| usize::try_from(index).ok())
                .filter(|index| *index < effects.len())
                .unwrap_or_else(|| {
                    panic!(
                        "{}: public native authority row has an invalid effect index: {authority}",
                        recipe.fixture_id
                    )
                });
            assert!(
                authority_effect_indexes.insert(effect_index),
                "{}: public native authority rows duplicate effect {effect_index}",
                recipe.fixture_id
            );
            assert_eq!(
                authority["principal"],
                serde_json::json!({ "kind": "root", "identity": "project-root" })
            );
            assert_eq!(authority["stratum"], expected_stratum);
            assert_eq!(authority["reason"], expected_stratum);
            if let Some(expected_source_prefix) = expected_source_prefix {
                assert!(
                    authority["sourceId"]
                        .as_str()
                        .is_some_and(|source| source.starts_with(expected_source_prefix)),
                    "{}: public native decision used the wrong authority source: {authority}",
                    recipe.fixture_id
                );
            } else {
                assert_eq!(authority["sourceId"], serde_json::Value::Null);
            }
        }
        assert_eq!(authority_effect_indexes.len(), effects.len());
    }
    if invocation.expected_result == "absent" {
        assert!(
            observed_actions.is_empty(),
            "{}: target/lockdown absence cannot invent observed actions",
            recipe.fixture_id
        );
    } else {
        assert!(
            native_observed_actions_are_reviewed(invocation, &observed_actions),
            "{}: observed actions {:?} exceed declared actions {:?} outside a reviewed native traversal",
            recipe.fixture_id,
            observed_actions,
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
                    && matches!(recipe.scenario.as_str(), "branch-selection" | "no-effect"))
                || native_closed_filesystem_mutation_result_is_reviewed(
                    &recipe.classification,
                    &recipe.scenario,
                    invocation,
                    invocation_result,
                ),
            "{}: a zero-decision public invocation did not select a reviewed zero-effect branch",
            recipe.fixture_id
        );
        probe.surface_observed_key.clone()
    } else if let Some(worker_terminals) = source_selected_auxiliary_terminals {
        assert_eq!(
            observed_terminals, worker_terminals,
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

#[derive(Default)]
struct NativePublicFixtureCleanup {
    files: Vec<std::path::PathBuf>,
    directories: Vec<std::path::PathBuf>,
}

impl Drop for NativePublicFixtureCleanup {
    fn drop(&mut self) {
        for path in &self.files {
            let _ = std::fs::remove_file(path);
        }
        for path in self.directories.iter().rev() {
            let _ = std::fs::remove_dir(path);
        }
    }
}

fn prepare_native_async_write_file_fixture(path: &str, cleanup: &mut NativePublicFixtureCleanup) {
    assert_eq!(path, NATIVE_ASYNC_WRITE_FILE_FIXTURE_PATH);
    // This exact path is the complete ownership boundary for stale-file
    // removal and cleanup. Another invocation of the same global cannot
    // borrow the fixture under a different path.
    // @ref LLP 0049#3-construction-rules
    cleanup.files.push(path.into());
    if let Err(error) = std::fs::remove_file(path) {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::NotFound,
            "clear stale owned async write-file fixture {path}: {error}"
        );
    }
}

fn finalize_native_async_write_file_fixture(path: &str, invocation_result: &mut serde_json::Value) {
    assert_eq!(path, NATIVE_ASYNC_WRITE_FILE_FIXTURE_PATH);
    if invocation_result["kind"] == "return" {
        assert_eq!(
            std::fs::read(path).expect("read async write-file fixture"),
            NATIVE_ASYNC_WRITE_FILE_FIXTURE_BYTES
        );
        std::fs::remove_file(path).expect("remove async write-file fixture");
        invocation_result["cleanup"] = serde_json::Value::String("removed-owned-file".into());
    } else {
        assert!(
            !std::path::Path::new(path).exists(),
            "denied async write-file invocation changed physical state"
        );
    }
}

struct InstalledConformanceObservationGuard {
    active: bool,
}

impl InstalledConformanceObservationGuard {
    fn begin(session_id: &str) -> Self {
        assert!(
            ibex_runtime::host::abi::begin_installed_conformance_observation(session_id),
            "public native observer has no installed host"
        );
        Self { active: true }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for InstalledConformanceObservationGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = ibex_runtime::host::abi::take_installed_conformance_observations();
        }
    }
}

async fn execute_native_public_recipe(
    engine: &mut AuthenticatedNativeEngine,
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
    let mut fixture_cleanup = NativePublicFixtureCleanup::default();
    if let Some(path) = &setup_state.sqlite_file_path {
        fixture_cleanup
            .files
            .extend(native_sqlite_owned_paths(path).map(Into::into));
    }
    let fs_path_async_directory_fixture = if invocation.global_name == "__exactFsPathAsync" {
        match (invocation.arguments.first(), invocation.arguments.get(1)) {
            (
                Some(NativeProbeArgument::JsonLiteral { value: operation }),
                Some(NativeProbeArgument::JsonLiteral { value: path }),
            ) if operation.as_str() == Some("mkdir") => Some(
                path.as_str()
                    .expect("filesystem fixture path must be a string")
                    .to_owned(),
            ),
            _ => None,
        }
    } else {
        None
    };
    if let Some(path) = &fs_path_async_directory_fixture {
        assert!(
            path.starts_with("target/ibex-capsec-fspathasync-"),
            "filesystem fixture cleanup path escaped its owned target prefix"
        );
        fixture_cleanup.directories.push(path.into());
        if let Err(error) = std::fs::remove_dir(path) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "clear stale owned directory fixture {path}: {error}"
            );
        }
    }
    let direct_mkdir_fixture = if invocation.global_name == "__exactMkdir" {
        match (invocation.arguments.first(), invocation.arguments.get(1)) {
            (
                Some(NativeProbeArgument::JsonLiteral { value: path }),
                Some(NativeProbeArgument::JsonLiteral { value: recursive }),
            ) if recursive == &serde_json::Value::Bool(false) => Some(
                path.as_str()
                    .expect("direct mkdir fixture path must be a string")
                    .to_owned(),
            ),
            _ => None,
        }
    } else {
        None
    };
    if let Some(path) = &direct_mkdir_fixture {
        assert_eq!(path, "target/ibex-capsec-mkdir");
        let _ = std::fs::remove_dir(path);
    }
    let direct_write_file_fixture = if invocation.global_name == "__exactWriteFile" {
        match invocation.arguments.first() {
            Some(NativeProbeArgument::JsonLiteral { value: path }) => Some(
                path.as_str()
                    .expect("direct write-file fixture path must be a string")
                    .to_owned(),
            ),
            _ => None,
        }
    } else {
        None
    };
    if let Some(path) = &direct_write_file_fixture {
        assert_eq!(path, "target/ibex-capsec-write-file");
        let _ = std::fs::remove_file(path);
    }
    let async_write_file_fixture =
        native_async_write_file_fixture_path(invocation).map(str::to_owned);
    if let Some(path) = &async_write_file_fixture {
        prepare_native_async_write_file_fixture(path, &mut fixture_cleanup);
    }
    let direct_append_file_fixture = if invocation.global_name == "__exactAppendFile" {
        match invocation.arguments.first() {
            Some(NativeProbeArgument::JsonLiteral { value: path }) => Some(
                path.as_str()
                    .expect("direct append-file fixture path must be a string")
                    .to_owned(),
            ),
            _ => None,
        }
    } else {
        None
    };
    if let Some(path) = &direct_append_file_fixture {
        assert_eq!(path, "target/ibex-capsec-append-file");
        std::fs::write(path, b"ibex-capsec-append-prefix:")
            .expect("create direct append-file fixture");
    }
    let direct_truncate_fixture = if invocation.global_name == "__exactTruncate" {
        match invocation.arguments.first() {
            Some(NativeProbeArgument::JsonLiteral { value: path }) => Some(
                path.as_str()
                    .expect("direct truncate fixture path must be a string")
                    .to_owned(),
            ),
            _ => None,
        }
    } else {
        None
    };
    if let Some(path) = &direct_truncate_fixture {
        assert_eq!(path, "target/ibex-capsec-truncate");
        std::fs::write(path, b"ibex-capsec-truncate-owned")
            .expect("create direct truncate fixture");
    }
    let direct_fs_open_fixture = if matches!(
        invocation.global_name.as_str(),
        "__exactFsOpen" | "__exactFsOpenAsync"
    ) {
        match invocation.arguments.first() {
            Some(NativeProbeArgument::JsonLiteral { value: path }) => Some(
                path.as_str()
                    .expect("direct fs-open fixture path must be a string")
                    .to_owned(),
            ),
            _ => None,
        }
    } else {
        None
    };
    if let Some(path) = &direct_fs_open_fixture {
        assert!(
            path.starts_with("target/ibex-capsec-fsopen-"),
            "direct fs-open fixture escaped its owned target prefix"
        );
        std::fs::write(path, b"ibex-capsec-fsopen-owned").expect("create direct fs-open fixture");
    }
    let direct_readdir_fixture = if invocation.global_name == "__exactReaddir" {
        match invocation.arguments.first() {
            Some(NativeProbeArgument::JsonLiteral { value: path }) => Some(
                path.as_str()
                    .expect("direct readdir fixture path must be a string")
                    .to_owned(),
            ),
            _ => None,
        }
    } else {
        None
    };
    if let Some(path) = &direct_readdir_fixture {
        assert_eq!(path, "target/ibex-capsec-readdir");
        let _ = std::fs::remove_file(format!("{path}/entry.txt"));
        let _ = std::fs::remove_dir(path);
        std::fs::create_dir(path).expect("create direct readdir fixture");
        std::fs::write(format!("{path}/entry.txt"), b"ibex-capsec-readdir")
            .expect("create direct readdir fixture entry");
    }
    let fs_path_async_file_fixture = if invocation.global_name == "__exactFsPathAsync" {
        match (invocation.arguments.first(), invocation.arguments.get(1)) {
            (
                Some(NativeProbeArgument::JsonLiteral { value: operation }),
                Some(NativeProbeArgument::JsonLiteral { value: path }),
            ) if matches!(operation.as_str(), Some("truncate" | "chmod" | "utime")) => Some((
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
        assert_eq!(path, &format!("target/ibex-capsec-fspathasync-{operation}"));
        fixture_cleanup.files.push(path.into());
        if let Err(error) = std::fs::remove_file(path) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "clear stale owned file fixture {path}: {error}"
            );
        }
        std::fs::write(path, b"ibex-capsec-retained-file")
            .expect("create owned retained-file fixture");
    }
    let session_id = format!("public-observation:{}", recipe.plan_digest);
    let mut observation_guard = InstalledConformanceObservationGuard::begin(&session_id);
    let result = if let Some(completion) = &invocation.completion {
        assert_eq!(completion.kind, "event-loop-quiescence");
        // The scheduling submission is not completion evidence. Keep the
        // observer open while the exact loaded engine settles its referenced
        // async work, and apply the authored bound to that whole lifecycle.
        // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
        tokio::time::timeout(
            std::time::Duration::from_millis(completion.timeout_milliseconds),
            async {
                let scheduled = engine
                    .eval_probe_immediate(&native_async_invocation_script(invocation, &arguments))
                    .await?;
                anyhow::ensure!(
                    matches!(scheduled.as_deref(), Some("scheduled" | "completed")),
                    "native public async invocation returned an invalid scheduling marker: {scheduled:?}"
                );
                engine.drive_event_loop_to_quiescence().await?;
                engine
                    .eval_immediate(&native_async_result_take_script())
                    .await
            },
        )
        .await
        .expect("native public async invocation exceeded its completion bound")
        .map_err(|error| anyhow::anyhow!("complete native public async invocation: {error:#}"))
    } else {
        engine
            .eval_probe_immediate(&native_invocation_script(
                invocation,
                &arguments,
                &setup_state,
            ))
            .await
    };
    // The enumeration result (property count, names, values) is captured
    // inside the observed invocation script itself: a second __exactGetAllEnv
    // call here would add its own typed decisions to the observation buffer
    // and corrupt the nonempty branch's pinned sequence.
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    observation_guard.disarm();
    let encoded = result
        .expect("execute native public invocation in Hermes")
        .expect("native public invocation returned no result");
    let mut invocation_result: serde_json::Value =
        serde_json::from_str(&encoded).expect("native public invocation returned invalid JSON");
    let retained_descriptor_operation = setup_state.fs_file_descriptor.is_some()
        && matches!(
            invocation.global_name.as_str(),
            "__exactFsRead"
                | "__exactFsReadv"
                | "__exactFsReadAsync"
                | "__exactFsReadvAsync"
                | "__exactFsReadFileAsync"
                | "__exactFsFstatSync"
                | "__exactFsFsyncSync"
                | "__exactFsFdatasyncSync"
                | "__exactFsFtruncateSync"
                | "__exactFsFdAsync"
                | "__exactFsWrite"
                | "__exactFsWriteAsync"
                | "__exactFsWritevAsync"
        );
    if retained_descriptor_operation {
        let descriptor = setup_state
            .fs_file_descriptor
            .expect("retained descriptor operation requires an owned setup descriptor");
        let cleanup = engine
            .eval_immediate(&format!(
                "JSON.stringify((function(){{try{{globalThis.__exactFsClose({});return {{kind:\"return\"}};}}catch(e){{return {{kind:\"throw\",errorMessage:String(e&&e.message||e)}};}}}})())",
                serde_json::to_string(&descriptor).expect("serialize setup descriptor")
            ))
            .await
            .expect("close retained setup descriptor")
            .expect("retained descriptor cleanup returned no result");
        let cleanup: serde_json::Value = serde_json::from_str(&cleanup)
            .expect("retained descriptor cleanup returned invalid JSON");
        assert_eq!(
            cleanup["kind"], "return",
            "retained descriptor cleanup failed"
        );
        if let Some(path) = &setup_state.fs_file_path {
            let expected_bytes = match invocation.global_name.as_str() {
                "__exactFsFtruncateSync" => b"ib".to_vec(),
                "__exactFsWrite" => b"ibex-capsec-retained-sync-append".to_vec(),
                "__exactFsWriteAsync" => b"ibex-capsec-retained-sync-async".to_vec(),
                "__exactFsWritevAsync" => {
                    let mut bytes = b"ibex-capsec-retained-sync".to_vec();
                    bytes.extend_from_slice(&[0; 5]);
                    bytes
                }
                _ => b"ibex-capsec-retained-sync".to_vec(),
            };
            assert_eq!(
                std::fs::read(path).expect("read retained sync fixture"),
                expected_bytes
            );
            std::fs::remove_file(path).expect("remove retained sync fixture");
            if invocation_result["kind"] == "return" {
                invocation_result["cleanup"] = serde_json::Value::String(
                    "closed-fs-file-descriptor-removed-owned-file".into(),
                );
            }
        } else if invocation_result["kind"] == "return" {
            invocation_result["cleanup"] =
                serde_json::Value::String("closed-fs-file-descriptor".into());
        }
    }
    let retained_sqlite_operation = setup_state.sqlite_database_handle.is_some()
        && matches!(
            invocation.global_name.as_str(),
            "__exactSqliteAll"
                | "__exactSqliteExec"
                | "__exactSqliteGet"
                | "__exactSqlitePrepare"
                | "__exactSqliteRun"
                | "__exactSqliteValues"
        );
    if retained_sqlite_operation && invocation_result["kind"] != "return" {
        let cleanup = engine
            .eval_immediate(&format!(
                "JSON.stringify((function(){{try{{var statement={};var database={};if(typeof statement===\"number\")globalThis.__exactSqliteFinalize(statement);globalThis.__exactSqliteClose(database);return {{kind:\"return\"}};}}catch(e){{return {{kind:\"throw\",errorMessage:String(e&&e.message||e)}};}}}})())",
                serde_json::to_string(&setup_state.sqlite_statement_handle)
                    .expect("serialize retained SQLite statement"),
                serde_json::to_string(
                    &setup_state
                        .sqlite_database_handle
                        .expect("retained SQLite cleanup requires a database")
                )
                .expect("serialize retained SQLite database")
            ))
            .await
            .expect("close retained file-backed SQLite handles")
            .expect("retained file-backed SQLite cleanup returned no result");
        let cleanup: serde_json::Value = serde_json::from_str(&cleanup)
            .expect("retained file-backed SQLite cleanup returned invalid JSON");
        assert_eq!(
            cleanup["kind"], "return",
            "retained file-backed SQLite cleanup failed: {cleanup}"
        );
    }
    if let Some(path) = &fs_path_async_directory_fixture {
        if invocation_result["kind"] == "return" {
            std::fs::remove_dir(path)
                .expect("remove directory created by async filesystem fixture");
            invocation_result["cleanup"] =
                serde_json::Value::String("removed-created-directory".into());
        }
    }
    if let Some(path) = &direct_mkdir_fixture {
        if invocation_result["kind"] == "return" {
            std::fs::remove_dir(path).expect("remove directory created by direct mkdir fixture");
            invocation_result["cleanup"] =
                serde_json::Value::String("removed-created-directory".into());
        }
    }
    if let Some(path) = &direct_write_file_fixture {
        if invocation_result["kind"] == "return" {
            assert_eq!(
                std::fs::read(path).expect("read direct write-file fixture"),
                b"ibex-capsec-write-file"
            );
            std::fs::remove_file(path).expect("remove direct write-file fixture");
            invocation_result["cleanup"] = serde_json::Value::String("removed-owned-file".into());
        }
    }
    if let Some(path) = &async_write_file_fixture {
        finalize_native_async_write_file_fixture(path, &mut invocation_result);
    }
    if let Some(path) = &direct_append_file_fixture {
        let expected = if invocation_result["kind"] == "return" {
            b"ibex-capsec-append-prefix:ibex-capsec-append-suffix".as_slice()
        } else {
            b"ibex-capsec-append-prefix:".as_slice()
        };
        assert_eq!(
            std::fs::read(path).expect("read direct append-file fixture"),
            expected
        );
        std::fs::remove_file(path).expect("remove direct append-file fixture");
        if invocation_result["kind"] == "return" {
            invocation_result["cleanup"] = serde_json::Value::String("removed-owned-file".into());
        }
    }
    if let Some(path) = &direct_truncate_fixture {
        let expected = if invocation_result["kind"] == "return" {
            b"ib".as_slice()
        } else {
            b"ibex-capsec-truncate-owned".as_slice()
        };
        assert_eq!(
            std::fs::read(path).expect("read direct truncate fixture"),
            expected
        );
        std::fs::remove_file(path).expect("remove direct truncate fixture");
        if invocation_result["kind"] == "return" {
            invocation_result["cleanup"] = serde_json::Value::String("removed-owned-file".into());
        }
    }
    if let Some(path) = &direct_fs_open_fixture {
        assert_eq!(
            std::fs::read(path).expect("read direct fs-open fixture"),
            b"ibex-capsec-fsopen-owned"
        );
        std::fs::remove_file(path).expect("remove direct fs-open fixture");
        if invocation_result["kind"] == "return" {
            assert_eq!(invocation_result["cleanup"], "closed-fs-file-descriptor");
            invocation_result["cleanup"] =
                serde_json::Value::String("closed-fs-file-descriptor-removed-owned-file".into());
        }
    }
    if let Some(path) = &direct_readdir_fixture {
        std::fs::remove_file(format!("{path}/entry.txt"))
            .expect("remove direct readdir fixture entry");
        std::fs::remove_dir(path).expect("remove direct readdir fixture");
        if invocation_result["kind"] == "return" {
            invocation_result["cleanup"] =
                serde_json::Value::String("removed-owned-directory".into());
        }
    }
    if let Some((operation, path)) = &fs_path_async_file_fixture {
        if invocation_result["kind"] == "return" {
            let metadata = std::fs::metadata(path).expect("read retained-file fixture metadata");
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
            invocation_result["cleanup"] = serde_json::Value::String("removed-owned-file".into());
        }
        std::fs::remove_file(path).expect("remove owned retained-file fixture");
    }
    if let Some(path) = &setup_state.sqlite_file_path {
        for owned_path in native_sqlite_owned_paths(path) {
            if let Err(error) = std::fs::remove_file(&owned_path) {
                assert_eq!(
                    error.kind(),
                    std::io::ErrorKind::NotFound,
                    "remove on-disk SQLite setup fixture {owned_path}: {error}"
                );
            }
        }
        if invocation_result["kind"] == "return" {
            let cleanup = invocation_result["cleanup"]
                .as_str()
                .expect("successful on-disk SQLite probe must report handle cleanup");
            let expected_cleanup = if retained_sqlite_operation
                && matches!(
                    invocation.global_name.as_str(),
                    "__exactSqliteAll"
                        | "__exactSqliteGet"
                        | "__exactSqlitePrepare"
                        | "__exactSqliteRun"
                        | "__exactSqliteValues"
                ) {
                "finalized-sqlite-statement-closed-db"
            } else {
                "closed-sqlite-db"
            };
            assert_eq!(
                cleanup, expected_cleanup,
                "successful on-disk SQLite probe used an unexpected cleanup"
            );
            invocation_result["cleanup"] = serde_json::Value::String(format!(
                "{cleanup}-removed-owned-file"
            ));
        }
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
    assert!(
        !pointer.is_null(),
        "host SQLite operation returned no result"
    );
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
    assert!(matches!(
        recipe.scenario.as_str(),
        "branch-selection" | "no-effect"
    ));
    assert!(recipe.action_ids.is_empty());
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(probe.kind, "public-surface-invocation");
    assert_eq!(
        probe.surface_observed_key,
        format!("host-abi:{}", invocation.function_name)
    );
    assert_eq!(probe.surface_observed_key, recipe.terminal_observed_key);
    assert!(recipe
        .route
        .alternatives
        .iter()
        .any(|alternative| { alternative.terminal_observed_key == probe.surface_observed_key }));
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
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id));
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

async fn execute_authenticated_module_runner_public_graph(
    project_root: &std::path::Path,
    entry: &std::path::Path,
    hermes_target: &str,
    producer_digest: &capsec_semantics::model::Digest,
    prepared_deployment_digest: Option<capsec_semantics::model::Digest>,
    session_id: &str,
    retain_context: bool,
) {
    use ibex_runtime::module_loader::runner_pipeline::{
        build_authenticated_source_graph_v1_for_host, load_prepared_source_graph_v1,
        publish_prepared_source_graph_v1, SourceModuleGraphBuildV1,
    };

    let relative_entry = entry
        .strip_prefix(project_root)
        .expect("module-runner public entry must remain beneath its project root")
        .to_str()
        .expect("module-runner public entry must be UTF-8")
        .replace('\\', "/");
    let entry_identity = format!("file:///project/{relative_entry}");
    let snapshot_entry_identity = entry_identity.clone();
    let (host, snapshot_digest) = build_armed_test_host_custom(
        Some(project_root),
        false,
        true,
        true,
        Vec::new(),
        None,
        move |snapshot| {
            snapshot["entry"] = serde_json::json!({
                "kind": "file",
                "identity": snapshot_entry_identity,
                "mode": "program",
            });
        },
    );
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create isolated module-runner host ABI engine");
    engine
        .load_runtime()
        .await
        .expect("load runtime before module-runner host ABI recipe");

    if retain_context {
        assert!(
            ibex_runtime::host::abi::begin_installed_conformance_observation(&format!(
                "{session_id}:retain"
            )),
            "module-runner retain observer has no installed host",
        );
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
        let (retain_legacy, retain_typed) =
            ibex_runtime::host::abi::take_installed_conformance_observations();
        assert!(
            retain_legacy.is_empty(),
            "module-runner context retention performed legacy authorization"
        );
        assert!(
            retain_typed.is_empty(),
            "module-runner context retention performed a typed capability decision"
        );
    }

    let vfs = host
        .virtual_file_system()
        .expect("create module-runner public virtual filesystem");
    let namespace = vfs
        .resolve_root_file_url(&entry_identity, None)
        .expect("resolve authenticated module-runner public entry");
    let session = host
        .mint_armed_session_token()
        .expect("mint module-runner public armed session");
    let mut sequence = ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())
        .expect("create module-runner public submission sequence");
    let submission = sequence
        .mint_file(
            namespace
                .logical_referrer()
                .expect("derive module-runner public logical referrer"),
            &[],
        )
        .expect("mint module-runner public file submission");
    let request = host
        .authenticated_vfs_file_read(&vfs, namespace, submission)
        .expect("read authenticated module-runner public entry")
        .into_capsule()
        .into_request()
        .expect("construct module-runner public source request");

    let graph_host = host.clone();
    let graph_entry = entry.to_path_buf();
    let graph_project_root = project_root.to_path_buf();
    let graph_producer_digest = producer_digest.clone();
    let graph_hermes_target = hermes_target.to_owned();
    let execution_session_id = format!("{session_id}:execution");
    let execution_observer_id = execution_session_id.clone();
    assert!(
        ibex_runtime::host::abi::begin_installed_conformance_observation(&format!(
            "{session_id}:admission"
        )),
        "module-runner admission observer has no installed host",
    );
    let evaluation = engine
        .evaluate_authenticated_module_graph(
            &session,
            request,
            Box::new(move |admitted_request| {
                let (admission_legacy, admission_typed) =
                    ibex_runtime::host::abi::take_installed_conformance_observations();
                assert!(
                    admission_legacy.is_empty(),
                    "module-runner admission performed legacy authorization"
                );
                assert!(
                    admission_typed.is_empty(),
                    "module-runner admission or generation pin performed a typed capability decision"
                );
                // Native admission must precede graph discovery and prepared
                // carrier selection; this callback is the production seam.
                // @ref LLP 0026#authenticate-before-discovery-and-execute-under-derived-identity
                // @ref LLP 0027#canonical-encoding-and-validation
                let graph = match build_authenticated_source_graph_v1_for_host(
                    &graph_host,
                    &graph_entry,
                    graph_producer_digest,
                    &graph_hermes_target,
                )? {
                    SourceModuleGraphBuildV1::Native(graph) => graph,
                    SourceModuleGraphBuildV1::LegacyRequired(requirement) => anyhow::bail!(
                        "module-runner public graph unexpectedly required legacy: {}",
                        requirement.reason
                    ),
                };
                let entry_join =
                    graph.validate_authenticated_entry_request(admitted_request)?;
                let graph = if let Some(deployment_digest) = prepared_deployment_digest {
                    let prepared_cache = publish_prepared_source_graph_v1(
                        &graph,
                        &graph_project_root,
                        deployment_digest.clone(),
                    )?;
                    load_prepared_source_graph_v1(
                        &prepared_cache,
                        &graph,
                        &entry_join,
                        &deployment_digest,
                    )?
                } else {
                    graph
                };
                // Graph discovery and authenticated source acquisition are
                // setup for this non-capability ABI fixture. Begin the exact
                // observation only after that setup is complete so loader
                // effects cannot be miscredited to the native module-runner
                // lifecycle surface selected by the recipe.
                // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
                assert!(
                    ibex_runtime::host::abi::begin_installed_conformance_observation(
                        &execution_observer_id,
                    ),
                    "module-runner execution observer has no installed host",
                );
                Ok(crate::engine::AuthenticatedModuleGraphPreparation::Native(
                    graph,
                ))
            }),
        )
        .await
        .expect("execute authenticated module-runner public graph");
    match evaluation {
        AuthenticatedEvaluation::Empty => {}
        AuthenticatedEvaluation::Value { receipt, .. } => {
            if let Some(receipt) = receipt {
                engine
                    .release_undisplayed_value(receipt)
                    .await
                    .expect("release module-runner public graph display receipt");
            }
        }
        AuthenticatedEvaluation::Throw(thrown) => {
            panic!("authenticated module-runner public graph threw: {thrown:?}")
        }
        AuthenticatedEvaluation::Cancelled => {
            panic!("authenticated module-runner public graph was cancelled")
        }
        AuthenticatedEvaluation::Lifecycle(code) => {
            panic!("authenticated module-runner public graph exited with lifecycle code {code}")
        }
    }
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(
        legacy.is_empty(),
        "module-runner execution performed legacy authorization"
    );
    let typed_summary = typed
        .iter()
        .flat_map(|decision| {
            decision.gates.iter().map(move |gate| {
                (
                    gate.coverage_edge_id.as_str().to_owned(),
                    format!("{:?}", decision.decision_set.context.stage),
                    format!("{:?}", decision.evidence.outcome),
                )
            })
        })
        .collect::<BTreeSet<_>>();
    const REVIEWED_MODULE_RUNNER_AUXILIARY_EDGES: [&str; 2] = [
        "surface.loader.require.resolve.12c9l9i",
        "surface.native.op.exactreadfile.1cmzco7",
    ];
    // The selected module-runner ABI is a non-capability lifecycle surface,
    // but reaching its CommonJS link/evaluation path now performs the exact
    // invocation-time require authorization and authenticated source reads.
    // Those separately reviewed auxiliary effects must remain allowed, must
    // stay attributed to their own edges, and are not credited to the ABI
    // fixture's expected zero-decision observation.
    // @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
    // @ref LLP 0026#7-commonjs-interop
    assert!(
        typed.iter().all(|decision| {
            decision.terminal_branch_id == execution_session_id
                && decision.evidence.outcome == capsec_semantics::decision::DecisionOutcome::Allow
                && !decision.gates.is_empty()
                && decision.gates.iter().all(|gate| {
                    REVIEWED_MODULE_RUNNER_AUXILIARY_EDGES.contains(&gate.coverage_edge_id.as_str())
                })
        }),
        "module-runner execution escaped its reviewed auxiliary effects: {typed_summary:#?}"
    );
    vfs.close();
    drop(engine);
}

async fn execute_module_runner_host_abi_public_recipe(
    recipe: &Recipe,
    engine_binary_digest: &str,
) -> serde_json::Value {
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
    assert_eq!(
        probe.surface_observed_key,
        format!("host-abi:{}", invocation.function_name)
    );
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
    assert_eq!(
        invocation.source_descriptor["functionName"],
        invocation.function_name
    );
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
    // This corpus intentionally stays inside the production-native subset.
    // Authored dynamic-import and CommonJS require edges select the bounded
    // compatibility loader before target discovery and cannot prove their
    // dormant native link ABIs through this public path.
    // @ref LLP 0026#6-top-level-await-and-dynamic-import
    let entry = project_root.join("entry.mjs");
    std::fs::write(
        &entry,
        "import { settled } from './asynchronous-entry.mjs';\n\
         import cjs from './commonjs-entry.cjs';\n\
         import { value as imported } from './dep.mjs';\n\
         export { other as forwarded } from './dep.mjs';\n\
         export * from './star.mjs';\n\
         export const local = imported + cjs.total + (settled ? 0 : 100);\n\
         export function loadDynamic() { return import('./dynamic.mjs'); }\n\
         export function loadComputed(name) { return import(name, { with: { 'ibex:site': 'esm-route' } }); }\n",
    )
    .expect("write module-runner public entry");
    std::fs::write(
        project_root.join("dep.mjs"),
        "export let value = 1; export const other = 2;\n",
    )
    .expect("write module-runner public dependency");
    std::fs::write(project_root.join("star.mjs"), "export const star = 3;\n")
        .expect("write module-runner public star dependency");
    let commonjs_entry = project_root.join("commonjs-entry.cjs");
    std::fs::write(
        &commonjs_entry,
        "const peer = require('./commonjs-peer.cjs');\n\
         const esm = require('./commonjs-esm.mjs');\n\
         exports.total = peer.value + esm.value;\n\
         exports.loadDynamic = () => import('./dynamic.mjs');\n\
         const route = './dynamic.mjs';\n\
         exports.loadComputed = () => import(route, { with: { 'ibex:site': 'cjs-route' } });\n",
    )
    .expect("write module-runner public CommonJS entry");
    std::fs::write(
        project_root.join("commonjs-peer.cjs"),
        "const peer = require('./commonjs-leaf.cjs');\n\
         const esm = require('./commonjs-leaf-esm.mjs');\n\
         exports.value = peer.value + esm.value;\n",
    )
    .expect("write module-runner public CommonJS dependency");
    std::fs::write(
        project_root.join("commonjs-leaf.cjs"),
        "exports.value = 1;\n",
    )
    .expect("write module-runner public CommonJS leaf");
    std::fs::write(
        project_root.join("commonjs-leaf-esm.mjs"),
        "export const value = 1;\n",
    )
    .expect("write module-runner public CommonJS-to-ESM leaf");
    std::fs::write(
        project_root.join("commonjs-esm.mjs"),
        "export const value = 3;\n",
    )
    .expect("write module-runner public CommonJS ESM dependency");
    // The declared computed-candidate target must resolve at graph
    // preparation even though no fixture ever invokes the dynamic route;
    // the import stays dormant and unexecuted.
    std::fs::write(
        project_root.join("dynamic.mjs"),
        "export const dormant = true;\n",
    )
    .expect("write module-runner public dormant dynamic candidate");
    std::fs::write(
        project_root.join("package.json"),
        r#"{"ibex":{"computedCandidates":{"sites":[{"requester":"commonjs-entry.cjs","label":"cjs-route","specifiers":["./dynamic.mjs"]},{"requester":"entry.mjs","label":"esm-route","specifiers":["./dynamic.mjs"]}]}}}"#,
    )
    .expect("write module-runner computed-candidate declarations");
    let asynchronous_entry = project_root.join("asynchronous-entry.mjs");
    std::fs::write(
        &asynchronous_entry,
        "await new Promise((resolve) => setTimeout(resolve, 0));\n\
         export const settled = true;\n",
    )
    .expect("write module-runner public asynchronous entry");

    let _reset = HostResetGuard;
    // Oxc executes inside the mapped Ibex image, not the separately loaded
    // Hermes image.
    // @ref LLP 0027#canonical-encoding-and-validation
    let producer_digest = crate::runtime::module_producer_binary_digest()
        .expect("authenticate mapped Ibex module producer");
    let deployment_digest = ibex_runtime::module_loader::artifact::digest_bytes(
        "ibex/capsec-module-runner-public-prepared/1",
        b"authenticated prepared graph",
    )
    .expect("digest module-runner public prepared graph");
    // Production pins generation 1 during admission and owns it until the
    // engine's owner-thread teardown. The direct unpin ABI is therefore not a
    // production-callable lifecycle surface for this evidence corpus.
    // @ref LLP 0027#esmcommonjs-interop-matrix
    unsafe { ibex_test_begin_module_runner_abi_observation() };
    let session_id = format!("public-module-runner-host-abi:{}", recipe.plan_digest);
    execute_authenticated_module_runner_public_graph(
        &project_root,
        &entry,
        "capsec-module-runner-public-esm",
        &producer_digest,
        None,
        &session_id,
        true,
    )
    .await;
    execute_authenticated_module_runner_public_graph(
        &project_root,
        &commonjs_entry,
        "capsec-module-runner-public-commonjs",
        &producer_digest,
        None,
        &session_id,
        false,
    )
    .await;
    execute_authenticated_module_runner_public_graph(
        &project_root,
        &asynchronous_entry,
        "capsec-module-runner-public-asynchronous",
        &producer_digest,
        None,
        &session_id,
        false,
    )
    .await;
    execute_authenticated_module_runner_public_graph(
        &project_root,
        &entry,
        "capsec-module-runner-public-esm",
        &producer_digest,
        Some(deployment_digest),
        &session_id,
        false,
    )
    .await;
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
    let encoded =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(label));
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
    use capsec_semantics::arming::SnapshotGenerations;
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
    assert_eq!(
        probe.surface_observed_key,
        format!("loader:{}", invocation.surface_name)
    );
    assert_eq!(probe.surface_observed_key, recipe.terminal_observed_key);
    assert!(recipe
        .route
        .alternatives
        .iter()
        .any(|alternative| { alternative.terminal_observed_key == probe.surface_observed_key }));
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
    assert_eq!(
        invocation.source_descriptor["kind"],
        "module-loader-function"
    );
    assert_eq!(
        invocation.source_descriptor["surfaceName"],
        invocation.surface_name
    );

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
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(&session_id));
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

#[cfg(test)]
const NATIVE_PUBLIC_BATCH_COMMANDS: [[&str; 10]; 2] = [
    [
        "cargo",
        "test",
        "--bin",
        "ibex",
        "--no-default-features",
        "--features",
        "standard,capsec-conformance-observer,openssl-crypto",
        "capsec_public_native_primary_batch",
        "--",
        "--test-threads=1",
    ],
    [
        "cargo",
        "test",
        "--bin",
        "ibex",
        "--no-default-features",
        "--features",
        "standard,capsec-conformance-observer,openssl-crypto",
        "capsec_public_native_secondary_batch",
        "--",
        "--test-threads=1",
    ],
];

#[cfg(test)]
fn is_native_public_batch_probe(probe: &PublicSurfaceProbe, expected_command: &[&str; 10]) -> bool {
    (probe.invocation.native().is_some()
        || probe.invocation.host_abi().is_some()
        || probe.invocation.module_loader().is_some())
        && probe
            .command
            .iter()
            .map(String::as_str)
            .eq(expected_command.iter().copied())
}

#[cfg(test)]
async fn run_capsec_public_native_recipe_batch(
    expected_command: &[&str; 10],
    recipe_path: String,
    output_path: Option<String>,
) {
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
                    recipe.status == "fully-executable"
                        && is_native_public_batch_probe(probe, expected_command)
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
    let portable = super::capsec_portable_public_batch::PortablePublicBatchContext::begin(
        "ibex-native-public-surface-harness",
    );
    assert_ne!(
        output_path.is_some(),
        portable.is_some(),
        "native public batch requires exactly one legacy output or portable plan"
    );
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
            let (host, _reset, snapshot_digest, probe_principals) = install_native_public_test_host(
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
            let mut engine = AuthenticatedNativeEngine {
                host,
                engine,
                publications: AuthenticatedPublicationTracker::default(),
                probe_principals,
            };
            let execution = execute_native_public_recipe(
                &mut engine,
                recipe,
                &coverage_terminals,
                listener,
                &identity_before.binary_digest,
            )
            .await;
            engine
                .finish()
                .expect("finish authenticated native-public publications");
            executions.push(execution);
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
    if let Some(portable) = portable {
        portable.finish(&executions);
        return;
    }
    let artifact = serde_json::json!({
        "publicBatchEvidenceSchema": "ibex/capsec-public-batch-evidence/1",
        "recipeCatalogDigest": catalog.recipe_catalog_digest,
        "loadedEngineIdentity": identity_before,
        "executions": executions,
    });
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path.expect("legacy native public batch has no output path"))
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

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn capsec_public_native_primary_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping native public recipe batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT").ok();
    run_capsec_public_native_recipe_batch(
        &NATIVE_PUBLIC_BATCH_COMMANDS[0],
        recipe_path,
        output_path,
    )
    .await;
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn capsec_public_native_secondary_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping native public recipe batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT").ok();
    run_capsec_public_native_recipe_batch(
        &NATIVE_PUBLIC_BATCH_COMMANDS[1],
        recipe_path,
        output_path,
    )
    .await;
}

mod inherited_intrinsic_alias {
    use super::super::{
        build_armed_test_host_at, hermes_engine_test_lock, AuthenticatedReplTestEvaluator,
        HermesEngine, HostResetGuard,
    };
    use crate::engine::Engine as _;
    include!("capsec_inherited_intrinsic_alias_batch.test.rs");
}
