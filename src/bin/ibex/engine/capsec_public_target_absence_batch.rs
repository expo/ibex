use super::*;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
#[cfg(not(feature = "host-http-server"))]
use std::io::Write as _;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecipeCatalog {
    recipe_catalog_schema: String,
    recipe_catalog_digest: String,
    target: Target,
    recipes: Vec<Recipe>,
}

#[derive(Debug, Deserialize)]
struct Target {
    triple: String,
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
struct TargetAbsenceProbe {
    kind: String,
    surface_observed_key: String,
    command: Vec<String>,
    invocation: TargetAbsenceInvocation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetAbsenceInvocation {
    invocation_schema: String,
    kind: String,
    surface_kind: String,
    surface_name: String,
    target_triple: String,
    source_descriptor: TargetAbsenceSourceDescriptor,
    source_descriptor_digest: String,
    expected_result: String,
    expected_typed_decision_count: usize,
    expected_typed_stages: Vec<String>,
    allowed_coverage_edge_ids: Vec<String>,
    expected_action_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetAbsenceSourceDescriptor {
    kind: String,
    surface_kind: String,
    surface_name: String,
    source_refs: Vec<String>,
    target_variants: Vec<String>,
    source_metadata: serde_json::Value,
    probe_mode: TargetAbsenceProbeMode,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum TargetAbsenceProbeMode {
    DynamicSymbol {
        #[serde(rename = "symbolName")]
        symbol_name: String,
    },
    PlatformBridge {
        #[serde(rename = "symbolName")]
        symbol_name: String,
    },
    RuntimeGlobalProperty {
        #[serde(rename = "globalName")]
        global_name: String,
        #[serde(rename = "memberName")]
        member_name: Option<String>,
    },
}

impl TargetAbsenceProbeMode {
    fn kind(&self) -> &'static str {
        match self {
            Self::DynamicSymbol { .. } => "dynamic-symbol",
            Self::PlatformBridge { .. } => "platform-bridge",
            Self::RuntimeGlobalProperty { .. } => "runtime-global-property",
        }
    }

    fn symbol_name(&self) -> Option<&str> {
        match self {
            Self::DynamicSymbol { symbol_name } | Self::PlatformBridge { symbol_name } => {
                Some(symbol_name)
            }
            Self::RuntimeGlobalProperty { .. } => None,
        }
    }
}

const TARGET_ABSENCE_BATCH_COMMAND: [&str; 9] = [
    "cargo",
    "test",
    "--bin",
    "ibex",
    "--features",
    "capsec-conformance-observer,openssl-crypto",
    "capsec_public_target_absence_batch",
    "--",
    "--test-threads=1",
];
fn tagged_jcs_digest(value: &serde_json::Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("target-absence evidence must have canonical JSON bytes");
    let digest = sha2::Sha256::digest(bytes);
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

fn tagged_value_digest<T: Serialize>(value: &T) -> String {
    tagged_jcs_digest(&serde_json::to_value(value).expect("target-absence value must serialize"))
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

fn implementation_variants() -> BTreeMap<String, BTreeSet<String>> {
    let value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/generated/implementation-manifest.json"
    )))
    .expect("checked implementation manifest must be JSON");
    let mut variants = BTreeMap::<String, BTreeSet<String>>::new();
    for row in value["surfaces"]
        .as_array()
        .expect("implementation manifest must contain surfaces")
    {
        variants
            .entry(
                row["edgeId"]
                    .as_str()
                    .expect("implementation row has no edge id")
                    .to_owned(),
            )
            .or_default()
            .insert(
                row["targetVariant"]
                    .as_str()
                    .expect("implementation row has no target variant")
                    .to_owned(),
            );
    }
    variants
}

fn target_absence_probe(recipe: &Recipe) -> Option<TargetAbsenceProbe> {
    let value = recipe.public_surface_probe.as_ref()?;
    if value["kind"] != "target-absence-probe"
        || value["invocation"]["invocationSchema"]
            != "ibex/capsec-target-absence-invocation/1"
    {
        return None;
    }
    Some(
        serde_json::from_value(value.clone())
            .expect("target-absence public probe must match its typed schema"),
    )
}

// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — an
// absence claim inspects the exact loaded process and must fail if any mapped
// image exports the target-specific ABI.
fn symbol_present(symbol_name: &str) -> bool {
    let symbol = CString::new(symbol_name).expect("absence symbol cannot contain NUL");
    #[cfg(unix)]
    unsafe {
        !libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()).is_null()
    }
    #[cfg(windows)]
    unsafe {
        use std::mem::size_of;
        use windows_sys::Win32::Foundation::HMODULE;
        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
        use windows_sys::Win32::System::ProcessStatus::K32EnumProcessModules;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        // Match RTLD_DEFAULT's process-wide lookup rather than checking only
        // the executable: a target-specific ABI exported by any mapped image
        // makes the claimed absence false.
        let process = GetCurrentProcess();
        let mut modules = vec![std::ptr::null_mut::<core::ffi::c_void>(); 64];
        loop {
            let byte_capacity = modules
                .len()
                .checked_mul(size_of::<HMODULE>())
                .and_then(|bytes| u32::try_from(bytes).ok())
                .expect("loaded-module buffer exceeds the Windows API limit");
            let mut bytes_needed = 0u32;
            if K32EnumProcessModules(
                process,
                modules.as_mut_ptr(),
                byte_capacity,
                &mut bytes_needed,
            ) == 0
            {
                panic!(
                    "enumerate loaded Windows modules for target absence: {}",
                    std::io::Error::last_os_error()
                );
            }
            if bytes_needed <= byte_capacity {
                modules.truncate(bytes_needed as usize / size_of::<HMODULE>());
                break;
            }
            let required = (bytes_needed as usize)
                .div_ceil(size_of::<HMODULE>())
                .checked_add(16)
                .expect("loaded-module count overflow");
            modules.resize(required, std::ptr::null_mut());
        }
        modules.into_iter().any(|module| {
            !module.is_null()
                && GetProcAddress(module, symbol.as_ptr().cast::<u8>()).is_some()
        })
    }
}

struct ExpectedTargetAbsenceCounts {
    os: &'static str,
    arch: &'static str,
    absent: usize,
    target_absence: usize,
    native_global_absence: usize,
}

fn expected_target_absence_counts(target_triple: &str) -> ExpectedTargetAbsenceCounts {
    match target_triple {
        "aarch64-apple-darwin" => ExpectedTargetAbsenceCounts {
            os: "macos",
            arch: "aarch64",
            absent: 110,
            target_absence: 102,
            native_global_absence: 8,
        },
        "x86_64-pc-windows-msvc" => ExpectedTargetAbsenceCounts {
            os: "windows",
            arch: "x86_64",
            absent: 211,
            target_absence: 125,
            native_global_absence: 86,
        },
        other => panic!("unsupported target-absence evidence target {other}"),
    }
}

async fn runtime_global_property_present(
    engine: &HermesEngine,
    global_name: &str,
    member_name: Option<&str>,
) -> bool {
    let global_name = serde_json::to_string(global_name).expect("serialize global name");
    let member_name = serde_json::to_string(&member_name).expect("serialize member name");
    let source = format!(
        r#"(() => {{
          const root = Object.getOwnPropertyDescriptor(globalThis, {global_name});
          if (root === undefined) return false;
          const member = {member_name};
          if (member === null) return true;
          if (!Object.prototype.hasOwnProperty.call(root, "value")) return true;
          let value = root.value;
          for (const segment of member.split('.')) {{
            if (value === null || (typeof value !== "object" && typeof value !== "function")) {{
              return false;
            }}
            const descriptor = Object.getOwnPropertyDescriptor(value, segment);
            if (descriptor === undefined) return false;
            if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) return true;
            value = descriptor.value;
          }}
          return true;
        }})()"#
    );
    match engine
        .eval_immediate(&source)
        .await
        .expect("inspect exact runtime global without invoking accessors")
        .as_deref()
    {
        Some("true") => true,
        Some("false") => false,
        other => panic!("runtime-global absence probe returned {other:?}"),
    }
}

async fn execute_target_absence_recipe(
    recipe: &Recipe,
    catalog_target: &Target,
    coverage: &BTreeMap<String, (String, String)>,
    variants: &BTreeMap<String, BTreeSet<String>>,
    engine_binary_digest: &str,
) -> serde_json::Value {
    let probe = target_absence_probe(recipe).expect("target-absence recipe has no typed probe");
    let invocation = &probe.invocation;
    assert_eq!(recipe.status, "fully-executable");
    assert_eq!(recipe.scenario, "absent");
    match recipe.classification.as_str() {
        "effects" => assert!(!recipe.action_ids.is_empty()),
        "closed" | "non-capability" => assert!(recipe.action_ids.is_empty()),
        other => panic!("unsupported target-absence classification {other}"),
    }
    assert_eq!(recipe.edge_ids.len(), 1);
    assert_eq!(recipe.expected_observation["kind"], "target-absence");
    assert_eq!(recipe.expected_observation["edgeId"], recipe.edge_ids[0]);
    assert_eq!(probe.kind, "target-absence-probe");
    assert!(
        probe
            .command
            .iter()
            .map(String::as_str)
            .eq(TARGET_ABSENCE_BATCH_COMMAND)
    );
    assert_eq!(invocation.invocation_schema, "ibex/capsec-target-absence-invocation/1");
    assert_eq!(invocation.kind, "target-absence");
    assert_eq!(invocation.target_triple, catalog_target.triple);
    let expected_counts = expected_target_absence_counts(&invocation.target_triple);
    assert_eq!(std::env::consts::OS, expected_counts.os);
    assert_eq!(std::env::consts::ARCH, expected_counts.arch);
    assert_eq!(invocation.expected_result, "absent");
    assert_eq!(invocation.expected_typed_decision_count, 0);
    assert!(invocation.expected_typed_stages.is_empty());
    assert!(invocation.allowed_coverage_edge_ids.is_empty());
    assert!(invocation.expected_action_ids.is_empty());
    assert_eq!(
        invocation.source_descriptor_digest,
        tagged_value_digest(&invocation.source_descriptor)
    );
    let descriptor = &invocation.source_descriptor;
    assert_eq!(descriptor.surface_kind, invocation.surface_kind);
    assert_eq!(descriptor.surface_name, invocation.surface_name);
    assert!(!descriptor.source_refs.is_empty());
    assert!(descriptor.source_metadata.is_object());
    let descriptor_variants = descriptor
        .target_variants
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(descriptor_variants.len(), descriptor.target_variants.len());
    assert!(descriptor_variants.iter().all(|variant| match expected_counts.os {
        "macos" => matches!(variant.as_str(), "android" | "ios"),
        "windows" => matches!(variant.as_str(), "android" | "ios" | "posix"),
        _ => false,
    }));
    assert_eq!(
        variants
            .get(&recipe.edge_ids[0])
            .expect("target-absence edge has no source implementation variants"),
        &descriptor_variants
    );
    match descriptor.surface_kind.as_str() {
        "host-abi" => {
            assert_eq!(descriptor.kind, "target-absent-host-abi");
            assert!(descriptor.probe_mode.symbol_name().is_some());
            if let Some(definitions) = descriptor.source_metadata["definitions"].as_array() {
                assert!(!definitions.is_empty());
                for definition in definitions {
                    assert!(descriptor.source_refs.iter().any(|source_ref| {
                        definition["sourceRef"].as_str() == Some(source_ref.as_str())
                    }));
                    assert!(descriptor_variants.contains(
                        definition["targetVariant"]
                            .as_str()
                            .expect("source definition has no target variant")
                    ));
                }
            } else {
                assert_eq!(
                    descriptor.source_metadata["targetVariant"]
                        .as_str()
                        .expect("source metadata has no target variant"),
                    descriptor.target_variants[0]
                );
            }
        }
        "native-op" => {
            assert_eq!(descriptor.kind, "target-absent-native-operation");
            assert!(matches!(
                &descriptor.probe_mode,
                TargetAbsenceProbeMode::RuntimeGlobalProperty { .. }
            ));
            let branches = descriptor.source_metadata["installationBranches"]
                .as_array()
                .expect("native target absence has no installation branches");
            assert!(!branches.is_empty());
            for branch in branches {
                assert!(descriptor_variants.contains(
                    branch["targetVariant"]
                        .as_str()
                        .expect("native installation branch has no target variant")
                ));
                let source_refs = branch["sourceRefs"]
                    .as_array()
                    .expect("native installation branch has no source refs");
                assert!(!source_refs.is_empty());
                assert!(source_refs.iter().all(|source_ref| descriptor
                    .source_refs
                    .iter()
                    .any(|expected| source_ref.as_str() == Some(expected.as_str()))));
            }
        }
        other => panic!("unsupported target-absence surface kind {other}"),
    }
    let (surface_kind, surface_name) = coverage
        .get(&recipe.edge_ids[0])
        .expect("target-absence recipe names an unknown coverage edge");
    assert_eq!(surface_kind, &invocation.surface_kind);
    assert_eq!(surface_name, &invocation.surface_name);
    let terminal_observed_key = format!("{surface_kind}:{surface_name}");
    assert_eq!(terminal_observed_key, recipe.terminal_observed_key);
    assert_eq!(terminal_observed_key, probe.surface_observed_key);

    let (host, snapshot_digest) =
        build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |_| {});
    assert_ne!(crate::host::abi::install_host(host), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&snapshot_digest))
        .expect("create isolated target-absence engine");
    engine
        .load_runtime()
        .await
        .expect("load exact runtime for target-absence probe");
    assert_eq!(
        engine
            .eval_immediate("'IBEX_CAPSEC_TARGET_ABSENCE_ENGINE_EXECUTED'")
            .await
            .expect("execute target-absence engine marker")
            .as_deref(),
        Some("IBEX_CAPSEC_TARGET_ABSENCE_ENGINE_EXECUTED")
    );
    let session_id = format!("public-observation:{}", recipe.plan_digest);
    assert!(ibex_runtime::host::abi::begin_installed_conformance_observation(
        &session_id
    ));
    let result = match &descriptor.probe_mode {
        TargetAbsenceProbeMode::DynamicSymbol { symbol_name }
        | TargetAbsenceProbeMode::PlatformBridge { symbol_name } => {
            let is_present = symbol_present(symbol_name);
            assert!(!is_present, "target-absent symbol {symbol_name} is loaded");
            serde_json::json!({
                "kind": "absent",
                "surfaceKind": surface_kind,
                "surfaceName": surface_name,
                "targetTriple": catalog_target.triple,
                "compiledTargetOs": std::env::consts::OS,
                "compiledTargetArch": std::env::consts::ARCH,
                "probeMode": descriptor.probe_mode.kind(),
                "symbolName": symbol_name,
                "symbolPresent": is_present,
            })
        }
        TargetAbsenceProbeMode::RuntimeGlobalProperty {
            global_name,
            member_name,
        } => {
            let is_present =
                runtime_global_property_present(&engine, global_name, member_name.as_deref()).await;
            assert!(
                !is_present,
                "target-absent runtime global property {global_name}{} is installed",
                member_name
                    .as_deref()
                    .map(|member| format!(".{member}"))
                    .unwrap_or_default()
            );
            serde_json::json!({
                "kind": "absent",
                "surfaceKind": surface_kind,
                "surfaceName": surface_name,
                "targetTriple": catalog_target.triple,
                "compiledTargetOs": std::env::consts::OS,
                "compiledTargetArch": std::env::consts::ARCH,
                "probeMode": descriptor.probe_mode.kind(),
                "globalName": global_name,
                "memberName": member_name,
                "surfacePresent": is_present,
            })
        }
    };
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert!(typed.is_empty());

    let runtime_observation = serde_json::json!({
        "observationSchema": "ibex/capsec-runtime-public-observation/1",
        "invocation": {
            "invocationSchema": invocation.invocation_schema,
            "kind": invocation.kind,
            "surfaceObservedKey": terminal_observed_key,
            "surfaceKind": surface_kind,
            "surfaceName": surface_name,
            "targetTriple": catalog_target.triple,
            "sourceDescriptorDigest": invocation.source_descriptor_digest,
            "result": result,
        },
        "legacyObservationCount": legacy.len(),
        "typedDecisions": [],
    });
    let mut observation = recipe.expected_observation.clone();
    observation
        .as_object_mut()
        .expect("expected target-absence observation must be an object")
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
        "executor": "ibex-target-absence-public-surface-harness",
        "evidence": evidence,
    })
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn capsec_public_target_absence_batch() {
    let Ok(recipe_path) = std::env::var("IBEX_CAPSEC_RECIPE_CATALOG") else {
        eprintln!("IBEX_CAPSEC_RECIPE_CATALOG is unset; skipping target-absence batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT")
        .expect("target-absence batch requires an owned evidence output path");
    let recipe_path = std::fs::canonicalize(recipe_path)
        .expect("canonicalize CapSec executable recipe catalog path");
    let catalog = load_catalog(&recipe_path);
    let expected_counts = expected_target_absence_counts(&catalog.target.triple);
    let recipe_indexes = catalog
        .recipes
        .iter()
        .enumerate()
        .filter_map(|(index, recipe)| target_absence_probe(recipe).map(|_| index))
        .collect::<Vec<_>>();
    let absent_fixtures = catalog
        .recipes
        .iter()
        .filter(|recipe| recipe.scenario == "absent")
        .count();
    let native_global_absence_fixtures = catalog
        .recipes
        .iter()
        .filter(|recipe| {
            recipe.scenario == "absent"
                && recipe.public_surface_probe.as_ref().is_some_and(|probe| {
                    probe["invocation"]["invocationSchema"]
                        == "ibex/capsec-native-global-invocation/1"
                })
        })
        .count();
    assert_eq!(absent_fixtures, expected_counts.absent);
    assert_eq!(
        native_global_absence_fixtures,
        expected_counts.native_global_absence,
        "native-global absence probes execute in the native public batch"
    );
    assert_eq!(
        recipe_indexes.len(),
        expected_counts.target_absence,
        "expected every target-absence invocation fixture"
    );
    assert_eq!(
        recipe_indexes.len() + native_global_absence_fixtures,
        absent_fixtures,
        "every absent fixture must execute in exactly one public batch"
    );
    let _lock = hermes_engine_test_lock().lock().await;
    let identity_before = HermesEngine::loaded_engine_identity()
        .expect("attest exact loaded Hermes before target-absence probes");
    let coverage = coverage_terminals();
    let variants = implementation_variants();
    let mut executions = Vec::with_capacity(recipe_indexes.len());
    for (position, index) in recipe_indexes.into_iter().enumerate() {
        let recipe = &catalog.recipes[index];
        eprintln!(
            "CapSec target-absence fixture {}/{}: {}",
            position + 1,
            expected_counts.target_absence,
            recipe.fixture_id
        );
        executions.push(
            execute_target_absence_recipe(
                recipe,
                &catalog.target,
                &coverage,
                &variants,
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
        .expect("attest exact loaded Hermes after target-absence probes");
    assert_eq!(identity_after, identity_before);
    ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity_before)
        .expect("re-verify mapped Hermes after target-absence probes");
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
        .expect("create owned target-absence evidence artifact");
    serde_json::to_writer_pretty(&mut output, &artifact)
        .expect("serialize target-absence evidence artifact");
    output
        .write_all(b"\n")
        .expect("finish target-absence evidence artifact");
    output
        .sync_all()
        .expect("sync target-absence evidence artifact");
}
