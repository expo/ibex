// Test-only expectation-free LLP 0023 output execution for production controls that
// close before project code. The caller owns the Hermes test lock and must
// invoke this after dropping any other live engine/Host guard: this executor
// installs a strict Host for CLI/startup checks and a separate armed Host for
// the two executable-loader checks.
//
// @ref LLP 0021#wp7--close-loader-process-inspector-stdio-and-escape-surfaces
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
// @ref LLP 0023#6-path-bearing-observables

use super::*;
use base64::Engine as _;
use clap::Parser as _;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::time::Duration;

const INVOCATION_SCHEMA: &str = "ibex/capsec-closed-control-output-invocation/1";
const SOURCE_DESCRIPTOR_KIND: &str = "authored-closed-control-output";
const TIMEOUT_MILLISECONDS: u64 = 1_000;
const MODULE_RESOLUTION_ERROR_CODE: &str = "ERR_IBEX_MODULE_RESOLUTION";
const MODULE_RESOLUTION_ERROR_MESSAGE: &str = "Module resolution failed";

fn tagged_jcs_digest(value: &Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("closed-control output descriptor must have canonical JSON bytes");
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(bytes))
    )
}

fn invocation(row: &Value) -> &Value {
    assert_eq!(row["probe"]["kind"], "loaded-engine-return-record");
    assert_eq!(row["probe"]["recordPath"], json!(["[[return]]"]));
    let outer = &row["probe"]["sourceDescriptor"];
    assert_eq!(outer["kind"], SOURCE_DESCRIPTOR_KIND);
    let invocation = &outer["invocation"];
    assert_eq!(invocation["invocationSchema"], INVOCATION_SCHEMA);
    assert_eq!(invocation["kind"], "closed-control-output");
    assert_eq!(invocation["coverageEdgeId"], row["key"]["surfaceId"]);
    assert_eq!(
        outer["surfaceObservedKey"],
        invocation["surfaceObservedKey"]
    );
    assert_eq!(
        invocation["sourceDescriptorDigest"],
        tagged_jcs_digest(&invocation["sourceDescriptor"])
    );
    assert_eq!(
        invocation["completion"],
        json!({
            "kind": "bounded-production-boundary",
            "timeoutMilliseconds": TIMEOUT_MILLISECONDS,
        })
    );
    invocation
}

fn raw_closed_refusal(error_name: Option<&str>, error_code: Option<&str>) -> Value {
    // Preserve the production boundary's actual failure as the catalog
    // observation. Do not turn it into a successful outer return containing a
    // harness-authored inner `resultKind`. CLI/startup return Rust errors with
    // no stable code or JavaScript name, so their raw throw carries neither.
    // Loader closures retain only the concrete JavaScript name and code caught
    // from the authenticated module loader. Any unrelated I/O/parser error is
    // residual and never reaches this constructor.
    let mut raw = json!({
        "kind": "throw",
        "rawValueShape": "throw",
        "value": null,
        "errorCode": error_code,
    });
    if let Some(error_name) = error_name {
        raw.as_object_mut()
            .expect("closed refusal must be an object")
            .insert("errorName".to_owned(), json!(error_name));
    }
    raw
}

fn return_record_result(row: &Value, raw: Value) -> Value {
    json!({
        "key": row["key"].clone(),
        "proof": {
            "kind": "loaded-engine-return-record",
            "fixtureId": row["probe"]["fixtureId"].clone(),
            "sourceDescriptorDigest": row["probe"]["sourceDescriptorDigest"].clone(),
            "recordPath": row["probe"]["recordPath"].clone(),
            "rawValueShape": raw["rawValueShape"].clone(),
        },
        "raw": raw,
    })
}

fn assert_closed_observations_join_reviewed_policy(observed: &[Value]) {
    let policy_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("capsec/registry/output-disposition-policy.json");
    let bytes = std::fs::read(&policy_path).unwrap_or_else(|error| {
        panic!(
            "read reviewed output policy {}: {error}",
            policy_path.display()
        )
    });
    let text = std::str::from_utf8(&bytes).expect("reviewed output policy must be UTF-8");
    let policy = capsec_semantics::strict_json::parse_strict(text)
        .expect("reviewed output policy must be strict JSON");
    let reviewed = policy["overrides"]
        .as_array()
        .expect("reviewed output policy has no overrides")
        .iter()
        .map(|row| {
            (
                serde_json::to_string(&row["key"]).expect("serialize reviewed output key"),
                row,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    for result in observed {
        let raw = &result["raw"];
        assert_eq!(raw["kind"], "throw");
        assert_eq!(raw["rawValueShape"], "throw");
        assert!(raw["value"].is_null());
        assert_eq!(result["proof"]["rawValueShape"], "throw");

        let key = serde_json::to_string(&result["key"])
            .expect("serialize closed-control output result key");
        let reviewed = reviewed
            .get(&key)
            .unwrap_or_else(|| panic!("closed-control output has no reviewed disposition: {key}"));
        assert_eq!(reviewed["disposition"], "closed");
        if result["key"]["sourceKind"] == "loader" {
            assert_eq!(raw["errorName"], "Error");
            assert_eq!(raw["errorCode"], MODULE_RESOLUTION_ERROR_CODE);
            assert_eq!(
                reviewed["expectation"],
                json!({
                    "outcome": "throw",
                    "normalizedValue": MODULE_RESOLUTION_ERROR_CODE,
                })
            );
        } else {
            assert!(raw.get("errorName").is_none());
            assert!(raw["errorCode"].is_null());
            assert_eq!(
                reviewed["expectation"],
                json!({
                    "outcome": "throw",
                    "normalizedValue": "throw-without-code",
                })
            );
        }
    }
}

fn unexercisable(row: &Value, reason: impl AsRef<str>) -> Value {
    json!({
        "key": row["key"].clone(),
        "reason": format!(
            "closed production control {} was not an authenticated output observation: {}",
            row["probe"]["fixtureId"].as_str().unwrap_or("<missing>"),
            reason.as_ref(),
        ),
    })
}

struct ClosedEnvironmentRestore(Vec<(String, Option<OsString>)>);

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

fn exact_cli_closure_message(invocation: &Value) -> Option<&'static str> {
    let source = &invocation["sourceDescriptor"];
    if source["kind"] != "closed-cli-control" {
        return None;
    }
    let control = &source["controlDescriptor"];
    let command_path = control["commandPath"].as_str()?;
    let argument_id = control["argumentId"].as_str();
    if matches!(command_path, "ibex debug" | "ibex debug modules") {
        return Some("production capability enforcement closes debug commands");
    }
    if argument_id.is_some_and(|argument_id| {
        matches!(
            argument_id,
            "allow_all" | "allow_env_endowments" | "capsec" | "capsec_allow_advisory"
        )
    }) {
        return Some(
            "production capability enforcement rejects legacy allow/deny, environment endowment widening, and advisory-attribution overrides",
        );
    }
    if argument_id.is_some_and(|argument_id| {
        matches!(
            argument_id,
            "expose_internals"
                | "inspect"
                | "inspect_host"
                | "inspect_open"
                | "inspect_pause"
                | "inspect_port"
                | "inspect_wait"
        )
    }) {
        return Some(
            "production capability enforcement closes compatibility, inspector, and runtime-fidelity overrides",
        );
    }
    None
}

async fn execute_cli_control(row: &Value) -> Result<Value, String> {
    let invocation = invocation(row);
    assert_eq!(row["key"]["sourceKind"], "cli");
    let operation = &invocation["operation"];
    assert_eq!(operation["kind"], "cli-control");
    let expected_message = exact_cli_closure_message(invocation).ok_or_else(|| {
        "the source-bound CLI route has no reviewed production closure".to_owned()
    })?;
    let placeholder = operation["projectCodePlaceholder"]
        .as_str()
        .ok_or_else(|| "the CLI route has no project-code placeholder".to_owned())?;
    let vectors = operation["argumentVectors"]
        .as_array()
        .filter(|vectors| !vectors.is_empty())
        .ok_or_else(|| "the CLI route has no argument vectors".to_owned())?;
    let missing = tempfile::tempdir()
        .map_err(|error| format!("could not create the closed CLI fixture: {error}"))?;
    let project_code = missing.path().join("project-code.js");
    let snapshot = missing.path().join("missing-snapshot.json");
    let identity = missing.path().join("missing-identity.json");

    for vector in vectors {
        let spelling = vector["spelling"]
            .as_str()
            .ok_or_else(|| "the CLI vector has no spelling".to_owned())?;
        let arguments = vector["args"]
            .as_array()
            .ok_or_else(|| format!("CLI vector {spelling} has no argument array"))?;
        let mut argv = vec![
            OsString::from("ibex"),
            OsString::from("--capsec-armed-snapshot"),
            snapshot.clone().into_os_string(),
            OsString::from("--capsec-arming-identity"),
            identity.clone().into_os_string(),
        ];
        for argument in arguments {
            let argument = argument
                .as_str()
                .ok_or_else(|| format!("CLI vector {spelling} has a non-string argument"))?;
            argv.push(if argument == placeholder {
                project_code.clone().into_os_string()
            } else {
                OsString::from(argument)
            });
        }
        let cli = crate::cli::Cli::try_parse_from(argv).map_err(|error| {
            format!("source-bound CLI vector {spelling} did not parse: {error}")
        })?;
        let observer_id = format!(
            "output-shape:{}:{spelling}",
            row["probe"]["fixtureId"].as_str().unwrap_or("closed-cli")
        );
        if !ibex_runtime::host::abi::begin_installed_conformance_observation(&observer_id) {
            return Err(format!(
                "the installed host refused the CLI observer for {spelling}"
            ));
        }
        let execution =
            tokio::time::timeout(Duration::from_millis(TIMEOUT_MILLISECONDS), crate::run(cli))
                .await;
        let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
        if !legacy.is_empty() || !typed.is_empty() {
            return Err(format!(
                "CLI vector {spelling} reached {} legacy and {} typed decisions",
                legacy.len(),
                typed.len()
            ));
        }
        let error = match execution {
            Err(_) => {
                return Err(format!(
                    "CLI vector {spelling} exceeded the bounded completion"
                ))
            }
            Ok(Ok(())) => {
                return Err(format!(
                    "CLI vector {spelling} returned instead of closing at the production boundary"
                ))
            }
            Ok(Err(error)) => format!("{error:#}"),
        };
        if error != expected_message {
            return Err(format!(
                "CLI vector {spelling} returned a non-closure error: {error}"
            ));
        }
    }
    if project_code.exists() {
        return Err("the closed CLI route reached project code".to_owned());
    }
    Ok(return_record_result(row, raw_closed_refusal(None, None)))
}

async fn execute_startup_environment(row: &Value) -> Result<Value, String> {
    let invocation = invocation(row);
    assert_eq!(row["key"]["sourceKind"], "startup");
    let operation = &invocation["operation"];
    assert_eq!(operation["kind"], "startup-environment");
    let environment_name = operation["environmentName"]
        .as_str()
        .ok_or_else(|| "the startup route has no environment name".to_owned())?;
    if invocation["sourceDescriptor"]["kind"] != "closed-startup-environment"
        || invocation["sourceDescriptor"]["environmentName"] != environment_name
        || !ibex_runtime::capsec_registry_generated::CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES
            .contains(&environment_name)
    {
        return Err(format!(
            "{environment_name} is not bound to the generated production reject set"
        ));
    }
    let missing = tempfile::tempdir()
        .map_err(|error| format!("could not create the startup fixture: {error}"))?;
    let project_code = missing.path().join("project-code.js");
    let cli = crate::cli::Cli::try_parse_from([
        OsString::from("ibex"),
        OsString::from("--capsec-armed-snapshot"),
        missing
            .path()
            .join("missing-snapshot.json")
            .into_os_string(),
        OsString::from("--capsec-arming-identity"),
        missing
            .path()
            .join("missing-identity.json")
            .into_os_string(),
        project_code.clone().into_os_string(),
    ])
    .map_err(|error| format!("startup production vector did not parse: {error}"))?;
    std::env::set_var(environment_name, "");
    let observer_id = format!(
        "output-shape:{}",
        row["probe"]["fixtureId"]
            .as_str()
            .unwrap_or("closed-startup")
    );
    if !ibex_runtime::host::abi::begin_installed_conformance_observation(&observer_id) {
        std::env::remove_var(environment_name);
        return Err("the installed host refused the startup observer".to_owned());
    }
    let execution =
        tokio::time::timeout(Duration::from_millis(TIMEOUT_MILLISECONDS), crate::run(cli)).await;
    std::env::remove_var(environment_name);
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    if !legacy.is_empty() || !typed.is_empty() {
        return Err(format!(
            "startup control reached {} legacy and {} typed decisions",
            legacy.len(),
            typed.len()
        ));
    }
    let error = match execution {
        Err(_) => return Err("startup control exceeded the bounded completion".to_owned()),
        Ok(Ok(())) => {
            return Err(
                "startup control returned instead of closing at production entry".to_owned(),
            )
        }
        Ok(Err(error)) => format!("{error:#}"),
    };
    let expected = format!(
        "production capability startup rejects closed environment controls: {environment_name}"
    );
    if error != expected {
        return Err(format!(
            "startup control returned a non-closure error: {error}"
        ));
    }
    if project_code.exists() {
        return Err("the closed startup control reached project code".to_owned());
    }
    Ok(return_record_result(row, raw_closed_refusal(None, None)))
}

async fn evaluate_closed_loader_file_json(
    engine: &HermesEngine,
    host: &crate::host::Host,
    entry_identity: &str,
    observer_id: &str,
) -> Result<Value, String> {
    let vfs = host
        .virtual_file_system()
        .map_err(|error| format!("could not create loader file VFS: {error}"))?;
    let result = async {
        let entry = vfs
            .resolve_root_file_url(entry_identity, None)
            .map_err(|error| format!("could not resolve loader probe entry: {error}"))?;
        let session = host
            .mint_armed_session_token()
            .map_err(|error| format!("could not mint loader file session: {error}"))?;
        let mut sequence =
            ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())
                .map_err(|error| format!("could not create loader file submission: {error}"))?;
        let submission = sequence
            .mint_file(
                entry
                    .logical_referrer()
                    .map_err(|error| format!("could not derive loader file referrer: {error}"))?,
                &[],
            )
            .map_err(|error| format!("could not mint loader file request: {error}"))?;
        let request = host
            .authenticated_vfs_file_read(&vfs, entry, submission)
            .map_err(|error| format!("could not authenticate loader probe entry: {error}"))?
            .into_capsule()
            .into_request()
            .map_err(|error| format!("could not bind loader probe entry: {error}"))?;
        // Entry-file VFS authentication is harness setup, not one of the two
        // loader operations under test.  It necessarily emits its own typed
        // allow decisions; close that scope only after the immutable request
        // is fully bound, then open the exact operation observer.
        let (setup_legacy, setup_typed) =
            ibex_runtime::host::abi::take_installed_conformance_observations();
        if !setup_legacy.is_empty()
            || setup_typed.iter().any(|decision| {
                decision.evidence.outcome != capsec_semantics::decision::DecisionOutcome::Allow
            })
        {
            return Err(format!(
                "loader probe entry setup did not authenticate cleanly: {} legacy, {} typed",
                setup_legacy.len(),
                setup_typed.len()
            ));
        }
        if !ibex_runtime::host::abi::begin_installed_conformance_observation(observer_id) {
            return Err("the installed host refused the loader observer".to_owned());
        }
        let evaluation = engine
            .evaluate_authenticated(&session, request)
            .await
            .map_err(|error| format!("authenticated loader file evaluation failed: {error:#}"))?;
        let AuthenticatedEvaluation::Value { display, receipt } = evaluation else {
            return Err(format!(
                "authenticated loader file evaluation returned no value: {evaluation:?}"
            ));
        };
        if display.kind != AuthenticatedDisplayKind::String {
            return Err(format!(
                "authenticated loader file evaluation returned {:?}, not a string",
                display.kind
            ));
        }
        let encoded: String = serde_json::from_str(&display.text)
            .map_err(|error| format!("loader file display was not a JSON string: {error}"))?;
        engine
            .release_undisplayed_value(
                receipt.ok_or_else(|| "loader file evaluation retained no receipt".to_owned())?,
            )
            .await
            .map_err(|error| format!("could not release loader file result: {error:#}"))?;
        engine
            .drive_authenticated_program_to_quiescence()
            .await
            .map_err(|error| format!("loader file program did not quiesce: {error:#}"))?;
        serde_json::from_str::<Value>(&encoded)
            .map_err(|error| format!("loader file result was not valid JSON: {error}"))
    }
    .await;
    vfs.close();
    result
}

async fn execute_loader_rows(rows: &[&Value]) -> (Vec<Value>, Vec<Value>) {
    if rows.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let project = match tempfile::tempdir() {
        Ok(project) => project,
        Err(error) => {
            return (
                Vec::new(),
                rows.iter()
                    .map(|row| {
                        unexercisable(row, format!("could not create loader fixture: {error}"))
                    })
                    .collect(),
            )
        }
    };
    // macOS presents the temporary directory through `/var` but authenticates
    // it through `/private/var`; bind the canonical spelling used by resolver
    // revalidation so the normal-JavaScript control proves this mount works.
    let project_root = match std::fs::canonicalize(project.path()) {
        Ok(project_root) => project_root,
        Err(error) => {
            return (
                Vec::new(),
                rows.iter()
                    .map(|row| {
                        unexercisable(
                            row,
                            format!("could not canonicalize loader fixture: {error}"),
                        )
                    })
                    .collect(),
            )
        }
    };
    let mut payloads = std::collections::BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        let invocation = invocation(row);
        assert_eq!(row["key"]["sourceKind"], "loader");
        let operation = &invocation["operation"];
        assert_eq!(operation["kind"], "loader-executable-file");
        let extension = operation["extension"]
            .as_str()
            .expect("loader output route has no extension");
        let loader_kind = operation["loaderKind"]
            .as_str()
            .expect("loader output route has no loader kind");
        assert_eq!(
            (loader_kind, extension),
            if loader_kind == "native-addon" {
                ("native-addon", ".node")
            } else {
                ("wasm", ".wasm")
            }
        );
        assert_eq!(
            invocation["sourceDescriptor"]["kind"],
            "closed-loader-executable-kind"
        );
        assert_eq!(invocation["sourceDescriptor"]["loaderKind"], loader_kind);
        assert_eq!(invocation["sourceDescriptor"]["extension"], extension);
        let payload = project.path().join(format!("payload-{index}{extension}"));
        if let Err(error) = std::fs::write(
            &payload,
            format!(
                "globalThis.__IBEX_CLOSED_OUTPUT_LOADER_{index}__ = true; module.exports = true;"
            ),
        ) {
            return (
                Vec::new(),
                rows.iter()
                    .map(|row| {
                        unexercisable(row, format!("could not write loader fixture: {error}"))
                    })
                    .collect(),
            );
        }
        payloads.insert(
            row["probe"]["fixtureId"]
                .as_str()
                .expect("loader output route has no fixture ID")
                .to_owned(),
            (payload, index),
        );
    }

    let probes = rows
        .iter()
        .map(|row| {
            let fixture_id = row["probe"]["fixtureId"]
                .as_str()
                .expect("loader output route has no fixture ID");
            let (payload, index) = payloads
                .get(fixture_id)
                .expect("loader fixture was not prepared");
            let virtual_path = format!(
                "/project/{}",
                payload
                    .file_name()
                    .and_then(|value| value.to_str())
                    .expect("loader fixture name must be UTF-8")
            );
            json!({
                "fixtureId": fixture_id,
                "path": virtual_path,
                "marker": format!("__IBEX_CLOSED_OUTPUT_LOADER_{index}__"),
            })
        })
        .collect::<Vec<_>>();
    let probe_source = format!(
        r#"JSON.stringify((function(probes) {{
  var control = require('node:path');
  if (!control || control.basename('/project/loader-control.js') !== 'loader-control.js') {{
    throw new Error('ordinary JavaScript loader control did not execute');
  }}
  var results = [];
  for (var index = 0; index < probes.length; index++) {{
    var probe = probes[index];
    var errorName = null;
    var errorMessage = null;
    var errorCode = null;
    try {{ require(probe.path); }}
    catch (error) {{
      errorName = String(error && error.name || 'Error');
      errorMessage = String(error && error.message || error);
      errorCode = error && typeof error.code === 'string' ? error.code : null;
    }}
    results.push({{
      fixtureId: probe.fixtureId,
      errorName: errorName,
      errorMessage: errorMessage,
      errorCode: errorCode,
      projectCodeExecuted: globalThis[probe.marker] === true
    }});
  }}
  return results;
}})({}))"#,
        serde_json::to_string(&probes).expect("serialize loader output probes"),
    );
    // Run the normal-JavaScript control and the two refused executable kinds
    // from one authenticated module entry.  This proves the mount and resolver
    // work before attributing either refusal to its exact extension branch.
    if let Err(error) = std::fs::write(project.path().join("loader-probe.mjs"), probe_source) {
        return (
            Vec::new(),
            rows.iter()
                .map(|row| unexercisable(row, format!("could not write loader probe: {error}")))
                .collect(),
        );
    }
    let loader_entry_identity = "file:///project/loader-probe.mjs";
    let (host, digest) = build_armed_test_host_custom(
        Some(&project_root),
        false,
        true,
        true,
        Vec::new(),
        None,
        |snapshot| {
            snapshot["entry"] = json!({
                "kind": "file",
                "identity": loader_entry_identity,
                "mode": "program",
            });
            snapshot["principals"][0]["imports"]["builtins"] = json!(["node:path"]);
        },
    );
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let reset = HostResetGuard;
    let engine = match HermesEngine::new_with_armed_snapshot(Some(&digest)) {
        Ok(engine) => engine,
        Err(error) => {
            drop(reset);
            return (
                Vec::new(),
                rows.iter()
                    .map(|row| {
                        unexercisable(
                            row,
                            format!("could not create loader observation engine: {error:#}"),
                        )
                    })
                    .collect(),
            );
        }
    };
    match tokio::time::timeout(
        Duration::from_millis(TIMEOUT_MILLISECONDS),
        engine.load_runtime(),
    )
    .await
    {
        Err(error) => {
            drop(engine);
            drop(reset);
            return (
                Vec::new(),
                rows.iter()
                    .map(|row| {
                        unexercisable(
                            row,
                            format!("loader observation runtime load timed out: {error}"),
                        )
                    })
                    .collect(),
            );
        }
        Ok(Err(error)) => {
            drop(engine);
            drop(reset);
            return (
                Vec::new(),
                rows.iter()
                    .map(|row| {
                        unexercisable(
                            row,
                            format!("loader observation runtime did not load: {error:#}"),
                        )
                    })
                    .collect(),
            );
        }
        Ok(Ok(())) => {}
    }

    let observer_id = "output-shape:closed-loader-executable-files";
    let execution = async {
        evaluate_closed_loader_file_json(&engine, &host, loader_entry_identity, observer_id)
            .await?
            .as_array()
            .cloned()
            .ok_or_else(|| "loader result had no operation array".to_owned())
    };
    let execution =
        match tokio::time::timeout(Duration::from_millis(TIMEOUT_MILLISECONDS), execution).await {
            Err(_) => Err("loader routes exceeded bounded completion".to_owned()),
            Ok(result) => result,
        };
    let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
    let mut observed = Vec::new();
    let mut residual = Vec::new();
    if !legacy.is_empty() || !typed.is_empty() {
        let reason = format!(
            "loader routes reached {} legacy and {} typed decisions: {}",
            legacy.len(),
            typed.len(),
            serde_json::to_string(&typed).expect("serialize loader typed decisions")
        );
        residual.extend(rows.iter().map(|row| unexercisable(row, &reason)));
    } else {
        match execution {
            Err(reason) => residual.extend(rows.iter().map(|row| unexercisable(row, &reason))),
            Ok(results) => {
                let mut by_fixture = results
                    .into_iter()
                    .map(|result| {
                        let fixture_id = result["fixtureId"]
                            .as_str()
                            .expect("loader result has no fixture ID")
                            .to_owned();
                        (fixture_id, result)
                    })
                    .collect::<std::collections::BTreeMap<_, _>>();
                for row in rows {
                    let fixture_id = row["probe"]["fixtureId"]
                        .as_str()
                        .expect("loader output route has no fixture ID");
                    let Some(result) = by_fixture.remove(fixture_id) else {
                        residual.push(unexercisable(row, "loader batch omitted its operation"));
                        continue;
                    };
                    let Some(error_message) = result["errorMessage"].as_str() else {
                        residual.push(unexercisable(
                            row,
                            "loader import returned instead of refusing",
                        ));
                        continue;
                    };
                    let Some(error_name) = result["errorName"].as_str() else {
                        residual.push(unexercisable(
                            row,
                            "loader import returned no concrete error name",
                        ));
                        continue;
                    };
                    if result["projectCodeExecuted"] != false
                        || result["errorCode"] != MODULE_RESOLUTION_ERROR_CODE
                        || error_message != MODULE_RESOLUTION_ERROR_MESSAGE
                    {
                        residual.push(unexercisable(
                            row,
                            format!("loader import returned a non-closure result: {result}"),
                        ));
                        continue;
                    }
                    observed.push(return_record_result(
                        row,
                        raw_closed_refusal(Some(error_name), Some(MODULE_RESOLUTION_ERROR_CODE)),
                    ));
                }
                assert!(
                    by_fixture.is_empty(),
                    "loader batch returned unknown operations"
                );
            }
        }
    }
    drop(engine);
    drop(reset);
    (observed, residual)
}

/// Execute actual production operations for expectation-free closed-control
/// output rows. The caller must hold `hermes_engine_test_lock`, have dropped
/// every other engine and Host guard, and accept that this function leaves the
/// installed Host in strict mode.
pub(super) async fn execute_closed_control_output_rows(rows: &[Value]) -> (Vec<Value>, Vec<Value>) {
    let _environment = ClosedEnvironmentRestore::clear();
    crate::host::abi::install_host(crate::host::Host::strict());
    let strict_reset = HostResetGuard;
    let mut by_key = std::collections::BTreeMap::new();
    let mut residual_by_key = std::collections::BTreeMap::new();
    let loader_rows = rows
        .iter()
        .filter(|row| invocation(row)["operation"]["kind"] == "loader-executable-file")
        .collect::<Vec<_>>();

    for row in rows {
        let result = match invocation(row)["operation"]["kind"].as_str() {
            Some("cli-control") => execute_cli_control(row).await,
            Some("startup-environment") => execute_startup_environment(row).await,
            Some("loader-executable-file") => continue,
            other => panic!("unsupported closed-control output operation {other:?}"),
        };
        let key = serde_json::to_string(&row["key"]).expect("serialize closed-control output key");
        match result {
            Ok(result) => assert!(by_key.insert(key, result).is_none()),
            Err(reason) => assert!(residual_by_key
                .insert(key, unexercisable(row, reason))
                .is_none()),
        }
    }
    drop(strict_reset);
    let (loader_observed, loader_residual) = execute_loader_rows(&loader_rows).await;
    for result in loader_observed {
        let key =
            serde_json::to_string(&result["key"]).expect("serialize closed loader result key");
        assert!(by_key.insert(key, result).is_none());
    }
    for result in loader_residual {
        let key =
            serde_json::to_string(&result["key"]).expect("serialize closed loader residual key");
        assert!(residual_by_key.insert(key, result).is_none());
    }

    let mut observed = Vec::new();
    let mut residual = Vec::new();
    for row in rows {
        let key =
            serde_json::to_string(&row["key"]).expect("serialize closed-control output plan key");
        match (by_key.remove(&key), residual_by_key.remove(&key)) {
            (Some(result), None) => observed.push(result),
            (None, Some(result)) => residual.push(result),
            _ => panic!("closed-control output executor did not account for {key} exactly once"),
        }
    }
    assert!(by_key.is_empty());
    assert!(residual_by_key.is_empty());
    (observed, residual)
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_closed_control_output_batch() {
    let Ok(plan_path) = std::env::var("IBEX_CAPSEC_CLOSED_CONTROL_OUTPUT_PLAN") else {
        eprintln!(
            "IBEX_CAPSEC_CLOSED_CONTROL_OUTPUT_PLAN is unset; skipping closed-control output batch"
        );
        return;
    };
    let bytes = std::fs::read(&plan_path).expect("read closed-control output plan");
    let text = std::str::from_utf8(&bytes).expect("closed-control output plan must be UTF-8");
    let plan = capsec_semantics::strict_json::parse_strict(text)
        .expect("closed-control output plan must be strict JSON");
    let rows = plan["rows"]
        .as_array()
        .expect("closed-control output plan has no rows")
        .iter()
        .filter(|row| row["probe"]["sourceDescriptor"]["kind"] == SOURCE_DESCRIPTOR_KIND)
        .cloned()
        .collect::<Vec<_>>();
    let counts = rows.iter().fold(
        std::collections::BTreeMap::<String, usize>::new(),
        |mut counts, row| {
            *counts
                .entry(
                    invocation(row)["operation"]["kind"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                )
                .or_default() += 1;
            counts
        },
    );
    assert_eq!(counts.get("cli-control"), Some(&114));
    assert_eq!(counts.get("startup-environment"), Some(&21));
    assert_eq!(counts.get("loader-executable-file"), Some(&2));
    assert_eq!(rows.len(), 137);
    let _lock = hermes_engine_test_lock().lock().await;
    let (observed, residual) = execute_closed_control_output_rows(&rows).await;
    assert_eq!(observed.len() + residual.len(), rows.len());
    assert_closed_observations_join_reviewed_policy(&observed);
    if let Ok(output_path) = std::env::var("IBEX_CAPSEC_CLOSED_CONTROL_OUTPUT_RESULT") {
        let output = json!({
            "observed": observed,
            "unexercisable": residual,
        });
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)
            .expect("create closed-control output result");
        serde_json::to_writer_pretty(&mut file, &output)
            .expect("serialize closed-control output result");
        use std::io::Write as _;
        file.write_all(b"\n")
            .expect("finish closed-control output result");
    }
    assert!(
        residual.is_empty(),
        "{} closed-control output rows were unexercisable: {}",
        residual.len(),
        serde_json::to_string_pretty(&residual).unwrap()
    );
}

#[test]
fn closed_control_refusal_classifier_is_exact() {
    let legacy = json!({
        "sourceDescriptor": {
            "kind": "closed-cli-control",
            "controlDescriptor": {"commandPath": "ibex", "argumentId": "allow_all"}
        }
    });
    let inspector = json!({
        "sourceDescriptor": {
            "kind": "closed-cli-control",
            "controlDescriptor": {"commandPath": "ibex run", "argumentId": "inspect"}
        }
    });
    let unrelated = json!({
        "sourceDescriptor": {
            "kind": "closed-cli-control",
            "controlDescriptor": {"commandPath": "ibex", "argumentId": "project_root"}
        }
    });
    assert!(exact_cli_closure_message(&legacy)
        .unwrap()
        .contains("rejects legacy allow/deny"));
    assert!(exact_cli_closure_message(&inspector)
        .unwrap()
        .contains("closes compatibility, inspector"));
    assert_eq!(exact_cli_closure_message(&unrelated), None);
}

#[test]
fn closed_control_refusal_is_the_actual_output_outcome() {
    let raw = raw_closed_refusal(None, None);
    assert_eq!(raw["kind"], "throw");
    assert_eq!(raw["rawValueShape"], "throw");
    assert!(raw["value"].is_null());
    assert!(raw.get("errorName").is_none());
    assert!(raw["errorCode"].is_null());

    let loader = raw_closed_refusal(Some("Error"), Some(MODULE_RESOLUTION_ERROR_CODE));
    assert_eq!(loader["kind"], "throw");
    assert_eq!(loader["rawValueShape"], "throw");
    assert!(loader["value"].is_null());
    assert_eq!(loader["errorName"], "Error");
    assert_eq!(loader["errorCode"], MODULE_RESOLUTION_ERROR_CODE);
}
