// Test-only loaded-engine executor for source-bound builtin callable/accessor output
// recipes. This module owns a fresh armed runtime, imports each exact public
// builtin before opening its per-operation observer, captures only normal
// outer source returns, and proves one-second quiescence plus cleanup.
//
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report
// @ref LLP 0023#6-path-bearing-observables

use super::*;
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const INVOCATION_SCHEMA: &str = "ibex/capsec-builtin-noncap-closed-output-invocation/1";
const SOURCE_DESCRIPTOR_KIND: &str = "authored-builtin-noncap-closed-output";
const TIMEOUT_MILLISECONDS: u64 = 1_000;
const OUTPUT_HARNESS: &str = include_str!("capsec_builtin_noncap_closed_output_invocation.js");
const INHERITED_HARNESS: &str = include_str!("capsec_public_noncap_builtin_invocation.js");

fn tagged_jcs_digest(value: &Value) -> String {
    let bytes = capsec_semantics::canonical::to_jcs_bytes(value)
        .expect("builtin output descriptor must have canonical JSON bytes");
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(bytes))
    )
}

pub(super) fn is_surface(row: &Value) -> bool {
    row["probe"]["sourceDescriptor"]["kind"] == SOURCE_DESCRIPTOR_KIND
}

fn is_public_builtin_family_output(row: &Value, raw: &Value) -> bool {
    row["probe"]["sourceDescriptor"]["invocation"]["route"]["outcomeCapture"]
        == "public-builtin-family"
        && matches!(
            raw["kind"].as_str(),
            Some("absent") | Some("return") | Some("throw")
        )
}

fn classification_accepts_raw(classification: &str, raw: &Value) -> bool {
    match classification {
        "non-capability" => raw["kind"] == "return",
        "closed" => matches!(raw["kind"].as_str(), Some("absent" | "throw")),
        _ => false,
    }
}

fn classification_accepts_decisions(
    classification: &str,
    observer_id: &str,
    legacy_count: usize,
    typed: &Value,
) -> bool {
    let Some(typed) = typed.as_array() else {
        return false;
    };
    if legacy_count != 0 {
        return false;
    }
    match classification {
        "non-capability" => typed.is_empty(),
        "closed" => typed.iter().all(|decision| {
            decision["terminalBranchId"] == observer_id
                && decision["evidence"]["outcome"] == "deny"
                && decision["gates"].as_array().is_some_and(|gates| {
                    !gates.is_empty()
                        && gates.iter().all(|gate| {
                            gate["definitionAndEdgePredicatesSatisfied"] == true
                                && gate["targetCell"] == "complete"
                        })
                })
        }),
        _ => false,
    }
}

#[test]
fn output_classification_rejects_laundered_throws_and_capability_decisions() {
    let returned = json!({"kind": "return"});
    let thrown = json!({"kind": "throw"});
    let absent = json!({"kind": "absent"});
    assert!(classification_accepts_raw("non-capability", &returned));
    assert!(!classification_accepts_raw("non-capability", &thrown));
    assert!(!classification_accepts_raw("non-capability", &absent));
    assert!(!classification_accepts_raw("closed", &returned));
    assert!(classification_accepts_raw("closed", &thrown));
    assert!(classification_accepts_raw("closed", &absent));

    assert!(classification_accepts_decisions(
        "non-capability",
        "output-shape:fixture",
        0,
        &json!([]),
    ));
    assert!(!classification_accepts_decisions(
        "non-capability",
        "output-shape:fixture",
        0,
        &json!([{"evidence": {"outcome": "allow"}}]),
    ));
    assert!(classification_accepts_decisions(
        "closed",
        "output-shape:fixture",
        0,
        &json!([{
            "terminalBranchId": "output-shape:fixture",
            "evidence": {"outcome": "deny"},
            "gates": [{
                "definitionAndEdgePredicatesSatisfied": true,
                "targetCell": "complete",
            }],
        }]),
    ));
    assert!(!classification_accepts_decisions(
        "closed",
        "output-shape:fixture",
        0,
        &json!([{
            "terminalBranchId": "output-shape:fixture",
            "evidence": {"outcome": "allow"},
            "gates": [{
                "definitionAndEdgePredicatesSatisfied": true,
                "targetCell": "complete",
            }],
        }]),
    ));
}

fn invocation(row: &Value) -> &Value {
    assert_eq!(row["probe"]["kind"], "loaded-engine-return-record");
    assert_eq!(row["probe"]["recordPath"], json!(["[[return]]"]));
    let outer = &row["probe"]["sourceDescriptor"];
    assert_eq!(outer["kind"], SOURCE_DESCRIPTOR_KIND);
    assert_eq!(
        outer["surfaceObservedKey"],
        row["probe"]["sourceDescriptor"]["invocation"]["surfaceObservedKey"]
    );
    assert_eq!(
        row["probe"]["sourceDescriptorDigest"],
        tagged_jcs_digest(outer)
    );
    let invocation = &outer["invocation"];
    assert_eq!(invocation["invocationSchema"], INVOCATION_SCHEMA);
    assert_eq!(invocation["kind"], "builtin-noncap-closed-output");
    assert_eq!(invocation["coverageEdgeId"], row["key"]["surfaceId"]);
    assert!(matches!(
        invocation["coverageClassification"].as_str(),
        Some("non-capability" | "closed")
    ));
    assert_eq!(
        invocation["sourceDescriptorDigest"],
        tagged_jcs_digest(&invocation["sourceDescriptor"])
    );
    assert_eq!(
        invocation["completion"],
        json!({
            "kind": "event-loop-quiescence",
            "timeoutMilliseconds": TIMEOUT_MILLISECONDS,
        })
    );
    invocation
}

#[test]
fn public_builtin_family_capture_is_source_scoped_and_expectation_free() {
    let row = json!({
        "probe": {
            "kind": "loaded-engine-return-record",
            "recordPath": ["[[return]]"],
            "sourceDescriptor": {
                "kind": SOURCE_DESCRIPTOR_KIND,
                "surfaceObservedKey": "builtin:export:node_stream:Writable._write",
                "invocation": {
                    "invocationSchema": INVOCATION_SCHEMA,
                    "kind": "builtin-noncap-closed-output",
                    "coverageEdgeId": "surface.fixture",
                    "surfaceObservedKey": "builtin:export:node_stream:Writable._write",
                    "route": {
                        "operation": "call",
                        "outcomeCapture": "public-builtin-family"
                    }
                }
            }
        },
        "key": { "surfaceId": "surface.fixture" }
    });
    assert!(is_public_builtin_family_output(
        &row,
        &json!({"kind": "return"})
    ));
    assert!(is_public_builtin_family_output(
        &row,
        &json!({"kind": "throw"})
    ));
    assert!(is_public_builtin_family_output(
        &row,
        &json!({"kind": "absent"})
    ));
    assert!(!is_public_builtin_family_output(
        &row,
        &json!({"kind": "policy-closed"})
    ));
    assert!(!serde_json::to_string(&row).unwrap().contains("expected"));
}

fn unexercisable(row: &Value, reason: impl AsRef<str>) -> Value {
    json!({
        "key": row["key"].clone(),
        "reason": format!(
            "source-bound builtin output {} was not a normal loaded-engine return: {}",
            row["probe"]["fixtureId"].as_str().unwrap_or("<missing>"),
            reason.as_ref(),
        ),
    })
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

fn import_refusal_result(row: &Value, raw: Value, execution: &Value) -> Value {
    let mut result = return_record_result(row, raw);
    result["refusal"] = json!({
        "operation": "require",
        "moduleSpecifier": invocation(row)["moduleSpecifier"].clone(),
        "errorName": execution["errorName"].clone(),
        "errorMessage": execution["errorMessage"].clone(),
        "errorCode": execution["errorCode"].clone(),
    });
    result
}

fn preload_script(module_specifier: &str) -> String {
    format!(
        "(function(){{require({});return 'ibex-capsec-builtin-output-preloaded';}})()",
        serde_json::to_string(module_specifier).expect("serialize builtin module specifier")
    )
}

fn invocation_script(row: &Value) -> String {
    format!(
        "JSON.stringify(({})({},{}))",
        OUTPUT_HARNESS.trim(),
        serde_json::to_string(invocation(row)).expect("serialize builtin output invocation"),
        INHERITED_HARNESS.trim(),
    )
}

fn completion_verification_script(token: &str) -> String {
    format!(
        "JSON.stringify((function(){{var token={};var store=globalThis.__ibexBuiltinOutputAsyncCompletions;var record=store&&store[token];if(store)delete store[token];return{{calls:record&&record.calls,error:record&&record.error,cleanupPerformed:record&&record.cleanupPerformed}};}})())",
        serde_json::to_string(token).expect("serialize builtin completion token")
    )
}

async fn drive_to_quiescence(engine: &HermesEngine) -> std::result::Result<(), String> {
    tokio::time::timeout(
        std::time::Duration::from_millis(TIMEOUT_MILLISECONDS),
        engine.drive_event_loop(),
    )
    .await
    .map_err(|_| "event loop did not reach the authored one-second bound".to_owned())?
    .map_err(|error| format!("event-loop completion failed: {error:#}"))
}

struct AuthenticatedBuiltinSweep {
    session: ibex_runtime::engine::evaluation::ArmedSessionToken,
    sequence: ibex_runtime::engine::evaluation::SubmissionSequence,
    active_work_units: BTreeMap<u64, AuthenticatedWorkUnitEvent>,
    due_schedules: BTreeSet<u64>,
}

impl AuthenticatedBuiltinSweep {
    fn new(host: &crate::host::Host) -> Self {
        let session = host
            .mint_armed_session_token()
            .expect("mint authenticated builtin-output session");
        let sequence = ibex_runtime::engine::evaluation::SubmissionSequence::new(session.clone())
            .expect("create authenticated builtin-output submission sequence");
        Self {
            session,
            sequence,
            active_work_units: BTreeMap::new(),
            due_schedules: BTreeSet::new(),
        }
    }

    async fn eval_string(
        &mut self,
        engine: &HermesEngine,
        source: &str,
    ) -> anyhow::Result<Option<String>> {
        use capsec_semantics::model::{LogicalPath, LogicalRoot};

        self.drain_publications(engine)?;
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
        let evaluation = engine
            .evaluate_authenticated(&self.session, request)
            .await
            .map_err(|error| {
                anyhow::anyhow!("authenticated builtin-output evaluation failed: {error:#}")
            })?;
        self.drain_publications(engine)?;
        match evaluation {
            AuthenticatedEvaluation::Empty => Ok(None),
            AuthenticatedEvaluation::Value { display, receipt } => {
                engine
                    .release_undisplayed_value(
                        receipt.expect("builtin-output value must retain a receipt"),
                    )
                    .await?;
                self.drain_publications(engine)?;
                anyhow::ensure!(
                    display.kind == AuthenticatedDisplayKind::String,
                    "authenticated builtin-output source returned {:?}, expected string",
                    display.kind
                );
                Ok(Some(serde_json::from_str(&display.text)?))
            }
            AuthenticatedEvaluation::Throw(thrown) => {
                anyhow::bail!("authenticated builtin-output source threw: {thrown:?}")
            }
            AuthenticatedEvaluation::Cancelled => {
                anyhow::bail!("authenticated builtin-output source was cancelled")
            }
            AuthenticatedEvaluation::Lifecycle(code) => {
                anyhow::bail!("authenticated builtin-output source exited with {code}")
            }
        }
    }

    fn drain_publications(&mut self, engine: &HermesEngine) -> anyhow::Result<()> {
        while let Some(event) = engine.next_authenticated_work_unit()? {
            match event.phase {
                AuthenticatedWorkUnitPhase::Due => {
                    anyhow::ensure!(
                        event.kind == AuthenticatedWorkUnitKind::Timer
                            && event.target_id == 0
                            && event.scheduling_id != 0,
                        "builtin-output source published malformed Due identities"
                    );
                    anyhow::ensure!(
                        self.due_schedules.insert(event.scheduling_id),
                        "builtin-output source duplicated Due {}",
                        event.scheduling_id
                    );
                }
                AuthenticatedWorkUnitPhase::Undue => {
                    anyhow::ensure!(
                        event.kind == AuthenticatedWorkUnitKind::Timer
                            && event.target_id == 0
                            && event.scheduling_id != 0,
                        "builtin-output source published malformed Undue identities"
                    );
                    anyhow::ensure!(
                        self.due_schedules.remove(&event.scheduling_id),
                        "builtin-output source published unknown Undue {}",
                        event.scheduling_id
                    );
                }
                AuthenticatedWorkUnitPhase::Begin => {
                    if event.kind == AuthenticatedWorkUnitKind::Timer && event.scheduling_id != 0 {
                        self.due_schedules.remove(&event.scheduling_id);
                    }
                    let target_id = event.target_id;
                    anyhow::ensure!(
                        self.active_work_units.insert(target_id, event).is_none(),
                        "builtin-output source duplicated Begin {target_id}"
                    );
                }
                AuthenticatedWorkUnitPhase::Suspended => {
                    let begin = self
                        .active_work_units
                        .get(&event.target_id)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "builtin-output source suspended {} without Begin",
                                event.target_id
                            )
                        })?;
                    anyhow::ensure!(
                        begin.kind == event.kind && begin.scheduling_id == event.scheduling_id,
                        "builtin-output source changed suspended identity {}",
                        event.target_id
                    );
                }
                AuthenticatedWorkUnitPhase::End => {
                    let begin =
                        self.active_work_units
                            .remove(&event.target_id)
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "builtin-output source ended {} without Begin",
                                    event.target_id
                                )
                            })?;
                    anyhow::ensure!(
                        begin.kind == event.kind && begin.scheduling_id == event.scheduling_id,
                        "builtin-output source changed ended identity {}",
                        event.target_id
                    );
                }
            }
        }
        anyhow::ensure!(
            self.active_work_units.is_empty(),
            "builtin-output source left {} active work units",
            self.active_work_units.len()
        );
        if let Some(event) = engine.next_authenticated_cancellation()? {
            anyhow::bail!(
                "builtin-output source published unexpected cancellation for {}: {:?}",
                event.target_id,
                event.resolution
            );
        }
        Ok(())
    }

    fn finish(&mut self, engine: &HermesEngine) -> anyhow::Result<()> {
        self.drain_publications(engine)?;
        anyhow::ensure!(
            self.due_schedules.is_empty(),
            "builtin-output source retained due timer schedules {:?}",
            self.due_schedules
        );
        Ok(())
    }
}

async fn execute_loaded_rows(
    rows: &[&Value],
) -> (BTreeMap<String, Value>, BTreeMap<String, Value>) {
    let mut import_specifiers = BTreeSet::new();
    for row in rows {
        if let Some(specifier) = invocation(row)["moduleSpecifier"].as_str() {
            import_specifiers.insert(specifier.to_owned());
        }
        if let Some(dependencies) =
            invocation(row)["route"]["dependencyModuleSpecifiers"].as_array()
        {
            for dependency in dependencies {
                import_specifiers.insert(
                    dependency
                        .as_str()
                        .expect("builtin dependency specifier must be a string")
                        .to_owned(),
                );
            }
        }
    }
    let imports = import_specifiers
        .iter()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let mut module_specifiers = rows
        .iter()
        .filter(|row| {
            !matches!(
                invocation(row)["route"]["operation"].as_str(),
                Some("import-refusal" | "import-return")
            )
        })
        .filter_map(|row| invocation(row)["moduleSpecifier"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    for row in rows {
        if let Some(dependencies) =
            invocation(row)["route"]["dependencyModuleSpecifiers"].as_array()
        {
            for dependency in dependencies {
                module_specifiers.insert(
                    dependency
                        .as_str()
                        .expect("builtin dependency specifier must be a string")
                        .to_owned(),
                );
            }
        }
    }
    let (host, digest) =
        build_armed_test_host_custom(None, true, true, true, Vec::new(), None, |snapshot| {
            snapshot["bootstrapCompatibilityModes"] = json!(["bun"]);
            snapshot["principals"][0]["imports"]["builtins"] = Value::Array(imports.clone());
            snapshot["entry"] = json!({
                "kind": "repl",
                "identity": "ibex:repl",
                "mode": "interactive",
            });
        });
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest))
        .expect("create source-bound builtin-output runtime");
    engine
        .load_runtime()
        .await
        .expect("load source-bound builtin-output runtime");
    let mut sweep = AuthenticatedBuiltinSweep::new(&host);

    let mut preload_failures = BTreeMap::new();
    for module_specifier in module_specifiers {
        let result = match sweep
            .eval_string(&engine, &preload_script(&module_specifier))
            .await
        {
            Ok(Some(marker)) if marker == "ibex-capsec-builtin-output-preloaded" => {
                drive_to_quiescence(&engine).await
            }
            Ok(value) => Err(format!("module preload returned {value:?}")),
            Err(error) => Err(format!("module preload failed: {error:#}")),
        };
        if let Err(reason) = result {
            preload_failures.insert(module_specifier, reason);
        }
    }

    let mut observed = BTreeMap::new();
    let mut residual = BTreeMap::new();
    for row in rows {
        let key = serde_json::to_string(&row["key"]).expect("serialize builtin output key");
        let module_specifier = invocation(row)["moduleSpecifier"]
            .as_str()
            .expect("executable builtin output has no module specifier");
        let route_operation = invocation(row)["route"]["operation"]
            .as_str()
            .expect("executable builtin output route has no operation");
        if !matches!(route_operation, "import-refusal" | "import-return") {
            if let Some(reason) = preload_failures.get(module_specifier) {
                residual.insert(key, unexercisable(row, reason));
                continue;
            }
        }

        let fixture_id = row["probe"]["fixtureId"]
            .as_str()
            .expect("builtin output route has no fixture ID");
        let observer_id = format!("output-shape:{fixture_id}");
        if !ibex_runtime::host::abi::begin_installed_conformance_observation(&observer_id) {
            residual.insert(
                key,
                unexercisable(row, "the installed Host refused the operation observer"),
            );
            continue;
        }
        let execution = sweep.eval_string(&engine, &invocation_script(row)).await;
        let quiescence = drive_to_quiescence(&engine).await;
        let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
        let typed_observations =
            serde_json::to_value(&typed).expect("serialize builtin output typed observations");
        let classification = invocation(row)["coverageClassification"]
            .as_str()
            .expect("builtin output route has no coverage classification");
        if !classification_accepts_decisions(
            classification,
            &observer_id,
            legacy.len(),
            &typed_observations,
        ) {
            residual.insert(
                key,
                unexercisable(
                    row,
                    format!(
                        "{classification} output observed {} legacy decisions or incompatible typed decisions: {}",
                        legacy.len(), typed_observations
                    ),
                ),
            );
            continue;
        }
        if let Err(reason) = quiescence {
            residual.insert(key, unexercisable(row, reason));
            continue;
        }
        let encoded = match execution {
            Ok(Some(encoded)) => encoded,
            Ok(None) => {
                residual.insert(
                    key,
                    unexercisable(row, "loaded invocation returned no result"),
                );
                continue;
            }
            Err(error) => {
                residual.insert(
                    key,
                    unexercisable(
                        row,
                        format!("loaded invocation failed before evidence: {error:#}"),
                    ),
                );
                continue;
            }
        };
        let result: Value = match serde_json::from_str(&encoded) {
            Ok(result) => result,
            Err(error) => {
                residual.insert(
                    key,
                    unexercisable(
                        row,
                        format!("loaded invocation returned invalid JSON: {error}"),
                    ),
                );
                continue;
            }
        };
        if let Some(completion_token) = result["completionToken"].as_str().filter(|_| {
            !(result["kind"] == "throw"
                && invocation(row)["route"]["outcomeCapture"] == "public-builtin-family")
        }) {
            let completion = sweep
                .eval_string(&engine, &completion_verification_script(completion_token))
                .await;
            let completion = match completion {
                Ok(Some(encoded)) => serde_json::from_str::<Value>(&encoded)
                    .map_err(|error| format!("completion proof was invalid JSON: {error}")),
                Ok(None) => Err("completion proof returned no value".to_owned()),
                Err(error) => Err(format!("completion proof evaluation failed: {error:#}")),
            };
            match completion {
                Ok(completion)
                    if completion["calls"].as_u64() == Some(1)
                        && completion["cleanupPerformed"] == true
                        && (completion["error"] == false
                            || invocation(row)["route"]["outcomeCapture"]
                                == "public-builtin-family") => {}
                Ok(completion) => {
                    residual.insert(
                        key,
                        unexercisable(
                            row,
                            format!("async callback did not complete successfully: {completion}"),
                        ),
                    );
                    continue;
                }
                Err(reason) => {
                    residual.insert(key, unexercisable(row, reason));
                    continue;
                }
            }
        }
        if result["sourceOperationAttempted"] != true {
            residual.insert(
                key,
                unexercisable(row, format!("source operation was not reached: {result}")),
            );
            continue;
        }
        if result["cleanupPerformed"] != true {
            residual.insert(
                key,
                unexercisable(row, format!("cleanup was not proven: {result}")),
            );
            continue;
        }
        let Some(raw) = result.get("rawOutput") else {
            residual.insert(
                key,
                unexercisable(
                    row,
                    format!("loaded invocation returned no raw output: {result}"),
                ),
            );
            continue;
        };
        if route_operation == "import-refusal" {
            let expected_message = format!(
                "Import denied: '{module_specifier}' is not permitted for this package (LLP 0013 import policy)"
            );
            if invocation(row)["sourceDescriptor"]["sourceKey"] != "node_async_hooks"
                || module_specifier != "node:async_hooks"
                || result["kind"] != "throw"
                || result["errorName"] != "Error"
                || result["errorMessage"] != expected_message
                || result["errorCode"] != "ERR_IBEX_IMPORT_DENIED"
                || raw["kind"] != "throw"
                || raw["rawValueShape"] != "throw"
                || !raw["value"].is_null()
                || raw["errorCode"] != "ERR_IBEX_IMPORT_DENIED"
                || raw["errorName"] != "Error"
            {
                residual.insert(
                    key,
                    unexercisable(
                        row,
                        format!(
                            "terminal builtin did not produce the exact public import refusal: raw={raw}; execution={result}"
                        ),
                    ),
                );
                continue;
            }
            let mut proof = import_refusal_result(row, raw.clone(), &result);
            let legacy_observations = serde_json::to_value(&legacy)
                .expect("serialize builtin output legacy observations");
            proof["diagnostic"] = json!({
                "legacyObservationCount": legacy.len(),
                "typedObservationCount": typed.len(),
                "legacyObservations": legacy_observations,
                "typedObservations": typed_observations,
            });
            observed.insert(key, proof);
            continue;
        }
        if !classification_accepts_raw(classification, raw) {
            residual.insert(
                key,
                unexercisable(
                    row,
                    format!(
                        "{classification} source outcome was incompatible with its coverage class: raw={raw}; execution={result}"
                    ),
                ),
            );
            continue;
        }
        let valid_raw_envelope = match raw["kind"].as_str() {
            Some("return") => raw["rawValueShape"].is_string() && raw["errorCode"].is_null(),
            Some("absent") => {
                raw["rawValueShape"] == "absent"
                    && raw["value"].is_null()
                    && raw["errorCode"].is_null()
            }
            Some("throw") => {
                raw["rawValueShape"] == "throw"
                    && raw["value"].is_null()
                    && (raw["errorCode"].is_null() || raw["errorCode"].is_string())
                    && raw["errorName"]
                        .as_str()
                        .is_some_and(|name| !name.is_empty())
            }
            _ => false,
        };
        if !valid_raw_envelope {
            residual.insert(
                key,
                unexercisable(row, format!("public source outcome envelope is invalid: {raw}")),
            );
            continue;
        }
        if invocation(row)["route"]
            .get("inheritedTemplateId")
            .is_none()
            && raw["kind"] == "return"
            && !matches!(
                result["descriptorProof"]["descriptorKind"].as_str(),
                Some("data") | Some("accessor") | Some("module-value")
            )
        {
            residual.insert(
                key,
                unexercisable(
                    row,
                    format!("exact source descriptor was not proven: {result}"),
                ),
            );
            continue;
        }
        let mut proof = return_record_result(row, raw.clone());
        let legacy_observations =
            serde_json::to_value(&legacy).expect("serialize builtin output legacy observations");
        proof["diagnostic"] = json!({
            "legacyObservationCount": legacy.len(),
            "typedObservationCount": typed.len(),
            "legacyObservations": legacy_observations,
            "typedObservations": typed_observations,
        });
        observed.insert(key, proof);
    }

    if let Err(error) = sweep.finish(&engine) {
        let prior = std::mem::take(&mut observed);
        for (key, result) in prior {
            let row = rows
                .iter()
                .find(|row| serde_json::to_string(&row["key"]).unwrap() == key)
                .expect("find row for retained-work failure");
            residual.insert(
                key,
                unexercisable(
                    row,
                    format!("runtime retained work after the batch: {error:#}; prior={result}"),
                ),
            );
        }
    }
    drop(sweep);
    drop(engine);
    drop(reset);
    (observed, residual)
}

/// Execute the exact source-bound builtin output rows. The caller owns the
/// Hermes test lock and must not retain another live Host/engine.
pub(super) async fn execute_builtin_noncap_closed_output_rows(
    rows: &[Value],
) -> (Vec<Value>, Vec<Value>) {
    let mut static_residual = BTreeMap::new();
    let mut executable = Vec::new();
    for row in rows {
        let key = serde_json::to_string(&row["key"]).expect("serialize builtin output plan key");
        let route = &invocation(row)["route"];
        if route["operation"] == "unexercisable" {
            static_residual.insert(
                key,
                unexercisable(
                    row,
                    format!(
                        "{}: {}",
                        route["reasonCode"].as_str().unwrap_or("unspecified"),
                        route["reason"].as_str().unwrap_or("unspecified reason")
                    ),
                ),
            );
        } else {
            executable.push(row);
        }
    }

    let (mut observed_by_key, dynamic_residual) = if executable.is_empty() {
        (BTreeMap::new(), BTreeMap::new())
    } else {
        execute_loaded_rows(&executable).await
    };
    static_residual.extend(dynamic_residual);

    let mut observed = Vec::new();
    let mut residual = Vec::new();
    for row in rows {
        let key = serde_json::to_string(&row["key"]).expect("serialize builtin output plan key");
        match (observed_by_key.remove(&key), static_residual.remove(&key)) {
            (Some(result), None) => observed.push(result),
            (None, Some(result)) => residual.push(result),
            _ => panic!("builtin output executor did not account for {key} exactly once"),
        }
    }
    assert!(observed_by_key.is_empty());
    assert!(static_residual.is_empty());
    (observed, residual)
}

#[tokio::test(flavor = "current_thread")]
async fn capsec_builtin_noncap_closed_output_batch() {
    let Ok(plan_path) = std::env::var("IBEX_CAPSEC_BUILTIN_NONCAP_CLOSED_OUTPUT_PLAN") else {
        eprintln!(
            "IBEX_CAPSEC_BUILTIN_NONCAP_CLOSED_OUTPUT_PLAN is unset; skipping builtin output batch"
        );
        return;
    };
    let bytes = std::fs::read(plan_path).expect("read builtin output plan");
    let text = std::str::from_utf8(&bytes).expect("builtin output plan must be UTF-8");
    let plan = capsec_semantics::strict_json::parse_strict(text)
        .expect("builtin output plan must be strict JSON");
    let rows = plan["rows"]
        .as_array()
        .expect("builtin output plan has no rows")
        .iter()
        .filter(|row| is_surface(row))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 716);
    assert_eq!(
        rows.iter()
            .filter(|row| invocation(row)["route"]["operation"] != "unexercisable")
            .count(),
        533
    );
    let _lock = hermes_engine_test_lock().lock().await;
    let (observed, residual) = execute_builtin_noncap_closed_output_rows(&rows).await;
    assert_eq!(observed.len() + residual.len(), rows.len());
    if let Ok(output_path) = std::env::var("IBEX_CAPSEC_BUILTIN_NONCAP_CLOSED_OUTPUT_RESULT") {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)
            .expect("create builtin output result");
        serde_json::to_writer_pretty(
            &mut file,
            &json!({ "observed": observed, "unexercisable": residual }),
        )
        .expect("serialize builtin output result");
        use std::io::Write as _;
        file.write_all(b"\n").expect("finish builtin output result");
    }
}
