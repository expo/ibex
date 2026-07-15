// This test-only file is included as a child module of the output-shape sweep batch.
// @ref LLP 0023#6-path-bearing-observables — callable output evidence is an
// actual loaded-engine call/construct/get completion; setup failures block
// promotion, while genuine returns, stable throws, and property absence are
// preserved as their distinct source completions.

use super::{AuthenticatedSweep, HermesEngine};
use serde_json::{Value, json};

const GLOBAL_CALLABLE_HARNESS: &str = include_str!("capsec_global_callable_invocation.js");
const INVOCATION_SCHEMA: &str = "ibex/capsec-global-callable-invocation/1";
const TIMEOUT_MILLISECONDS: u64 = 1_000;

pub(super) fn is_surface(row: &Value) -> bool {
    row["probe"]["sourceDescriptor"]["kind"] == "authored-global-callable-invocation"
}

fn invocation(row: &Value) -> &Value {
    let source = &row["probe"]["sourceDescriptor"];
    assert_eq!(source["kind"], "authored-global-callable-invocation");
    assert_eq!(row["probe"]["recordPath"], json!(["[[return]]"]));
    let invocation = &source["invocation"];
    assert_eq!(invocation["invocationSchema"], INVOCATION_SCHEMA);
    assert_eq!(invocation["kind"], "global-callable-invocation");
    assert_eq!(
        invocation["completion"],
        json!({
            "kind": "event-loop-quiescence",
            "timeoutMilliseconds": TIMEOUT_MILLISECONDS,
        })
    );
    invocation
}

fn unexercisable(row: &Value, reason_code: &str, reason: impl AsRef<str>) -> Value {
    json!({
        "key": row["key"].clone(),
        "reason": format!(
            "authored global callable {} was not an authenticated outer-return observation [{}]: {}",
            row["probe"]["fixtureId"].as_str().unwrap_or("<missing>"),
            reason_code,
            reason.as_ref(),
        ),
    })
}

fn block(
    blocked: &mut Vec<Value>,
    diagnostic_details: &mut Vec<Value>,
    row: &Value,
    reason_code: &str,
    reason: impl AsRef<str>,
    details: Value,
) {
    let reason = reason.as_ref();
    blocked.push(unexercisable(row, reason_code, reason));
    diagnostic_details.push(json!({
        "key": row["key"].clone(),
        "reasonCode": reason_code,
        "reason": reason,
        "details": details,
    }));
}

fn invocation_script(row: &Value) -> String {
    format!(
        "JSON.stringify(({})({}))",
        GLOBAL_CALLABLE_HARNESS.trim(),
        serde_json::to_string(invocation(row)).expect("serialize authored global callable"),
    )
}

async fn drive_to_quiescence(engine: &HermesEngine) -> Result<(), String> {
    tokio::time::timeout(
        std::time::Duration::from_millis(TIMEOUT_MILLISECONDS),
        engine.drive_event_loop(),
    )
    .await
    .map_err(|_| "event loop did not reach the authored one-second bound".to_owned())?
    .map_err(|error| format!("event-loop completion failed: {error:#}"))
}

fn source_completion_result(row: &Value, raw: Value) -> Value {
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

fn source_completion_is_exercised(raw: &Value) -> bool {
    match raw["kind"].as_str() {
        Some("return") => {
            raw["rawValueShape"].is_string()
                && raw["rawValueShape"] != "throw"
                && raw["errorCode"].is_null()
        }
        Some("throw") => {
            raw["rawValueShape"] == "throw"
                && raw["value"].is_null()
                && raw["errorCode"]
                    .as_str()
                    .is_some_and(|error_code| !error_code.is_empty())
        }
        Some("absent") => {
            raw["rawValueShape"] == "absent" && raw["value"].is_null() && raw["errorCode"].is_null()
        }
        _ => false,
    }
}

fn descriptor_matches_source_completion(descriptor_kind: Option<&str>, raw: &Value) -> bool {
    match raw["kind"].as_str() {
        Some("absent") => descriptor_kind == Some("absent"),
        Some("return") | Some("throw") => {
            matches!(descriptor_kind, Some("data") | Some("accessor"))
        }
        _ => false,
    }
}

#[test]
fn exercised_source_completion_preserves_throws_as_throws() {
    assert!(source_completion_is_exercised(&json!({
        "kind": "return",
        "rawValueShape": "undefined",
        "value": null,
        "errorCode": null,
    })));
    assert!(source_completion_is_exercised(&json!({
        "kind": "throw",
        "rawValueShape": "throw",
        "value": null,
        "errorCode": "ERR_IBEX_PASSWORD_UNAVAILABLE",
    })));
    assert!(!source_completion_is_exercised(&json!({
        "kind": "invalid",
        "rawValueShape": "invalid",
        "value": null,
        "errorCode": null,
    })));
    assert!(source_completion_is_exercised(&json!({
        "kind": "absent",
        "rawValueShape": "absent",
        "value": null,
        "errorCode": null,
    })));
}

#[test]
fn descriptor_proof_distinguishes_absence_from_callable_completion() {
    let absent = json!({"kind": "absent"});
    let returned = json!({"kind": "return"});
    let thrown = json!({"kind": "throw"});

    assert!(descriptor_matches_source_completion(
        Some("absent"),
        &absent
    ));
    assert!(!descriptor_matches_source_completion(Some("data"), &absent));
    assert!(descriptor_matches_source_completion(
        Some("data"),
        &returned
    ));
    assert!(descriptor_matches_source_completion(
        Some("accessor"),
        &thrown
    ));
    assert!(!descriptor_matches_source_completion(
        Some("absent"),
        &returned
    ));
}

fn validate_typed_authority(
    route: &Value,
    observer_id: &str,
    typed_decisions: &Value,
) -> Result<(), String> {
    let decisions = typed_decisions
        .as_array()
        .ok_or_else(|| "typed decision capture was not an array".to_owned())?;
    let grants = route
        .get("authority")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if decisions.is_empty() && grants.is_empty() {
        return Ok(());
    }
    if grants.is_empty() {
        return Err(format!(
            "{} typed decisions were observed without authored route authority",
            decisions.len()
        ));
    }

    let mut matched = vec![false; grants.len()];
    for decision in decisions {
        if decision["terminalBranchId"] != observer_id {
            return Err("typed decision escaped its exact callable observer".to_owned());
        }
        if decision["evidence"]["outcome"] != "allow" {
            return Err("typed decision did not produce an authenticated allow".to_owned());
        }
        let gates = decision["gates"]
            .as_array()
            .ok_or_else(|| "typed decision gates were not an array".to_owned())?;
        if gates.is_empty()
            || gates.iter().any(|gate| {
                gate["targetCell"] != "complete"
                    || gate["definitionAndEdgePredicatesSatisfied"] != true
            })
        {
            return Err("typed decision did not traverse complete satisfied gates".to_owned());
        }
        let effects = decision["decisionSet"]["effects"]
            .as_array()
            .ok_or_else(|| "typed decision effects were not an array".to_owned())?;
        if effects.is_empty() {
            return Err("typed decision carried no effects".to_owned());
        }
        for effect in effects {
            let Some(index) = grants.iter().position(|grant| {
                grant["kind"] == "typed-effect"
                    && grant["cap"] == effect["cap"]
                    && grant["resourceKind"] == effect["resource"]["kind"]
                    && grant["requested"] == effect["resource"]["requested"]
            }) else {
                return Err(format!(
                    "typed effect was outside the authored route authority: {effect}"
                ));
            };
            matched[index] = true;
        }
    }
    if matched.iter().any(|matched| !matched) {
        return Err("authored route authority was broader than the observed effects".to_owned());
    }
    Ok(())
}

fn write_diagnostic_if_requested(
    rows: &[Value],
    observed: &[Value],
    blocked: &[Value],
    blocked_details: &[Value],
    authority_observations: &[Value],
) {
    let Ok(output_path) = std::env::var("IBEX_CAPSEC_GLOBAL_CALLABLE_DIAGNOSTIC_OUTPUT") else {
        return;
    };
    let plan_path = std::env::var("IBEX_CAPSEC_OUTPUT_SHAPE_PLAN")
        .expect("global callable diagnostic requires the bound sweep plan path");
    let plan_bytes = std::fs::read(&plan_path).expect("read global callable diagnostic plan");
    let plan_text =
        std::str::from_utf8(&plan_bytes).expect("global callable diagnostic plan must be UTF-8");
    let plan = capsec_semantics::strict_json::parse_strict(plan_text)
        .expect("global callable diagnostic plan must be strict JSON");
    let plan_rows = plan["rows"]
        .as_array()
        .expect("global callable diagnostic plan rows");
    let plan_descriptors = plan_rows
        .iter()
        .filter(|row| is_surface(row))
        .map(|row| {
            (
                serde_json::to_string(&row["key"]).expect("serialize diagnostic plan key"),
                row["probe"]["sourceDescriptorDigest"].clone(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        plan_descriptors.len(),
        rows.len(),
        "diagnostic plan and executed global callable rows must be one-to-one"
    );

    let source_descriptor_bindings = rows
        .iter()
        .map(|row| {
            let key = serde_json::to_string(&row["key"])
                .expect("serialize executed global callable key");
            assert_eq!(
                plan_descriptors.get(&key),
                Some(&row["probe"]["sourceDescriptorDigest"]),
                "diagnostic callable descriptor must match its exact plan row"
            );
            json!({
                "key": row["key"].clone(),
                "probeSourceDescriptorDigest": row["probe"]["sourceDescriptorDigest"].clone(),
                "invocationSourceDescriptorDigest": row["probe"]["sourceDescriptor"]["invocation"]["sourceDescriptorDigest"].clone(),
            })
        })
        .collect::<Vec<_>>();
    let diagnostic = json!({
        "globalCallableDiagnosticSchema": "ibex/capsec-global-callable-diagnostic/1",
        "sweepPlanDigest": plan["sweepPlanDigest"].clone(),
        "sourceRevision": plan["sourceRevision"].clone(),
        "sourceTreeDigest": plan["sourceTreeDigest"].clone(),
        "engine": plan["engine"].clone(),
        "sourceDescriptorBindings": source_descriptor_bindings,
        "observations": observed,
        "unexercisable": blocked,
        "unexercisableDetails": blocked_details,
        "authorityObservations": authority_observations,
    });
    let bytes = serde_json::to_vec_pretty(&diagnostic)
        .expect("serialize global callable diagnostic result");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(output_path)
        .expect("create new global callable diagnostic result");
    std::io::Write::write_all(&mut file, &bytes).expect("write global callable diagnostic result");
    std::io::Write::write_all(&mut file, b"\n")
        .expect("terminate global callable diagnostic result");
    file.sync_all()
        .expect("sync global callable diagnostic result");
}

pub(super) async fn results(
    engine: &HermesEngine,
    sweep: &mut AuthenticatedSweep,
    rows: &[Value],
) -> (Vec<Value>, Vec<Value>) {
    let mut observed = Vec::new();
    let mut blocked = Vec::new();
    let mut blocked_details = Vec::new();
    let mut authority_observations = Vec::new();

    for row in rows {
        let invocation = invocation(row);
        let route = &invocation["route"];
        if route["operation"] == "unexercisable" {
            block(
                &mut blocked,
                &mut blocked_details,
                row,
                route["reasonCode"].as_str().unwrap_or("unspecified"),
                route["reason"].as_str().unwrap_or("unspecified reason"),
                json!({"route": route}),
            );
            continue;
        }

        let fixture_id = row["probe"]["fixtureId"]
            .as_str()
            .expect("authored global callable route has no fixture ID");
        let observer_id = format!("output-shape:{fixture_id}");
        if !ibex_runtime::host::abi::begin_installed_conformance_observation(&observer_id) {
            block(
                &mut blocked,
                &mut blocked_details,
                row,
                "observer-installation-refused",
                "the installed host refused the callable observer",
                Value::Null,
            );
            continue;
        }

        let execution = sweep.eval_string(engine, &invocation_script(row)).await;
        let quiescence = drive_to_quiescence(engine).await;
        let (legacy, typed) = ibex_runtime::host::abi::take_installed_conformance_observations();
        let typed = serde_json::to_value(typed)
            .expect("serialize typed global callable capability decisions");
        if !legacy.is_empty() {
            block(
                &mut blocked,
                &mut blocked_details,
                row,
                "legacy-capability-decision-observed",
                format!(
                    "call/construct or setup reached {} legacy capability decisions",
                    legacy.len(),
                ),
                json!({"legacyDecisions": legacy, "typedDecisions": typed}),
            );
            continue;
        }
        if let Err(reason) = validate_typed_authority(route, &observer_id, &typed) {
            block(
                &mut blocked,
                &mut blocked_details,
                row,
                "typed-authority-mismatch",
                reason,
                json!({"authoredAuthority": route.get("authority"), "typedDecisions": typed}),
            );
            continue;
        }
        if typed
            .as_array()
            .is_some_and(|decisions| !decisions.is_empty())
        {
            authority_observations.push(json!({
                "key": row["key"].clone(),
                "authoredAuthority": route["authority"].clone(),
                "typedDecisions": typed,
            }));
        }
        if let Err(error) = quiescence {
            block(
                &mut blocked,
                &mut blocked_details,
                row,
                "event-loop-completion-failed",
                error,
                Value::Null,
            );
            continue;
        }

        let encoded = match execution {
            Ok(Some(encoded)) => encoded,
            Ok(None) => {
                block(
                    &mut blocked,
                    &mut blocked_details,
                    row,
                    "loaded-invocation-no-result",
                    "loaded invocation returned no result",
                    Value::Null,
                );
                continue;
            }
            Err(error) => {
                block(
                    &mut blocked,
                    &mut blocked_details,
                    row,
                    "loaded-invocation-evaluation-failed",
                    format!("loaded invocation failed before returning evidence: {error:#}"),
                    Value::Null,
                );
                continue;
            }
        };
        let result: Value = match serde_json::from_str(&encoded) {
            Ok(result) => result,
            Err(error) => {
                block(
                    &mut blocked,
                    &mut blocked_details,
                    row,
                    "loaded-invocation-invalid-json",
                    format!("loaded invocation returned invalid JSON: {error}"),
                    Value::Null,
                );
                continue;
            }
        };
        if result["sourceOperationAttempted"] != true {
            block(
                &mut blocked,
                &mut blocked_details,
                row,
                "source-operation-not-attempted",
                format!("receiver/setup never reached the exact source call: {result}"),
                json!({"result": result}),
            );
            continue;
        }
        if result["cleanupPerformed"] != true {
            block(
                &mut blocked,
                &mut blocked_details,
                row,
                "cleanup-unproven",
                format!("post-call cleanup was not proven: {result}"),
                json!({"result": result}),
            );
            continue;
        }
        let Some(raw) = result.get("rawOutput") else {
            block(
                &mut blocked,
                &mut blocked_details,
                row,
                "raw-output-missing",
                format!("loaded source call returned no raw output: {result}"),
                json!({"result": result}),
            );
            continue;
        };
        if !source_completion_is_exercised(raw) {
            block(
                &mut blocked,
                &mut blocked_details,
                row,
                "invalid-source-completion-envelope",
                format!(
                    "the exact source operation produced no valid return/throw envelope: {raw}"
                ),
                json!({"raw": raw}),
            );
            continue;
        }
        let descriptor_kind = result["descriptorProof"]["descriptorKind"].as_str();
        if !descriptor_matches_source_completion(descriptor_kind, raw) {
            block(
                &mut blocked,
                &mut blocked_details,
                row,
                "source-descriptor-completion-mismatch",
                format!(
                    "loaded property descriptor did not match the exact source completion: {result}"
                ),
                json!({"result": result}),
            );
            continue;
        }
        observed.push(source_completion_result(row, raw.clone()));
    }

    assert_eq!(observed.len() + blocked.len(), rows.len());
    assert_eq!(blocked.len(), blocked_details.len());
    write_diagnostic_if_requested(
        rows,
        &observed,
        &blocked,
        &blocked_details,
        &authority_observations,
    );
    (observed, blocked)
}
