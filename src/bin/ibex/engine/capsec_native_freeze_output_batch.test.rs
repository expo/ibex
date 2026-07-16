// This test-only file is included as a child of the output-shape sweep batch.
// @ref LLP 0023#6-path-bearing-observables — the exact patched native freeze
// completion is observed before runtime bootstrap removes its private global.

use super::HermesEngine;
use serde_json::{json, Value};
use std::collections::BTreeSet;

const SOURCE_DESCRIPTOR_KIND: &str = "authored-native-freeze-invocation";
const INVOCATION_SCHEMA: &str = "ibex/capsec-native-freeze-output-invocation/1";
const HARNESS: &str = include_str!("capsec_native_freeze_output_invocation.js");

pub(super) fn is_surface(row: &Value) -> bool {
    row["probe"]["sourceDescriptor"]["kind"] == SOURCE_DESCRIPTOR_KIND
}

fn assert_exact_keys(value: &Value, expected: &[&str], label: &str) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("{label} must be an object"));
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "{label} has unexpected fields");
}

fn invocation(row: &Value) -> &Value {
    assert!(is_surface(row));
    assert_eq!(row["probe"]["kind"], "loaded-engine-return-record");
    assert_eq!(row["probe"]["recordPath"], json!(["[[return]]"]));
    let source = &row["probe"]["sourceDescriptor"];
    assert_exact_keys(
        source,
        &["kind", "surfaceObservedKey", "invocation"],
        "native freeze source route",
    );
    let invocation = &source["invocation"];
    assert_exact_keys(
        invocation,
        &[
            "invocationSchema",
            "kind",
            "coverageEdgeId",
            "coverageClassification",
            "surfaceObservedKey",
            "sourceDescriptor",
            "sourceDescriptorDigest",
            "operation",
            "completion",
        ],
        "native freeze invocation",
    );
    assert_eq!(invocation["invocationSchema"], INVOCATION_SCHEMA);
    assert_eq!(invocation["kind"], "native-freeze-output");
    assert_eq!(invocation["coverageEdgeId"], row["key"]["surfaceId"]);
    assert_eq!(invocation["coverageClassification"], "non-capability");
    assert_eq!(
        invocation["surfaceObservedKey"],
        source["surfaceObservedKey"]
    );
    assert_eq!(
        invocation["surfaceObservedKey"],
        Value::String(format!(
            "native-op:{}",
            row["key"]["alias"]
                .as_str()
                .expect("native freeze alias must be a string")
        ))
    );

    let descriptor = &invocation["sourceDescriptor"];
    assert_exact_keys(
        descriptor,
        &[
            "kind",
            "globalName",
            "implementationSymbol",
            "implementationPath",
            "freezeSemantics",
            "inventorySourceRefs",
            "implementationSourceRefs",
        ],
        "native freeze implementation descriptor",
    );
    assert_eq!(descriptor["kind"], "native-freeze-global");
    assert_eq!(descriptor["globalName"], row["key"]["alias"]);
    let (symbol, path, semantics) = match descriptor["globalName"].as_str() {
        Some("__exactDeepFreeze") => (
            "exactDeepFreeze",
            "patches/hermes/0006-eval-binding-and-native-deep-freeze.patch",
            "deep",
        ),
        Some("__exactNativeFreeze") => (
            "exactNativeFreeze",
            "patches/hermes/0005-native-compartment-refinements.patch",
            "shallow",
        ),
        other => panic!("unsupported native freeze global {other:?}"),
    };
    assert_eq!(descriptor["implementationSymbol"], symbol);
    assert_eq!(descriptor["implementationPath"], path);
    assert_eq!(descriptor["freezeSemantics"], semantics);
    let refs = descriptor["implementationSourceRefs"]
        .as_array()
        .expect("native freeze route must carry exact implementation refs");
    assert!(!refs.is_empty());
    assert!(refs.iter().all(|source_ref| source_ref
        .as_str()
        .is_some_and(|source_ref| source_ref.starts_with(&format!("{path}#region:")))));
    assert!(refs.iter().any(|source_ref| source_ref
        .as_str()
        .is_some_and(|source_ref| source_ref.contains("return args.getArg(0);"))));
    assert!(refs.iter().any(
        |source_ref| source_ref
            .as_str()
            .is_some_and(|source_ref| source_ref.contains(&format!(
                "createASCIIRef(\"{}\")",
                descriptor["globalName"].as_str().unwrap()
            )))
    ));

    let operation = &invocation["operation"];
    assert_exact_keys(
        operation,
        &["kind", "sentinelId", "identityCheck", "freezeCheck"],
        "native freeze identity operation",
    );
    assert_eq!(operation["kind"], "native-freeze-argument-identity");
    assert_eq!(operation["identityCheck"], "strict-equality");
    match row["key"]["mode"].as_str() {
        Some("primitive-sentinel") => {
            assert_eq!(operation["sentinelId"], "primitive-number-1729");
            assert_eq!(operation["freezeCheck"], "not-applicable");
        }
        Some("object-sentinel") => {
            assert_eq!(operation["sentinelId"], "null-prototype-two-node-graph-v1");
            assert_eq!(operation["freezeCheck"], semantics);
        }
        other => panic!("unsupported native freeze sentinel mode {other:?}"),
    }
    assert_eq!(
        invocation["completion"],
        json!({"kind": "synchronous-loaded-hermes"})
    );
    invocation
}

fn invocation_script(row: &Value) -> String {
    format!(
        "JSON.stringify(({})({}))",
        HARNESS.trim(),
        serde_json::to_string(invocation(row)).expect("serialize native freeze invocation"),
    )
}

pub(super) async fn results(engine: &HermesEngine, rows: &[Value]) -> Vec<Value> {
    let mut observed = Vec::with_capacity(rows.len());
    for row in rows {
        let encoded = engine
            .eval_immediate(&invocation_script(row))
            .await
            .expect("execute native freeze identity invocation")
            .expect("native freeze identity invocation returned no result");
        let result: Value = serde_json::from_str(&encoded)
            .expect("native freeze identity invocation returned invalid JSON");
        assert_eq!(
            result["kind"], "return",
            "native freeze identity invocation failed: {result}"
        );
        assert_eq!(result["sourceOperationAttempted"], true);
        assert_eq!(result["identityProven"], true);
        assert_eq!(result["freezingSemanticsProven"], true);
        let raw = &result["rawOutput"];
        assert_exact_keys(
            raw,
            &["kind", "rawValueShape", "value", "errorCode"],
            "native freeze raw output",
        );
        assert_eq!(
            raw,
            &json!({
                "kind": "return",
                "rawValueShape": "argument-identity",
                "value": "same-as-argument-0",
                "errorCode": null,
            })
        );
        observed.push(super::return_record_result(row, raw.clone()));
    }
    observed
}

fn test_row(name: &str, mode: &str) -> Value {
    let (symbol, path, semantics) = match name {
        "__exactDeepFreeze" => (
            "exactDeepFreeze",
            "patches/hermes/0006-eval-binding-and-native-deep-freeze.patch",
            "deep",
        ),
        "__exactNativeFreeze" => (
            "exactNativeFreeze",
            "patches/hermes/0005-native-compartment-refinements.patch",
            "shallow",
        ),
        _ => unreachable!(),
    };
    let surface_id = format!("surface.native.op.{}.test", &name[2..].to_lowercase());
    let sentinel_id = if mode == "primitive-sentinel" {
        "primitive-number-1729"
    } else {
        "null-prototype-two-node-graph-v1"
    };
    let freeze_check = if mode == "primitive-sentinel" {
        "not-applicable"
    } else {
        semantics
    };
    json!({
        "key": {
            "surfaceId": surface_id,
            "output": "[[return]]",
            "alias": name,
            "mode": mode,
            "sourceKind": "native-op",
            "returnVariant": "same-as-argument-0",
            "contextId": "runtime.bootstrap-native-call-loaded",
        },
        "probe": {
            "kind": "loaded-engine-return-record",
            "fixtureId": format!("native-freeze-{name}-{mode}"),
            "sourceDescriptor": {
                "kind": SOURCE_DESCRIPTOR_KIND,
                "surfaceObservedKey": format!("native-op:{name}"),
                "invocation": {
                    "invocationSchema": INVOCATION_SCHEMA,
                    "kind": "native-freeze-output",
                    "coverageEdgeId": surface_id,
                    "coverageClassification": "non-capability",
                    "surfaceObservedKey": format!("native-op:{name}"),
                    "sourceDescriptor": {
                        "kind": "native-freeze-global",
                        "globalName": name,
                        "implementationSymbol": symbol,
                        "implementationPath": path,
                        "freezeSemantics": semantics,
                        "inventorySourceRefs": [format!("{path}#inventory:{name}")],
                        "implementationSourceRefs": [
                            format!("{path}#region:CallResult<HermesValue> {symbol}(void *, Runtime &runtime)..return args.getArg(0);#tokens:return args.getArg(0);"),
                            format!("{path}#region:runtime, createASCIIRef(\"{name}\")..{symbol},#tokens:createASCIIRef(\"{name}\")+{symbol},"),
                        ],
                    },
                    "sourceDescriptorDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "operation": {
                        "kind": "native-freeze-argument-identity",
                        "sentinelId": sentinel_id,
                        "identityCheck": "strict-equality",
                        "freezeCheck": freeze_check,
                    },
                    "completion": {"kind": "synchronous-loaded-hermes"},
                },
            },
            "sourceDescriptorDigest": "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "recordPath": ["[[return]]"],
        },
    })
}

#[tokio::test(flavor = "current_thread")]
async fn loaded_hermes_native_freeze_identity_and_semantics() {
    let _lock = super::hermes_engine_test_lock().lock().await;
    let engine = HermesEngine::new().expect("create native freeze proof runtime");
    let rows = ["__exactDeepFreeze", "__exactNativeFreeze"]
        .into_iter()
        .flat_map(|name| {
            ["primitive-sentinel", "object-sentinel"]
                .into_iter()
                .map(move |mode| test_row(name, mode))
        })
        .collect::<Vec<_>>();
    let observed = results(&engine, &rows).await;
    assert_eq!(observed.len(), 4);
    assert!(observed.iter().all(|row| {
        row["raw"]
            == json!({
                "kind": "return",
                "rawValueShape": "argument-identity",
                "value": "same-as-argument-0",
                "errorCode": null,
            })
    }));
}
