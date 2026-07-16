//! Executable implementation adapters for the four LLP 0024 session gates.
//!
//! The native observer used here is intentionally metadata-only. Values and
//! completions are observed through the authenticated evaluator itself, so the
//! test feature never gains a second evaluator or a live-value extraction ABI.
//! @ref LLP 0024#77-deviations-and-the-four-gates-that-prove-them

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{json, Map, Value};
use tempfile::TempDir;

use crate::cli::Cli;
use crate::engine::{
    AuthenticatedDisplayKind, AuthenticatedEvaluation, DisplayDisposition, Engine,
};
use crate::runtime::{ReplSessionIngress, Runtime};

const GENERATED_FIXTURES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/capsec/session-semantics/fixtures.json"
));

struct HarnessSession {
    _project: TempDir,
    _host: crate::host::Host,
    engine: Arc<dyn Engine>,
    ingress: ReplSessionIngress,
}

impl HarnessSession {
    async fn new(label: &str) -> Result<Self> {
        let project = tempfile::Builder::new()
            .prefix(&format!("ibex-session-gate-{label}-"))
            .tempdir()?;
        write_project_modules(project.path())?;
        let (host, engine, ingress) =
            crate::runtime::tests::session_conformance_repl_parts(project.path())?;
        engine.load_runtime().await?;
        Ok(Self {
            _project: project,
            _host: host,
            engine,
            ingress,
        })
    }

    async fn evaluate(&mut self, source: &str) -> Result<AuthenticatedEvaluation> {
        self.ingress
            .evaluate_inline(self.engine.as_ref(), source.as_bytes().to_vec())
            .await
            .map_err(anyhow::Error::new)
    }

    async fn release(&self, evaluation: AuthenticatedEvaluation) -> Result<()> {
        if let AuthenticatedEvaluation::Value {
            receipt: Some(receipt),
            ..
        } = evaluation
        {
            self.engine.release_undisplayed_value(receipt).await?;
        }
        Ok(())
    }

    async fn metadata(&self, names: &[String]) -> Result<Value> {
        let names = names.iter().map(String::as_str).collect::<Vec<_>>();
        self.engine.session_conformance_metadata(&names).await
    }
}

fn write_project_modules(root: &Path) -> Result<()> {
    std::fs::write(
        root.join("package.json"),
        "{\"name\":\"session-gate\",\"private\":true,\"type\":\"module\"}\n",
    )?;
    std::fs::write(
        root.join("throwing.mjs"),
        r#"Object.defineProperty(globalThis, "moduleSideEffect", {
  value: 1, writable: true, enumerable: true, configurable: true
});
throw new Error("module failed");
export const imported = 7;
"#,
    )?;
    std::fs::write(
        root.join("freeze.mjs"),
        "Object.preventExtensions(globalThis);\nexport const imported = 7;\n",
    )?;
    std::fs::write(root.join("value.mjs"), "export const imported = 42;\n")?;
    Ok(())
}

fn setup_source(id: &str) -> Option<&'static str> {
    match id {
        "bare-var-object-adopts-without-clobber"
        | "function-object-clobbers-without-creation-provenance" => Some(
            r#"Object.defineProperty(globalThis, "__ibexObjectBefore", {
  value: Object, writable: false, enumerable: false, configurable: true
});"#,
        ),
        "function-overwrite-does-not-launder-provenance" => Some(
            r#"Object.defineProperty(globalThis, "p", {
  value: "endowment", writable: true, enumerable: true, configurable: false
});"#,
        ),
        "adopted-configurable-property-can-delete-and-recreate" => Some(
            r#"Object.defineProperty(globalThis, "q", {
  value: "before", writable: false, enumerable: false, configurable: true
});"#,
        ),
        "all-cross-kind-matrix-rows-are-executable" => Some(
            r#"(function () {
  for (const [name, value] of [
    ["adoptedVar", "adopted-var"],
    ["adoptedFunction", "adopted-function"],
    ["deletedVar", "delete-var"],
    ["deletedFunction", "delete-function"],
    ["objectToLexical", "under-lexical"]
  ]) Object.defineProperty(globalThis, name, {
    value, writable: true, enumerable: true, configurable: true
  });
  for (const [name, value] of [
    ["inheritedVar", "inherited-var"],
    ["inheritedFunction", "inherited-function"]
  ]) Object.defineProperty(Object.getPrototypeOf(globalThis), name, {
    value, writable: true, enumerable: true, configurable: true
  });
})();"#,
        ),
        _ => None,
    }
}

fn input_source(id: &str, index: usize) -> &'static str {
    match (id, index) {
        ("var-created-then-lexical-shadows", 0) => "var x = 1;",
        ("var-created-then-lexical-shadows", 1) => "let x = 2;",
        ("bare-var-object-adopts-without-clobber", 0) => "var Object;",
        ("function-object-clobbers-without-creation-provenance", 0) => "function Object() {}",
        ("var-undefined-cannot-launder-restricted-global", 0) => "var undefined;",
        ("var-undefined-cannot-launder-restricted-global", 1) => "let undefined = 1;",
        ("function-overwrite-does-not-launder-provenance", 0) => "function p() {}",
        ("function-overwrite-does-not-launder-provenance", 1) => "let p = 1;",
        // The armed realm's intrinsic prototypes are intentionally immutable.
        // Alpha-rename this model row to a pre-existing inherited property;
        // the row observes only that a `var` creates a fresh own property.
        ("inherited-var-creates-own-property", 0) => "var toString;",
        ("uninitialized-lexical-restores-displaced-cell", 0) => "const x = 1;",
        ("uninitialized-lexical-restores-displaced-cell", 1) => {
            "let x = (() => { throw new Error('initializer failed'); })();"
        }
        ("initialized-lexical-commits-on-throw", 0) => {
            "let x = 1; throw new Error('after initialization');"
        }
        ("destructuring-commits-per-initialized-cell", 0) => {
            r#"let [a, b] = {
  [Symbol.iterator]: function () {
    let index = 0;
    return { next: function () {
      index += 1;
      if (index === 1) return { value: 1, done: false };
      throw new Error("iterator failed before b");
    }};
  }
};"#
        }
        ("var-commits-and-displaces-lexical-on-throw", 0) => "let x = 1;",
        ("var-commits-and-displaces-lexical-on-throw", 1) => {
            "var x = 2; throw new Error('after var assignment');"
        }
        ("throwing-import-publishes-no-declarations", 0) => {
            "import { imported } from './throwing.mjs'; var w;"
        }
        ("phase-five-recheck-prevents-partial-instantiation", 0) => {
            "import { imported } from './freeze.mjs'; var x; var y;"
        }
        ("import-cell-is-initialized-and-read-only", 0) => {
            "import { imported } from './value.mjs'; throw new Error('after import commit');"
        }
        ("import-cell-is-initialized-and-read-only", 1) => "imported = 43;",
        ("last-value-uninitialized-lexical-disable-rolls-back", 0) => {
            "let $_ = (() => { throw new Error('before initializer'); })();"
        }
        ("last-value-initialized-lexical-disable-commits", 0) => {
            "let $_ = 5; throw new Error('after initializer');"
        }
        ("same-input-lexical-var-collision-is-atomic", 0) => "var x; let x;",
        ("same-input-var-function-function-wins", 0) => "var f; function f() {}",
        ("const-assignment-throws-without-changing-value", 0) => "const c = 9;",
        ("const-assignment-throws-without-changing-value", 1) => "c = 10;",
        ("class-cell-initializes-and-remains-mutable", 0) => "class C {}",
        ("class-cell-initializes-and-remains-mutable", 1) => "C = 'replacement';",
        ("adopted-configurable-property-can-delete-and-recreate", 0) => "var q;",
        ("adopted-configurable-property-can-delete-and-recreate", 1) => "var q;",
        ("all-cross-kind-matrix-rows-are-executable", 0) => "var absentVar;",
        ("all-cross-kind-matrix-rows-are-executable", 1) => "function absentFunction() {}",
        ("all-cross-kind-matrix-rows-are-executable", 2) => "var varOwnVar;",
        ("all-cross-kind-matrix-rows-are-executable", 3) => "var varOwnVar;",
        ("all-cross-kind-matrix-rows-are-executable", 4) => "var varOwnFunction;",
        ("all-cross-kind-matrix-rows-are-executable", 5) => "function varOwnFunction() {}",
        ("all-cross-kind-matrix-rows-are-executable", 6) => "var deletedVar;",
        ("all-cross-kind-matrix-rows-are-executable", 7) => "var deletedVar;",
        ("all-cross-kind-matrix-rows-are-executable", 8) => "var deletedFunction;",
        ("all-cross-kind-matrix-rows-are-executable", 9) => "function deletedFunction() {}",
        ("all-cross-kind-matrix-rows-are-executable", 10) => "var adoptedVar;",
        ("all-cross-kind-matrix-rows-are-executable", 11) => "function adoptedFunction() {}",
        ("all-cross-kind-matrix-rows-are-executable", 12) => "var inheritedVar;",
        ("all-cross-kind-matrix-rows-are-executable", 13) => "function inheritedFunction() {}",
        ("all-cross-kind-matrix-rows-are-executable", 14) => "let objectToLexical = 'lexical';",
        ("all-cross-kind-matrix-rows-are-executable", 15) => "let lexicalToVar = 1;",
        ("all-cross-kind-matrix-rows-are-executable", 16) => "var lexicalToVar;",
        ("all-cross-kind-matrix-rows-are-executable", 17) => "let lexicalToFunction = 1;",
        ("all-cross-kind-matrix-rows-are-executable", 18) => "function lexicalToFunction() {}",
        ("all-cross-kind-matrix-rows-are-executable", 19) => "let lexicalToLexical = 1;",
        ("all-cross-kind-matrix-rows-are-executable", 20) => "const lexicalToLexical = 2;",
        _ => panic!("no concrete input adapter for {id} input {index}"),
    }
}

fn expected_display(value: &Value) -> (AuthenticatedDisplayKind, String) {
    if let Some(symbol) = value.get("$sessionValue").and_then(Value::as_str) {
        return match symbol {
            "undefined" => (AuthenticatedDisplayKind::Undefined, "undefined".into()),
            "function" | "class" | "builtin" => {
                (AuthenticatedDisplayKind::Function, "[Function]".into())
            }
            other => panic!("unsupported model display symbol {other}"),
        };
    }
    match value {
        Value::Null => (AuthenticatedDisplayKind::Null, "null".into()),
        Value::Bool(value) => (AuthenticatedDisplayKind::Boolean, value.to_string()),
        Value::Number(value) => (AuthenticatedDisplayKind::Number, value.to_string()),
        Value::String(value) => (
            AuthenticatedDisplayKind::String,
            serde_json::to_string(value).expect("string JSON"),
        ),
        other => panic!("unsupported concrete model value {other}"),
    }
}

fn throw_message_matches(expected: &str, actual: &str) -> bool {
    if let Some((_, binding_name)) = expected
        .strip_prefix("assignment to read-only ")
        .and_then(|description| description.rsplit_once(' '))
    {
        // LLP 0024 fixes the read-only cell semantics, not engine-specific
        // TypeError prose. Hermes reports these cells as constant bindings;
        // the reference model additionally records whether the cell was a
        // `const` or an `import`. Preserve the semantic/name check without
        // making the conformance gate depend on either spelling.
        let lower = actual.to_ascii_lowercase();
        return actual.contains(binding_name)
            && (lower.contains("constant binding") || lower.contains("read-only"));
    }
    actual.contains(expected)
}

#[test]
fn read_only_binding_diagnostics_compare_semantics_not_engine_prose() {
    assert!(throw_message_matches(
        "assignment to read-only import imported",
        "Assignment to constant binding 'imported'",
    ));
    assert!(throw_message_matches(
        "assignment to read-only const c",
        "assignment to read-only const c",
    ));
    assert!(!throw_message_matches(
        "assignment to read-only import imported",
        "Assignment to constant binding 'other'",
    ));
    assert!(!throw_message_matches(
        "initializer failed",
        "another failure"
    ));
}

fn rename_model_name(value: &Value, from: &str, to: &str) -> Value {
    match value {
        Value::String(value) if value == from => Value::String(to.to_owned()),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| rename_model_name(value, from, to))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| {
                    (
                        if key == from {
                            to.to_owned()
                        } else {
                            key.clone()
                        },
                        rename_model_name(value, from, to),
                    )
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

async fn assert_evaluation(
    session: &mut HarnessSession,
    source: &str,
    expected: &Value,
    label: &str,
) -> Result<()> {
    let outcome = expected["outcome"]
        .as_str()
        .context("model event has no outcome")?;
    let evaluation = session.evaluate(source).await?;
    match (outcome, &evaluation) {
        ("success", AuthenticatedEvaluation::Empty)
            if expected["completion"]["$sessionValue"] == "empty" => {}
        ("success", AuthenticatedEvaluation::Value { display, .. }) => {
            let (kind, text) = expected_display(&expected["completion"]);
            assert_eq!(
                (display.kind, display.text.as_str()),
                (kind, text.as_str()),
                "{label}"
            );
        }
        ("throw", AuthenticatedEvaluation::Throw(actual)) => {
            if expected["error"]["predicate"] == "ModifiedHasRestrictedGlobalProperty" {
                let name = expected["error"]["name"]
                    .as_str()
                    .context("restricted-global refusal has no name")?;
                let expected_message = format!("session declaration '{name}' is not permitted");
                assert_eq!(
                    actual.metadata.message(),
                    Some(expected_message.as_str()),
                    "{label}: restricted-global refusal must remain a JavaScript throw"
                );
            }
            if let Some(message) = expected["error"]["message"].as_str() {
                assert!(
                    actual
                        .metadata
                        .message()
                        .is_some_and(|actual| throw_message_matches(message, actual)),
                    "{label}: expected throw containing {message:?}, got {actual:?}"
                );
            }
        }
        ("cancelled", AuthenticatedEvaluation::Cancelled) => {}
        _ => panic!("{label}: model expected {expected}, implementation returned {evaluation:?}"),
    }
    session.release(evaluation).await
}

async fn assert_value_evaluation(
    session: &mut HarnessSession,
    source: &str,
    expected: &Value,
    label: &str,
) -> Result<()> {
    let evaluation = session.evaluate(source).await?;
    match &evaluation {
        AuthenticatedEvaluation::Value { display, .. } => {
            let (kind, text) = expected_display(expected);
            assert_eq!(
                (display.kind, display.text.as_str()),
                (kind, text.as_str()),
                "{label}"
            );
        }
        other => panic!("{label}: expected value {expected}, got {other:?}"),
    }
    session.release(evaluation).await
}

fn requested_names(fixture: &Value) -> Vec<String> {
    fn collect(value: &Value, names: &mut BTreeSet<String>) {
        match value {
            Value::Array(values) => values.iter().for_each(|value| collect(value, names)),
            Value::Object(values) => {
                if let Some(name) = values.get("name").and_then(Value::as_str) {
                    names.insert(name.to_owned());
                }
                values.values().for_each(|value| collect(value, names));
            }
            _ => {}
        }
    }
    let mut names = BTreeSet::from(["$_".to_owned()]);
    collect(&fixture["program"], &mut names);
    for key in ["declarativeRecord", "objectRecord"] {
        let map = if key == "objectRecord" {
            fixture["final"][key]["own"].as_object()
        } else {
            fixture["final"][key].as_object()
        };
        if let Some(map) = map {
            names.extend(map.keys().cloned());
        }
    }
    names.into_iter().collect()
}

fn expected_metadata(fixture: &Value, requested: &[String]) -> Value {
    let mut declarative = Map::new();
    for (name, cell) in fixture["final"]["declarativeRecord"]
        .as_object()
        .expect("declarative record")
    {
        declarative.insert(
            name.clone(),
            json!({ "kind": cell["kind"], "initialized": cell["initialized"] }),
        );
    }
    let requested = requested.iter().collect::<BTreeSet<_>>();
    let mut own = Map::new();
    for (name, descriptor) in fixture["final"]["objectRecord"]["own"]
        .as_object()
        .expect("object record")
    {
        if !requested.contains(name) {
            continue;
        }
        let shape = if descriptor["type"] == "data" {
            json!({
                "type": "data",
                "writable": descriptor["writable"],
                "enumerable": descriptor["enumerable"],
                "configurable": descriptor["configurable"],
            })
        } else {
            json!({
                "type": "accessor",
                "hasGetter": !descriptor["getter"].is_null(),
                "hasSetter": !descriptor["setter"].is_null(),
                "enumerable": descriptor["enumerable"],
                "configurable": descriptor["configurable"],
            })
        };
        own.insert(name.clone(), shape);
    }
    json!({
        "declarativeRecord": declarative,
        "varDeclaredNames": fixture["final"]["varDeclaredNames"],
        "sessionCreatedVars": fixture["final"]["sessionCreatedVars"],
        "own": own,
    })
}

fn value_assertion(expression: &str, expected: &Value) -> String {
    if let Some(symbol) = expected.get("$sessionValue").and_then(Value::as_str) {
        return match symbol {
            "undefined" => format!("typeof ({expression}) === 'undefined'"),
            "function" | "class" | "builtin" => {
                format!("typeof ({expression}) === 'function'")
            }
            other => panic!("unsupported final value symbol {other}"),
        };
    }
    format!(
        "Object.is(({expression}), {})",
        serde_json::to_string(expected).expect("model value JSON")
    )
}

async fn assert_final_values(session: &mut HarnessSession, fixture: &Value) -> Result<()> {
    if fixture["id"] == "phase-five-recheck-prevents-partial-instantiation" {
        return Ok(());
    }
    for (name, cell) in fixture["final"]["declarativeRecord"]
        .as_object()
        .expect("declarative record")
    {
        if cell["initialized"] == true {
            let assertion = value_assertion(name, &cell["value"]);
            assert_value_evaluation(
                session,
                &assertion,
                &json!(true),
                &format!("{} cell {name}", fixture["id"]),
            )
            .await?;
        }
    }
    for (name, descriptor) in fixture["final"]["objectRecord"]["own"]
        .as_object()
        .expect("object record")
    {
        if name == "$_" || descriptor["type"] != "data" {
            continue;
        }
        let expression = format!("globalThis[{}]", serde_json::to_string(name)?);
        let assertion = value_assertion(&expression, &descriptor["value"]);
        assert_value_evaluation(
            session,
            &assertion,
            &json!(true),
            &format!("{} global {name}", fixture["id"]),
        )
        .await?;
    }
    let assertion = value_assertion("globalThis.$_", &fixture["final"]["lastValue"]["value"]);
    assert_value_evaluation(
        session,
        &assertion,
        &json!(true),
        &format!("{} last value", fixture["id"]),
    )
    .await?;
    match fixture["id"].as_str() {
        Some("bare-var-object-adopts-without-clobber") => {
            assert_value_evaluation(
                session,
                "Object === globalThis.__ibexObjectBefore",
                &json!(true),
                "bare var Object identity",
            )
            .await?;
        }
        Some("function-object-clobbers-without-creation-provenance") => {
            assert_value_evaluation(
                session,
                "Object !== globalThis.__ibexObjectBefore",
                &json!(true),
                "function Object identity",
            )
            .await?;
        }
        _ => {}
    }
    Ok(())
}

async fn run_gate_1_fixture(fixture: &Value) -> Result<()> {
    let id = fixture["id"].as_str().context("fixture id")?;
    let concrete_fixture = (id == "inherited-var-creates-own-property")
        .then(|| rename_model_name(fixture, "inheritedName", "toString"));
    let fixture = concrete_fixture.as_ref().unwrap_or(fixture);
    let mut session = HarnessSession::new(id).await?;
    if let Some(setup) = setup_source(id) {
        let evaluation = session.evaluate(setup).await?;
        if matches!(evaluation, AuthenticatedEvaluation::Throw(_)) {
            anyhow::bail!("{id}: initial realm setup threw: {evaluation:?}");
        }
        session.release(evaluation).await?;
    }

    let program = fixture["program"].as_array().context("fixture program")?;
    let events = fixture["events"].as_array().context("fixture events")?;
    assert_eq!(program.len(), events.len(), "{id}: model event cardinality");
    let mut input_index = 0usize;
    for (action_index, (action, event)) in program.iter().zip(events).enumerate() {
        let label = format!("{id} action {action_index}");
        match action["type"].as_str().context("action type")? {
            "input" => {
                let source = input_source(id, input_index);
                input_index += 1;
                assert_evaluation(&mut session, source, &event["result"], &label).await?;
            }
            "read" => {
                let name = action["name"].as_str().context("read name")?;
                assert_value_evaluation(&mut session, name, &event["value"], &label).await?;
            }
            "typeof" => {
                let name = action["name"].as_str().context("typeof name")?;
                assert_value_evaluation(
                    &mut session,
                    &format!("typeof {name}"),
                    &event["value"],
                    &label,
                )
                .await?;
            }
            "assign" => {
                let name = action["name"].as_str().context("assign name")?;
                let source = format!("{name} = {}", serde_json::to_string(&action["value"])?);
                assert_value_evaluation(&mut session, &source, &event["value"], &label).await?;
            }
            "delete-global" => {
                let name = action["name"].as_str().context("delete name")?;
                let source = format!("delete globalThis[{}]", serde_json::to_string(name)?);
                assert_value_evaluation(&mut session, &source, &event["deleted"], &label).await?;
            }
            "display-ack" => {
                let source = serde_json::to_string(&action["value"])?;
                let evaluation = session.evaluate(&source).await?;
                let receipt = match evaluation {
                    AuthenticatedEvaluation::Value {
                        receipt: Some(receipt),
                        ..
                    } => receipt,
                    other => panic!("{label}: display ACK source returned {other:?}"),
                };
                let disposition = match action["disposition"].as_str() {
                    Some("displayed") => DisplayDisposition::Displayed,
                    Some("fallback") => DisplayDisposition::Fallback,
                    other => panic!("{label}: unsupported display disposition {other:?}"),
                };
                session
                    .engine
                    .acknowledge_display(receipt, disposition)
                    .await?;
            }
            other => panic!("{label}: unsupported concrete action {other}"),
        }
    }

    let names = requested_names(fixture);
    let actual = session.metadata(&names).await?;
    let expected = expected_metadata(fixture, &names);
    assert_eq!(actual, expected, "{id}: final metadata/provenance");
    assert_final_values(&mut session, fixture).await
}

async fn run_gate_1() -> Result<()> {
    {
        let mut accessor_session = HarnessSession::new("last-value-accessor-shape").await?;
        let initial = accessor_session.evaluate("void 0").await?;
        accessor_session.release(initial).await?;
        let accessor_metadata = accessor_session.metadata(&["$_".to_owned()]).await?;
        assert_eq!(
            accessor_metadata["own"]["$_"],
            json!({
                "type": "accessor",
                "hasGetter": true,
                "hasSetter": true,
                "enumerable": false,
                "configurable": true,
            }),
            "runtime-owned $_ accessor shape"
        );
    }

    let document: Value = serde_json::from_str(GENERATED_FIXTURES)?;
    let fixtures = document["fixtures"]
        .as_array()
        .context("generated fixtures")?;
    assert_eq!(
        fixtures.len(),
        23,
        "Gate 1 fixture corpus changed; add concrete adapters"
    );
    for fixture in fixtures {
        let id = fixture["id"].as_str().unwrap_or("<missing-id>");
        run_gate_1_fixture(fixture)
            .await
            .with_context(|| format!("Gate 1 fixture {id}"))?;
    }
    Ok(())
}

fn gate_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("packages/ibex-devtools/src/scripts/session-semantics-engine-gates.mjs")
}

fn node_gate_output(argument: &str) -> Result<Value> {
    let output = Command::new("node")
        .arg(gate_script())
        .arg(argument)
        .output()
        .with_context(|| format!("failed to execute Node gate adapter {argument}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "Node gate adapter {argument} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("Node gate adapter returned invalid JSON")
}

async fn run_gate_2() -> Result<()> {
    let cases = node_gate_output("--emit-restricted")?;
    for case in cases.as_array().context("restricted engine cases")? {
        let id = case["id"].as_str().context("restricted case id")?;
        let mut session = HarnessSession::new(id).await?;
        assert_evaluation(
            &mut session,
            case["growingSource"].as_str().context("growing source")?,
            &json!({
                "outcome": "success",
                "completion": match case["expectedCompletion"]["outcome"].as_str() {
                    Some("empty") => json!({ "$sessionValue": "empty" }),
                    Some("value") => case["expectedCompletion"].get("value")
                        .cloned()
                        .unwrap_or_else(|| json!({ "$sessionValue": case["expectedCompletion"]["symbolic"] })),
                    other => panic!("{id}: unsupported model completion {other:?}"),
                }
            }),
            id,
        )
        .await?;
        let names = case["requestedOwnNames"]
            .as_array()
            .context("requested own names")?
            .iter()
            .map(|value| value.as_str().expect("name").to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            session.metadata(&names).await?,
            case["expectedMetadata"],
            "{id}: growing Script differs from the reference model"
        );
    }
    Ok(())
}

async fn direct_hermes_completion(source: &str) -> Result<String> {
    let project = tempfile::tempdir()?;
    let file = project.path().join("audit.js");
    std::fs::write(&file, "void 0;\n")?;
    let cli = Cli::try_parse_from([
        "ibex",
        "capsec",
        "audit",
        file.to_str().context("audit path is not UTF-8")?,
    ])?;
    let runtime = Runtime::from_audit_cli(&cli)?;
    runtime.load_runtime().await?;
    runtime
        .engine()
        .eval_immediate(source)
        .await?
        .context("direct Hermes evaluation returned no completion")
}

async fn run_gate_3() -> Result<()> {
    const CASES: &[(&str, &str)] = &[
        ("compound-assignment", "let g3x = 1; g3x += 2; g3x;"),
        (
            "destructuring-order",
            "let g3order = 0; let [g3a, g3b] = [++g3order, ++g3order]; g3a * 100 + g3b * 10 + g3order;",
        ),
        (
            "for-of-completion",
            "let g3sum = 0; for (const g3value of [1, 2, 3]) { g3sum += g3value; } g3sum;",
        ),
        (
            "class-mutable-cell",
            "class Gate3Class {}; Gate3Class = 'replacement'; Gate3Class === 'replacement';",
        ),
        (
            "update-expression",
            "let g3counter = 4; let g3before = g3counter++; g3before * 10 + g3counter;",
        ),
    ];
    for (id, source) in CASES {
        let direct = direct_hermes_completion(source).await?;
        let mut lowered = HarnessSession::new(id).await?;
        let evaluation = lowered.evaluate(source).await?;
        let display = match &evaluation {
            AuthenticatedEvaluation::Value { display, .. } => display,
            other => panic!("{id}: one-input lowering returned {other:?}"),
        };
        assert_eq!(display.text, direct, "{id}: lowered vs direct completion");
        lowered.release(evaluation).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn implementation_matches_reference_model_gate() -> Result<()> {
    run_gate_1().await
}

#[tokio::test(flavor = "current_thread")]
async fn reference_model_matches_same_engine_growing_script_gate() -> Result<()> {
    run_gate_2().await
}

#[tokio::test(flavor = "current_thread")]
async fn single_input_lowering_fidelity_gate() -> Result<()> {
    run_gate_3().await
}

#[tokio::test(flavor = "current_thread")]
async fn suspended_top_level_await_resumes_without_assimilating_completion() -> Result<()> {
    let mut session = HarnessSession::new("suspended-top-level-await").await?;

    assert_value_evaluation(
        &mut session,
        "await new Promise((resolve) => setTimeout(resolve, 5)); 42",
        &serde_json::json!(42),
        "timer-backed top-level await",
    )
    .await?;

    let rejected = session
        .evaluate("await new Promise((_, reject) => setTimeout(() => reject('late-rejection'), 5))")
        .await?;
    assert!(
        matches!(rejected, AuthenticatedEvaluation::Throw(_)),
        "a rejected TLA settlement must be the evaluation's throw outcome"
    );
    session.release(rejected).await?;

    let thenable = session
        .evaluate("await 0; ({ then() { globalThis.__ibexAssimilated = true; } })")
        .await?;
    assert!(
        matches!(
            &thenable,
            AuthenticatedEvaluation::Value { display, .. }
                if display.kind == AuthenticatedDisplayKind::Object
                    && display.text == "[Object]"
        ),
        "thenable completion must remain an ordinary object value: {thenable:?}"
    );
    session.release(thenable).await?;
    assert_value_evaluation(
        &mut session,
        "typeof globalThis.__ibexAssimilated",
        &serde_json::json!("undefined"),
        "completion thenable was not assimilated",
    )
    .await
}

#[test]
fn standards_engine_fresh_realm_gate() -> Result<()> {
    let output = node_gate_output("--run-standards")?;
    assert_eq!(output["freshRealm"], "node-subprocess-per-probe");
    assert_eq!(output["observed"].as_array().map(Vec::len), Some(7));
    Ok(())
}
