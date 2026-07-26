//! `ibex compat --probe '<expr>'` — executable multi-point fault localization
//! for engine-attributed incompatibilities (Exact LLP 0404 N-1; filed as
//! issues/20260726-compat-probe-harness.md).
//!
//! Runs one probe expression at each observation point of the serving path and
//! emits a single JSON measurement tuple naming the first edge where behavior
//! diverges. The points, in serving order:
//!
//!   1. `rawEngine` — the pinned standalone `hermes` binary with no ibex
//!      bootstrap at all (resolution mirrors the conformance runners:
//!      `IBEX_HERMES_BIN`, then a checkout-local `tools/hermes/hermes`, then
//!      the exact monorepo's copy when ibex is vendored at `vendor/ibex`).
//!   2. `postBootstrap` — a fresh in-process `HermesEngine` after
//!      `load_runtime()` (prelude, polyfills, intrinsics lockdown) — the same
//!      surface the engine-level lockdown regression tests observe.
//!   3. `moduleRecord` — the served app-module record. Not implemented yet;
//!      always `null` (absent) so the report shape is forward-compatible.
//!   4. `packagedHbc` — packaged bytecode delivery. Not implemented yet;
//!      always `null`.
//!
//! The probe is a JS expression. Its completion value is JSON-serialized
//! (`undefined` normalizes to `null`); a thrown value is captured as
//! `{"error": {"name", "message"}}`. A failure of the harness itself at one
//! point (missing binary is fatal instead; nonzero engine exit, timeout,
//! unparseable output) is recorded as `{"error": {"name": "EngineFailure"}}`
//! so the tuple stays comparable. Divergence is deep JSON inequality between
//! consecutive *measured* points; absent (null) points are skipped, so the
//! first edge is named over the points actually observed.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{json, Value};

/// Observation points in serving order. The order is the measurement contract:
/// `firstDivergence` edges are named over consecutive measured points.
const POINT_ORDER: [&str; 4] = ["rawEngine", "postBootstrap", "moduleRecord", "packagedHbc"];

/// Default per-point evaluation timeout when `--timeout` is not given.
/// Matches the conformance runners' standalone-Hermes spawn bound rather than
/// the suite's per-test default (a probe boots a full runtime for the
/// post-bootstrap point).
const DEFAULT_PROBE_TIMEOUT_MS: u64 = 30_000;

/// Entry point for `ibex compat --probe`.
pub async fn run_probe(probe: &str, timeout_override_ms: Option<u64>) -> Result<()> {
    let timeout = Duration::from_millis(timeout_override_ms.unwrap_or(DEFAULT_PROBE_TIMEOUT_MS));

    let raw_engine = run_raw_engine_point(probe, timeout).await?;
    let post_bootstrap = run_post_bootstrap_point(probe, timeout).await?;

    let points = vec![
        ("rawEngine", Some(raw_engine)),
        ("postBootstrap", Some(post_bootstrap)),
        ("moduleRecord", None),
        ("packagedHbc", None),
    ];
    let report = build_report(probe, points);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

/// Assemble the measurement tuple. `points` must follow [`POINT_ORDER`];
/// unmeasured points are `None` and serialize as JSON `null`.
fn build_report(probe: &str, points: Vec<(&'static str, Option<Value>)>) -> Value {
    debug_assert_eq!(
        points.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        POINT_ORDER
    );
    let first_divergence = first_divergence(&points);
    let mut point_map = serde_json::Map::new();
    for (name, value) in points {
        point_map.insert(name.to_string(), value.unwrap_or(Value::Null));
    }
    json!({
        "probe": probe,
        "points": Value::Object(point_map),
        "firstDivergence": first_divergence,
    })
}

/// Name the first edge between consecutive *measured* points whose serialized
/// results are deep-unequal, as `"<from>-><to>"`. Absent points (`None`) are
/// skipped: with only two measured points the only nameable edge is between
/// them, and when the later points land they join the same walk without a
/// shape change.
fn first_divergence(points: &[(&'static str, Option<Value>)]) -> Option<String> {
    let measured: Vec<(&str, &Value)> = points
        .iter()
        .filter_map(|(name, value)| value.as_ref().map(|v| (*name, v)))
        .collect();
    measured.windows(2).find_map(|pair| {
        let (from_name, from_value) = pair[0];
        let (to_name, to_value) = pair[1];
        (from_value != to_value).then(|| format!("{from_name}->{to_name}"))
    })
}

/// Wrap the probe expression so every point yields one JSON document with the
/// same shape: `{"value": <completion>}` or `{"error": {"name", "message"}}`.
/// The wrapper is shared by all points — the observation must vary only in
/// the environment, never in the harness code around the expression.
fn probe_wrapper_expression(probe: &str) -> String {
    format!(
        r#"(function () {{
  "use strict";
  var __out;
  try {{
    var __value = (
{probe}
    );
    __out = {{ value: __value === undefined ? null : __value }};
  }} catch (__error) {{
    __out = {{ error: {{
      name: __error && __error.name !== undefined ? String(__error.name) : "Error",
      message: __error && __error.message !== undefined ? String(__error.message) : String(__error)
    }} }};
  }}
  try {{
    var __json = JSON.stringify(__out);
    if (__json === undefined) {{
      return JSON.stringify({{ error: {{ name: "SerializationError", message: "probe result is not JSON-serializable" }} }});
    }}
    return __json;
  }} catch (__serializeError) {{
    return JSON.stringify({{ error: {{ name: "SerializationError", message: String(__serializeError) }} }});
  }}
}})()"#
    )
}

/// A harness-level failure at one observation point (the engine crashed, timed
/// out, or produced unparseable output), normalized into the same result shape
/// so the tuple stays comparable.
fn engine_failure(message: impl std::fmt::Display) -> Value {
    json!({ "error": { "name": "EngineFailure", "message": message.to_string() } })
}

fn parse_point_output(raw: &str) -> Value {
    match serde_json::from_str::<Value>(raw.trim()) {
        Ok(value) => value,
        Err(err) => engine_failure(format!(
            "probe wrapper produced unparseable output ({err}): {raw}"
        )),
    }
}

/// Resolve the pinned standalone `hermes` binary, mirroring the conformance
/// runners (`run-hermes-compat-corpus.mjs::resolveHermesBin`): the
/// `IBEX_HERMES_BIN` override wins, then a checkout-local
/// `tools/hermes/hermes` found by walking up from the executable and the cwd
/// (which also covers the exact monorepo's `tools/hermes` when ibex is
/// vendored at `<exact>/vendor/ibex`).
fn resolve_raw_hermes_binary() -> Option<PathBuf> {
    if let Some(overridden) = std::env::var_os("IBEX_HERMES_BIN") {
        let path = PathBuf::from(overridden);
        if path.is_file() {
            return Some(path);
        }
        return None;
    }

    let mut starts: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            starts.push(dir.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        starts.push(cwd);
    }
    for start in starts {
        let mut current = start;
        loop {
            let candidate = current.join("tools").join("hermes").join("hermes");
            if candidate.is_file() {
                return Some(candidate);
            }
            if !current.pop() {
                break;
            }
        }
    }
    None
}

/// Point 1: the pinned `hermes` binary with no bootstrap. The wrapper's JSON
/// string is emitted through Hermes's own `print`, the only output channel a
/// raw engine has. `-Xes6-block-scoping` matches the engine configuration the
/// conformance corpus pins (`IBEX_LEGACY_HERMES_BLOCK_SCOPING` opts out, same
/// as there).
async fn run_raw_engine_point(probe: &str, timeout: Duration) -> Result<Value> {
    let hermes = resolve_raw_hermes_binary().context(
        "no raw hermes binary available: set IBEX_HERMES_BIN or build/install \
         tools/hermes (scripts/download-hermes.sh); the rawEngine observation \
         point cannot be measured without it",
    )?;

    let dir = tempfile::tempdir().context("create raw-engine probe tempdir")?;
    let fixture = dir.path().join("probe.js");
    std::fs::write(
        &fixture,
        format!("print({});\n", probe_wrapper_expression(probe)),
    )
    .context("write raw-engine probe fixture")?;

    let legacy_block_scoping = std::env::var("IBEX_LEGACY_HERMES_BLOCK_SCOPING")
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    let mut cmd = tokio::process::Command::new(&hermes);
    if !legacy_block_scoping {
        cmd.arg("-Xes6-block-scoping");
    }
    cmd.arg(&fixture);
    cmd.stdin(std::process::Stdio::null());

    let output = match tokio::time::timeout(timeout, cmd.output()).await {
        Err(_) => {
            return Ok(engine_failure(format!(
                "raw engine probe timed out after {} ms",
                timeout.as_millis()
            )))
        }
        Ok(spawned) => spawned.with_context(|| format!("failed to spawn {}", hermes.display()))?,
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(engine_failure(format!(
            "hermes exited with {:?}: {}",
            output.status.code(),
            stderr.trim()
        )));
    }
    Ok(parse_point_output(&String::from_utf8_lossy(&output.stdout)))
}

/// Point 2: a fresh in-process runtime after the full engine bootstrap
/// (prelude, polyfills, intrinsics lockdown) — `load_runtime()`, the same
/// surface the lockdown regression tests observe
/// (`lockdown_enables_error_prototype_overrides`). Engine construction
/// mirrors the explicit foreground diagnostic posture (`ibex capsec audit`,
/// `Runtime::from_audit_cli`): an Audit-mode host plus an unarmed engine is
/// the sanctioned way to boot a fresh runtime outside an authenticated
/// session, and it does not widen production startup because this process is
/// already in the named harness posture.
async fn run_post_bootstrap_point(probe: &str, timeout: Duration) -> Result<Value> {
    let host = crate::host::Host::new(crate::host::HostConfig {
        mode: crate::host::SecurityMode::Audit,
        ..Default::default()
    });
    crate::host::abi::install_host(host);
    let engine =
        crate::engine::create_engine("hermes", None).context("create post-bootstrap engine")?;
    if let Err(err) = tokio::time::timeout(timeout, engine.load_runtime())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "runtime bootstrap timed out after {} ms",
                timeout.as_millis()
            )
        })
        .and_then(|loaded| loaded)
    {
        return Ok(engine_failure(format!("runtime bootstrap failed: {err}")));
    }

    let wrapper = probe_wrapper_expression(probe);
    match tokio::time::timeout(timeout, engine.eval_immediate(&wrapper)).await {
        Err(_) => Ok(engine_failure(format!(
            "post-bootstrap probe timed out after {} ms",
            timeout.as_millis()
        ))),
        Ok(Err(err)) => Ok(engine_failure(format!(
            "post-bootstrap evaluation failed: {err}"
        ))),
        Ok(Ok(None)) => Ok(engine_failure(
            "post-bootstrap evaluation produced no completion value",
        )),
        Ok(Ok(Some(raw))) => Ok(parse_point_output(&raw)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measured(value: Value) -> Option<Value> {
        Some(value)
    }

    #[test]
    fn identical_measured_points_report_no_divergence() {
        let points = vec![
            ("rawEngine", measured(json!({ "value": 2 }))),
            ("postBootstrap", measured(json!({ "value": 2 }))),
            ("moduleRecord", None),
            ("packagedHbc", None),
        ];
        assert_eq!(first_divergence(&points), None);
    }

    #[test]
    fn deep_unequal_points_name_the_first_edge() {
        let points = vec![
            (
                "rawEngine",
                measured(json!({ "value": { "writable": true, "configurable": true } })),
            ),
            (
                "postBootstrap",
                measured(json!({ "value": { "configurable": false } })),
            ),
            ("moduleRecord", None),
            ("packagedHbc", None),
        ];
        assert_eq!(
            first_divergence(&points).as_deref(),
            Some("rawEngine->postBootstrap")
        );
    }

    #[test]
    fn absent_points_are_skipped_when_naming_edges() {
        // Once moduleRecord lands, an edge can be named across an absent
        // neighbor is NOT the contract — the walk is over measured points
        // only, so a divergence introduced at the last measured point is
        // attributed to the last measured edge.
        let points = vec![
            ("rawEngine", measured(json!({ "value": 1 }))),
            ("postBootstrap", None),
            ("moduleRecord", measured(json!({ "value": 2 }))),
            ("packagedHbc", None),
        ];
        assert_eq!(
            first_divergence(&points).as_deref(),
            Some("rawEngine->moduleRecord")
        );
    }

    #[test]
    fn error_shapes_participate_in_divergence_like_values() {
        let points = vec![
            ("rawEngine", measured(json!({ "value": 1 }))),
            (
                "postBootstrap",
                measured(json!({ "error": { "name": "TypeError", "message": "nope" } })),
            ),
            ("moduleRecord", None),
            ("packagedHbc", None),
        ];
        assert_eq!(
            first_divergence(&points).as_deref(),
            Some("rawEngine->postBootstrap")
        );
    }

    #[test]
    fn later_edges_are_named_only_when_earlier_ones_agree() {
        let points = vec![
            ("rawEngine", measured(json!({ "value": 1 }))),
            ("postBootstrap", measured(json!({ "value": 1 }))),
            ("moduleRecord", measured(json!({ "value": 3 }))),
            ("packagedHbc", None),
        ];
        assert_eq!(
            first_divergence(&points).as_deref(),
            Some("postBootstrap->moduleRecord")
        );
    }

    #[test]
    fn report_shape_includes_absent_points_as_null() {
        let report = build_report(
            "1+1",
            vec![
                ("rawEngine", measured(json!({ "value": 2 }))),
                ("postBootstrap", measured(json!({ "value": 2 }))),
                ("moduleRecord", None),
                ("packagedHbc", None),
            ],
        );
        assert_eq!(report["probe"], "1+1");
        assert_eq!(report["points"]["rawEngine"], json!({ "value": 2 }));
        assert_eq!(report["points"]["postBootstrap"], json!({ "value": 2 }));
        assert_eq!(report["points"]["moduleRecord"], Value::Null);
        assert_eq!(report["points"]["packagedHbc"], Value::Null);
        assert_eq!(report["firstDivergence"], Value::Null);
    }

    #[test]
    fn wrapper_serializes_completion_and_errors() {
        // The wrapper must be valid on any engine; sanity-check the generated
        // source stays an expression (parenthesized IIFE) and interpolates
        // the probe verbatim.
        let wrapper = probe_wrapper_expression("Object.keys({a: 1})");
        assert!(wrapper.starts_with("(function ()"));
        assert!(wrapper.contains("Object.keys({a: 1})"));
        assert!(wrapper.trim_end().ends_with("})()"));
    }
}
