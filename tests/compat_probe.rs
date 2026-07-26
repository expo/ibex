//! End-to-end tests for `ibex compat --probe` (the Exact LLP 0404 N-1
//! fault-localization harness; issues/20260726-compat-probe-harness.md),
//! driving the real binary like tests/cli_eval.rs does.
//!
//! The harness evaluates one JS expression at each observation point of the
//! serving path — `rawEngine` (the pinned standalone `hermes` binary, no
//! bootstrap) and `postBootstrap` (a fresh runtime after prelude/polyfills/
//! intrinsics lockdown) today; `moduleRecord` / `packagedHbc` are reported as
//! `null` until they land — and emits one JSON tuple naming the first edge
//! where behavior diverges.
//!
//! The rawEngine point needs a standalone Hermes binary. Resolution mirrors
//! the conformance runners (`IBEX_HERMES_BIN`, then a checkout-local
//! `tools/hermes/hermes`); like tests/hermes_compat_conformance.rs, machines
//! without one skip the probe assertions instead of failing a fresh clone
//! (tools/hermes is git-ignored).
//!
//! Run with: `scripts/run-tests.sh --scope test compat_probe` (or
//! `cargo test --test compat_probe`).

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

/// A probe boots a full runtime for the postBootstrap point; give it the same
/// cold-binary headroom as the diagnostic evaluations in tests/cli_eval.rs.
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);

/// Standalone Hermes resolution for the rawEngine point, mirroring
/// `run-hermes-compat-corpus.mjs::resolveHermesBin` (env override first, then
/// the checkout-local git-ignored tools/hermes).
fn raw_hermes_available() -> bool {
    if let Ok(overridden) = std::env::var("IBEX_HERMES_BIN") {
        return Path::new(&overridden).is_file();
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tools")
        .join("hermes")
        .join("hermes")
        .is_file()
}

async fn run_probe(expr: &str) -> Value {
    let mut cmd = Command::new(IBEX);
    cmd.arg("compat").arg("--probe").arg(expr);
    let output = timeout(PROBE_TIMEOUT, cmd.output())
        .await
        .expect("ibex compat --probe timed out")
        .expect("failed to spawn ibex compat --probe");
    assert!(
        output.status.success(),
        "ibex compat --probe {expr:?} failed (exit {:?}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("probe stdout is not one JSON document ({err}):\n{stdout}"))
}

/// An identical result at every measured point must report no divergence, and
/// the deferred points must be present as JSON null (the forward-compatible
/// shape the ticket pins).
#[tokio::test]
async fn trivially_identical_probe_reports_no_divergence() {
    if !raw_hermes_available() {
        eprintln!(
            "skipping: no standalone hermes (IBEX_HERMES_BIN / tools/hermes) on this machine"
        );
        return;
    }
    let report = run_probe("1+1").await;

    assert_eq!(report["probe"], "1+1", "{report}");
    assert_eq!(report["points"]["rawEngine"]["value"], 2, "{report}");
    assert_eq!(report["points"]["postBootstrap"]["value"], 2, "{report}");
    assert_eq!(report["points"]["moduleRecord"], Value::Null, "{report}");
    assert_eq!(report["points"]["packagedHbc"], Value::Null, "{report}");
    assert_eq!(report["firstDivergence"], Value::Null, "{report}");
}

/// The motivating P0 (Error.prototype.name under lockdown): the raw engine is
/// spec-correct (writable/configurable data property), while the bootstrap's
/// lockdown converts it into the SES override-enabled accessor — so the probe
/// must localize the change to the rawEngine->postBootstrap edge. JSON
/// serialization drops the accessor's get/set functions, leaving the
/// enumerable/configurable shape, which is exactly the observable divergence.
#[tokio::test]
async fn error_prototype_name_descriptor_diverges_at_bootstrap_edge() {
    if !raw_hermes_available() {
        eprintln!(
            "skipping: no standalone hermes (IBEX_HERMES_BIN / tools/hermes) on this machine"
        );
        return;
    }
    let report = run_probe("Object.getOwnPropertyDescriptor(Error.prototype,'name')").await;

    let raw = &report["points"]["rawEngine"]["value"];
    assert_eq!(raw["value"], "Error", "{report}");
    assert_eq!(raw["writable"], true, "{report}");
    assert_eq!(raw["configurable"], true, "{report}");

    let bootstrapped = &report["points"]["postBootstrap"]["value"];
    assert!(
        bootstrapped.get("writable").is_none(),
        "post-bootstrap descriptor must be an accessor (no writable field): {report}"
    );
    assert_eq!(bootstrapped["configurable"], false, "{report}");

    assert_eq!(
        report["firstDivergence"], "rawEngine->postBootstrap",
        "{report}"
    );
}

/// Thrown probe results are measurements, not harness failures: both points
/// capture them as {"error": {name, message}} and identical errors do not
/// diverge.
#[tokio::test]
async fn thrown_probe_errors_are_captured_not_fatal() {
    if !raw_hermes_available() {
        eprintln!(
            "skipping: no standalone hermes (IBEX_HERMES_BIN / tools/hermes) on this machine"
        );
        return;
    }
    let report = run_probe("null.missing").await;

    for point in ["rawEngine", "postBootstrap"] {
        assert_eq!(
            report["points"][point]["error"]["name"], "TypeError",
            "{point}: {report}"
        );
        assert!(
            report["points"][point]["error"]["message"].is_string(),
            "{point}: {report}"
        );
    }
    assert_eq!(report["firstDivergence"], Value::Null, "{report}");
}
