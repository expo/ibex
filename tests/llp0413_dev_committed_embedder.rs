//! Exact LLP 0413 Phase 2: dev-unarmed committed embedder — admission +
//! REAL native module-runner evaluation of an Exact adapter-1 prepared
//! publication (compat-loader factory ABI, `exact-compat-loader-cjs-8`)
//! through `ibex_dev_unarmed_committed_prepared_startup_v1`.
//!
//! Gated on `EXACT_LLP0413_DEV_COMMITTED_FIXTURE_DIR` — a directory produced
//! by the Exact repo's `scripts/produce-dev-committed-fixture.mjs`
//! containing `publication/`, `commitment.json`, and a fully
//! self-consistent `sibling-publication/` for the substitution probe. Skips
//! silently when unset so ibex CI is unaffected. Requires features
//! `dev-committed-embedder,sfe-dev-spike` (the second only for the
//! diagnostic runtime owner + probe eval used by this harness).
//!
//! What this proves, beyond the Phase 1 admission harnesses:
//! 1. the compat-loader 8-parameter factory ABI is POSITIONALLY compatible
//!    with the native CommonJS record invocation (require/module/exports/
//!    __filename/__dirname/dynamicImport) — the entry executes and its
//!    static import wiring observably ran;
//! 2. a literal dynamic `import()` lowered to `__exactDynamicImport(...)`
//!    resolves through the record-level dynamic-import binding and settles
//!    on the native event loop;
//! 3. the §5.4 phase split: a self-consistent substituted publication and a
//!    tampered commitment refuse with exit code 1 (pre-evaluation, fallback
//!    lane permitted), never 2;
//! 4. the receipt names the non-production authority and the LLP 0043
//!    interim fingerprint posture.

#![cfg(all(feature = "dev-committed-embedder", feature = "sfe-dev-spike"))]

use std::ffi::CString;
use std::path::PathBuf;

use ibex_runtime::engine::module_runner::DiagnosticModuleRuntime;
use ibex_runtime::module_loader::runner_pipeline::dev_committed_embedder::ibex_dev_unarmed_committed_prepared_startup_v1;

fn fixture_dir() -> Option<PathBuf> {
    std::env::var_os("EXACT_LLP0413_DEV_COMMITTED_FIXTURE_DIR").map(PathBuf::from)
}

struct StartupOutcome {
    status: i32,
    report: Option<serde_json::Value>,
    error: Option<String>,
}

fn run_startup(
    runtime: &DiagnosticModuleRuntime,
    publication_dir: &std::path::Path,
    commitment_text: &str,
    expected_target: &str,
) -> StartupOutcome {
    let (raw, nonce) = runtime.raw_parts();
    let publication_dir = CString::new(publication_dir.to_str().unwrap()).unwrap();
    let commitment = CString::new(commitment_text).unwrap();
    let target = CString::new(expected_target).unwrap();
    let project_root = CString::new("/exact-dev-fixture-project").unwrap();
    let mut out_report: *mut std::ffi::c_char = std::ptr::null_mut();
    let mut out_error: *mut std::ffi::c_char = std::ptr::null_mut();
    let status = unsafe {
        ibex_dev_unarmed_committed_prepared_startup_v1(
            raw.as_ptr(),
            nonce,
            publication_dir.as_ptr(),
            commitment.as_ptr(),
            target.as_ptr(),
            project_root.as_ptr(),
            &mut out_report,
            &mut out_error,
        )
    };
    let take = |pointer: *mut std::ffi::c_char| -> Option<String> {
        if pointer.is_null() {
            return None;
        }
        let text = unsafe { std::ffi::CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned();
        ibex_runtime::host::abi::ex_host_free_string(pointer);
        Some(text)
    };
    StartupOutcome {
        status,
        report: take(out_report).map(|text| serde_json::from_str(&text).expect("report is JSON")),
        error: take(out_error),
    }
}

#[test]
fn dev_unarmed_committed_startup_evaluates_compat_abi_factories() {
    let Some(root) = fixture_dir() else {
        eprintln!(
            "llp0413_dev_committed_embedder: skipped (EXACT_LLP0413_DEV_COMMITTED_FIXTURE_DIR \
             unset; produce with Exact scripts/produce-dev-committed-fixture.mjs)"
        );
        return;
    };
    let commitment_text = std::fs::read_to_string(root.join("commitment.json")).unwrap();

    ibex_runtime::host::abi::install_host(ibex_runtime::host::Host::strict());
    let mut runtime = DiagnosticModuleRuntime::new().unwrap();

    // 1+2: admission + evaluation succeed on the genuine publication.
    let outcome = run_startup(
        &runtime,
        &root.join("publication"),
        &commitment_text,
        "exact-dev:test",
    );
    assert_eq!(
        outcome.status, 0,
        "dev committed startup failed: {:?}",
        outcome.error
    );
    let report = outcome.report.expect("success carries a report");
    assert_eq!(
        report["authority"],
        "dev-unarmed-dev-served (non-production)"
    );
    assert_eq!(report["posture"], "dev-unarmed");
    assert_eq!(report["nonProduction"], true);
    assert!(report["fingerprintPosture"]
        .as_str()
        .unwrap()
        .contains("LLP 0043 pending"));
    assert_eq!(report["carrierCount"], 1);
    assert_eq!(report["recordCount"], 3);
    assert_eq!(report["principalCount"], 1);

    // Static import wiring ran during entry execution (compat ABI positions
    // 1-5 bind require/module/exports/__filename/__dirname).
    let probe = runtime
        .eval_text(
            "JSON.stringify(globalThis.__devCommittedProbe || null)",
            "llp0413-dev-committed-probe",
        )
        .unwrap();
    let probe: serde_json::Value = serde_json::from_str(probe.trim()).unwrap();
    assert_eq!(probe["sum"], 5, "static import result: {probe}");

    // Microtask canary: plain promise chains settle under the drive loop.
    runtime
        .eval_text(
            "Promise.resolve(41).then((v) => { globalThis.__microCanary = v + 1; }); ''",
            "llp0413-micro-canary",
        )
        .unwrap();
    runtime.drive_compiled_event_loop_to_quiescence().unwrap();
    let canary = runtime
        .eval_text("String(globalThis.__microCanary)", "llp0413-micro-canary-read")
        .unwrap();
    assert_eq!(canary.trim(), "42", "microtask canary did not settle");

    // Literal dynamic import (lowered to __exactDynamicImport, bound
    // positionally to the native dynamicImport) settles on the event loop.
    runtime.drive_compiled_event_loop_to_quiescence().unwrap();
    let mut probe = serde_json::Value::Null;
    for _ in 0..5 {
        runtime.drive_compiled_event_loop_to_quiescence().unwrap();
        let text = runtime
            .eval_text(
                "JSON.stringify(globalThis.__devCommittedProbe || null)",
                "llp0413-dev-committed-probe-2",
            )
            .unwrap();
        probe = serde_json::from_str(text.trim()).unwrap();
        if probe["lazy"] == 7 || !probe["lazyError"].is_null() {
            break;
        }
    }
    assert_eq!(probe["lazy"], 7, "dynamic import result: {probe}");

    // 3a: a fully self-consistent SIBLING publication refuses at the
    // commitment root check, pre-evaluation (status 1, never 2), on a fresh
    // runtime (the evaluated app owns the first one).
    let sibling_runtime = DiagnosticModuleRuntime::new().unwrap();
    let outcome = run_startup(
        &sibling_runtime,
        &root.join("sibling-publication"),
        &commitment_text,
        "exact-dev:test",
    );
    assert_eq!(outcome.status, 1, "substitution must refuse pre-evaluation");
    let error = outcome.error.unwrap();
    assert!(
        error.contains("IBEX_PREPARED_COMMITMENT_MISMATCH"),
        "substitution refusal must name commitment mismatch, got: {error}"
    );

    // 3b: a tampered commitment byte refuses as non-canonical/corrupt,
    // pre-evaluation.
    let tampered = commitment_text.replacen("production", "productioN", 1);
    let outcome = run_startup(
        &sibling_runtime,
        &root.join("publication"),
        &tampered,
        "exact-dev:test",
    );
    assert_eq!(outcome.status, 1);
    assert!(outcome.error.unwrap().contains("IBEX_DEV_COMMITTED"));

    // 3c: a target mismatch refuses pre-evaluation with the typed code.
    let outcome = run_startup(
        &sibling_runtime,
        &root.join("publication"),
        &commitment_text,
        "exact-dev:other-target",
    );
    assert_eq!(outcome.status, 1);
    assert!(outcome
        .error
        .unwrap()
        .contains("IBEX_DEV_COMMITTED_TARGET"));
}
