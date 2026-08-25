//! LLP 0056 slice 3: real package-aware C-ABI startup over authenticated
//! JavaScript factory carriers. The fixture is self-contained so this suite
//! never depends on an Exact checkout or an environment variable.

#![cfg(all(feature = "dev-committed-embedder", feature = "sfe-dev-spike"))]

use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

use ibex_runtime::engine::module_runner::DiagnosticModuleRuntime;
use ibex_runtime::module_loader::runner_pipeline::dev_committed_embedder::ibex_dev_unarmed_composition_prepared_startup_v1;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/prepared-composition/v1/runtime-composition")
}

fn take_string(pointer: *mut std::ffi::c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let text = unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    ibex_runtime::host::abi::ex_host_free_string(pointer);
    Some(text)
}

#[test]
fn composition_c_entry_evaluates_agent_invokes_bootstrap_then_evaluates_app() {
    ibex_runtime::host::abi::install_host(ibex_runtime::host::Host::strict());
    let root = fixture_dir();
    let commitment = std::fs::read_to_string(root.join("commitment.json")).unwrap();
    let expectations = std::fs::read_to_string(root.join("expectations.json")).unwrap();
    let mut runtime = DiagnosticModuleRuntime::new().unwrap();
    let (raw, nonce) = runtime.raw_parts();
    let root_c = CString::new(root.to_str().unwrap()).unwrap();
    let commitment_c = CString::new(commitment).unwrap();
    let expectations_c = CString::new(expectations).unwrap();
    let mut out_report = std::ptr::null_mut();
    let mut out_error = std::ptr::null_mut();

    let status = unsafe {
        ibex_dev_unarmed_composition_prepared_startup_v1(
            raw.as_ptr(),
            nonce,
            root_c.as_ptr(),
            commitment_c.as_ptr(),
            expectations_c.as_ptr(),
            root_c.as_ptr(),
            &mut out_report,
            &mut out_error,
        )
    };
    let error = take_string(out_error);
    assert_eq!(status, 0, "composition startup failed: {error:?}");
    let report: serde_json::Value =
        serde_json::from_str(&take_string(out_report).expect("success report")).unwrap();
    assert_eq!(report["admissionStatus"], "admitted");
    assert_eq!(report["agentEvaluatedRecordCount"], 2);
    assert_eq!(report["appEvaluatedRecordCount"], 1);
    assert_eq!(report["sharedEvaluatedRecordCount"], 1);
    assert_eq!(report["agentInvokeReturnedThenable"], false);
    assert!(report["packages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|package| package["verificationStatus"] == "verified"));

    let probe = runtime
        .eval_text(
            "JSON.stringify({order:globalThis.__compositionOrder,agentMain:globalThis.__compositionAgentMain,appMain:globalThis.__compositionAppMain})",
            "llp0056-composition-integration-probe",
        )
        .unwrap();
    let probe: serde_json::Value = serde_json::from_str(probe.trim()).unwrap();
    assert_eq!(
        probe["order"],
        serde_json::json!(["lib", "agent", "invoke", "app"])
    );
    assert_eq!(probe["agentMain"], false);
    assert_eq!(probe["appMain"], true);
}
