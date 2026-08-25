//! LLP 0056 slice 3: real package-aware C-ABI startup over authenticated
//! JavaScript factory carriers. The fixture is self-contained so this suite
//! never depends on an Exact checkout or an environment variable.

#![cfg(all(feature = "dev-committed-embedder", feature = "sfe-dev-spike"))]

use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

use ibex_runtime::engine::module_runner::DiagnosticModuleRuntime;
use ibex_runtime::module_loader::artifact::digest_bytes;
use ibex_runtime::module_loader::composition::{
    compute_alias_import_site_inventory_digest, AliasImportSiteV1, PREPARED_ALIAS_TABLE_DOMAIN_V1,
    PREPARED_COMPOSITION_ROOT_DOMAIN_V1,
};
use ibex_runtime::module_loader::identity::SourceId;
use ibex_runtime::module_loader::runner_pipeline::dev_committed_embedder::{
    ibex_dev_unarmed_composition_prepared_startup_v1, resolve_retained_composition_id_v1,
};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/prepared-composition/v1/runtime-composition")
}

fn copy_fixture_tree(source: &Path, target: &Path) {
    std::fs::create_dir_all(target).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_fixture_tree(&entry.path(), &destination);
        } else {
            std::fs::copy(entry.path(), destination).unwrap();
        }
    }
}

fn fixture_with_computed_bootstrap_alias() -> (tempfile::TempDir, String, SourceId) {
    let directory = tempfile::tempdir().unwrap();
    copy_fixture_tree(&fixture_dir(), directory.path());
    let composition_path = directory.path().join("composition.json");
    let mut composition: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&composition_path).unwrap()).unwrap();
    let representative_wire = composition["entryPlan"]["entries"][0]["root"]
        .as_str()
        .unwrap()
        .to_owned();
    let representative = SourceId::decode(&representative_wire).unwrap();
    let agent_index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.path().join("packages/agent/index.json")).unwrap(),
    )
    .unwrap();
    let representative_integrity = agent_index["records"][0]["artifact"]["semantics"]
        ["sourceIntegrity"]
        .as_str()
        .unwrap();
    let alias = "/@fs/repo/src/computed-bootstrap.ts?v=0056&t=7&import".to_owned();
    let rows = serde_json::json!([{
        "aliasId": alias.clone(),
        "representativeSourceId": representative_wire,
        "representativeSourceIntegrity": representative_integrity,
        "importSiteInventoryDigest": compute_alias_import_site_inventory_digest(
            &Vec::<AliasImportSiteV1>::new(),
        )
        .unwrap(),
    }]);
    let alias_bytes = capsec_semantics::canonical::to_jcs_bytes(&rows).unwrap();
    composition["aliasTable"] = serde_json::json!({
        "digest": digest_bytes(PREPARED_ALIAS_TABLE_DOMAIN_V1, &alias_bytes).unwrap(),
        "rows": rows,
    });
    let composition_bytes = capsec_semantics::canonical::to_jcs_bytes(&composition).unwrap();
    std::fs::write(&composition_path, &composition_bytes).unwrap();

    let commitment_path = directory.path().join("commitment.json");
    let mut commitment: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&commitment_path).unwrap()).unwrap();
    commitment["compositionRootDigest"] = serde_json::to_value(
        digest_bytes(PREPARED_COMPOSITION_ROOT_DOMAIN_V1, &composition_bytes).unwrap(),
    )
    .unwrap();
    std::fs::write(
        commitment_path,
        capsec_semantics::canonical::to_jcs_bytes(&commitment).unwrap(),
    )
    .unwrap();
    (directory, alias, representative)
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
    let (fixture, computed_alias, alias_representative) = fixture_with_computed_bootstrap_alias();
    let root = fixture.path().to_owned();
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
    assert_eq!(
        resolve_retained_composition_id_v1(raw, nonce, &computed_alias),
        Some(alias_representative),
        "the §3.4 C startup must publish an alias-aware host bridge session"
    );
}
