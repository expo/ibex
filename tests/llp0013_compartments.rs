//! Revision-2 retirement guard for the former LLP 0013 legacy-policy suite.
//!
//! LLP 0021 deliberately replaced the string-policy, permissive/audit mode,
//! ambient endowment, and advisory-attribution plane that the original 69-test
//! binary suite exercised. Keeping those tests alive by passing their old
//! weakening inputs to production would test a runtime that no longer exists.
//!
//! Retained security mechanics have current, authenticated coverage:
//! `capsec_callback_invariant_mechanisms_smoke` exercises lockdown,
//! compartment withholding, tamed evaluators, callback attribution,
//! generation rechecks, and authority non-widening in an armed Hermes runtime;
//! `typed_handles_attenuate_delegate_and_revoke_as_a_cascade` covers typed
//! handle attenuation and revocation; the `armed_*` Hermes tests cover typed
//! filesystem, network, import, process, environment, and retained-object
//! decisions; and `capsec-semantics` plus the devtools contract suites cover
//! canonical policy generation and decision algebra.
//!
//! This target keeps a checked one-to-one retirement map plus the boundaries
//! that remain useful at the executable layer: a stale LLP 0013 policy cannot
//! reopen production, while native byte-view validation and dynamic-import
//! referrer correctness remain executable through the explicitly diagnostic
//! compatibility runtime.
//! @ref LLP 0021#wp11--reconcile-the-corpus-and-remove-the-legacy-plane

use std::path::Path;
use std::process::Command;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");
const RETIRED_CASES: &[&str] = &[
    "advisory_attribution_flag_makes_downgrade_explicit",
    "async_detached_deputy_control_permissive_leaks",
    "async_detached_deputy_read_is_contained_but_granted_self_async_works",
    "attenuator_handle_delegation_scoping_and_revocation",
    "audit_mode_reports_would_deny_but_proceeds",
    "bun_which_requires_process_spawn_capability",
    "capsec_aliases_parse",
    "capsec_enforce_fails_closed_on_missing_attribution_prerequisites",
    "coexisting_versions_get_distinct_policy_treatment",
    "committed_grants_artifact_is_in_sync",
    "compartment_withholds_powerful_globals_and_honors_endowments",
    "compromised_dependency_cannot_read_env_under_lockdown",
    "compromised_dependency_succeeds_without_lockdown",
    "detached_deputy_read_is_contained_but_app_wrapped_read_works",
    "dns_requires_network_resolve_capability",
    "dropped_handle_is_auto_revoked_when_garbage_collected",
    "dynamic_permissions_are_tri_state_and_bounded_by_the_ceiling",
    "dynamic_relative_import_uses_the_calling_module_referrer",
    "enforce_closes_runtime_capability_escapes",
    "enforce_rejects_disabled_package_isolation_without_advisory_flag",
    "env_endowments_cannot_widen_policy_under_enforce",
    "env_reads_are_gated_with_no_plain_snapshot_bypass",
    "eval_and_function_inherit_the_caller_compartment",
    "exact_fs_grant_cannot_mint_subtree_handle",
    "fetch_endpoint_capabilities_are_host_scoped",
    "frame_attribution_control_permissive_leaks",
    "frame_attribution_denies_deferred_dependency_but_allows_app",
    "fs_write_requires_fs_write_capability",
    "gc_of_delegation_parent_does_not_over_revoke_live_child",
    "generated_builtins_artifact_is_in_sync",
    "generated_policy_closes_builtins_axis",
    "generated_policy_endows_granted_package_and_contains_the_rest",
    "generated_policy_keeps_delegation_version_local",
    "generated_policy_observed_builtins_are_version_scoped",
    "generated_policy_observes_relative_cjs_bridge_dependencies",
    "host_scheduled_detached_deputy_control_permissive_leaks",
    "host_scheduled_detached_deputy_read_is_contained_across_timer_channels",
    "import_gate_denies_restricted_package_builtin",
    "import_gate_is_inert_without_restriction",
    "lazy_installers_present_without_lockdown",
    "link_own_metadata_gates_the_link_path_not_the_target",
    "lockdown_conformance_keeps_runtime_usable",
    "lockdown_is_off_by_default",
    "lockdown_seals_lazy_installers_and_self_grant_channel",
    "mkdtemp_checks_the_created_directory_path_not_only_the_prefix",
    "native_byte_extraction_rejects_forged_arraybuffer_view_bounds",
    "native_compartment_control_no_containment_without_compartments",
    "native_compartment_withholds_globals_without_rewrite",
    "native_deep_freeze_freezes_a_graph_without_invoking_getters",
    "native_freeze_primitive_freezes_objects",
    "native_lockdown_freezes_intrinsics_and_contains_redteam",
    "native_tcp_handles_cannot_be_stolen_by_guessing_ids",
    "path_scoped_write_grant_cannot_escape_through_a_symlink",
    "per_package_chunks_give_bundled_apps_frame_attribution",
    "permission_acquisition_is_async_with_a_pluggable_broker",
    "permission_onchange_signals_grants_and_revocations",
    "policy_check_reports_builtin_expansion_on_drift",
    "policy_check_reports_capability_expansion_on_drift",
    "policy_declared_enforce_auto_enables_bundled_attribution",
    "posix_access_w_ok_requires_fs_write_capability",
    "raw_ipc_helpers_reject_unowned_file_descriptors",
    "redteam_all_contained_under_lockdown",
    "redteam_ambient_attacks_succeed_without_lockdown",
    "server_and_socket_host_functions_require_network_capabilities",
    "stack_intersection_denies_deputy_driven_by_ungranted_caller",
    "stack_intersection_is_off_by_default",
    "timer_microtask_drain_does_not_launder_detached_deputy_into_owner",
    "udp_connect_only_socket_cannot_receive_or_expose_fd_without_listen",
    "without_generated_policy_no_package_is_endowed",
];

fn clear_closed_production_environment(command: &mut Command) {
    for name in ibex_runtime::capsec_registry_generated::CAPSEC_CLOSED_STARTUP_ENVIRONMENT_NAMES {
        command.env_remove(name);
    }
}

#[test]
fn stale_llp0013_policy_cannot_reopen_production() {
    let directory = tempfile::tempdir().expect("create legacy-policy fixture directory");
    std::fs::write(
        directory.path().join("ibex-policy.json"),
        r#"{"mode":"enforce","allow":["fs","process","network"]}"#,
    )
    .expect("write stale LLP 0013 policy");
    std::fs::write(
        directory.path().join("app.js"),
        "console.log('LEGACY_PROJECT_CODE_EXECUTED');\n",
    )
    .expect("write refusal marker entry");

    let mut command = Command::new(IBEX);
    clear_closed_production_environment(&mut command);
    let output = command
        .args([
            "--capsec",
            "enforce",
            "--policy",
            "ibex-policy.json",
            "run",
            "app.js",
        ])
        .current_dir(directory.path())
        .output()
        .expect("run production legacy-policy refusal");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "stale policy unexpectedly armed");
    assert!(
        !stdout.contains("LEGACY_PROJECT_CODE_EXECUTED")
            && !stderr.contains("LEGACY_PROJECT_CODE_EXECUTED"),
        "production observed project code before refusing the stale policy:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("canonical production policy has invalid policySchema"),
        "unexpected stale-policy refusal:\n{stderr}"
    );
}

#[test]
fn every_retired_llp0013_case_has_live_named_rev2_coverage() {
    let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
        "fixtures/capsec-rev2/llp0013-retirement-map.json"
    ))
    .expect("retirement map must be JSON");
    assert_eq!(manifest["schema"], "ibex/capsec-legacy-suite-retirement/1");
    let catalog = manifest["coverageCatalog"]
        .as_object()
        .expect("retirement map must have a coverage catalog");
    let cases = manifest["cases"]
        .as_array()
        .expect("retirement map must have cases");
    assert_eq!(cases.len(), RETIRED_CASES.len());

    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut used_coverage = std::collections::BTreeSet::new();
    for (case, expected_name) in cases.iter().zip(RETIRED_CASES) {
        assert_eq!(
            case["legacyTest"].as_str(),
            Some(*expected_name),
            "retirement cases must be a complete sorted set"
        );
        assert!(
            matches!(
                case["disposition"].as_str(),
                Some("migrated" | "superseded" | "replaced-by-closure")
            ),
            "{expected_name} has no honest retirement disposition"
        );
        let coverage_ids = case["coverageIds"]
            .as_array()
            .expect("retirement case must name current coverage");
        assert!(
            !coverage_ids.is_empty(),
            "{expected_name} has no current coverage"
        );
        let mut unique_ids = std::collections::BTreeSet::new();
        for coverage_id in coverage_ids {
            let coverage_id = coverage_id.as_str().expect("coverage id must be a string");
            assert!(
                unique_ids.insert(coverage_id),
                "{expected_name} repeats coverage id {coverage_id}"
            );
            used_coverage.insert(coverage_id);
            assert!(
                catalog.contains_key(coverage_id),
                "{expected_name} names missing coverage id {coverage_id}"
            );
        }
    }

    for (coverage_id, coverage) in catalog {
        assert!(
            used_coverage.contains(coverage_id.as_str()),
            "unused retirement coverage entry {coverage_id}"
        );
        let relative = coverage["path"]
            .as_str()
            .expect("coverage path must be a string");
        let path = Path::new(relative);
        assert!(
            !path.is_absolute()
                && path
                    .components()
                    .all(|component| component != std::path::Component::ParentDir),
            "coverage path escapes the repository: {relative}"
        );
        let anchor = coverage["anchor"]
            .as_str()
            .expect("coverage anchor must be a string");
        let source = std::fs::read_to_string(repository.join(path))
            .unwrap_or_else(|error| panic!("read coverage source {relative}: {error}"));
        assert!(
            source.contains(anchor),
            "coverage {coverage_id} lost named test anchor {anchor:?} in {relative}"
        );
    }
}

#[test]
fn dynamic_relative_import_uses_the_calling_module_referrer() {
    let directory = tempfile::tempdir().expect("create dynamic-import fixture directory");
    write_text(
        &directory
            .path()
            .join("node_modules/dynamic-pkg/package.json"),
        r#"{"name":"dynamic-pkg","version":"1.0.0","main":"index.js"}"#,
    );
    write_text(
        &directory.path().join("node_modules/dynamic-pkg/index.js"),
        r#"exports.run = async function() {
  return import('./local.js').then(function(module) {
    return module.value || (module.default && module.default.value);
  });
};
"#,
    );
    write_text(
        &directory.path().join("node_modules/dynamic-pkg/local.js"),
        "exports.value = 'LOCAL';\n",
    );
    write_text(
        &directory.path().join("app.js"),
        r#"require('dynamic-pkg').run().then(function(value) {
  console.log('dynamic-local=' + value);
}, function(error) {
  console.error(error && error.stack || error);
  process.exitCode = 1;
});
"#,
    );

    let output = run_audit(directory.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("dynamic-local=LOCAL"),
        "dynamic import did not resolve from its calling package:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn native_byte_extraction_rejects_forged_arraybuffer_view_bounds() {
    let directory = tempfile::tempdir().expect("create byte-view fixture directory");
    let output_path = directory.path().join("out.bin");
    let source = format!(
        r#"var fs = require('fs');
var fd = fs.openSync({output_path}, 'w');
try {{
  globalThis.__exactFsWrite(fd, new Uint8Array([1, 2, 3, 4]), -1);
  console.log('real-view: WROTE');
  var forged = {{ buffer: new ArrayBuffer(4), byteOffset: 3, byteLength: 4 }};
  globalThis.__exactFsWrite(fd, forged, -1);
  console.log('forged-view: ACCEPTED');
}} catch (error) {{
  console.log('forged-view: REJECTED');
}} finally {{
  fs.closeSync(fd);
}}
console.log('forged-size: ' + fs.statSync({output_path}).size);
"#,
        output_path = serde_json::to_string(path_text(&output_path)).unwrap(),
    );
    std::fs::write(directory.path().join("app.js"), source).expect("write byte-view fixture");

    let output = run_audit(directory.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "byte-view fixture failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("real-view: WROTE")
            && stdout.contains("forged-view: REJECTED")
            && stdout.contains("forged-size: 4")
            && !stdout.contains("forged-view: ACCEPTED"),
        "native byte extraction accepted forged bounds or corrupted output:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("temporary fixture path must be UTF-8")
}

fn run_audit(directory: &Path) -> std::process::Output {
    Command::new(IBEX)
        .args(["capsec", "audit", "app.js"])
        .current_dir(directory)
        .env("EXACT_COMPAT_TEST", "1")
        .output()
        .expect("run diagnostic compatibility fixture")
}

fn write_text(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture parent");
    }
    std::fs::write(path, contents).expect("write fixture file");
}
