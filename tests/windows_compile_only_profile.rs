#[path = "../build_support/windows_compile_only_profile.rs"]
mod windows_compile_only_profile;

use windows_compile_only_profile::{
    select, validate_artifacts, SelectorRequest, FORBIDDEN_SELECTOR_ENVS, POISON_LIBRARY,
    REQUIRED_DIRECTORY_ENVS,
};

fn valid_request<'a>() -> SelectorRequest<'a> {
    SelectorRequest {
        mode_value: Some("1"),
        target_os: "windows",
        target_triple: "x86_64-pc-windows-msvc",
        host_triple: Some("aarch64-apple-darwin"),
        legacy_block_scoping: Some("1"),
        require_provenance: Some("0"),
        present_forbidden_selectors: &[],
        missing_required_directories: &[],
    }
}

#[test]
fn absent_selector_keeps_the_runtime_profile() {
    let mut request = valid_request();
    request.mode_value = None;
    assert_eq!(select(request).unwrap(), None);
}

#[test]
fn valid_cross_target_selector_returns_a_non_runtime_plan() {
    let plan = select(valid_request()).unwrap().unwrap();
    assert!(!plan.stage_runtime_dlls);
    assert!(!plan.add_runtime_bin_search);
    assert!(plan.embed_null_provenance);
    assert!(plan.poison_codegen_link);
    assert_eq!(
        POISON_LIBRARY,
        "IBEX_WINDOWS_COMPILE_ONLY_PROFILE_MUST_NOT_LINK"
    );
}

#[test]
fn identity_and_semantic_mutations_fail_closed() {
    let mut wrong_value = valid_request();
    wrong_value.mode_value = Some("true");
    assert!(select(wrong_value).is_err());

    let mut wrong_os = valid_request();
    wrong_os.target_os = "macos";
    assert!(select(wrong_os).is_err());

    let mut wrong_target = valid_request();
    wrong_target.target_triple = "aarch64-pc-windows-msvc";
    assert!(select(wrong_target).is_err());

    let mut native = valid_request();
    native.host_triple = Some("x86_64-pc-windows-msvc");
    assert!(select(native).is_err());

    let mut cross_arch_windows = valid_request();
    cross_arch_windows.host_triple = Some("aarch64-pc-windows-msvc");
    assert!(select(cross_arch_windows).is_err());

    let mut missing_host = valid_request();
    missing_host.host_triple = None;
    assert!(select(missing_host).is_err());

    let mut modern_semantics = valid_request();
    modern_semantics.legacy_block_scoping = Some("0");
    assert!(select(modern_semantics).is_err());

    let mut provenance_claim = valid_request();
    provenance_claim.require_provenance = Some("1");
    assert!(select(provenance_claim).is_err());
}

#[test]
fn every_ambient_selector_is_rejected() {
    for selector in FORBIDDEN_SELECTOR_ENVS {
        let present = [*selector];
        let mut request = valid_request();
        request.present_forbidden_selectors = &present;
        let error = select(request).unwrap_err();
        assert!(error.contains(selector), "{selector}: {error}");
    }
}

#[test]
fn every_explicit_directory_is_required() {
    for directory in REQUIRED_DIRECTORY_ENVS {
        let missing = [*directory];
        let mut request = valid_request();
        request.missing_required_directories = &missing;
        let error = select(request).unwrap_err();
        assert!(error.contains(directory), "{directory}: {error}");
    }
}

#[test]
fn artifact_profile_requires_empty_bin_and_regular_import_library() {
    validate_artifacts(&[], true, "C:/fixture/lib/hermes.lib").unwrap();

    let entries = vec!["C:/fixture/bin/hermesvm.dll".to_owned()];
    assert!(validate_artifacts(&entries, true, "C:/fixture/lib/hermes.lib").is_err());
    assert!(validate_artifacts(&[], false, "C:/fixture/lib/hermes.lib").is_err());
}
