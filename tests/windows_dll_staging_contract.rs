//! Cross-host contract checks for Windows Hermes DLL staging (ENG-24264).
//! The actual locked-file behavior is exercised by Windows CI/build hosts;
//! these checks keep the fail-closed and content-digest rules from silently
//! regressing on platforms that cannot lock a DLL the Windows way.

#[test]
fn windows_dll_staging_is_digest_bound_and_never_reuses_a_known_stale_file() {
    let build = include_str!("../build.rs");
    let start = build
        .find("fn stage_windows_runtime_dlls")
        .expect("staging function present");
    let end = build[start..]
        .find("fn generate_runtime_bundle_bytecode_header")
        .map(|offset| start + offset)
        .expect("staging function boundary");
    let staging = &build[start..end];

    assert!(staging.contains("file_sha256(source)"));
    assert!(staging.contains("file_sha256(destination)"));
    assert!(staging.contains("does not match source"));
    assert!(staging.contains("destination may be locked"));
    assert!(
        !staging.contains("using existing file"),
        "a known-mismatched locked DLL must fail the build"
    );
    assert!(
        !staging.contains("modified()"),
        "mtime is not runtime artifact identity"
    );
}
