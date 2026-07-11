//! Source-level contract checks for the Windows-only C++ filesystem bridge.
//!
//! The Windows translation unit cannot be compiled by a macOS test runner,
//! but these checks keep the platform build wiring and the safety-critical
//! ABI choices from silently regressing between Windows CI runs.

const WINDOWS_FS: &str = include_str!("../src/engine/hermes_runtime_fs_windows.cc");
const HOST_ABI: &str = include_str!("../src/host/abi.rs");

#[test]
fn windows_async_fs_surface_is_registered() {
    for hook in [
        "__exactFsReadFileAsync",
        "__exactFsWriteFileAsync",
        "__exactFsReadAsync",
        "__exactFsWriteAsync",
        "__exactFsReadvAsync",
        "__exactFsWritevAsync",
        "__exactFsPathAsync",
        "__exactFsStatAsync",
    ] {
        assert!(
            WINDOWS_FS.contains(hook),
            "missing Windows async hook {hook}"
        );
    }
}

#[test]
fn windows_worker_errors_use_same_thread_host_errno() {
    assert!(HOST_ABI.contains("pub extern \"C\" fn ex_host_fs_last_error"));
    assert!(WINDOWS_FS.contains("error = ex_host_fs_last_error()"));
    assert!(
        !WINDOWS_FS.contains("!path.empty() && ex_host_fs_access(path.c_str(), 0) != 0"),
        "failure classification must not probe the path and rewrite every access failure as ENOENT"
    );
}

#[test]
fn windows_append_and_flush_are_handle_based() {
    assert!(HOST_ABI.contains("const FS_APPEND: u32 = 16"));
    assert!(HOST_ABI.contains("opts.append(flags & FS_APPEND != 0)"));
    assert!(WINDOWS_FS.contains("constexpr uint32_t EXACT_FS_APPEND = 16"));
    assert!(
        !WINDOWS_FS.contains("ex_host_fs_append("),
        "fd append must not reopen by path"
    );
    assert!(WINDOWS_FS.contains("__exactFsFsyncSync"));
    assert!(WINDOWS_FS.contains("__exactFsFdatasyncSync"));
    assert!(HOST_ABI.contains("pub extern \"C\" fn ex_host_fs_sync"));
    assert!(HOST_ABI.contains("pub extern \"C\" fn ex_host_fs_fstat"));
    assert!(WINDOWS_FS.contains("ex_host_fs_fstat(file->handle)"));
}

#[test]
fn windows_file_handle_lifetime_is_shared_with_workers() {
    assert!(WINDOWS_FS.contains("std::shared_ptr<WindowsFileHandle>"));
    assert!(WINDOWS_FS.contains("std::mutex ioMutex"));
    assert!(WINDOWS_FS.contains("g_files.erase(it)"));
}
