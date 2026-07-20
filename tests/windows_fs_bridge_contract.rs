//! Source-level contract checks for the Windows-only C++ filesystem bridge.
//!
//! The Windows translation unit cannot be compiled by a macOS test runner,
//! but these checks keep the platform build wiring and the safety-critical
//! ABI choices from silently regressing between Windows CI runs.

const WINDOWS_FS: &str = include_str!("../src/engine/hermes_runtime_fs_windows.cc");
const POSIX_FS: &str = include_str!("../src/engine/hermes_runtime_fs.cc");
const HOST_ABI: &str = include_str!("../src/host/abi.rs");
const HERMES_RUNTIME: &str = include_str!("../src/engine/hermes_runtime.cc");
const ENGINE_TRAIT: &str = include_str!("../src/bin/ibex/engine/mod.rs");
const HERMES_ENGINE: &str = include_str!("../src/bin/ibex/engine/hermes.rs");
const CLI_RUNTIME: &str = include_str!("../src/bin/ibex/runtime.rs");
const PROCESS_RUNTIME: &str = include_str!("../packages/ibex-runtime-js/src/node/process.ts");
const RUNTIME_BOOTSTRAP: &str = include_str!("../packages/ibex-runtime-js/src/bootstrap.ts");

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
fn windows_sync_write_preserves_process_owned_stdout_and_stderr() {
    let write = WINDOWS_FS
        .split("auto fsWriteFn")
        .nth(1)
        .expect("Windows sync write registration")
        .split("rt.global().setProperty(rt, \"__exactFsWrite\"")
        .next()
        .unwrap();
    assert!(write.contains("if (fd == 1 || fd == 2)"));
    assert!(write.contains("principalMayUseProcessStdio(principal)"));
    assert!(WINDOWS_FS.contains("#define NOMINMAX"));
    assert!(write.contains("_get_osfhandle(fd)"));
    assert!(write.contains("WriteFile("));
    assert!(
        write.find("if (fd == 1 || fd == 2)") < write.find("getFileEntry(runtime, fd)"),
        "process stdio must not be rejected by the filesystem-handle registry"
    );
}

#[test]
fn windows_cli_runtime_reconciles_async_and_compatibility_state() {
    assert!(PROCESS_RUNTIME.contains("g.__exactUncaughtExceptionHandler = function(error: any)"));
    assert!(PROCESS_RUNTIME.contains("self.emit('uncaughtException', error)"));
    assert!(RUNTIME_BOOTSTRAP.contains("enableBunCompatibilityIdentity();"));
    assert!(PROCESS_RUNTIME.contains("value: BUN_COMPAT_VERSION"));
    assert!(ENGINE_TRAIT.contains("async fn eval_awaited_entry"));
    assert!(HERMES_ENGINE.contains("eval_str(code, \"ibex:awaited-entry\")"));
    assert!(CLI_RUNTIME.contains("self.engine.eval_awaited_entry(&wrapped)"));
    assert!(HERMES_RUNTIME.contains("source == \"ibex:awaited-entry\""));
    assert!(HERMES_RUNTIME.contains("shouldUnwrapPromiseResult && result.isObject()"));
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

#[test]
fn retained_parent_cache_is_bounded_and_runtime_scoped() {
    assert!(POSIX_FS.contains("kMaxParentFdCacheKeys = 4096"));
    assert!(POSIX_FS.contains("it->second.expired()"));
    assert!(POSIX_FS.contains("g_parent_fd_cache.erase(g_parent_fd_cache.begin())"));
    assert!(POSIX_FS.contains("const auto prefix = std::to_string(runtimeNonce) + \":\""));
}

#[test]
fn rollback_eligible_creates_are_exclusive_and_fd_entries_are_identity_checked() {
    assert!(POSIX_FS.contains("baseFlags | O_CREAT | O_EXCL"));
    assert!(POSIX_FS.contains("baseFlags & ~(O_CREAT | O_EXCL)"));
    assert!(POSIX_FS.contains("openArmedTargetAtomically("));
    assert!(POSIX_FS.contains("it->second.objectDevice != static_cast<uint64_t>(sb.st_dev)"));
    assert!(POSIX_FS.contains("if (!stale && fd >= STDIN_FILENO && fd <= STDERR_FILENO"));
    assert!(POSIX_FS.contains("principalMayUseProcessStdio(principal) || isAllowAll()"));
    assert!(POSIX_FS.contains("entry->runtimeNonce != exactCurrentRuntimeNonce()"));
    assert!(POSIX_FS.contains("g_transferable_fds.erase(fd)"));
}

#[test]
fn windows_path_worker_implements_node_metadata_and_exclusive_copy_ops() {
    for hook in [
        "ex_host_fs_mkdir_recursive_result",
        "ex_host_fs_copy_exclusive",
        "ex_host_fs_truncate",
        "ex_host_fs_utimes",
        "ex_host_fs_statfs",
    ] {
        assert!(WINDOWS_FS.contains(hook), "missing Windows path ABI {hook}");
        assert!(HOST_ABI.contains(hook), "missing Rust path ABI {hook}");
    }
    assert!(WINDOWS_FS.contains("op == \"copyfile_excl\""));
    assert!(WINDOWS_FS.contains("op == \"truncate\""));
    assert!(WINDOWS_FS.contains("op == \"utime\""));
    assert!(WINDOWS_FS.contains("op == \"statfs\""));
}
