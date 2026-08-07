//! Source-level contract checks for the Windows-only C++ filesystem bridge.
//!
//! The Windows translation unit cannot be compiled by a macOS test runner,
//! but these checks keep the platform build wiring and the safety-critical
//! ABI choices from silently regressing between Windows CI runs.

const WINDOWS_FS: &str = include_str!("../src/engine/hermes_runtime_fs_windows.cc");
const POSIX_FS: &str = include_str!("../src/engine/hermes_runtime_fs.cc");
const RUNTIME_INTERNAL: &str = include_str!("../src/engine/hermes_runtime_internal.h");
const PUBLIC_RUNTIME_ABI: &str = include_str!("../include/exact_runtime.h");
const RUNTIME: &str = include_str!("../src/engine/hermes_runtime.cc");
const BUILTIN_FS: &str = include_str!("../src/builtins/fs.js");
const HOST_ABI: &str = include_str!("../src/host/abi.rs");
const POSIX_CRYPTO: &str = include_str!("../src/engine/hermes_runtime_crypto.cc");
const WINDOWS_CRYPTO: &str = include_str!("../src/engine/hermes_runtime_crypto_windows.cc");
const POSIX_PROCESS: &str = include_str!("../src/engine/hermes_runtime_process.cc");

fn source_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start_offset = source
        .find(start)
        .unwrap_or_else(|| panic!("missing source-section start: {start}"));
    let remaining = &source[start_offset..];
    let end_offset = remaining
        .find(end)
        .unwrap_or_else(|| panic!("missing source-section end: {end}"));
    &remaining[..end_offset]
}

fn assert_before(source: &str, earlier: &str, later: &str) {
    let earlier_offset = source
        .find(earlier)
        .unwrap_or_else(|| panic!("missing earlier source token: {earlier}"));
    let later_offset = source
        .find(later)
        .unwrap_or_else(|| panic!("missing later source token: {later}"));
    assert!(
        earlier_offset < later_offset,
        "expected {earlier:?} before {later:?}"
    );
}

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

#[test]
fn windows_fs_workers_share_the_runtime_generation_lease_contract() {
    for source in [POSIX_FS, WINDOWS_FS] {
        assert!(source.contains("enum class FsOperationLeaseState"));
        assert!(source.contains("FsOperationLeaseState::Queued"));
        assert!(source.contains("FsOperationLeaseState::Committed"));
        assert!(source.contains("cancelQueued(RuntimeCallbackTarget target)"));
        assert!(source.contains("void exactCancelQueuedFsOperations("));
        assert!(source.contains("operationLease->target = target"));
        assert!(source.contains("operationLease->principalStack = principalStack"));
        assert!(source.contains("operationLease->decidedWork = workPtr"));
    }
    assert!(POSIX_FS.contains("lease->acquireForWorker()"));
    assert!(WINDOWS_FS.contains("lease->commit()"));
    assert!(RUNTIME_INTERNAL.contains("void exactCancelQueuedFsOperations("));
    let destroy = &RUNTIME[RUNTIME
        .find("extern \"C\" void ex_hermes_destroy(")
        .expect("runtime destroy entry")..];
    assert_before(
        destroy,
        "exactCancelQueuedFsOperations(target)",
        "finishRuntimeTeardown(target)",
    );
    assert_before(
        destroy,
        "finishRuntimeTeardown(target)",
        "ex_host_vfs_unbind_runtime(runtime->runtime_nonce)",
    );
    assert_before(
        destroy,
        "ex_host_vfs_unbind_runtime(runtime->runtime_nonce)",
        "exactCleanupRuntimeFileDescriptors(runtime->runtime_nonce)",
    );
}

#[test]
fn terminal_session_descriptor_policy_precedes_cross_platform_native_routes() {
    for symbol in [
        "ex_host_session_descriptor_is_protected",
        "ex_host_session_descriptor_read_route",
        "ex_host_session_descriptor_write_route",
        "ex_host_session_descriptor_close_route",
        "ex_host_session_descriptor_alias_source_route",
        "ex_host_session_descriptor_alias_target_route",
    ] {
        assert!(HOST_ABI.contains(symbol), "missing Host ABI route {symbol}");
    }
    assert!(HOST_ABI.contains("arm_terminal_session_descriptor_policy"));
    assert!(HOST_ABI.contains("TerminalSessionDescriptorPolicyGuard"));

    for source in [POSIX_FS, WINDOWS_FS] {
        assert!(source.contains("sessionDescriptorReadIsEof"));
        assert!(source.contains("requireSessionDescriptorWrite"));
        assert!(source.contains("sessionDescriptorCloseIsNoOp"));
        assert!(source.contains("requireSessionDescriptorGeneric"));
    }
    assert!(POSIX_FS.contains("requireSessionDescriptorAliasSource"));
    assert!(POSIX_FS.contains("retainFdForAsyncWrite"));
    assert!(POSIX_PROCESS.contains("requireSpawnDescriptorAlias"));
    assert!(POSIX_CRYPTO.contains("ex_host_session_descriptor_read_route(0)"));
    assert!(WINDOWS_CRYPTO.contains("ex_host_session_descriptor_read_route(0)"));
}

#[test]
fn retained_parent_cache_is_bounded_and_runtime_scoped() {
    assert!(POSIX_FS.contains("kMaxParentFdCacheKeys = 4096"));
    assert!(POSIX_FS.contains("it->second.expired()"));
    assert!(POSIX_FS.contains("g_parent_fd_cache.erase(g_parent_fd_cache.begin())"));
    assert!(POSIX_FS.contains("const auto prefix = std::to_string(runtimeNonce) + \":\""));
}

#[test]
fn armed_creates_are_exclusive_and_fd_entries_are_identity_checked() {
    assert!(POSIX_FS.contains("kMaxStateRaces = 64"));
    assert!(POSIX_FS.contains("O_CREAT | O_EXCL |"));
    assert!(POSIX_FS.contains("targetFlags & ~(O_CREAT | O_EXCL | O_TRUNC)"));
    assert!(POSIX_FS.contains("openArmedPathTarget("));
    assert!(POSIX_FS.contains("sameFdObject(targetRaw, *resolved.target)"));
    assert!(!POSIX_FS.contains("rollbackCreatedFile("));
    assert!(POSIX_FS.contains("it->second.objectDevice != static_cast<uint64_t>(sb.st_dev)"));
    assert!(POSIX_FS.contains("if (!stale && fd >= STDIN_FILENO && fd <= STDERR_FILENO"));
    assert!(POSIX_FS.contains("principalMayUseProcessStdio(principal) || isAllowAll()"));
    assert!(POSIX_FS.contains("entry->runtimeNonce != exactCurrentRuntimeNonce()"));
    assert!(POSIX_FS.contains("g_transferable_fds.erase(fd)"));
}

#[test]
fn windows_process_stdio_bypasses_only_the_opaque_file_table() {
    assert!(WINDOWS_FS.contains("principalMayUseProcessStdio(currentPrincipalId())"));
    assert!(WINDOWS_FS.contains("GetStdHandle(fd == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE)"));
    assert!(WINDOWS_FS.contains("if (fd == 1 || fd == 2)"));
    assert!(WINDOWS_FS.contains("return writeProcessStdio(runtime, fd, bytes)"));
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
    let path_worker = source_section(
        WINDOWS_FS,
        "FsAsyncResult fsPathOpWork(",
        "bool parseWindowsIoVecArguments(",
    );
    let mkdir_worker = source_section(path_worker, "if (op == \"mkdir\")", "if (op == \"rmdir\")");
    assert!(mkdir_worker.contains("y >= 0 && ex_host_is_armed() != 1"));
    assert!(mkdir_worker.contains("a.backing.c_str(), static_cast<uint32_t>(y)"));
}

#[test]
fn windows_open_sync_paths_keep_backing_bytes_native_and_virtual_paths_public() {
    let unary = source_section(
        WINDOWS_FS,
        "facebook::jsi::Function unaryPathJsonFunction(",
        "struct FsAsyncResult",
    );
    assert!(unary.contains("exactResolveVfsPath(runtime, pathArg(runtime, args[0]))"));
    assert!(unary.contains("requireReadCapability(runtime, path.virtualPath)"));
    assert!(unary.contains("host_fn(path.backing.c_str())"));
    assert!(unary.contains("syscall, path.virtualPath"));
    for hook in ["__exactStat", "__exactLstat", "__exactReaddir"] {
        assert!(
            WINDOWS_FS.contains(hook),
            "missing resolved unary hook {hook}"
        );
    }

    let read_file = source_section(WINDOWS_FS, "auto readFileFn =", "auto writeFileFn =");
    assert!(read_file.contains("auto input = pathArg(runtime, args[0])"));
    assert!(read_file.contains("exactResolveVfsPath(runtime, input)"));
    assert!(read_file.contains("requireReadCapability(runtime, path.virtualPath)"));
    assert!(read_file.contains("ex_host_fs_read_file(path.backing.c_str()"));
    assert!(read_file.contains("throwFs(runtime, \"open\", path.virtualPath)"));

    let write_file = source_section(WINDOWS_FS, "auto writeFileFn =", "auto fsOpenFn =");
    assert!(write_file.contains("exactResolveVfsPath(runtime, pathArg(runtime, args[0]))"));
    assert!(write_file.contains("requireWriteCapability(runtime, path.virtualPath)"));
    assert!(write_file.contains("path.backing.c_str()"));
    assert!(write_file.contains("throwFs(runtime, \"write\", path.virtualPath)"));

    let open = source_section(WINDOWS_FS, "auto fsOpenFn =", "auto fsCloseFn =");
    assert!(open.contains("auto input = pathArg(runtime, args[0])"));
    assert!(open.contains("exactResolveVfsPath(runtime, input)"));
    assert!(open.contains("requireReadCapability(runtime, path.virtualPath)"));
    assert!(open.contains("requireWriteCapability(runtime, path.virtualPath)"));
    assert!(open.contains("ex_host_fs_open(path.backing.c_str(), host_flags)"));
    assert!(open.contains("throwFs(runtime, \"open\", path.virtualPath)"));
    assert!(open.contains("file,\n            virtualPath,"));

    for (start, end, host_call, capability, syscall) in [
        (
            "auto mkdirFn =",
            "auto unaryClosedVoid =",
            "ex_host_fs_mkdir(path.backing.c_str()",
            "requireWriteCapability(runtime, path.virtualPath)",
            "mkdir",
        ),
        (
            "auto accessFn =",
            "auto chmodFn =",
            "ex_host_fs_access(path.backing.c_str()",
            "requireReadCapability(runtime, path.virtualPath)",
            "access",
        ),
        (
            "auto truncateFn =",
            "auto utimesFn =",
            "ex_host_fs_truncate(\n                path.backing.c_str()",
            "requireWriteCapability(runtime, path.virtualPath)",
            "truncate",
        ),
        (
            "auto statfsFn =",
            "auto mkdtempFn =",
            "ex_host_fs_statfs(path.backing.c_str())",
            "requireReadCapability(runtime, path.virtualPath)",
            "statfs",
        ),
    ] {
        let entry = source_section(WINDOWS_FS, start, end);
        assert!(
            entry.contains("exactResolveVfsPath("),
            "{syscall} bypasses VFS resolution"
        );
        assert!(
            entry.contains(host_call),
            "{syscall} does not use backing bytes"
        );
        assert!(
            entry.contains(capability),
            "{syscall} capability uses backing bytes"
        );
        assert!(
            entry.contains("path.virtualPath"),
            "{syscall} loses its virtual spelling"
        );
        assert!(
            !entry.contains("path.c_str()"),
            "{syscall} forwards a public spelling to Host"
        );
    }
}

#[test]
fn windows_open_async_paths_preserve_both_spellings_across_workers() {
    let read_worker = source_section(
        WINDOWS_FS,
        "FsAsyncResult fsReadFilePathWork(",
        "FsAsyncResult fsWriteAllHandleWork(",
    );
    assert!(read_worker.contains("ex_host_fs_read_file(backingPath.c_str()"));
    assert!(read_worker.contains("fsAsyncSyscallError(\"open\", virtualPath"));

    let write_worker = source_section(
        WINDOWS_FS,
        "FsAsyncResult fsWriteFilePathWork(",
        "FsAsyncResult fsReadChunkWork(",
    );
    assert!(write_worker.contains("ex_host_fs_open(backingPath.c_str()"));
    assert!(write_worker.contains("fsAsyncSyscallError(\"open\", virtualPath)"));
    assert!(write_worker.contains("fsWriteAllHandleWork(file, virtualPath"));

    let stat_worker = source_section(
        WINDOWS_FS,
        "FsAsyncResult fsStatPathWork(",
        "FsAsyncResult fsFstatWork(",
    );
    assert!(stat_worker.contains("ex_host_fs_lstat(backingPath.c_str())"));
    assert!(stat_worker.contains("ex_host_fs_stat(backingPath.c_str())"));
    assert!(stat_worker.contains("isLstat ? \"lstat\" : \"stat\", virtualPath"));

    let path_worker = source_section(
        WINDOWS_FS,
        "FsAsyncResult fsPathOpWork(",
        "bool parseWindowsIoVecArguments(",
    );
    assert!(path_worker.contains("const ExactResolvedVfsPath& a"));
    assert!(path_worker.contains("const ExactResolvedVfsPath& b"));
    assert!(path_worker.contains("ex_host_fs_readdir(a.backing.c_str())"));
    assert!(path_worker.contains("fsAsyncSyscallError(\"scandir\", a.virtualPath)"));
    assert!(path_worker.contains("ex_host_fs_access(a.backing.c_str()"));
    assert!(path_worker.contains("ex_host_fs_statfs(a.backing.c_str())"));
    assert!(!path_worker.contains("a.c_str()"));
    assert!(!path_worker.contains("b.c_str()"));

    let read_entry = source_section(
        WINDOWS_FS,
        "auto readFileAsyncFn =",
        "auto writeFileAsyncFn =",
    );
    assert!(read_entry.contains("auto input = pathArg(runtime, args[0])"));
    assert!(read_entry.contains("exactResolveVfsPath(runtime, input)"));
    assert!(read_entry.contains("requireReadCapability(runtime, path.virtualPath)"));
    assert!(read_entry.contains("backingPath = path.backing"));
    assert!(read_entry.contains("virtualPath = path.virtualPath"));

    let write_entry = source_section(
        WINDOWS_FS,
        "auto writeFileAsyncFn =",
        "auto fsReadAsyncFn =",
    );
    assert!(write_entry.contains("exactResolveVfsPath(runtime, pathArg(runtime, args[0]))"));
    assert!(write_entry.contains("requireWriteCapability(runtime, path.virtualPath)"));
    assert!(write_entry.contains("backingPath = path.backing"));
    assert!(write_entry.contains("virtualPath = path.virtualPath"));

    let path_entry = source_section(WINDOWS_FS, "auto fsPathAsyncFn =", "auto fsStatAsyncFn =");
    assert!(path_entry.contains("auto a = exactResolveVfsPath(runtime, rawA)"));
    assert!(path_entry.contains("b = exactResolveVfsPath(runtime, rawB)"));
    assert!(path_entry.contains("requireReadCapability(runtime, a.virtualPath)"));
    assert!(path_entry.contains("requireWriteCapability(runtime, a.virtualPath)"));
    assert!(path_entry.contains("runtimeNonce = handle->runtime_nonce"));
    assert!(path_entry
        .contains("fsPathOpWork(\n                  runtimeNonce, op, a, b, x, y, principal)"));

    let stat_entry = source_section(WINDOWS_FS, "auto fsStatAsyncFn =", "auto makeSync =");
    assert!(stat_entry.contains("auto path = exactResolveVfsPath("));
    assert!(stat_entry.contains("requireReadCapability(runtime, path.virtualPath)"));
    assert!(stat_entry.contains("backingPath = path.backing"));
    assert!(stat_entry.contains("virtualPath = path.virtualPath"));
}

#[test]
fn windows_realpath_and_readlink_never_publish_backing_spellings() {
    assert!(RUNTIME_INTERNAL.contains("ibex_private_vfs_project_realpath("));
    assert!(RUNTIME_INTERNAL.contains("uint8_t** out_virtual"));
    assert!(RUNTIME_INTERNAL.contains("uint64_t* out_virtual_len"));
    assert!(
        !PUBLIC_RUNTIME_ABI.contains("ibex_private_vfs_project_realpath"),
        "the session-bound projector is an internal adapter, not public Host ABI"
    );
    assert!(!WINDOWS_FS.contains("virtualPathForCanonicalBacking"));
    assert!(!WINDOWS_FS.contains("windowsPathComponentEqual"));
    assert!(!WINDOWS_FS.contains("comparableWindowsPath"));

    let projection = source_section(
        WINDOWS_FS,
        "FsAsyncResult projectRealpathIdentity(",
        "FsAsyncResult fsRealpathWork(",
    );
    assert!(projection.contains("ibex_private_vfs_project_realpath("));
    assert!(projection.contains("requested.virtualPath.data()"));
    assert!(projection.contains("canonicalBacking.data()"));
    assert!(projection.contains("ex_host_free_buffer(projected, projectedLength)"));
    assert!(projection.contains("ERR_IBEX_OUTSIDE_MOUNT"));
    assert!(projection.contains("ERR_IBEX_STALE_SESSION"));

    let realpath = source_section(WINDOWS_FS, "auto realpathFn =", "auto readlinkFn =");
    assert!(realpath.contains("exactResolveVfsPath(runtime, pathArg(runtime, args[0]))"));
    assert!(realpath.contains("requireReadCapability(runtime, path.virtualPath)"));
    assert!(realpath.contains("fsRealpathWork(handle->runtime_nonce, path)"));
    assert!(realpath.contains("path.virtualPath"));
    assert!(!realpath.contains("ex_host_fs_realpath"));
    assert!(!realpath.contains("path.backing"));

    let realpath_worker = source_section(
        WINDOWS_FS,
        "FsAsyncResult fsRealpathWork(",
        "FsAsyncResult fsPathOpWork(",
    );
    assert!(realpath_worker.contains("uint64_t runtimeNonce"));
    assert!(realpath_worker.contains("if (ex_host_is_armed() != 1)"));
    assert!(realpath_worker.contains("ex_host_fs_realpath(path.backing.c_str())"));
    assert!(realpath_worker.contains("fsAsyncSyscallError(\"realpath\", path.virtualPath)"));
    assert_eq!(
        realpath_worker
            .matches("ex_host_fs_realpath(path.backing.c_str())")
            .count(),
        1,
        "the raw-path bridge must remain confined to the unarmed branch"
    );
    assert!(realpath_worker.contains("std::filesystem::canonical("));
    assert!(realpath_worker.contains("projectRealpathIdentity(\n      runtimeNonce, path"));
    assert_before(
        realpath_worker,
        "ex_host_fs_realpath(path.backing.c_str())",
        "std::filesystem::canonical(",
    );

    let readlink = source_section(WINDOWS_FS, "auto readlinkFn =", "auto accessFn =");
    assert!(readlink.contains("exactResolveVfsPath(runtime, pathArg(runtime, args[0]))"));
    assert!(readlink.contains("requireReadCapability(runtime, path.virtualPath)"));
    assert!(readlink.contains("fsErrorMessage(\"readlink\", path.virtualPath, ENOSYS)"));
    assert!(!readlink.contains("ex_host_fs_realpath"));

    let path_worker = source_section(
        WINDOWS_FS,
        "FsAsyncResult fsPathOpWork(",
        "bool parseWindowsIoVecArguments(",
    );
    let async_readlink = source_section(
        path_worker,
        "if (op == \"readlink\")",
        "if (op == \"access\")",
    );
    assert!(async_readlink.contains("fsAsyncUnsupported(\"readlink\", a.virtualPath)"));
}

#[test]
fn windows_armed_mutation_closure_precedes_path_and_fd_lookup() {
    assert!(WINDOWS_FS.contains("case EPERM: return \"EPERM\";"));
    assert!(WINDOWS_FS.contains("case EPERM: return \"operation not permitted\";"));

    let mutation_refusal = source_section(
        WINDOWS_FS,
        "void refuseClosedArmedFsMutation(",
        "void refuseClosedArmedFsRoute(",
    );
    assert!(mutation_refusal.contains("ex_host_is_armed() != 1"));
    assert!(mutation_refusal.contains("throwStructuredFsError("));

    let route_refusal = source_section(
        WINDOWS_FS,
        "void refuseClosedArmedFsRoute(",
        "void throwSessionDescriptorRefused(",
    );
    assert!(route_refusal.contains("ex_host_is_armed() != 1"));
    assert!(route_refusal.contains("throwStructuredFsError("));

    let install_guard = source_section(WINDOWS_FS, "auto mutationGuardFn =", "auto readFileFn =");
    assert!(install_guard.contains("__exactFsMutationGuard"));
    assert!(install_guard.contains("refuseClosedArmedFsMutation(runtime, operation)"));
    assert_before(
        RUNTIME,
        "installFsMutationGuardHostFunction(handle)",
        "installModuleLoader(handle)",
    );
    let finish_bootstrap = source_section(
        RUNTIME,
        "extern \"C\" uint32_t ex_hermes_finish_bootstrap(",
        "extern \"C\" void ex_hermes_destroy(",
    );
    assert_before(
        finish_bootstrap,
        "capturePrivateBridgeConsumers(runtime)",
        "sealRootGlobalSessionBridges(runtime)",
    );
    assert_before(
        finish_bootstrap,
        "sealRootGlobalSessionBridges(runtime)",
        "verifyRootGlobalDisposition(runtime)",
    );
    let public_guard = source_section(
        BUILTIN_FS,
        "function _guardClosedFsMutation(",
        "function _getStreamModule(",
    );
    assert!(!public_guard.contains("g.__exactFsMutationGuard"));
    assert!(public_guard.contains("throw _makeFsError({ code: 'EPERM' }"));

    let mkdir = source_section(WINDOWS_FS, "auto mkdirFn =", "auto unaryClosedVoid =");
    assert!(mkdir.contains("PropNameID::forAscii(rt, \"__exactMkdir\"),\n      3,"));
    assert!(mkdir.contains("count > 2 && args[2].isNumber()"));
    assert_before(
        mkdir,
        "refuseClosedArmedFsRoute(runtime, \"mkdir\")",
        "auto path =",
    );
    assert!(mkdir.contains("mode >= 0 && ex_host_is_armed() != 1"));

    let unary_closed = source_section(WINDOWS_FS, "auto unaryClosedVoid =", "auto renameFn =");
    assert_before(
        unary_closed,
        "refuseClosedArmedFsMutation(runtime, syscall)",
        "pathArg(runtime, args[0])",
    );
    for hook in ["__exactRmdir", "__exactUnlink"] {
        assert!(
            unary_closed.contains(hook),
            "missing closed unary hook {hook}"
        );
    }

    for (start, end, operation, first_path_conversion) in [
        ("auto renameFn =", "auto copyFn =", "rename", "auto from ="),
        (
            "auto copyFn =",
            "auto realpathFn =",
            "copyfile",
            "auto from =",
        ),
        (
            "auto chmodFn =",
            "auto truncateFn =",
            "chmod",
            "auto path =",
        ),
        ("auto utimesFn =", "auto statfsFn =", "utime", "auto path ="),
        (
            "auto mkdtempFn =",
            "auto readFileAsyncFn =",
            "mkdtemp",
            "auto prefix =",
        ),
    ] {
        let entry = source_section(WINDOWS_FS, start, end);
        assert_before(
            entry,
            &format!("refuseClosedArmedFsMutation(runtime, \"{operation}\")"),
            first_path_conversion,
        );
    }

    assert!(WINDOWS_FS
        .contains("rt, \"__exactFsFsyncSync\", makeSync(\"__exactFsFsyncSync\", \"fsync\", 0)"));
    assert!(WINDOWS_FS.contains(
        "\"__exactFsFdatasyncSync\",\n      makeSync(\"__exactFsFdatasyncSync\", \"fdatasync\", 1)"
    ));
}

#[test]
fn windows_armed_residual_routes_close_before_legacy_effect_inputs() {
    let direct_routes = [
        (
            "auto writeFileFn =",
            "rt.global().setProperty(rt, \"__exactWriteFile\"",
            "refuseClosedArmedFsRoute(runtime, \"write\")",
            "exactResolveVfsPath(runtime",
        ),
        (
            "auto mkdirFn =",
            "auto unaryClosedVoid =",
            "refuseClosedArmedFsRoute(runtime, \"mkdir\")",
            "exactResolveVfsPath(",
        ),
        (
            "auto realpathFn =",
            "auto readlinkFn =",
            "refuseClosedArmedFsRoute(runtime, \"realpath\")",
            "exactResolveVfsPath(runtime",
        ),
        (
            "auto readlinkFn =",
            "auto accessFn =",
            "refuseClosedArmedFsRoute(runtime, \"readlink\")",
            "exactResolveVfsPath(runtime",
        ),
        (
            "auto accessFn =",
            "auto chmodFn =",
            "refuseClosedArmedFsRoute(runtime, \"access\")",
            "exactResolveVfsPath(",
        ),
        (
            "auto truncateFn =",
            "auto utimesFn =",
            "refuseClosedArmedFsRoute(runtime, \"truncate\")",
            "exactResolveVfsPath(runtime",
        ),
        (
            "auto statfsFn =",
            "auto mkdtempFn =",
            "refuseClosedArmedFsRoute(runtime, \"statfs\")",
            "exactResolveVfsPath(runtime",
        ),
        (
            "auto writeFileAsyncFn =",
            "auto fsReadAsyncFn =",
            "refuseClosedArmedFsRoute(runtime, \"write\")",
            "extractBytes(runtime, args[1])",
        ),
    ];
    for (start, end, refusal, first_effect_input) in direct_routes {
        let route = source_section(WINDOWS_FS, start, end);
        assert_before(route, refusal, first_effect_input);
    }

    let path_async = source_section(WINDOWS_FS, "auto fsPathAsyncFn =", "auto fsStatAsyncFn =");
    assert_before(
        path_async,
        "refuseClosedArmedFsRoute(runtime, op)",
        "auto rawA =",
    );
    assert_before(
        path_async,
        "refuseClosedArmedFsRoute(runtime, op)",
        "exactResolveVfsPath(runtime, rawA)",
    );

    let stat_async = source_section(WINDOWS_FS, "auto fsStatAsyncFn =", "auto makeSync =");
    assert_before(
        stat_async,
        "refuseClosedArmedFsRoute(runtime, kind)",
        "getFileEntry(runtime",
    );
    assert_before(
        stat_async,
        "refuseClosedArmedFsRoute(runtime, kind)",
        "exactResolveVfsPath(",
    );

    let writev_sync = source_section(BUILTIN_FS, "function writevSync(", "function readv(");
    assert!(writev_sync.contains("typeof g.__exactFsWritev !== 'function'"));
    assert_before(
        writev_sync,
        "_guardClosedFsMutation('writev')",
        "writeSync(fd, buffer",
    );
}
