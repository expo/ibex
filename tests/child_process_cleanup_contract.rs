//! Cross-host source contracts for spawned-process lifetime ownership. Live
//! POSIX behavior is covered by `child_process_native`; these checks keep the
//! Windows-only registry and the shared destruction hook from drifting on
//! non-Windows development hosts.

const POSIX_PROCESS: &str = include_str!("../src/engine/hermes_runtime_process.cc");
const WINDOWS_PROCESS: &str = include_str!("../src/engine/hermes_runtime_platform_windows.cc");
const CHILD_PROCESS_JS: &str = include_str!("../src/builtins/child-process.js");
const HERMES_RUNTIME: &str = include_str!("../src/engine/hermes_runtime.cc");
const HERMES_INTERNAL: &str = include_str!("../src/engine/hermes_runtime_internal.h");

#[test]
fn child_ref_and_unref_update_owner_validated_native_state() {
    for (name, source) in [("POSIX", POSIX_PROCESS), ("Windows", WINDOWS_PROCESS)] {
        assert!(
            source.contains("\"__exactSpawnSetReferenced\""),
            "{name} must register the native reference-state host function"
        );
        assert!(
            source.contains("handle belongs to a different runtime")
                && source.contains("currentPrincipalId()"),
            "{name} reference-state mutation must validate runtime and principal ownership"
        );
        assert!(
            source.contains("bool referenced = true;"),
            "{name} process entries must default to referenced"
        );
    }

    assert!(
        CHILD_PROCESS_JS.contains("_setNativeChildProcessReferenced(this, true);")
            && CHILD_PROCESS_JS.contains("_setNativeChildProcessReferenced(this, false);"),
        "ChildProcess.ref()/unref() must update native teardown state"
    );
}

#[test]
fn runtime_cleanup_preserves_unrefed_children_cross_platform() {
    assert!(
        POSIX_PROCESS.contains("reapUnreferencedSpawnEventually(proc->pid);")
            && POSIX_PROCESS.contains("if (proc->referenced)"),
        "POSIX teardown must preserve and asynchronously reap unref'ed children"
    );
    assert!(
        WINDOWS_PROCESS.contains("if (proc->referenced &&")
            && WINDOWS_PROCESS.contains("TerminateProcess(proc->process, 1)")
            && WINDOWS_PROCESS.contains("closeHandleIfValid(proc->process)"),
        "Windows teardown must terminate only referenced children and close unref'ed handles"
    );
    assert!(
        HERMES_RUNTIME.contains("exactCleanupRuntimeSpawnedProcesses(runtime->runtime_nonce);")
            && HERMES_INTERNAL.contains(
                "extern \"C\" void exactCleanupRuntimeSpawnedProcesses(uint64_t runtimeNonce);",
            ),
        "the shared runtime destructor must drain its native process registry"
    );
}
