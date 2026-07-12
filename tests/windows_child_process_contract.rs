//! Cross-host source checks for cancellation and registration in the
//! Windows-only async child-process bridge. Windows CI supplies the live test;
//! these checks keep macOS/Linux development from silently removing the
//! cancellation primitives.

const WINDOWS_PROCESS: &str = include_str!("../src/engine/hermes_runtime_platform_windows.cc");

#[test]
fn windows_stdin_writer_is_cancelable_and_pipe_close_is_serialized() {
    for required in [
        "HANDLE stdinWriterThread",
        "DuplicateHandle(",
        "CancelSynchronousIo(proc->stdinWriterThread)",
        "requestWindowsStdinClose(proc, true, true)",
    ] {
        assert!(
            WINDOWS_PROCESS.contains(required),
            "missing Windows stdin cancellation primitive: {required}"
        );
    }
    assert!(
        WINDOWS_PROCESS.contains("std::lock_guard<std::mutex> lock(proc->stdinMutex);"),
        "stdin teardown must serialize against the writer"
    );
}

#[test]
fn windows_spawn_sync_host_registration_has_one_name_and_one_arity() {
    let start = WINDOWS_PROCESS
        .find("auto spawnSyncFn")
        .expect("spawnSync registration");
    let end = WINDOWS_PROCESS[start..]
        .find("rt.global().setProperty(rt, \"__exactSpawnSync\"")
        .expect("spawnSync setProperty");
    let registration = &WINDOWS_PROCESS[start..start + end];
    assert_eq!(
        registration.matches("PropNameID::forAscii").count(),
        1,
        "createFromHostFunction must receive exactly one property-name argument"
    );
    assert!(registration.contains("\"__exactSpawnSync\"),\n      3,"));
}
