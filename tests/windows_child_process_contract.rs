//! Cross-host source checks for cancellation and registration in the
//! Windows-only async child-process bridge. Windows CI supplies the live test;
//! these checks keep macOS/Linux development from silently removing the
//! cancellation primitives.

const WINDOWS_PROCESS: &str = include_str!("../src/engine/hermes_runtime_platform_windows.cc");
const CHILD_PROCESS: &str = include_str!("../src/builtins/child-process.js");

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

#[test]
fn windows_spawn_distinguishes_omitted_and_explicitly_empty_environment() {
    for required in [
        "struct WindowsEnvironmentOptions",
        "bool present = false",
        "env.present = findTopLevelJsonValue(optsJson, \"env\", pos)",
        "buildEnvironmentBlock(environment.entries, environment.present)",
        "environment.present ? applicationName.c_str() : nullptr",
        "environment.present ? const_cast<wchar_t*>(envBlock.data()) : nullptr",
    ] {
        assert!(
            WINDOWS_PROCESS.contains(required),
            "Windows spawn lost explicit environment presence: {required}"
        );
    }
    assert_eq!(
        WINDOWS_PROCESS
            .matches("environment.present ? applicationName.c_str() : nullptr")
            .count(),
        2,
        "sync and async CreateProcessW calls must both avoid inheriting env: {{}}"
    );
}

#[test]
fn windows_spawn_does_not_fallback_for_an_explicitly_empty_path() {
    for required in [
        "auto configuredPath = windowsEnvironmentValue(environment.entries, \"PATH\")",
        "std::string search = configuredPath.value_or(getenvString(\"PATH\"))",
        "return windowsJoinPath(childCwd, wideFile)",
    ] {
        assert!(
            WINDOWS_PROCESS.contains(required),
            "Windows child executable lookup lost PATH presence semantics: {required}"
        );
    }
}

#[test]
fn windows_spawn_rejects_every_unimplemented_extra_stdio_mode() {
    let sync_spawn = WINDOWS_PROCESS
        .split("std::string spawnSyncWindowsJson(")
        .nth(1)
        .expect("Windows sync spawn implementation")
        .split("struct WindowsSpawnPipeBuffer")
        .next()
        .unwrap();
    let async_spawn = WINDOWS_PROCESS
        .split("std::string spawnAsyncWindowsJson(")
        .nth(1)
        .expect("Windows async spawn implementation");

    for (backend, body) in [("sync", sync_spawn), ("async", async_spawn)] {
        assert!(
            body.contains("for (size_t i = 3; i < stdioModes.size(); ++i)"),
            "Windows {backend} spawn must inspect every extra stdio slot, including fd3"
        );
        assert!(
            body.contains("if (stdioModes[i] != \"ignore\")"),
            "Windows {backend} spawn must reject pipe, inherit, fd, and IPC modes in extra slots"
        );
    }
    assert!(
        WINDOWS_PROCESS
            .contains("std::vector<std::string> modes = {\"pipe\", \"pipe\", \"pipe\"};"),
        "the default Windows stdio vector must contain only stdin/stdout/stderr"
    );
    assert!(
        !WINDOWS_PROCESS.contains("modes[3] = mode;"),
        "string stdio shorthand must not synthesize an unsupported fd3 slot"
    );
    assert!(sync_spawn
        .contains("child_process extra stdio is not supported by the Windows sync spawn backend"));
    assert!(async_spawn
        .contains("child_process extra stdio is not supported by the Windows async spawn backend"));
}

#[test]
fn child_process_defaults_do_not_synthesize_an_extra_stdio_pipe() {
    let normalizer = CHILD_PROCESS
        .split("function _normalizeSpawnOptions(options, command)")
        .nth(1)
        .expect("child-process spawn option normalizer")
        .split("function _normalizeForkEnv")
        .next()
        .unwrap();
    let string_stdio = normalizer
        .split("if (typeof stdio === 'string')")
        .nth(1)
        .unwrap()
        .split("} else if (typeof stdio === 'number')")
        .next()
        .unwrap();
    let numeric_stdio = normalizer
        .split("} else if (typeof stdio === 'number')")
        .nth(1)
        .unwrap()
        .split("} else if (Array.isArray(stdio))")
        .next()
        .unwrap();

    assert_eq!(
        string_stdio
            .matches("_normalizeSpawnMode(stdio, 'pipe')")
            .count(),
        3,
        "stdio string shorthand must configure only stdin/stdout/stderr"
    );
    assert_eq!(
        numeric_stdio
            .matches("_normalizeSpawnMode(stdio, 'pipe')")
            .count(),
        3,
        "numeric stdio shorthand must configure only stdin/stdout/stderr"
    );
    assert!(normalizer.contains("normalized.stdio = ['pipe', 'pipe', 'pipe'];"));
    assert!(!normalizer.contains("normalized.stdio = ['pipe', 'pipe', 'pipe', 'pipe'];"));
    assert!(normalizer.contains("si < 3 ? 'pipe' : 'ignore'"));
    assert!(normalizer.contains("si2 < 3 ? 'pipe' : 'ignore'"));
    assert!(CHILD_PROCESS.contains("mappedSyncStdio[ssi] = ssi < 3 ? 'pipe' : 'ignore';"));
    assert!(
        CHILD_PROCESS.contains("normalizedStdio[si] = _normalizeSpawnMode(stdio[si], 'ignore');")
    );
}

#[test]
fn windows_spawn_rejects_ipc_stdio_in_every_slot() {
    let sync_spawn = WINDOWS_PROCESS
        .split("std::string spawnSyncWindowsJson(")
        .nth(1)
        .expect("Windows sync spawn implementation")
        .split("struct WindowsSpawnPipeBuffer")
        .next()
        .unwrap();
    let async_spawn = WINDOWS_PROCESS
        .split("std::string spawnAsyncWindowsJson(")
        .nth(1)
        .expect("Windows async spawn implementation");

    for (backend, body) in [("sync", sync_spawn), ("async", async_spawn)] {
        let ipc_rejection = body
            .find("if (mode == \"ipc\")")
            .unwrap_or_else(|| panic!("Windows {backend} spawn must inspect IPC in every slot"));
        let create_process = body
            .find("CreateProcessW(")
            .expect("Windows spawn must create a process");
        assert!(
            body[..ipc_rejection].contains("for (const auto& mode : stdioModes)"),
            "Windows {backend} spawn must reject IPC independent of its slot"
        );
        assert!(
            ipc_rejection < create_process,
            "Windows {backend} spawn must reject IPC before process creation"
        );
        assert!(body.contains(&format!(
            "child_process IPC is not supported by the Windows {backend} spawn backend"
        )));
    }
}

#[test]
fn windows_spawn_rejects_descriptor_stdio_in_every_slot() {
    let sync_spawn = WINDOWS_PROCESS
        .split("std::string spawnSyncWindowsJson(")
        .nth(1)
        .expect("Windows sync spawn implementation")
        .split("struct WindowsSpawnPipeBuffer")
        .next()
        .unwrap();
    let async_spawn = WINDOWS_PROCESS
        .split("std::string spawnAsyncWindowsJson(")
        .nth(1)
        .expect("Windows async spawn implementation");

    for (backend, body) in [("sync", sync_spawn), ("async", async_spawn)] {
        let fd_rejection = body
            .find("mode.size() > 3 && mode.substr(0, 3) == \"fd:\"")
            .or_else(|| {
                body.find("stdioModes[i].size() > 3 && stdioModes[i].substr(0, 3) == \"fd:\"")
            })
            .unwrap_or_else(|| {
                panic!("Windows {backend} spawn must reject fd:N before selecting stdio")
            });
        let extra_rejection = body
            .find("for (size_t i = 3; i < stdioModes.size(); ++i)")
            .expect("Windows spawn must inspect extra stdio slots");
        assert!(
            fd_rejection < extra_rejection,
            "Windows {backend} spawn must report fd:N explicitly, including in extra slots"
        );
        assert!(
            body.contains(&format!(
                "child_process fd:N stdio is not supported by the Windows {backend} spawn backend"
            )),
            "Windows {backend} spawn must return an explicit fd:N error"
        );
    }
}
