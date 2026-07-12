//! Cross-target source contracts for runtime callback generation and teardown.
//!
//! Windows/Android producers are not compiled on every CI host, so this keeps
//! the security invariant visible wherever the repository is tested.

use std::path::Path;

fn source(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

#[test]
fn registry_identity_is_pointer_plus_nonce_with_an_explicit_closing_phase() {
    let runtime = source("src/engine/hermes_runtime.cc");
    let header = source("src/engine/hermes_runtime_internal.h");

    assert!(header.contains("struct RuntimeCallbackTarget"));
    assert!(header.contains("ExactHermesRuntime* runtime{nullptr};"));
    assert!(header.contains("uint64_t nonce{0};"));
    assert!(runtime.contains("std::unordered_map<ExactHermesRuntime*, RuntimeRegistryEntry>"));
    assert!(runtime.contains("enum class RuntimeLifecycleState"));
    assert!(runtime.contains("Running") && runtime.contains("Closing"));
    assert!(runtime.contains("it->second.nonce == target.nonce"));
    assert!(runtime.contains("beginRuntimeTeardown(target)"));
    assert!(runtime.contains("finishRuntimeTeardown(target)"));
}

#[test]
fn dead_runtime_callbacks_are_not_intentionally_leaked() {
    let runtime = source("src/engine/hermes_runtime.cc");
    let push = runtime
        .split("void pushRuntimeCallback(")
        .nth(1)
        .and_then(|tail| tail.split("bool pushRuntimeFinalizer(").next())
        .expect("pushRuntimeCallback body");

    assert!(push.contains("RuntimeCallbackTarget target"));
    assert!(push.contains("runtimeTargetMatchesLocked(target, true)"));
    assert!(!push.contains("new std::function"));
    assert!(!push.contains("leak-on-dead-runtime"));
    assert!(runtime.contains("discardRuntimeCallbacksOnOwnerThread(runtime)"));
    assert!(runtime.contains("drainRuntimeFinalizers(runtime)"));
}

#[test]
fn every_jsi_bearing_worker_family_holds_a_teardown_pin() {
    for path in [
        "src/engine/hermes_runtime_dns.cc",
        "src/engine/hermes_runtime_fs.cc",
        "src/engine/hermes_runtime_fs_windows.cc",
        "src/engine/hermes_runtime_http.cc",
        "src/engine/hermes_runtime_fetch.cc",
        "src/engine/hermes_runtime_websocket.cc",
        "src/engine/hermes_runtime_android.cc",
    ] {
        let text = source(path);
        assert!(
            text.contains("exactPinRuntimeNativeWorker(target)"),
            "{path} must pin its exact runtime generation before JSI leaves the owner thread"
        );
        assert!(
            text.contains("exactUnpinRuntimeNativeWorker"),
            "{path} must retire its producer pin"
        );
        assert!(
            text.split("pushRuntimeCallback(").skip(1).any(|tail| {
                let tail = tail.trim_start();
                tail.starts_with("target,")
                    || tail.starts_with("t.target,")
                    || tail.starts_with("entry.target,")
            }),
            "{path} must enqueue with a nonce-bearing target"
        );
    }
}

#[test]
fn unpinned_event_sources_also_carry_generation_tokens() {
    let runtime = source("src/engine/hermes_runtime.cc");
    let signal = source("src/engine/hermes_runtime_crypto.cc");
    let android = source("src/engine/hermes_runtime_android.cc");
    let debugger = source("src/engine/hermes_runtime_debugger.cc");

    assert!(signal.contains("RuntimeCallbackTarget g_signal_runtime"));
    assert!(signal.contains("unregisterSignalRuntime"));
    assert!(signal.contains("pushRuntimeCallback(target"));
    assert!(android.contains("std::vector<RuntimeCallbackTarget> runtimes"));
    assert!(android.contains("pushRuntimeCallback(target"));
    assert!(debugger.contains("withRuntimePinned(target"));
    assert!(runtime.contains("auto target = registeredRuntimeCallbackTarget(runtime);"));
}

#[test]
fn delayed_fetch_and_host_call_completions_resolve_target_before_deref() {
    let runtime = source("src/engine/hermes_runtime.cc");
    let fetch = source("src/engine/hermes_runtime_fetch.cc");

    assert!(fetch.contains("std::unordered_map<uint32_t, RuntimeCallbackTarget> g_fetchTargets"));
    assert!(fetch.contains("auto target = takeFetchTarget(req_id);"));
    assert!(fetch.contains("if (!target || !exactPinRuntimeNativeWorker(target)) return;"));
    assert!(
        runtime.contains("std::unordered_map<uint64_t, RuntimeCallbackTarget> g_hostCallTargets")
    );
    assert!(runtime.contains("auto target = takeHostCallTarget(runtime, call_id);"));
    assert!(runtime.contains("forgetHostCallTargets(target);"));
}

#[test]
fn websocket_final_release_is_marshaled_without_a_leak_fallback() {
    let runtime = source("src/engine/hermes_runtime.cc");
    let websocket = source("src/engine/hermes_runtime_websocket.cc");

    assert!(websocket.contains("callbackContext->runtime_pin_held = true;"));
    assert!(runtime.contains("pushRuntimeFinalizer(target, [ctx]() { delete ctx; })"));
    assert!(runtime.contains("backlog += runtime->finalizerQueue.size();"));
    assert!(runtime.contains("exactUnpinRuntimeNativeWorker(target);"));
    assert!(!runtime.contains("intentionally leak the context"));
}
