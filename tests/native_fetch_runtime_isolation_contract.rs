use std::path::Path;

fn source(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

#[test]
fn every_native_fetch_backend_accepts_and_checks_the_runtime_nonce() {
    for path in [
        "src/engine/native_fetch_linux.cc",
        "src/engine/native_fetch_macos.mm",
        "src/engine/native_fetch_windows.cc",
        "src/engine/native_android_networking.cc",
    ] {
        let text = source(path);
        let perform = text
            .split("native_fetch_perform(")
            .nth(1)
            .unwrap_or_else(|| panic!("{path} lacks native_fetch_perform"));
        assert!(
            perform.contains("uint64_t runtime_nonce"),
            "{path} must receive the owner nonce before registering a request"
        );
        let cancel = text
            .split("native_fetch_cancel(")
            .nth(1)
            .unwrap_or_else(|| panic!("{path} lacks native_fetch_cancel"));
        assert!(
            cancel.contains("uint64_t runtime_nonce"),
            "{path} must receive the cancelling runtime nonce"
        );
        assert!(
            text.contains("runtime_nonce != runtime_nonce")
                || text.contains("runtime_nonce != runtimeNonce")
                || text.contains("unsignedLongLongValue] != runtime_nonce"),
            "{path} must compare the registered owner before cancellation"
        );
    }
}

#[test]
fn fetch_ids_are_process_global_and_never_runtime_local() {
    let bridge = source("src/engine/hermes_runtime_fetch.cc");
    let runtime = source("src/engine/hermes_runtime_internal.h");
    assert!(bridge.contains("std::atomic<uint32_t> g_nextFetchId{1}"));
    assert!(bridge.contains("allocateFetchId()"));
    assert!(bridge.contains("handle->runtime_nonce"));
    assert!(
        !runtime.contains("nextFetchId"),
        "per-runtime counters collide in process-global native backend maps"
    );
}
