//! Cross-host source contracts for native WebSocket callback lifetime and
//! terminal event ordering. Linux-specific C++ is not compiled on macOS or
//! Windows CI, so keep the ownership invariant visible on every host.

#[test]
fn linux_callback_context_is_snapshotted_under_the_teardown_lock() {
    let source = include_str!("../src/engine/native_websocket_linux.cc");

    assert!(
        source.contains("std::mutex context_mutex;"),
        "Linux WebSocket entries need a callback-context teardown lock"
    );
    assert!(
        source.contains("static void* acquire_context(")
            && source.contains("std::lock_guard<std::mutex> lock(entry->context_mutex);")
            && source.contains("native_ws_retain_context(entry->context);"),
        "callbacks must snapshot and retain the context atomically"
    );
    assert!(
        source.contains("static void release_context(")
            && source.contains("context = entry->context;\n        entry->context = nullptr;")
            && source.contains("release_context(entry);"),
        "teardown must null the context under the same lock before releasing it"
    );
    assert_eq!(
        source.matches("= acquire_context(entry);").count(),
        5,
        "open/message/error/close/bytes-sent callbacks must all use a retained snapshot"
    );
}

#[test]
fn error_does_not_consume_the_nonzero_socket_close_notification() {
    let source = include_str!("../src/engine/hermes_runtime_websocket.cc");
    let error_callback = source
        .split("[](uint32_t ws_id, const char* message, void* ctx)")
        .nth(1)
        .and_then(|tail| tail.split("[](uint32_t ws_id, size_t bytes_sent").next())
        .expect("WebSocket error callback body");

    assert!(
        error_callback.contains("if (ws_id == 0)")
            && error_callback.contains("unregisterWebSocket(0, context)")
            && error_callback.contains("webSocketCallbackIsCurrent(ws_id, context)")
            && error_callback.contains("if (closeAfterError)")
            && error_callback.contains("getPropertyAsFunction(rt, \"_handleClose\")"),
        "a zero-id setup error must synthesize close; a live socket must preserve its native close"
    );
    assert!(
        !error_callback.contains("unregisterWebSocket(ws_id, context)"),
        "a nonzero error must not unregister the socket before native close arrives"
    );
}
