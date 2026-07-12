const ANDROID_NETWORKING: &str =
    include_str!("../platform/android/java/dev/ibex/runtime/IbexNetworking.java");

#[test]
fn paused_android_websockets_bound_count_and_bytes_and_close_on_overflow() {
    for required in [
        "MAX_WS_PENDING_MESSAGES",
        "MAX_WS_PENDING_BYTES",
        "entry.pending.size() >= MAX_WS_PENDING_MESSAGES",
        "nextBytes > MAX_WS_PENDING_BYTES",
        "entry.pendingBytes = nextBytes",
        "entry.pendingBytes -= message.bytes.length",
        "overflowSocket.close(1009, \"Receive queue overflow\")",
        "text.getBytes(StandardCharsets.UTF_8)",
        "bytes.toByteArray()",
        "entry.pending.clear()",
        "entry.pendingBytes = 0",
        "clearPendingMessages(entry)",
    ] {
        assert!(
            ANDROID_NETWORKING.contains(required),
            "Android WebSocket backpressure contract is missing {required:?}"
        );
    }
}
