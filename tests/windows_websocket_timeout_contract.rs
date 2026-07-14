//! Source contract for the WinHTTP WebSocket timeout split. This runs on every
//! host so non-Windows CI still catches a regression that would otherwise need
//! a Windows socket to remain idle for more than five minutes.

#[test]
fn healthy_windows_websocket_has_no_receive_timeout_but_close_is_bounded() {
    let source = include_str!("../src/engine/native_websocket_windows.cc");
    assert!(
        source.contains("WinHttpSetTimeouts(session, 30000, 30000, 30000, 0)"),
        "the normal receive timeout must remain infinite for >5-minute idle sockets"
    );
    assert!(
        source.contains("WinHttpSetTimeouts(entry->session, 30000, 30000, 30000, 5000)"),
        "only a locally initiated close may install the five-second bound"
    );
    assert_eq!(
        source.matches("30000, 30000, 30000, 5000").count(),
        1,
        "the close-only timeout must not leak into connection setup"
    );
    assert!(
        source.contains("close_callback_sent.exchange(true"),
        "timed-out and acknowledged close paths must share an exactly-once callback gate"
    );
}
