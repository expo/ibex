//! Cross-platform source contract for the Windows-only WebSocket shim. The
//! behavioral companion test executes the embedded JavaScript under Bun, but
//! this keeps the owner/retry ordering covered in the default Cargo matrix too.

fn windows_websocket_shim(source: &str) -> &str {
    let marker = "static const char* windowsWebSocketShim = R\"JS(";
    let start = source
        .find(marker)
        .map(|offset| offset + marker.len())
        .expect("missing Windows WebSocket shim");
    let end = source[start..]
        .find(")JS\";")
        .map(|offset| start + offset)
        .expect("unterminated Windows WebSocket shim");
    &source[start..end]
}

fn javascript_function<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing JavaScript function {signature}"));
    let open = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .expect("function has no body");
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated JavaScript function {signature}");
}

#[test]
fn selector_and_callback_driven_lifecycle_are_not_public_wrapper_state() {
    let source = include_str!("../src/engine/hermes_runtime_websocket.cc");
    let shim = windows_websocket_shim(source);

    assert!(shim.contains("var windowsWebSocketStates = new WeakMap();"));
    assert!(shim.contains("windowsWebSocketStates.set(this, state);"));
    assert!(shim.contains("var exactWsConnect = g.__exactWsConnect;"));
    assert!(shim.contains("var exactWsSend = g.__exactWsSend;"));
    assert!(shim.contains("var exactWsClose = g.__exactWsClose;"));
    assert!(shim.contains("var exactNetOwner = g.__exactNetOwner;"));
    assert!(shim.contains("ownerStamp: exactNetOwner('new')"));
    assert!(shim.contains("exactNetOwner('assert', state.ownerStamp);"));
    assert!(shim.contains("exactWsConnect(state.url, String(protocolList), bridge)"));
    assert!(!shim.contains("this._socketId"));
    assert!(!shim.contains("this._handleOpen"));
    assert!(!shim.contains("WebSocket.prototype._handleOpen"));
    assert!(!shim.contains("exactWsSend(this."));
    assert!(!shim.contains("exactWsClose(this."));
}

#[test]
fn native_owner_checked_close_succeeds_before_terminal_js_commit() {
    let source = include_str!("../src/engine/hermes_runtime_websocket.cc");
    let shim = windows_websocket_shim(source);
    let close = javascript_function(shim, "WebSocket.prototype.close = function(");

    let native_close = close
        .find("exactWsClose(")
        .expect("close must reach the native owner boundary");
    let terminal_commit = close
        .find("state.readyState = WebSocket.CLOSING")
        .expect("close must commit CLOSING after native success");
    assert!(
        native_close < terminal_commit,
        "foreign owner denial must not poison the retained wrapper before an owner retry\n{close}"
    );
    assert!(close.contains("state.socketId"));
}

#[test]
fn native_owner_preflight_precedes_send_data_and_buffer_mutation() {
    let source = include_str!("../src/engine/hermes_runtime_websocket.cc");
    let shim = windows_websocket_shim(source);
    let send = javascript_function(shim, "WebSocket.prototype.send = function(");

    let owner_preflight = send
        .find("exactWsSend(state.socketId, undefined)")
        .expect("send must authenticate before queue-visible work");
    let data_read = send
        .find("typeof data")
        .expect("send must inspect the payload");
    let buffer_commit = send
        .find("state.bufferedAmount += bytes")
        .expect("send must account buffered bytes");
    let native_send = send
        .rfind("exactWsSend(state.socketId, data)")
        .expect("send must reach the native transport");

    assert!(owner_preflight < data_read);
    assert!(owner_preflight < buffer_commit);
    assert!(owner_preflight < native_send);
}

#[test]
fn message_delivery_requires_an_open_socket() {
    let source = include_str!("../src/engine/hermes_runtime_websocket.cc");
    let shim = windows_websocket_shim(source);
    let handle_message = javascript_function(shim, "function handleMessage(");

    assert!(
        handle_message.contains("state.readyState !== WebSocket.OPEN"),
        "queued messages must not be delivered after close enters CLOSING\n{handle_message}"
    );
}
