//! Cross-language source contract for the TLS engine's private selector and
//! native runtime/principal ownership boundary. Live Hermes tests cover the
//! behavior; these checks keep non-Hermes development builds from silently
//! weakening it.

const TLS_JS: &str = include_str!("../src/builtins/tls.js");
const TLS_RUST: &str = include_str!("../src/engine/tls_bridge.rs");
const TLS_JSI: &str = include_str!("../src/engine/hermes_runtime_tls.cc");

#[test]
fn javascript_keeps_engine_selectors_private_and_retryable() {
    assert!(TLS_JS.contains(
        "var _nativeTlsEngineIds = typeof WeakMap === 'function' ? new WeakMap() : null;"
    ));
    assert!(!TLS_JS.contains("socket._tlsEngineId ="));

    let release = TLS_JS
        .split("function _tlsBridgeRelease(socket) {")
        .nth(1)
        .expect("TLS release helper")
        .split("function _tlsBridgeFail")
        .next()
        .unwrap();
    let close = release
        .find("__exactTlsEngineClose(id);")
        .expect("native close call");
    let forget = release
        .find("_tlsDeleteEngineId(socket);")
        .expect("private selector deletion");
    assert!(
        close < forget,
        "a failed ownership-checked close must leave the selector retryable"
    );
}

#[test]
fn native_close_distinguishes_missing_from_wrong_owner() {
    let free = TLS_RUST
        .split("pub extern \"C\" fn ibex_tls_free(id: u64) -> i32 {")
        .nth(1)
        .expect("TLS native release")
        .split("pub extern \"C\" fn ibex_tls_cleanup_runtime")
        .next()
        .unwrap();
    assert!(free.contains("owned.runtime_nonce != runtime_nonce"));
    assert!(free.contains("owned.owner != principal"));
    assert!(free.contains("return -1;"));
    assert!(free.contains("return -2;"));
    assert!(free.contains("return 0;"));
    assert!(free.contains("map.remove(&id);"));

    assert!(TLS_JSI.contains("int32_t ibex_tls_free(uint64_t id);"));
    assert!(TLS_JSI.contains("const int32_t closed = ibex_tls_free(id);"));
    assert!(TLS_JSI.contains("if (closed == -2)"));
    assert!(TLS_JSI.contains("if (closed < 0)"));
    assert!(TLS_JSI.contains("engine has an in-progress read"));
    assert!(TLS_JSI.contains("engine belongs to another runtime or principal"));
}
