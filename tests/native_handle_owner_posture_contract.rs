use std::path::Path;

fn source(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|error| panic!("failed to read {path}: {error}"))
}

fn function_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing function {signature}"));
    let open = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .unwrap();
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
    panic!("unterminated function {signature}");
}

fn assert_owner_precedes_allow_all(body: &str, owner_check: &str, bypass: &str) {
    let owner = body
        .find(owner_check)
        .unwrap_or_else(|| panic!("missing unconditional owner check {owner_check:?}\n{body}"));
    let bypass = body
        .find(bypass)
        .unwrap_or_else(|| panic!("missing allow-all authorization bypass {bypass:?}\n{body}"));
    assert!(
        owner < bypass,
        "allow-all bypass executes before numeric-handle ownership check\n{body}"
    );
}

fn assert_owner_precedes_live_authority(body: &str) {
    let owner = body
        .find("if (entry.owner != currentPrincipalId())")
        .unwrap_or_else(|| panic!("missing unconditional owner check\n{body}"));
    let live_authority = body
        .find("if (requireLiveAuthority &&")
        .unwrap_or_else(|| panic!("missing explicit live-authority check\n{body}"));
    assert!(
        owner < live_authority,
        "live authority was checked before numeric-handle ownership\n{body}"
    );
}

fn assert_numeric_validation_precedes_cast(
    body: &str,
    number_name: &str,
    cast: &str,
    extra_upper_bound: Option<&str>,
) {
    let cast_position = body
        .find(cast)
        .unwrap_or_else(|| panic!("missing guarded numeric cast {cast:?}\n{body}"));
    for guard in [
        format!("std::isfinite({number_name})"),
        format!("{number_name} < 1.0"),
        "kMaxSafeInteger".to_string(),
        format!("std::floor({number_name}) != {number_name}"),
    ] {
        let guard_position = body
            .find(&guard)
            .unwrap_or_else(|| panic!("missing numeric guard {guard:?}\n{body}"));
        assert!(
            guard_position < cast_position,
            "numeric cast executes before guard {guard:?}\n{body}"
        );
    }
    if let Some(upper_bound) = extra_upper_bound {
        let bound_position = body
            .find(upper_bound)
            .unwrap_or_else(|| panic!("missing cast-width guard {upper_bound:?}\n{body}"));
        assert!(
            bound_position < cast_position,
            "numeric cast executes before width guard {upper_bound:?}\n{body}"
        );
    }
}

#[test]
fn allow_all_never_bypasses_primary_native_handle_ownership() {
    let http = source("src/engine/hermes_runtime_http.cc");
    let sqlite = source("src/engine/hermes_runtime_sqlite.cc");
    let websocket = source("src/engine/hermes_runtime_websocket.cc");
    let net = source("src/engine/hermes_runtime_net.cc");
    let windows_net = source("src/engine/hermes_runtime_platform_windows.cc");

    let http_owner = function_body(&http, "bool requireHttpServerOwner(");
    assert!(http_owner.contains("if (entry.owner != currentPrincipalId())"));

    let websocket_owner = function_body(&websocket, "WebSocketEntry requireWebSocketOwner(");
    assert!(websocket_owner.contains("if (entry.owner != currentPrincipalId())"));

    for signature in [
        "SqliteHandleEntry requireSqliteDb(",
        "SqliteStatementEntry requireSqliteStatement(",
    ] {
        let body = function_body(&sqlite, signature);
        assert_owner_precedes_allow_all(
            body,
            "if (entry.owner != currentPrincipalId())",
            "if (requireLiveAuthority && !isAllowAll())",
        );
    }

    let typed_io = function_body(&net, "LockedSocketIo requireSocketIo(");
    assert_owner_precedes_allow_all(
        typed_io,
        "if (entry.owner != currentPrincipalId())",
        "if (isAllowAll()) return",
    );
    let generic_socket = function_body(&net, "SocketEntry requireSocketHandle(");
    assert_owner_precedes_allow_all(
        generic_socket,
        "if (entry.owner != currentPrincipalId())",
        "if (!isAllowAll())",
    );

    let windows_socket = function_body(&windows_net, "WindowsSocketEntry requireWindowsSocket(");
    assert_owner_precedes_allow_all(
        windows_socket,
        "if (entry.owner != currentPrincipalId())",
        "if (!isAllowAll())",
    );
}

#[test]
fn authority_reducing_release_survives_positive_grant_revocation() {
    let http = source("src/engine/hermes_runtime_http.cc");
    let sqlite = source("src/engine/hermes_runtime_sqlite.cc");
    let websocket = source("src/engine/hermes_runtime_websocket.cc");

    let http_owner = function_body(&http, "bool requireHttpServerOwner(");
    assert!(http_owner.contains("bool requireLiveAuthority = true"));
    assert_owner_precedes_live_authority(http_owner);
    assert!(http.contains("runtime, server_id, \"__exactHttpClose\", false"));
    assert!(http.contains("runtime, server_id, \"__exactHttpRespondAbort\", false"));
    assert!(http.contains("runtime, server_id, \"__exactHttpRespondEnd\", false"));
    assert!(http.contains("runtime, server_id, \"__exactHttpRespondEndTry\", false"));
    assert!(http.contains("runtime, server_id, \"__exactHttpOwner\", false"));
    assert_eq!(
        http.matches("\"__exactHttpClose\", false").count(),
        1,
        "only HTTP close may bypass live positive authority"
    );
    assert_eq!(
        http.matches("\"__exactHttpRespondAbort\", false").count(),
        1,
        "only HTTP response abort may skip live positive authority"
    );
    assert_eq!(
        http.matches("\"__exactHttpRespondEnd\", false").count(),
        1,
        "HTTP response end must remain available after revocation"
    );
    assert_eq!(
        http.matches("\"__exactHttpRespondEndTry\", false").count(),
        1,
        "non-blocking HTTP response end must remain available after revocation"
    );
    assert_eq!(
        http.matches("\"__exactHttpOwner\", false").count(),
        1,
        "the non-mutating HTTP owner check must ignore positive grant revocation"
    );

    for signature in [
        "SqliteHandleEntry requireSqliteDb(",
        "SqliteStatementEntry requireSqliteStatement(",
    ] {
        let body = function_body(&sqlite, signature);
        assert!(body.contains("bool requireLiveAuthority = true"));
        assert_owner_precedes_live_authority(body);
    }
    assert_eq!(
        sqlite.matches("\"__exactSqliteClose\", false").count(),
        1,
        "only SQLite database close may skip its live authority check"
    );
    assert_eq!(
        sqlite.matches("\"__exactSqliteFinalize\", false").count(),
        1,
        "only SQLite statement finalization may skip its live authority check"
    );

    let websocket_owner = function_body(&websocket, "WebSocketEntry requireWebSocketOwner(");
    assert!(websocket_owner.contains("bool requireLiveAuthority = true"));
    assert_owner_precedes_live_authority(websocket_owner);
    assert_eq!(
        websocket.matches("\"__exactWsClose\", false").count(),
        1,
        "only WebSocket close may skip its live authority check"
    );
}

#[test]
fn allow_all_never_bypasses_transfer_release_or_mutation_ownership() {
    let posix_fs = source("src/engine/hermes_runtime_fs.cc");
    let windows_fs = source("src/engine/hermes_runtime_fs_windows.cc");
    let net = source("src/engine/hermes_runtime_net.cc");

    let consume = function_body(
        &posix_fs,
        "bool exactConsumeTransferableFdForCurrentPrincipal(",
    );
    assert!(consume.contains("it->second.principal != principal"));
    assert!(!consume.contains("!isAllowAll() && it->second.principal"));

    assert!(!windows_fs.contains("!isAllowAll() && it->second.owner"));
    assert!(!net.contains("!isAllowAll() && entry.owner"));
    assert!(!net.contains("!isAllowAll() && it->second.owner"));
    assert!(!net.contains("isAllowAll() || it->second.owner"));

    let raw_adoption = function_body(&net, "void requireRawSocketAdoptionAllowed(");
    assert!(raw_adoption.contains("exactConsumeTransferableFdForCurrentPrincipal(fd)"));
    assert!(
        !raw_adoption.contains("isAllowAll()"),
        "permissive packages must still prove ownership before adopting a raw fd"
    );
}

#[test]
fn retained_net_socket_owner_stamp_is_cross_platform_and_captured() {
    let net_js = source("src/builtins/net.js");
    let posix = source("src/engine/hermes_runtime_net.cc");
    let windows = source("src/engine/hermes_runtime_platform_windows.cc");

    assert!(net_js.contains(
        "var _netOwnerHost = typeof __exactNetOwner === 'function' ? __exactNetOwner : null;"
    ));
    assert!(net_js.contains("_netOwnerHost('assert', state.ownerStamp, nativeHandle)"));
    assert!(net_js.contains("var _drainWriteQueueOwned = Socket.prototype._drainWriteQueue"));

    for platform in [&posix, &windows] {
        assert!(platform.contains("\"__exactNetOwner\""));
        assert!(platform.contains("action == \"new\""));
        assert!(platform.contains("action != \"assert\""));
        assert!(platform.contains("runtimeNonce != exactCurrentRuntimeNonce()"));
        assert!(platform.contains("owner != currentPrincipalId()"));
    }
    assert!(posix.contains("cleanupRuntimeNetOwnerStamps(runtimeNonce)"));
    assert!(windows.contains("g_windows_net_owner_stamps.erase(it)"));
}

#[test]
fn owner_host_numeric_selectors_are_validated_before_native_casts() {
    let http = source("src/engine/hermes_runtime_http.cc");
    let posix = source("src/engine/hermes_runtime_net.cc");
    let windows = source("src/engine/hermes_runtime_platform_windows.cc");
    let tls = source("src/engine/hermes_runtime_tls.cc");

    for (platform, stamp_signature, handle_signature, handle_call) in [
        (
            &posix,
            "void requireNetOwnerStamp(",
            "int requireNetOwnerSocketHandle(",
            "requireNetOwnerSocketHandle(runtime, args[2])",
        ),
        (
            &windows,
            "void requireWindowsNetOwnerStamp(",
            "int requireWindowsNetOwnerSocketHandle(",
            "requireWindowsNetOwnerSocketHandle(runtime, args[2])",
        ),
    ] {
        assert_numeric_validation_precedes_cast(
            function_body(platform, stamp_signature),
            "number",
            "static_cast<uint64_t>(number)",
            None,
        );
        assert_numeric_validation_precedes_cast(
            function_body(platform, handle_signature),
            "number",
            "static_cast<int>(number)",
            Some("std::numeric_limits<int>::max()"),
        );
        let installer = function_body(platform, "void installNetOwnerHostFunction(");
        assert!(installer.contains(handle_call));
        assert!(!installer.contains("static_cast<int>(args[2].asNumber())"));
    }

    assert_numeric_validation_precedes_cast(
        function_body(&http, "bool parseHttpOwnerServerId("),
        "number",
        "static_cast<uint32_t>(number)",
        Some("std::numeric_limits<uint32_t>::max()"),
    );
    let http_installer = function_body(&http, "void installHttpHostFunctions(");
    assert!(http_installer.contains("parseHttpOwnerServerId(args[0], server_id)"));

    // The other newly retained native owner-token boundary already follows
    // the same safe-JavaScript-integer rule; keep it in this contract so a
    // future shared refactor cannot reintroduce unchecked floating-point casts.
    assert_numeric_validation_precedes_cast(
        function_body(&tls, "uint64_t requireTlsOwnerToken("),
        "value",
        "static_cast<uint64_t>(value)",
        None,
    );
}

#[test]
fn retained_net_owner_is_installed_once_before_websocket_bootstrap() {
    let runtime = source("src/engine/hermes_runtime.cc");
    let internal = source("src/engine/hermes_runtime_internal.h");
    let posix = source("src/engine/hermes_runtime_net.cc");
    let windows = source("src/engine/hermes_runtime_platform_windows.cc");

    assert!(internal.contains("void installNetOwnerHostFunction(ExactHermesRuntime* handle);"));

    let owner_install = runtime
        .find("installNetOwnerHostFunction(handle);")
        .expect("runtime must eagerly install the retained network owner");
    let websocket_install = runtime
        .find("installWebSocketGlobals(handle);")
        .expect("runtime must install the WebSocket native bridge");
    let shared_runtime_install = runtime
        .find("sharedRuntimeInstalled = installModuleLoader(handle);")
        .expect("runtime must install the shared runtime bundle");
    assert!(
        owner_install < websocket_install && websocket_install < shared_runtime_install,
        "the owner primitive must exist before both WebSocket shims and the shared bundle"
    );
    assert_eq!(
        runtime
            .matches("installNetOwnerHostFunction(handle);")
            .count(),
        1,
        "startup must not replace the captured owner function"
    );

    for platform in [&posix, &windows] {
        assert_eq!(
            platform
                .matches("void installNetOwnerHostFunction(")
                .count(),
            1,
            "each selected platform must define one owner installer"
        );
        let owner = function_body(platform, "void installNetOwnerHostFunction(");
        assert!(owner.contains("\"__exactNetOwner\""));
        assert!(!owner.contains("ensureWinsock()"));

        let full_net = function_body(platform, "void installNetHostFunctions(");
        assert!(
            !full_net.contains("\"__exactNetOwner\""),
            "lazy full-net setup must not replace the eagerly captured owner function"
        );
    }
    assert!(
        function_body(&windows, "void installNetHostFunctions(").contains("ensureWinsock()"),
        "Winsock initialization must remain lazy with the full net surface"
    );
}

#[test]
fn retained_http_response_owner_check_is_captured_and_revocation_safe() {
    let http_js = source("src/builtins/http.js");
    let http_native = source("src/engine/hermes_runtime_http.cc");

    assert!(http_js.contains(
        "var _httpOwnerHost = typeof __exactHttpOwner === 'function' ? __exactHttpOwner : null;"
    ));
    assert!(http_js.contains(
        "var _httpNetOwnerHost = typeof __exactNetOwner === 'function' ? __exactNetOwner : null;"
    ));
    assert_eq!(
        http_js
            .matches("_httpNetOwnerHost('new')")
            .count(),
        2,
        "ServerResponse and http.Server each need a fresh-owner construction path"
    );
    assert!(http_js.contains("_httpNetOwnerHost('assert', state.ownerStamp)"));
    assert!(http_js.contains("_httpOwnerHost(state.serverId) !== true"));
    assert!(http_js.contains("function _sealHttpOwnedOwnProperties("));
    assert!(http_js.contains("function _sealHttpInheritedProperties("));
    assert!(http_js.contains("_sealHttpServerOwnerState(this);"));
    assert!(http_js.contains("_installServerResponseCopiedProperty(target, name, descriptor)"));
    assert!(
        http_js.contains("_assertServerResponseOwner(response);\n      return state.ownerSocket;")
    );
    assert!(http_native.contains("\"__exactHttpOwner\""));
    assert!(http_native.contains("runtime, server_id, \"__exactHttpOwner\", false"));
}
