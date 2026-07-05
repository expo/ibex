//! Engine support utilities
//!
//! The C++ Hermes adapter (`hermes_runtime.cc`) is compiled by build.rs and
//! linked into this crate. It exposes C functions (`ex_hermes_create`,
//! `ex_hermes_eval`, `ex_hermes_poll`, etc.) that can be called from both
//! Rust (via the CLI's hermes.rs wrapper) and Swift (via the bridging header).
//!
//! This module provides supporting utilities like source map handling.

pub mod sourcemap;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Flag set when a background callback is pushed.
/// iOS polls this to know when to wake up the event loop.
static CALLBACK_PENDING: AtomicBool = AtomicBool::new(false);

/// Host wake hook (exact LLP 0297 W4b/B8): a wake-driven host executor
/// parks its runtime thread on a condition variable instead of polling the
/// pending flag, so it needs a push notification when a cross-thread
/// callback lands. Stored as raw words so invocation from arbitrary
/// threads is lock-free. Registration is expected once at host boot;
/// re-registration is not synchronized against a concurrent notify (a
/// racing reader may pair the new fn with the old context).
static HOST_WAKE_HOOK_FN: AtomicUsize = AtomicUsize::new(0);
static HOST_WAKE_HOOK_CTX: AtomicUsize = AtomicUsize::new(0);

/// Register (or clear, with `None`) the host wake hook invoked whenever a
/// background thread pushes a runtime callback. The hook runs on the
/// pushing thread and must only do cheap, bounded work (enqueue + signal a
/// condvar). Only the default (non-`cli-notify`) notify path invokes it —
/// the CLI's tokio-based notify has its own wake mechanism.
#[no_mangle]
pub extern "C" fn ex_hermes_set_host_wake_hook(
    hook: Option<extern "C" fn(*mut std::ffi::c_void)>,
    context: *mut std::ffi::c_void,
) {
    HOST_WAKE_HOOK_CTX.store(context as usize, Ordering::Release);
    HOST_WAKE_HOOK_FN.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

fn invoke_host_wake_hook() {
    let raw_fn = HOST_WAKE_HOOK_FN.load(Ordering::Acquire);
    if raw_fn == 0 {
        return;
    }
    let context = HOST_WAKE_HOOK_CTX.load(Ordering::Acquire) as *mut std::ffi::c_void;
    // SAFETY: raw_fn was stored from a valid `extern "C" fn(*mut c_void)`
    // in ex_hermes_set_host_wake_hook and is only transmuted back to that
    // exact type.
    let hook: extern "C" fn(*mut std::ffi::c_void) = unsafe { std::mem::transmute(raw_fn) };
    hook(context);
}

/// Default implementation of ex_hermes_notify_callback for iOS/standalone use.
/// This is called from C++ (hermes_runtime.cc) when async callbacks are pushed
/// from background threads.
///
/// The CLI provides its own implementation in hermes.rs that uses
/// tokio::sync::Notify for more efficient wakeup. When building the CLI,
/// enable the `cli-notify` feature to skip this default implementation.
///
/// The `test` arm keeps the symbol defined for this crate's own lib test:
/// under `cargo test --workspace`, feature unification turns on `cli-notify`
/// for every ibex-runtime target, but the CLI's replacement
/// is not part of the lib-test link unit, which otherwise fails with an
/// undefined `_ex_hermes_notify_callback`. `cfg(test)` is never set when
/// other crates link this one, so the CLI build still gets exactly one
/// definition.
#[cfg(any(not(feature = "cli-notify"), test))]
#[no_mangle]
pub extern "C" fn ex_hermes_notify_callback() {
    CALLBACK_PENDING.store(true, Ordering::Release);
    invoke_host_wake_hook();
}

/// Check and clear the callback pending flag.
/// Called from the event loop polling code.
pub fn take_callback_pending() -> bool {
    CALLBACK_PENDING.swap(false, Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use std::os::raw::c_char;

    #[repr(C)]
    struct HermesRuntimeOpaque {
        _private: [u8; 0],
    }

    extern "C" {
        fn ex_hermes_create() -> *mut HermesRuntimeOpaque;
        fn ex_hermes_destroy(runtime: *mut HermesRuntimeOpaque);
        fn ex_hermes_eval(
            runtime: *mut HermesRuntimeOpaque,
            data: *const u8,
            len: usize,
            source_url: *const c_char,
            is_bytecode: i32,
            out_value: *mut *mut c_char,
        ) -> i32;
        #[cfg(target_os = "windows")]
        fn ex_host_install();
        fn ex_hermes_free_string(value: *mut c_char);
        fn ex_hermes_poll(runtime: *mut HermesRuntimeOpaque, now_ms: u64) -> i32;
        fn ex_hermes_next_timer(runtime: *mut HermesRuntimeOpaque) -> i64;
        fn ex_hermes_now_ms() -> u64;
    }

    fn eval(runtime: *mut HermesRuntimeOpaque, source: &str) -> (i32, Option<String>) {
        let url = std::ffi::CString::new("r1-test.js").expect("source url");
        let mut out: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_eval(
                runtime,
                source.as_ptr(),
                source.len(),
                url.as_ptr(),
                0,
                &mut out,
            )
        };
        let value = if out.is_null() {
            None
        } else {
            let text = unsafe { std::ffi::CStr::from_ptr(out) }
                .to_string_lossy()
                .into_owned();
            unsafe { ex_hermes_free_string(out) };
            Some(text)
        };
        (status, value)
    }

    /// A one-shot timer whose callback throws must be retired before the
    /// error propagates out of `ex_hermes_poll`; before the fix it stayed
    /// due and refired on every subsequent poll. @ref LLP 0006#degrade-diagnostics-never-the-caller
    #[test]
    fn throwing_one_shot_timer_does_not_refire() {
        unsafe {
            std::env::set_var("IBEX_SUPPRESS_CONSOLE_MIRROR", "1");
            let runtime = ex_hermes_create();
            assert!(!runtime.is_null());

            let (status, value) = eval(
                runtime,
                "globalThis.__r1Count = 0;\n\
                 setTimeout(function () { globalThis.__r1Count++; throw new Error('boom'); }, 0);\n\
                 'armed';",
            );
            assert_eq!(status, 0, "arming eval failed: {value:?}");

            // Timer due_ms is monotonic-ms since process start; a huge `now`
            // guarantees the timer is due on the first poll.
            let now = u64::MAX / 2;
            let first = ex_hermes_poll(runtime, now);
            assert_eq!(first, -1, "throwing timer should surface a poll error");

            let second = ex_hermes_poll(runtime, now + 1_000);
            assert_eq!(second, 0, "retired one-shot timer must not refire");
            let third = ex_hermes_poll(runtime, now + 2_000);
            assert_eq!(third, 0, "retired one-shot timer must not refire");

            let (status, value) = eval(runtime, "String(globalThis.__r1Count)");
            assert_eq!(status, 0);
            assert_eq!(value.as_deref(), Some("1"));

            ex_hermes_destroy(runtime);
        }
    }

    /// setTimeout/setInterval store `due_ms = nowMs() + delay` on a MONOTONIC
    /// clock, and the Rust event loop reads that same clock via
    /// `ex_hermes_now_ms()` for the `now` it feeds to `ex_hermes_poll`. A large
    /// numeric delay lets us confirm both sides share one clock domain: due_ms
    /// minus a freshly-read now must be ~= the delay (not wildly off, as it
    /// would be if the two used different clock epochs).
    #[test]
    fn timer_due_time_shares_monotonic_clock_domain() {
        unsafe {
            std::env::set_var("IBEX_SUPPRESS_CONSOLE_MIRROR", "1");
            let runtime = ex_hermes_create();
            assert!(!runtime.is_null());

            let t0 = ex_hermes_now_ms();
            let (status, _) = eval(
                runtime,
                "globalThis.__c = 0; setTimeout(function () { globalThis.__c++; }, 100000); 'ok';",
            );
            assert_eq!(status, 0);

            let due = ex_hermes_next_timer(runtime);
            assert!(due >= 0, "an armed timer must report a non-negative due time");
            let rel = (due as u64).saturating_sub(t0);
            assert!(
                (90_000..=110_000).contains(&rel),
                "due_ms - ex_hermes_now_ms() = {rel}ms, expected ~100000ms; \
                 the Rust loop clock and the C++ timer clock must be the same domain",
            );

            // Passing that due time straight to poll fires the timer.
            let fired = ex_hermes_poll(runtime, due as u64);
            assert!(fired >= 1, "timer should fire once its due time is reached");
            let (_, value) = eval(runtime, "String(globalThis.__c)");
            assert_eq!(value.as_deref(), Some("1"));

            ex_hermes_destroy(runtime);
        }
    }

    /// setTimeout/setInterval must (a) ToNumber-coerce a non-number delay like
    /// `'100000'` instead of silently treating it as 0, and (b) clamp negative
    /// and NaN delays to 0. Before the fix the delay went through
    /// `static_cast<uint64_t>(asNumber())`: strings became 0, and negative/NaN
    /// were UB — on x86_64 they cast to 0x8000000000000000, so `nowMs() + delay`
    /// landed ~292M years out and the callback NEVER fired.
    #[test]
    fn timer_delay_is_coerced_and_clamped() {
        unsafe {
            std::env::set_var("IBEX_SUPPRESS_CONSOLE_MIRROR", "1");
            let runtime = ex_hermes_create();
            assert!(!runtime.is_null());

            // (a) A string delay is coerced via ToNumber, so a '100000' timer is
            // due ~100s out — not immediately (which is what treating it as 0
            // would produce).
            let t0 = ex_hermes_now_ms();
            let (status, _) = eval(
                runtime,
                "globalThis.__s = 0; setTimeout(function () { globalThis.__s++; }, '100000'); 'ok';",
            );
            assert_eq!(status, 0);
            let due = ex_hermes_next_timer(runtime);
            assert!(due >= 0);
            let rel = (due as u64).saturating_sub(t0);
            assert!(
                rel >= 90_000,
                "string delay '100000' must coerce to ~100000ms, got {rel}ms \
                 (a non-coerced delay would be ~0)",
            );
            // Retire it so it doesn't interfere with the clamp cases below.
            ex_hermes_poll(runtime, due as u64);
            let (_, value) = eval(runtime, "String(globalThis.__s)");
            assert_eq!(value.as_deref(), Some("1"));
            assert_eq!(ex_hermes_next_timer(runtime), -1);

            // (b) Negative, NaN, non-coercible-object, and missing delays all
            // clamp to 0: each timer is due ~immediately (a small offset, NOT a
            // ~292M-year deadline) and fires on the next poll.
            let cases = [
                ("neg", "setTimeout(function () { globalThis.__f++; }, -1);"),
                ("nan", "setTimeout(function () { globalThis.__f++; }, NaN);"),
                ("obj", "setTimeout(function () { globalThis.__f++; }, {});"),
                ("none", "setTimeout(function () { globalThis.__f++; });"),
            ];
            for (label, arm) in cases {
                let base = ex_hermes_now_ms();
                let (status, _) =
                    eval(runtime, &format!("globalThis.__f = 0; {arm} 'ok';"));
                assert_eq!(status, 0, "{label}: setTimeout must not throw");
                let due = ex_hermes_next_timer(runtime);
                assert!(due >= 0, "{label}: delay must not become a far-future deadline");
                let rel = (due as u64).saturating_sub(base);
                assert!(
                    rel <= 1_000,
                    "{label}: delay must clamp to ~0ms, got {rel}ms (bogus deadline?)",
                );
                // now >= due, so the timer is due and fires.
                let fired = ex_hermes_poll(runtime, ex_hermes_now_ms());
                assert!(fired >= 1, "{label}: clamped-to-0 timer must fire");
                let (_, value) = eval(runtime, "String(globalThis.__f)");
                assert_eq!(value.as_deref(), Some("1"), "{label}: callback should run once");
                assert_eq!(ex_hermes_next_timer(runtime), -1, "{label}: one-shot retired");
            }

            ex_hermes_destroy(runtime);
        }
    }

    #[cfg(target_os = "windows")]
    mod windows_native_smoke {
        use super::*;
        use base64::{engine::general_purpose, Engine as _};
        use sha1::{Digest, Sha1};
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::{Duration, Instant};

        struct RuntimeGuard(*mut HermesRuntimeOpaque);

        impl RuntimeGuard {
            fn new() -> Self {
                unsafe {
                    ex_host_install();
                    let runtime = ex_hermes_create();
                    assert!(!runtime.is_null());
                    Self(runtime)
                }
            }

            fn as_ptr(&self) -> *mut HermesRuntimeOpaque {
                self.0
            }
        }

        impl Drop for RuntimeGuard {
            fn drop(&mut self) {
                unsafe { ex_hermes_destroy(self.0) };
            }
        }

        fn eval_ok(runtime: *mut HermesRuntimeOpaque, source: &str) -> Option<String> {
            let (status, value) = eval(runtime, source);
            assert_eq!(status, 0, "eval failed: {value:?}");
            value
        }

        fn eval_ok_with_permissive_host(
            runtime: *mut HermesRuntimeOpaque,
            source: &str,
        ) -> Option<String> {
            unsafe { ex_host_install() };
            let (mut status, mut value) = eval(runtime, source);
            if status != 0
                && value
                    .as_deref()
                    .is_some_and(|message| message.contains("Permission denied"))
            {
                unsafe { ex_host_install() };
                (status, value) = eval(runtime, source);
            }
            assert_eq!(status, 0, "eval failed: {value:?}");
            value
        }

        fn json_string(value: &str) -> String {
            serde_json::to_string(value).expect("JSON string")
        }

        fn install_ascii_text_encoder(runtime: *mut HermesRuntimeOpaque) {
            let value = eval_ok(
                runtime,
                r#"
                if (typeof TextEncoder === 'undefined') {
                  globalThis.TextEncoder = function TextEncoder() {};
                  TextEncoder.prototype.encode = function(value) {
                    var text = String(value);
                    var out = new Uint8Array(text.length);
                    for (var i = 0; i < text.length; i++) {
                      out[i] = text.charCodeAt(i) & 255;
                    }
                    return out;
                  };
                }
                'text-encoder-ready';
                "#,
            );
            assert_eq!(value.as_deref(), Some("text-encoder-ready"));
        }

        fn wait_for_js_result(runtime: *mut HermesRuntimeOpaque, expression: &str) -> String {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut tick = u64::MAX / 4;
            while Instant::now() < deadline {
                let poll_status = unsafe { ex_hermes_poll(runtime, tick) };
                assert!(
                    poll_status >= 0,
                    "Hermes poll failed while waiting for {expression}"
                );
                tick = tick.saturating_add(20);

                let value = eval_ok(runtime, expression).unwrap_or_default();
                if !value.is_empty() {
                    return value;
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!("timed out waiting for {expression}");
        }

        fn read_http_headers(stream: &mut TcpStream) -> String {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let mut request = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let read = stream.read(&mut buf).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            String::from_utf8_lossy(&request).into_owned()
        }

        fn spawn_http_server() -> (String, thread::JoinHandle<()>) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind HTTP server");
            let port = listener.local_addr().expect("HTTP local addr").port();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept HTTP client");
                let request = read_http_headers(&mut stream);
                assert!(request.starts_with("GET /native-fetch "));
                let body = b"ibex-winhttp-fetch";
                let response = format!(
                    "HTTP/1.1 203 Non-Authoritative Information\r\n\
                     Content-Length: {}\r\n\
                     Content-Type: text/plain\r\n\
                     X-Ibex-Backend: winhttp\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write HTTP headers");
                stream.write_all(body).expect("write HTTP body");
            });
            (format!("http://127.0.0.1:{port}/native-fetch"), handle)
        }

        fn websocket_accept_key(client_key: &str) -> String {
            let mut sha = Sha1::new();
            sha.update(client_key.as_bytes());
            sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            general_purpose::STANDARD.encode(sha.finalize())
        }

        fn read_websocket_text_frame(stream: &mut TcpStream) -> String {
            let mut header = [0u8; 2];
            stream
                .read_exact(&mut header)
                .expect("read WebSocket frame header");
            assert_eq!(header[0] & 0x0f, 0x1, "expected text frame");
            let masked = (header[1] & 0x80) != 0;
            assert!(masked, "client WebSocket frames must be masked");
            let mut len = (header[1] & 0x7f) as usize;
            if len == 126 {
                let mut ext = [0u8; 2];
                stream
                    .read_exact(&mut ext)
                    .expect("read extended frame length");
                len = u16::from_be_bytes(ext) as usize;
            } else if len == 127 {
                let mut ext = [0u8; 8];
                stream
                    .read_exact(&mut ext)
                    .expect("read extended frame length");
                len = u64::from_be_bytes(ext) as usize;
            }
            let mut mask = [0u8; 4];
            stream.read_exact(&mut mask).expect("read frame mask");
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).expect("read frame payload");
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
            String::from_utf8(payload).expect("text frame utf8")
        }

        fn write_websocket_text_frame(stream: &mut TcpStream, text: &str) {
            let payload = text.as_bytes();
            let mut frame = vec![0x81];
            if payload.len() < 126 {
                frame.push(payload.len() as u8);
            } else {
                frame.push(126);
                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            frame.extend_from_slice(payload);
            stream
                .write_all(&frame)
                .expect("write WebSocket text frame");
        }

        fn spawn_websocket_echo_server() -> (String, thread::JoinHandle<()>) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind WebSocket server");
            let port = listener.local_addr().expect("WebSocket local addr").port();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept WebSocket client");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set WebSocket timeout");
                let request = read_http_headers(&mut stream);
                let key = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if name.eq_ignore_ascii_case("sec-websocket-key") {
                            Some(value.trim().to_string())
                        } else {
                            None
                        }
                    })
                    .expect("Sec-WebSocket-Key header");
                let accept = websocket_accept_key(&key);
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write WebSocket handshake");
                let message = read_websocket_text_frame(&mut stream);
                assert_eq!(message, "ibex-winhttp-websocket");
                write_websocket_text_frame(&mut stream, "winhttp-websocket-echo");
                thread::sleep(Duration::from_millis(250));
                let _ = stream.write_all(&[0x88, 0x02, 0x03, 0xe8]);
            });
            (format!("ws://127.0.0.1:{port}/native-websocket"), handle)
        }

        fn spawn_tcp_echo_server() -> (u16, thread::JoinHandle<()>) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind TCP server");
            let port = listener.local_addr().expect("TCP local addr").port();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept TCP client");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set TCP timeout");
                let mut buf = [0u8; 64];
                let read = stream.read(&mut buf).expect("read TCP payload");
                assert_eq!(&buf[..read], b"ibex-winsock-tcp");
                stream
                    .write_all(b"winsock-tcp-echo")
                    .expect("write TCP echo");
            });
            (port, handle)
        }

        #[test]
        fn windows_runtime_uses_native_platform_backends() {
            let _host_guard = crate::host::abi::host_test_lock();
            let runtime = RuntimeGuard::new();
            install_ascii_text_encoder(runtime.as_ptr());

            let tempdir = tempfile::tempdir().expect("tempdir");
            let file = tempdir.path().join("native-fs.txt");
            let file_js = json_string(file.to_str().expect("utf8 temp path"));
            let sync_source = format!(
                r#"(function() {{
                  var crypto = require('crypto');
                  var fs = require('fs');
                  var os = require('os');
                  var cp = require('child_process');
                  var file = {file_js};
                  fs.writeFileSync(file, 'ibex-windows-fs');
                  var fsText = fs.readFileSync(file, 'utf8');
                  var hash = crypto.createHash('sha256').update('abc').digest('hex');
                  var hmac = crypto.createHmac('sha256', 'key').update('abc').digest('hex');
                  var spawn = cp.spawnSync('cmd.exe', ['/d', '/c', 'echo ibex-windows-spawn']);
                  var stdout = spawn.stdout && typeof spawn.stdout.toString === 'function'
                    ? spawn.stdout.toString()
                    : String(spawn.stdout || '');
                  return [
                    process.platform,
                    os.platform(),
                    String(os.totalmem() > 0),
                    hash,
                    hmac,
                    fsText,
                    String(fs.statSync(file).isFile()),
                    String(spawn.status),
                    stdout.replace(/\s+$/, '')
                  ].join('|');
                }})()"#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &sync_source).as_deref(),
                Some(
                    "win32|win32|true|\
                     ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad|\
                     9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab|\
                     ibex-windows-fs|true|0|ibex-windows-spawn"
                )
            );

            let (fetch_url, fetch_server) = spawn_http_server();
            let fetch_url_js = json_string(&fetch_url);
            let fetch_source = format!(
                r#"
                globalThis.__windowsNativeFetch = {{ done: false, result: '' }};
                fetch({fetch_url_js}).then(function(response) {{
                  return response.text().then(function(text) {{
                    globalThis.__windowsNativeFetch.result =
                      String(response.status) + ':' + response.headers.get('x-ibex-backend') + ':' + text;
                    globalThis.__windowsNativeFetch.done = true;
                  }});
                }}, function(error) {{
                  globalThis.__windowsNativeFetch.result = 'ERR:' + (error && error.message || String(error));
                  globalThis.__windowsNativeFetch.done = true;
                }});
                'armed';
                "#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &fetch_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeFetch.done ? globalThis.__windowsNativeFetch.result : ''",
                ),
                "203:winhttp:ibex-winhttp-fetch"
            );
            fetch_server.join().expect("HTTP server thread");

            let (ws_url, ws_server) = spawn_websocket_echo_server();
            let ws_url_js = json_string(&ws_url);
            let ws_source = format!(
                r#"
                globalThis.__windowsNativeWs = {{ done: false, result: '' }};
                var ws = new WebSocket({ws_url_js});
                ws.onopen = function() {{
                  ws.send('ibex-winhttp-websocket');
                }};
                ws.onmessage = function(event) {{
                  globalThis.__windowsNativeWs.result = 'ws:' + event.data;
                  globalThis.__windowsNativeWs.done = true;
                  ws.close(1000, 'done');
                }};
                ws.onerror = function(event) {{
                  globalThis.__windowsNativeWs.result = 'ERR:' + (event && event.message || 'websocket error');
                  globalThis.__windowsNativeWs.done = true;
                }};
                'armed';
                "#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &ws_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeWs.done ? globalThis.__windowsNativeWs.result : ''",
                ),
                "ws:winhttp-websocket-echo"
            );
            ws_server.join().expect("WebSocket server thread");

            let dns_source = r#"
              globalThis.__windowsNativeDns = { done: false, result: '' };
              require('dns').lookup('localhost', { family: 4 }, function(error, address, family) {
                var normalizedFamily = family === 'IPv4' ? 4 : family;
                globalThis.__windowsNativeDns.result = error
                  ? 'ERR:' + (error.code || error.message)
                  : 'dns:' + String(normalizedFamily) + ':' + String(!!address);
                globalThis.__windowsNativeDns.done = true;
              });
              'armed';
            "#;
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), dns_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeDns.done ? globalThis.__windowsNativeDns.result : ''",
                ),
                "dns:4:true"
            );

            let (tcp_port, tcp_server) = spawn_tcp_echo_server();
            let tcp_source = format!(
                r#"
                globalThis.__windowsNativeTcp = {{ done: false, result: '' }};
                __exactEnsureNet();
                var tcpHandle = __exactTcpConnect('127.0.0.1', {tcp_port}, null, null);
                __exactTcpWrite(tcpHandle, 'ibex-winsock-tcp');
                function __tcpBytesToText(bytes) {{
                  if (bytes === null || bytes === '') return '';
                  var out = '';
                  for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
                  return out;
                }}
                function __pollTcp() {{
                  try {{
                    var chunk = __exactTcpRead(tcpHandle, 65536);
                    if (chunk === '') {{
                      setTimeout(__pollTcp, 5);
                      return;
                    }}
                    if (chunk === null) {{
                      globalThis.__windowsNativeTcp.result = 'ERR:closed';
                      globalThis.__windowsNativeTcp.done = true;
                      return;
                    }}
                    globalThis.__windowsNativeTcp.result = 'tcp:' + __tcpBytesToText(chunk);
                    globalThis.__windowsNativeTcp.done = true;
                    __exactTcpClose(tcpHandle);
                  }} catch (error) {{
                    globalThis.__windowsNativeTcp.result = 'ERR:' + (error && error.message || String(error));
                    globalThis.__windowsNativeTcp.done = true;
                  }}
                }}
                __pollTcp();
                'armed';
                "#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &tcp_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeTcp.done ? globalThis.__windowsNativeTcp.result : ''",
                ),
                "tcp:winsock-tcp-echo"
            );
            tcp_server.join().expect("TCP server thread");
        }
    }
}
