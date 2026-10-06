//! Storage installed into an independently created runtime, without its loader.
use ibex2::stdlib::app_fs::AppDirectories;
use ibex2::{
    bindings::{Context, Groups},
    grant::GrantSet,
};
use std::{
    ffi::{c_char, c_void, CStr, CString},
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[repr(C)]
struct CompiledScript {
    name: *const c_char,
    bytes: *const u8,
    len: usize,
}

extern "C" {
    fn bindings_validate_groups(groups: u16, error: *mut *mut c_char) -> i32;
    fn bindings_expected_scripts(groups: u16, error: *mut *mut c_char) -> *mut c_char;
    fn bindings_consumer_create_uninstalled(queue: *const c_void) -> *mut c_void;
    fn bindings_consumer_install(
        handle: *mut c_void,
        bindings: *const ibex2::bindings::Ibex2Bindings,
        groups: u16,
        scripts: *const CompiledScript,
        script_count: usize,
        error: *mut *mut c_char,
    ) -> i32;
    fn bindings_consumer_install_with_fetch_primitives(
        handle: *mut c_void,
        bindings: *const ibex2::bindings::Ibex2Bindings,
        groups: u16,
        scripts: *const CompiledScript,
        script_count: usize,
        fetch_primitives: *const c_char,
        error: *mut *mut c_char,
    ) -> i32;
    fn bindings_consumer_install_with_options(
        handle: *mut c_void,
        bindings: *const ibex2::bindings::Ibex2Bindings,
        groups: u16,
        scripts: *const CompiledScript,
        script_count: usize,
        fetch_primitives: *const c_char,
        abort_hooks: *const c_char,
        error: *mut *mut c_char,
    ) -> i32;
    fn bindings_consumer_harden(
        handle: *mut c_void,
        bytes: *const u8,
        len: usize,
        error: *mut *mut c_char,
    ) -> i32;
    fn bindings_consumer_create(
        queue: *const c_void,
        bindings: *const ibex2::bindings::Ibex2Bindings,
        groups: u16,
        scripts: *const CompiledScript,
        script_count: usize,
        error: *mut *mut c_char,
    ) -> *mut c_void;
    fn storage_consumer_create(
        queue: *const c_void,
        grants: *const c_void,
        factory: *const u8,
        len: usize,
        harden: *const u8,
        harden_len: usize,
        error: *mut *mut c_char,
    ) -> *mut c_void;
    fn storage_consumer_eval(
        h: *mut c_void,
        data: *const u8,
        len: usize,
        out: *mut *mut c_char,
    ) -> i32;
    fn storage_consumer_step(h: *mut c_void, deliver: bool, out: *mut *mut c_char) -> i32;
    fn storage_consumer_subscribe(h: *mut c_void, callback_name: *const c_char) -> u64;
    fn storage_consumer_subscribe_native_throw(h: *mut c_void) -> u64;
    fn storage_consumer_detach(h: *mut c_void);
    fn storage_consumer_destroy(h: *mut c_void);
    fn storage_consumer_free(s: *mut c_char);
    fn ibex2_test_publish_event(state: *const c_void, subscription: u64) -> i32;
}

fn compiled_script(name: &str) -> CompiledScript {
    let name: &'static [u8] = match name {
        "headers" => b"headers\0",
        "timers" => b"timers\0",
        "url" => b"url\0",
        "domexception" => b"domexception\0",
        "crypto" => b"crypto\0",
        "events" => b"events\0",
        "abort" => b"abort\0",
        "websocket" => b"websocket\0",
        "blob" => b"blob\0",
        "structured_clone" => b"structured_clone\0",
        "fetch" => b"fetch\0",
        "sqlite" => b"sqlite\0",
        #[cfg(all(target_os = "linux", feature = "intl"))]
        "intl_number_format" => b"intl_number_format\0",
        #[cfg(all(target_os = "linux", feature = "intl"))]
        "intl_case" => b"intl_case\0",
        #[cfg(all(target_os = "linux", feature = "intl"))]
        "intl_datetime" => b"intl_datetime\0",
        _ => unreachable!(),
    };
    let script_name = std::str::from_utf8(&name[..name.len() - 1]).unwrap();
    let bytes = compiled_bytes(script_name);
    CompiledScript {
        name: name.as_ptr().cast(),
        bytes: bytes.as_ptr(),
        len: bytes.len(),
    }
}

fn compiled_bytes(name: &str) -> &'static [u8] {
    ibex2::bindings::compiled_scripts(Groups::ALL)
        .expect("ALL is a valid binding selection")
        .into_iter()
        .find(|script| script.name == name)
        .unwrap_or_else(|| panic!("{name} is part of Groups::ALL"))
        .bytes
}

struct BareConsumer {
    handle: *mut c_void,
    context: Option<Context>,
    directory: PathBuf,
}

impl BareConsumer {
    fn new(groups: Groups) -> Self {
        ibex2_runtime::ensure_linked();
        Self::from_context(groups, Context::new(GrantSet::none()))
    }
    fn from_context(groups: Groups, context: Context) -> Self {
        Self::from_context_with_primitives(groups, context, None)
    }
    fn from_context_with_primitives(
        groups: Groups,
        context: Context,
        fetch_primitives: Option<&str>,
    ) -> Self {
        Self::from_context_with_outputs(groups, context, fetch_primitives, None)
    }
    fn from_context_with_outputs(
        groups: Groups,
        context: Context,
        fetch_primitives: Option<&str>,
        abort_hooks: Option<&str>,
    ) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "ibex2-groups-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let scripts: Vec<_> = ibex2::bindings::scripts(groups)
            .unwrap()
            .into_iter()
            .map(|(name, _)| compiled_script(name))
            .collect();
        let mut error = std::ptr::null_mut();
        let fetch_primitives = fetch_primitives
            .map(|name| CString::new(name).expect("primitive name contains no NUL"));
        let abort_hooks =
            abort_hooks.map(|name| CString::new(name).expect("abort-hook name contains no NUL"));
        let handle = if fetch_primitives.is_some() || abort_hooks.is_some() {
            let handle = unsafe { bindings_consumer_create_uninstalled(context.state_ptr()) };
            assert!(!handle.is_null(), "uninstalled borrowed runtime");
            let installed = unsafe {
                bindings_consumer_install_with_options(
                    handle,
                    context.bindings_ptr(),
                    groups.bits(),
                    scripts.as_ptr(),
                    scripts.len(),
                    fetch_primitives
                        .as_ref()
                        .map_or(std::ptr::null(), |name| name.as_ptr()),
                    abort_hooks
                        .as_ref()
                        .map_or(std::ptr::null(), |name| name.as_ptr()),
                    &mut error,
                )
            };
            assert_eq!(installed, 1, "{}", take(error));
            handle
        } else {
            unsafe {
                bindings_consumer_create(
                    context.state_ptr(),
                    context.bindings_ptr(),
                    groups.bits(),
                    scripts.as_ptr(),
                    scripts.len(),
                    &mut error,
                )
            }
        };
        assert!(!handle.is_null(), "{}", take(error));
        Self {
            handle,
            context: Some(context),
            directory,
        }
    }

    fn eval_result(&self, source: &str) -> Result<String, String> {
        let input = self.directory.join("test.js");
        let output = self.directory.join("test.hbc");
        std::fs::write(&input, source).unwrap();
        let compiler = PathBuf::from(ibex2_runtime::HERMESC_PATH);
        assert!(std::process::Command::new(compiler)
            .args(["-O", "-emit-binary", "-out"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap()
            .success());
        let bytes = std::fs::read(output).unwrap();
        let mut out = std::ptr::null_mut();
        let status =
            unsafe { storage_consumer_eval(self.handle, bytes.as_ptr(), bytes.len(), &mut out) };
        let text = take(out);
        if status == 0 {
            Ok(text)
        } else {
            Err(text)
        }
    }

    fn eval(&self, source: &str) -> String {
        self.eval_result(source).unwrap()
    }

    /// `Adapter::harden` with the given bytecode.
    fn harden(&self, bytecode: &[u8]) -> Result<(), String> {
        let mut error = std::ptr::null_mut();
        let hardened = unsafe {
            bindings_consumer_harden(self.handle, bytecode.as_ptr(), bytecode.len(), &mut error)
        };
        if hardened == 1 {
            Ok(())
        } else {
            Err(take(error))
        }
    }

    fn detach_and_drop_context(&mut self) {
        unsafe { storage_consumer_detach(self.handle) };
        drop(self.context.take());
    }

    fn step(&self, deliver: bool) -> i32 {
        let mut out = std::ptr::null_mut();
        let result = unsafe { storage_consumer_step(self.handle, deliver, &mut out) };
        assert!(result >= 0, "{}", take(out));
        result
    }

    fn finish(&self) -> String {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            self.step(false);
            let result = self.eval("globalThis.result || ''");
            if !result.is_empty() {
                return result;
            }
            assert!(Instant::now() < end, "application did not settle");
            self.context
                .as_ref()
                .expect("live borrowed context")
                .wait(Duration::from_millis(50));
            self.step(true);
        }
    }
}

impl Drop for BareConsumer {
    fn drop(&mut self) {
        unsafe { storage_consumer_destroy(self.handle) };
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

struct Consumer {
    handle: *mut c_void,
    context: Context,
    directory: PathBuf,
    wakes: Arc<AtomicUsize>,
}
fn take(s: *mut c_char) -> String {
    if s.is_null() {
        return String::new();
    }
    let result = unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned();
    unsafe { storage_consumer_free(s) };
    result
}
impl Consumer {
    fn new(grants: &str) -> Self {
        Self::configured(grants, true)
    }
    fn configured(grants: &str, hardened: bool) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "ibex2-embed-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        for name in ["data", "cache", "tmp"] {
            std::fs::create_dir_all(directory.join(name)).unwrap();
        }
        let context = Context::new(GrantSet::parse(grants).unwrap());
        context
            .set_app_directories(
                AppDirectories::new(
                    directory.join("data"),
                    directory.join("cache"),
                    directory.join("tmp"),
                )
                .unwrap(),
            )
            .unwrap();
        context
            .set_sqlite_provider(Arc::new(ibex2_sqlite::SqliteProvider))
            .unwrap();
        let wakes = Arc::new(AtomicUsize::new(0));
        let observed = wakes.clone();
        context.set_wake(Arc::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
        }));
        let factory = compiled_bytes("sqlite");
        let harden = ibex2::bindings::HARDEN_BYTECODE;
        let mut error = std::ptr::null_mut();
        let handle = unsafe {
            storage_consumer_create(
                context.state_ptr(),
                context.grants_ptr(),
                factory.as_ptr(),
                factory.len(),
                harden.as_ptr(),
                if hardened { harden.len() } else { 0 },
                &mut error,
            )
        };
        assert!(!handle.is_null(), "{}", take(error));
        Self {
            handle,
            context,
            directory,
            wakes,
        }
    }
    fn eval(&self, source: &str) -> Result<String, String> {
        let input = self.directory.join("test.js");
        let output = self.directory.join("test.hbc");
        std::fs::write(&input, source).unwrap();
        let compiler = PathBuf::from(ibex2_runtime::HERMESC_PATH);
        assert!(std::process::Command::new(compiler)
            .args(["-O", "-emit-binary", "-out"])
            .arg(&output)
            .arg(&input)
            .output()
            .unwrap()
            .status
            .success());
        let bytes = std::fs::read(output).unwrap();
        let mut out = std::ptr::null_mut();
        let status =
            unsafe { storage_consumer_eval(self.handle, bytes.as_ptr(), bytes.len(), &mut out) };
        let text = take(out);
        if status == 0 {
            Ok(text)
        } else {
            Err(text)
        }
    }
    fn step(&self, deliver: bool) -> i32 {
        let mut out = std::ptr::null_mut();
        let n = unsafe { storage_consumer_step(self.handle, deliver, &mut out) };
        assert!(n >= 0, "{}", take(out));
        n
    }
    fn finish(&self) -> String {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            self.step(false);
            let result = self.eval("globalThis.result || ''").unwrap();
            if !result.is_empty() {
                return result;
            }
            assert!(Instant::now() < end, "application did not settle");
            self.context.wait(Duration::from_millis(50));
            self.step(true);
        }
    }
}
impl Drop for Consumer {
    fn drop(&mut self) {
        unsafe { storage_consumer_destroy(self.handle) };
        // Context shutdown follows destruction; all tests explicitly close DBs.
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn global_names(consumer: &BareConsumer) -> std::collections::BTreeSet<String> {
    consumer
        .eval("Object.getOwnPropertyNames(globalThis).sort().join(',')")
        .split(',')
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

#[test]
fn pure_installs_exactly_its_globals_into_a_bare_runtime() {
    let baseline = global_names(&BareConsumer::new(Groups::empty()));
    let installed = global_names(&BareConsumer::new(Groups::PURE));
    let added: std::collections::BTreeSet<_> = installed.difference(&baseline).cloned().collect();
    let expected: std::collections::BTreeSet<_> = [
        "URL",
        "URLSearchParams",
        "Headers",
        "TextEncoder",
        "TextDecoder",
        "atob",
        "btoa",
        "DOMException",
        "QuotaExceededError",
        "structuredClone",
    ]
    .into_iter()
    .map(str::to_string)
    .filter(|name| !baseline.contains(name))
    .collect();
    assert_eq!(added, expected);
}

#[cfg(feature = "websocket")]
#[test]
fn borrowed_runtime_keeps_a_global_websocket_bound_to_its_endowment() {
    struct Counting(std::sync::mpsc::SyncSender<()>);
    impl ibex2::stdlib::websocket::SocketTransport for Counting {
        fn connect(
            &self,
            _: &url::Url,
            _: usize,
            _: &ibex2::stdlib::abort::AbortSignal,
        ) -> Result<Box<dyn ibex2::stdlib::websocket::MessageSource>, ibex2::boundary::HostError>
        {
            self.0.send(()).expect("open observer remains alive");
            Err(ibex2::boundary::HostError::Failed(
                "borrowed transport reached".into(),
            ))
        }
    }

    let (opened, opened_rx) = std::sync::mpsc::sync_channel(1);
    let bindings = ibex2::host::Host::new()
        .with_socket_transport(Box::new(Counting(opened)))
        .endow(GrantSet::parse("net.websocket ws://borrowed.example\n").expect("borrowed grant"));
    let context = Context::from_bindings(&bindings);
    let consumer = BareConsumer::from_context(Groups::DEFAULT, context);
    assert_eq!(consumer.eval("typeof globalThis.WebSocket"), "function");
    consumer.eval(
        r#"
        globalThis.borrowedLog = [];
        var borrowedSocket = new WebSocket("ws://borrowed.example/");
        borrowedSocket.onerror = function () {
          borrowedLog.push("error:" + borrowedSocket.readyState);
        };
        borrowedSocket.onclose = function (event) {
          borrowedLog.push("close:" + event.code);
        };
        "#,
    );
    opened_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("borrowed transport was reached");
    let deliver_one = || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if consumer.step(true) == 1 {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("WebSocket event was not admitted");
    };
    deliver_one();
    deliver_one();
    assert_eq!(consumer.eval("borrowedLog.join('|')"), "error:3|close:1006");
}

#[test]
fn fetch_group_does_not_install_timers_or_crypto() {
    let baseline = global_names(&BareConsumer::new(Groups::empty()));
    let installed = global_names(&BareConsumer::new(
        Groups::PURE | Groups::ABORT | Groups::FETCH,
    ));
    let added: std::collections::BTreeSet<_> = installed.difference(&baseline).cloned().collect();
    let expected: std::collections::BTreeSet<_> = [
        "URL",
        "URLSearchParams",
        "Headers",
        "TextEncoder",
        "TextDecoder",
        "atob",
        "btoa",
        "DOMException",
        "QuotaExceededError",
        "AbortController",
        "AbortSignal",
        "fetch",
        "structuredClone",
    ]
    .into_iter()
    .map(str::to_string)
    .filter(|name| !baseline.contains(name))
    .collect();
    assert_eq!(added, expected);
}

#[test]
fn abort_hooks_are_opt_in_frozen_and_run_before_public_abort_listeners() {
    const NAME: &str = "__exact_ibex2_abort_hooks";
    let groups = Groups::PURE | Groups::ABORT;
    let ordinary = BareConsumer::new(groups);
    assert_eq!(
        ordinary.eval("typeof globalThis.__ibex2_abort"),
        "undefined"
    );
    assert!(!global_names(&ordinary).contains(NAME));

    let consumer = BareConsumer::from_context_with_outputs(
        groups,
        Context::new(GrantSet::none()),
        None,
        Some(NAME),
    );
    assert_eq!(
        consumer.eval(&format!(
            r#"
            (function (hooks) {{
              var order = [];
              var controller = new AbortController();
              controller.signal.addEventListener("abort", function (event) {{
                order.push("app");
                event.stopImmediatePropagation();
              }});
              hooks.subscribe(controller.signal, function () {{ order.push("hook"); }});
              controller.abort();
              return [
                Object.isFrozen(hooks),
                Object.keys(hooks).sort().join(","),
                order.join(",")
              ].join("|");
            }})(globalThis.{NAME})
            "#
        )),
        "true|own,subscribe|hook,app"
    );
}

#[test]
fn adapter_harden_refuses_reachable_abort_hooks_and_members() {
    const NAME: &str = "__exact_ibex2_abort_hooks";
    let make = || {
        BareConsumer::from_context_with_outputs(
            Groups::PURE | Groups::ABORT,
            Context::new(GrantSet::none()),
            None,
            Some(NAME),
        )
    };

    let object = make();
    assert!(object
        .harden(ibex2::bindings::HARDEN_BYTECODE)
        .unwrap_err()
        .contains(&format!(
            "refusing to harden while abort hooks global \"{NAME}\" is present"
        )));
    object.eval(&format!(
        "globalThis.abortAlias = globalThis.{NAME}; delete globalThis.{NAME}"
    ));
    assert!(object
        .harden(ibex2::bindings::HARDEN_BYTECODE)
        .unwrap_err()
        .contains("the abort hooks object is still reachable"));
    assert_eq!(object.eval("delete globalThis.abortAlias; 'gone'"), "gone");
    object
        .harden(ibex2::bindings::HARDEN_BYTECODE)
        .expect("the captured object may remain only in a closure or native root");

    let member = make();
    member.eval(&format!(
        "globalThis.abortMember = globalThis.{NAME}.subscribe; delete globalThis.{NAME}"
    ));
    assert!(member
        .harden(ibex2::bindings::HARDEN_BYTECODE)
        .unwrap_err()
        .contains("abort hooks member subscribe is still reachable"));
}

#[test]
fn raw_fetch_primitive_and_global_fetch_share_the_context_grant() {
    const NAME: &str = "__borrowed_fetch_primitives";
    let context = Context::new(GrantSet::none());
    let consumer = BareConsumer::from_context_with_primitives(
        Groups::PURE | Groups::ABORT | Groups::FETCH,
        context,
        Some(NAME),
    );
    consumer.eval(&format!(
        r#"
        globalThis.result = "";
        var p = globalThis.{NAME};
        var headers = new Headers();
        var token = p.fetchControl(0);
        var ordinary = fetch("https://denied.example/").then(
          function () {{ return "unexpected success"; }},
          function (error) {{ return String(error.message || error); }}
        );
        var raw = p.fetch(
          "https://denied.example/", "GET", undefined, "manual", headers._handle, token
        ).then(function () {{
          p.headersFree(headers._handle);
          p.fetchControl(2, token);
          return "unexpected success";
        }}, function (error) {{
          p.headersFree(headers._handle);
          p.fetchControl(2, token);
          return String(error.message || error);
        }});
        Promise.all([ordinary, raw]).then(function (values) {{
          result = JSON.stringify(values);
        }});
        "#
    ));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&consumer.finish()).unwrap(),
        serde_json::json!(["denied: net.fetch", "denied: net.fetch"])
    );
}

#[test]
fn fetch_primitives_refuse_an_ordinary_response_and_stale_or_forged_handles() {
    const NAME: &str = "__borrowed_fetch_primitives";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx")
                .unwrap();
        }
    });
    let context = Context::new(GrantSet::parse(&format!("net.fetch {origin}\n")).unwrap());
    let consumer = BareConsumer::from_context_with_primitives(
        Groups::PURE | Groups::ABORT | Groups::FETCH,
        context,
        Some(NAME),
    );
    consumer.eval(&format!(
        r#"
        globalThis.runHandleBoundary = (function (p) {{
          delete globalThis.{NAME};
          function typeError(call) {{
            try {{ call(); return "accepted"; }}
            catch (error) {{ return error instanceof TypeError ? "TypeError" : String(error); }}
          }}
          function raw(url) {{
            var headers = new Headers();
            var token = p.fetchControl(0);
            return p.fetch(url, "GET", undefined, "manual", headers._handle, token).then(
              function (handle) {{
                p.headersFree(headers._handle);
                p.fetchControl(2, token);
                return handle;
              }},
              function (error) {{
                p.headersFree(headers._handle);
                p.fetchControl(2, token);
                throw error;
              }}
            );
          }}
          return function (url) {{
            return fetch(url).then(function () {{
              // Ordinary fetch allocated request headers, a control token, a
              // response, and response headers. The next monotonic token lets
              // the test address the still-live ordinary response without
              // receiving that handle from the primitives object.
              var marker = p.fetchControl(0);
              var ordinaryResponse = marker - 2;
              var foreign = typeError(function () {{
                return p.responseField(ordinaryResponse, 0);
              }});
              var foreignHeaders = new Headers();
              var foreignHeader = typeError(function () {{
                return p.headersFree(foreignHeaders._handle);
              }});
              var forgedControl = typeError(function () {{
                return p.fetchControl(1, 9007199254740991);
              }});
              p.fetchControl(2, marker);
              return raw(url).then(function (handle) {{
                p.responseField(handle, 8);
                return {{
                  foreign: foreign,
                  foreignHeader: foreignHeader,
                  forgedControl: forgedControl,
                  stale: typeError(function () {{ return p.responseField(handle, 0); }}),
                  forged: typeError(function () {{ return p.responseField(9007199254740991, 0); }})
                }};
              }});
            }});
          }};
        }})(globalThis.{NAME});
        globalThis.result = "";
        runHandleBoundary({origin:?}).then(function (value) {{
          result = JSON.stringify(value);
        }});
        "#
    ));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&consumer.finish()).unwrap(),
        serde_json::json!({
            "foreign": "TypeError",
            "foreignHeader": "TypeError",
            "forgedControl": "TypeError",
            "stale": "TypeError",
            "forged": "TypeError",
        })
    );
    server.join().unwrap();
}

#[test]
fn adapter_harden_refuses_until_fetch_primitives_are_unreachable() {
    const NAME: &str = "__borrowed_fetch_primitives";
    ibex2_runtime::ensure_linked();
    let consumer = BareConsumer::from_context_with_primitives(
        Groups::PURE | Groups::ABORT | Groups::FETCH,
        Context::new(GrantSet::none()),
        Some(NAME),
    );
    let error = consumer
        .harden(ibex2::bindings::HARDEN_BYTECODE)
        .unwrap_err();
    assert!(
        error.contains(&format!(
            "refusing to harden while fetch primitives global \"{NAME}\" is present"
        )),
        "{error}"
    );
    assert_eq!(
        consumer.eval(&format!(
            "globalThis.alias = globalThis.{NAME}; delete globalThis.{NAME}; 'moved'"
        )),
        "moved"
    );
    let error = consumer
        .harden(ibex2::bindings::HARDEN_BYTECODE)
        .unwrap_err();
    assert!(
        error.contains("the fetch primitives object is still reachable"),
        "{error}"
    );
    assert_eq!(
        consumer.eval("String(Object.isFrozen(Array.prototype))"),
        "false"
    );
    let error = consumer.harden(b"not bytecode").unwrap_err();
    assert!(
        error.contains("truncated Hermes bytecode header"),
        "{error}"
    );
    assert_eq!(consumer.eval("delete globalThis.alias; 'gone'"), "gone");
    consumer
        .harden(ibex2::bindings::HARDEN_BYTECODE)
        .expect("no path to the primitives remains");
    assert_eq!(
        consumer.eval("String(Object.isFrozen(Array.prototype))"),
        "true"
    );
}

#[test]
fn adapter_install_with_refuses_non_identifier_and_colliding_names() {
    ibex2_runtime::ensure_linked();
    let groups = Groups::PURE | Groups::ABORT | Groups::FETCH;
    for (name, expected) in [
        ("na\u{ef}ve", "must be an ASCII JavaScript identifier"),
        ("1abc", "must be an ASCII JavaScript identifier"),
        ("a-b", "must be an ASCII JavaScript identifier"),
        ("", "require a non-empty global name"),
        ("toString", "fetch primitives global already exists"),
        ("Object", "fetch primitives global already exists"),
    ] {
        let context = Context::new(GrantSet::none());
        let scripts: Vec<_> = ibex2::bindings::scripts(groups)
            .unwrap()
            .into_iter()
            .map(|(script, _)| compiled_script(script))
            .collect();
        let handle = unsafe { bindings_consumer_create_uninstalled(context.state_ptr()) };
        assert!(!handle.is_null(), "uninstalled borrowed runtime");
        let c_name = CString::new(name).unwrap();
        let mut error = std::ptr::null_mut();
        let installed = unsafe {
            bindings_consumer_install_with_fetch_primitives(
                handle,
                context.bindings_ptr(),
                groups.bits(),
                scripts.as_ptr(),
                scripts.len(),
                c_name.as_ptr(),
                &mut error,
            )
        };
        let error = take(error);
        unsafe { storage_consumer_destroy(handle) };
        assert_eq!(installed, 0, "{name:?} was accepted");
        assert!(error.contains(expected), "{name:?}: {error}");
    }
}

#[test]
fn blob_group_installs_only_its_globals_and_requires_pure() {
    let baseline = global_names(&BareConsumer::new(Groups::empty()));
    let installed = global_names(&BareConsumer::new(Groups::PURE | Groups::BLOB));
    let pure = global_names(&BareConsumer::new(Groups::PURE));
    let added: std::collections::BTreeSet<_> = installed.difference(&pure).cloned().collect();
    let expected = ["Blob", "File", "FormData"]
        .into_iter()
        .map(str::to_string)
        .filter(|name| !baseline.contains(name))
        .collect();
    assert_eq!(added, expected);
}

#[test]
fn omitted_crypto_group_exposes_no_crypto_surface_or_subtle_ops() {
    let consumer = BareConsumer::new(Groups::PURE);
    assert_eq!(
        consumer.eval(
            r#"[
              typeof crypto,
              typeof Crypto,
              typeof CryptoKey,
              typeof SubtleCrypto,
              typeof globalThis.__ibex2_random_uuid,
              typeof globalThis.__ibex2_get_random_values,
              typeof globalThis.__ibex2_subtle
            ].join(',')"#,
        ),
        "undefined,undefined,undefined,undefined,undefined,undefined,undefined"
    );
    assert_eq!(
        consumer.eval(
            r#"try {
              globalThis.__ibex2_subtle.digest("SHA-256", new Uint8Array());
              "reachable";
            } catch (error) {
              error instanceof TypeError ? "unreachable" : error.name;
            }"#,
        ),
        "unreachable"
    );
}

#[test]
fn borrowed_runtime_refuses_fetch_without_its_dependencies() {
    let context = Context::new(GrantSet::none());
    let mut error = std::ptr::null_mut();
    let handle = unsafe {
        bindings_consumer_create(
            context.state_ptr(),
            context.bindings_ptr(),
            Groups::FETCH.bits(),
            std::ptr::null(),
            0,
            &mut error,
        )
    };
    assert!(handle.is_null(), "dependency-invalid groups were installed");
    let error = take(error);
    assert!(
        error.contains("missing a dependency"),
        "unexpected dependency error: {error}"
    );
}

#[test]
fn rust_and_cpp_group_validation_tables_agree() {
    let group_bits = [
        Groups::PURE,
        Groups::CONSOLE,
        Groups::TIMERS,
        Groups::ABORT,
        Groups::CRYPTO,
        Groups::FETCH,
        Groups::STORAGE,
        Groups::ENV,
        Groups::SECRETS,
        Groups::KV,
        Groups::INTL,
        Groups::EVENTS,
        Groups::BLOB,
        Groups::WEBSOCKET,
    ];
    for mask in 0..(1usize << group_bits.len()) {
        let mut groups = Groups::empty();
        for (index, group) in group_bits.iter().enumerate() {
            if mask & (1 << index) != 0 {
                groups |= *group;
            }
        }
        let mut error = std::ptr::null_mut();
        let cpp_valid = unsafe { bindings_validate_groups(groups.bits(), &mut error) } == 1;
        if !error.is_null() {
            let _ = take(error);
        }
        assert_eq!(
            cpp_valid,
            groups.validate().is_ok(),
            "Rust and C++ disagree for {groups:?}"
        );
        if groups.validate().is_ok() {
            let mut error = std::ptr::null_mut();
            let cpp_scripts = unsafe { bindings_expected_scripts(groups.bits(), &mut error) };
            assert!(error.is_null(), "C++ script list refused {groups:?}");
            assert!(!cpp_scripts.is_null(), "C++ returned no script list");
            let cpp_scripts = take(cpp_scripts);
            let cpp_scripts: Vec<_> = cpp_scripts.lines().collect();
            let rust_scripts = ibex2::bindings::scripts(groups).unwrap();
            let rust_scripts: Vec<_> = rust_scripts.iter().map(|(name, _)| *name).collect();
            assert_eq!(
                cpp_scripts, rust_scripts,
                "script order differs for {groups:?}"
            );
        }
    }

    let mut error = std::ptr::null_mut();
    let cpp_intl = unsafe { bindings_validate_groups(Groups::INTL.bits(), &mut error) } == 1;
    if !error.is_null() {
        let _ = take(error);
    }
    assert_eq!(cpp_intl, cfg!(all(target_os = "linux", feature = "intl")));
}

#[test]
fn public_header_documents_every_bindings_handle_producer_and_releaser() {
    let header = include_str!("../../ibex2/include/ibex2_jsi.h");
    for name in [
        "Context::bindings_ptr()",
        "ibex2_bindings_adopt",
        "ibex2_bindings_destroy",
    ] {
        assert!(
            header.lines().take(20).any(|line| line.contains(name)),
            "the Ibex2Bindings header comment omits {name}"
        );
    }
}

#[test]
fn retained_pure_bindings_refuse_after_detach_and_context_drop() {
    let mut consumer = BareConsumer::new(Groups::PURE);
    assert_eq!(
        consumer.eval("globalThis.SavedHeaders = Headers; globalThis.SavedURL = URL; 'saved'"),
        "saved"
    );
    consumer.detach_and_drop_context();

    for source in ["new SavedHeaders()", "new SavedURL('https://example.com')"] {
        let error = consumer.eval_result(source).unwrap_err();
        assert!(
            error.contains("Ibex2 bindings are detached"),
            "unexpected detached error for {source}: {error}"
        );
    }
}

#[test]
fn borrowed_runtime_context_shutdown_cancels_queued_events_before_delivery() {
    // Declared before the consumer so panic unwinding always destroys the
    // adapter before releasing this non-owner storage reference.
    let state_keepalive: Arc<ibex2::task::RuntimeState>;
    let mut consumer = BareConsumer::new(Groups::PURE | Groups::EVENTS);
    consumer.eval(
        "globalThis.eventCalls = 0; globalThis.eventCallback = function () { eventCalls++; };",
    );
    let callback = std::ffi::CString::new("eventCallback").unwrap();
    let subscription = unsafe { storage_consumer_subscribe(consumer.handle, callback.as_ptr()) };
    assert_ne!(subscription, 0);

    let state = consumer.context.as_ref().unwrap().state_ptr();
    let state_ptr = state.cast::<ibex2::task::RuntimeState>();
    // Model a worker storage reference: it keeps the allocation valid but is
    // deliberately not an owner lease, so Context drop still starts shutdown.
    unsafe {
        Arc::increment_strong_count(state_ptr);
        state_keepalive = Arc::from_raw(state_ptr);
    }
    assert_eq!(unsafe { ibex2_test_publish_event(state, subscription) }, 1);

    drop(consumer.context.take());

    assert_eq!(consumer.step(true), 0);
    assert_eq!(consumer.eval("String(eventCalls)"), "0");
    consumer.detach_and_drop_context();
    drop(state_keepalive);
}

#[test]
fn borrowed_runtime_reports_callback_exceptions_instead_of_throwing_from_delivery() {
    let consumer = BareConsumer::new(Groups::PURE | Groups::EVENTS);
    let _ = ibex2::boundary_abi::drain_console();
    consumer.eval(
        r#"
        globalThis.eventErrors = [];
        addEventListener('error', function (event) {
          eventErrors.push(event.message + ':' + event.isTrusted);
          event.preventDefault();
        });
        globalThis.throwEvent = function () { throw new Error('javascript callback boom'); };
        "#,
    );
    let callback = std::ffi::CString::new("throwEvent").unwrap();
    let javascript = unsafe { storage_consumer_subscribe(consumer.handle, callback.as_ptr()) };
    let native = unsafe { storage_consumer_subscribe_native_throw(consumer.handle) };
    assert_ne!(javascript, 0);
    assert_ne!(native, 0);

    let state = consumer.context.as_ref().unwrap().state_ptr();
    assert_eq!(unsafe { ibex2_test_publish_event(state, javascript) }, 1);
    assert_eq!(consumer.step(true), 1);
    assert_eq!(unsafe { ibex2_test_publish_event(state, native) }, 1);
    assert_eq!(consumer.step(true), 1);

    let observed = consumer.eval("eventErrors.join('|')");
    assert!(
        observed.contains("javascript callback boom:true"),
        "{observed}"
    );
    assert!(observed.contains("native callback boom:true"), "{observed}");
    assert!(
        ibex2::boundary_abi::drain_console().is_empty(),
        "preventDefault did not cancel host reporting"
    );
}

#[test]
fn borrowed_unhardened_runtime_cannot_forge_event_trust_through_intrinsics() {
    let consumer = BareConsumer::new(Groups::PURE | Groups::EVENTS);
    assert_eq!(
        consumer.eval(
            r#"
            var originalWeakSet = WeakMap.prototype.set;
            var originalWeakGet = WeakMap.prototype.get;
            var originalDefineProperty = Object.defineProperty;
            WeakMap.prototype.set = function (key, state) {
              if (state && state.trusted === false) state.trusted = true;
              return originalWeakSet.call(this, key, state);
            };
            WeakMap.prototype.get = function (key) {
              var state = originalWeakGet.call(this, key);
              if (state && typeof state.trusted === 'boolean') state.trusted = true;
              return state;
            };
            Object.defineProperty = function (target, name, descriptor) {
              if (name === 'isTrusted') {
                return originalDefineProperty(target, name, {
                  value: true, enumerable: true
                });
              }
              return originalDefineProperty(target, name, descriptor);
            };

            var event = new Event('application');
            var target = new EventTarget();
            var seen = [];
            target.addEventListener('application', function (received) {
              seen.push(received === event, received.isTrusted);
            });
            var dispatched = target.dispatchEvent(event);
            [event.isTrusted, seen.join(','), dispatched,
             event.target === target].join('|');
            "#,
        ),
        "false|true,false|true|true"
    );
}

#[test]
fn borrowed_unhardened_runtime_inherited_setters_never_see_private_event_records() {
    let consumer = BareConsumer::new(Groups::PURE | Groups::EVENTS);
    assert_eq!(
        consumer.eval(
            r#"
            var captured = [];
            ['detail', 'message', 'filename', 'lineno', 'colno', 'error',
             'promise', 'reason', 'removed', 'abortRelease', 'trusted'
            ].forEach(function (name) {
              Object.defineProperty(Object.prototype, name, {
                configurable: true,
                set: function (value) { captured.push(this); },
                get: function () { return undefined; }
              });
            });
            var events = [
              new CustomEvent('c', { detail: 1 }),
              new ErrorEvent('e', { message: 'm', filename: 'f', lineno: 1, colno: 2, error: 3 }),
              new PromiseRejectionEvent('p', { promise: Promise.resolve(), reason: 4 })
            ];
            var target = new EventTarget();
            var listener = function () {};
            target.addEventListener('c', listener);
            target.removeEventListener('c', listener);
            for (var i = 0; i < captured.length; i++) {
              try { captured[i].trusted = true; } catch (_) {}
            }
            var seen = [];
            target.addEventListener('c', function (e) { seen.push(e.isTrusted); });
            target.dispatchEvent(events[0]);
            [captured.length,
             events.map(function (e) { return e.isTrusted; }).join(','),
             seen.join(','),
             events[0].detail, events[1].message, events[2].reason].join('|');
            "#,
        ),
        "0|false,false,false|false|1|m|4"
    );
}

#[test]
fn borrowed_unhardened_runtime_array_hooks_never_see_private_event_lists() {
    let consumer = BareConsumer::new(Groups::PURE | Groups::EVENTS);
    // The script itself avoids arrays: the hooks below would fire for its own
    // pushes too. It records through a counter and a string.
    assert_eq!(
        consumer.eval(
            r#"
            var captures = 0;
            var log = '';
            for (var index = 0; index < 4; index++) {
              Object.defineProperty(Array.prototype, String(index), {
                configurable: true,
                set: function (value) { captures++; },
                get: function () { return undefined; }
              });
            }
            var target = new EventTarget();
            var first = function (e) { log += 'first:' + e.isTrusted + ','; };
            var second = function (e) { log += 'second,'; };
            target.addEventListener('x', first);
            target.addEventListener('x', second);
            Object.defineProperty(Array.prototype, 'constructor', {
              configurable: true,
              get: function () { captures++; return Array; }
            });
            var event = new Event('x');
            target.dispatchEvent(event);
            event.composedPath();
            target.removeEventListener('x', first);
            target.dispatchEvent(new Event('x'));
            delete Array.prototype.constructor;
            for (var j = 0; j < 4; j++) delete Array.prototype[String(j)];
            captures + '|' + log + '|' + event.isTrusted;
            "#,
        ),
        "0|first:false,second,second,|false"
    );
}

#[test]
fn borrowed_unhardened_runtime_cannot_recover_or_write_platform_brand_registry() {
    let consumer = BareConsumer::new(Groups::PURE);
    assert_eq!(
        consumer.eval(
            r#"
            var originalWeakGet = WeakMap.prototype.get;
            var originalWeakSet = WeakMap.prototype.set;
            var capturedRegistry = null;
            var getCalls = 0;
            var setCalls = 0;
            WeakMap.prototype.get = function (key) {
              getCalls++;
              capturedRegistry = this;
              return originalWeakGet.call(this, key);
            };
            WeakMap.prototype.set = function (key, value) {
              setCalls++;
              capturedRegistry = this;
              return originalWeakSet.call(this, key, value);
            };

            var plain = { marker: 1 };
            structuredClone(plain);
            new Headers();
            if (capturedRegistry) {
              originalWeakSet.call(capturedRegistry, plain, {
                kind: 'DOMException',
                data: { name: 'AbortError', message: 'forged' }
              });
            }
            var clone = structuredClone(plain);
            [getCalls, setCalls, capturedRegistry === null, clone !== plain,
             Object.getPrototypeOf(clone) === Object.prototype,
             clone.marker === 1, clone instanceof DOMException].join('|');
            "#,
        ),
        "0|0|true|true|true|true|false"
    );
}

#[test]
fn dropping_the_last_context_owner_cancels_fetch_without_a_late_wake() {
    use ibex2::host::Host;
    use ibex2::stdlib::fetch::{Request, StreamingResponse, Transport};
    use std::sync::{mpsc, Condvar, Mutex};

    struct BlockingTransport {
        entered: mpsc::Sender<()>,
        cancelled: mpsc::Sender<()>,
        returned: mpsc::Sender<()>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }
    impl Transport for BlockingTransport {
        fn open(
            &self,
            _request: &Request,
            signal: &ibex2::stdlib::abort::AbortSignal,
        ) -> Result<StreamingResponse, ibex2::boundary::HostError> {
            let cancelled = Arc::new((Mutex::new(false), Condvar::new()));
            let notify = Arc::clone(&cancelled);
            let _registration = signal.register(move || {
                *notify.0.lock().unwrap() = true;
                notify.1.notify_all();
            });
            self.entered.send(()).unwrap();
            let mut was_cancelled = cancelled.0.lock().unwrap();
            while !*was_cancelled {
                was_cancelled = cancelled.1.wait(was_cancelled).unwrap();
            }
            self.cancelled.send(()).unwrap();
            drop(was_cancelled);

            // Keep the worker alive until after Context::drop returns. Its Arc
            // must not count as an owner or preserve the wake callback.
            let mut release = self.release.0.lock().unwrap();
            while !*release {
                release = self.release.1.wait(release).unwrap();
            }
            self.returned.send(()).unwrap();
            signal.check()?;
            unreachable!()
        }
    }

    let (entered_tx, entered_rx) = mpsc::channel();
    let (cancelled_tx, cancelled_rx) = mpsc::channel();
    let (returned_tx, returned_rx) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let bindings = Host::with_transport(Box::new(BlockingTransport {
        entered: entered_tx,
        cancelled: cancelled_tx,
        returned: returned_tx,
        release: Arc::clone(&release),
    }))
    .endow(GrantSet::parse("net.fetch https://blocked.example\n").unwrap());
    let context = Context::from_bindings(&bindings);
    let (wake_tx, wake_rx) = mpsc::channel();
    context.set_wake(Arc::new(move || {
        let _ = wake_tx.send(());
    }));
    let groups = Groups::PURE | Groups::ABORT | Groups::FETCH;
    let mut consumer = BareConsumer::from_context(groups, context);
    consumer.eval("fetch('https://blocked.example/').catch(function () {})");
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("fetch did not reach transport");

    consumer.detach_and_drop_context();
    cancelled_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("Context drop did not promptly cancel fetch");
    *release.0.lock().unwrap() = true;
    release.1.notify_all();
    returned_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("cancelled transport did not return");
    assert!(
        wake_rx.recv_timeout(Duration::from_millis(200)).is_err(),
        "a completion invoked the wake callback after Context drop"
    );
}

#[test]
fn grouped_install_refuses_source_bytes() {
    let context = Context::new(GrantSet::none());
    let name = b"headers\0";
    let source = include_bytes!("../../ibex2/src/bindings/headers.js");
    let mut scripts: Vec<_> = ibex2::bindings::scripts(Groups::PURE)
        .unwrap()
        .into_iter()
        .map(|(name, _)| compiled_script(name))
        .collect();
    scripts[0] = CompiledScript {
        name: name.as_ptr().cast(),
        bytes: source.as_ptr(),
        len: source.len(),
    };
    let mut error = std::ptr::null_mut();
    let handle = unsafe {
        bindings_consumer_create(
            context.state_ptr(),
            context.bindings_ptr(),
            Groups::PURE.bits(),
            scripts.as_ptr(),
            scripts.len(),
            &mut error,
        )
    };
    assert!(handle.is_null(), "source payload unexpectedly installed");
    let error = take(error);
    assert!(
        error.contains("not Hermes bytecode"),
        "unexpected install error: {error}"
    );
}

#[test]
fn grouped_install_refuses_a_grant_pointer_as_the_install_handle() {
    let context = Context::new(GrantSet::none());
    let scripts: Vec<_> = ibex2::bindings::scripts(Groups::PURE)
        .unwrap()
        .into_iter()
        .map(|(name, _)| compiled_script(name))
        .collect();
    let mut error = std::ptr::null_mut();
    let handle = unsafe {
        bindings_consumer_create(
            context.state_ptr(),
            context.grants_ptr().cast(),
            Groups::PURE.bits(),
            scripts.as_ptr(),
            scripts.len(),
            &mut error,
        )
    };
    assert!(
        handle.is_null(),
        "a grant pointer installed as an endowment"
    );
    let error = take(error);
    assert!(
        error.contains("live endowment"),
        "unexpected error: {error}"
    );
}

fn assert_failed_install_is_terminal(
    context: &Context,
    first: &[CompiledScript],
    expected_error: &str,
) -> String {
    let valid: Vec<_> = ibex2::bindings::scripts(Groups::PURE)
        .unwrap()
        .into_iter()
        .map(|(name, _)| compiled_script(name))
        .collect();
    let handle = unsafe { bindings_consumer_create_uninstalled(context.state_ptr()) };
    assert!(!handle.is_null(), "test runtime");

    let mut error = std::ptr::null_mut();
    let installed = unsafe {
        bindings_consumer_install(
            handle,
            context.bindings_ptr(),
            Groups::PURE.bits(),
            first.as_ptr(),
            first.len(),
            &mut error,
        )
    };
    assert_eq!(installed, 0, "malformed bytecode unexpectedly installed");
    let error = take(error);
    assert!(
        error.contains(expected_error),
        "unexpected first error: {error}"
    );

    let mut retry_error = std::ptr::null_mut();
    let retried = unsafe {
        bindings_consumer_install(
            handle,
            context.bindings_ptr(),
            Groups::PURE.bits(),
            valid.as_ptr(),
            valid.len(),
            &mut retry_error,
        )
    };
    assert_eq!(retried, 0, "a failed Adapter accepted a retry");
    let retry_error = take(retry_error);
    assert!(
        retry_error.contains("spent") && retry_error.contains("discarded"),
        "retry did not require runtime disposal: {retry_error}"
    );
    unsafe { storage_consumer_destroy(handle) };
    error
}

#[test]
fn truncated_binding_bytecode_is_refused_and_spends_the_adapter() {
    let context = Context::new(GrantSet::none());
    let mut bytes = compiled_bytes("headers").to_vec();
    bytes.truncate(bytes.len() - 1);
    let name = b"headers\0";
    let mut scripts: Vec<_> = ibex2::bindings::scripts(Groups::PURE)
        .unwrap()
        .into_iter()
        .map(|(name, _)| compiled_script(name))
        .collect();
    scripts[0] = CompiledScript {
        name: name.as_ptr().cast(),
        bytes: bytes.as_ptr(),
        len: bytes.len(),
    };
    let _ = assert_failed_install_is_terminal(&context, &scripts, "declared length");
}

#[test]
fn spoofed_binding_header_is_refused_in_preflight_and_spends_the_adapter() {
    let context = Context::new(GrantSet::none());
    let valid = compiled_bytes("headers");
    let mut bytes = [0; 36];
    bytes[..12].copy_from_slice(&valid[..12]);
    bytes[32..36].copy_from_slice(&36u32.to_le_bytes());
    let name = b"headers\0";
    let mut scripts: Vec<_> = ibex2::bindings::scripts(Groups::PURE)
        .unwrap()
        .into_iter()
        .map(|(name, _)| compiled_script(name))
        .collect();
    scripts[0] = CompiledScript {
        name: name.as_ptr().cast(),
        bytes: bytes.as_ptr(),
        len: bytes.len(),
    };
    let error =
        assert_failed_install_is_terminal(&context, &scripts, "truncated Hermes bytecode header");
    assert!(
        !error.contains("after mutating"),
        "the fixed-header refusal happened after publication: {error}"
    );
}

#[test]
fn wrong_binding_version_is_refused_and_spends_a_versioned_adapter() {
    let context = Context::new(GrantSet::none());
    let mut bytes = compiled_bytes("headers").to_vec();
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    bytes[8..12].copy_from_slice(&version.wrapping_add(1).to_le_bytes());
    let name = b"headers\0";
    let mut scripts: Vec<_> = ibex2::bindings::scripts(Groups::PURE)
        .unwrap()
        .into_iter()
        .map(|(name, _)| compiled_script(name))
        .collect();
    scripts[0] = CompiledScript {
        name: name.as_ptr().cast(),
        bytes: bytes.as_ptr(),
        len: bytes.len(),
    };
    let _ = assert_failed_install_is_terminal(&context, &scripts, "version does not match");
}

#[test]
fn caller_owns_checkpoints_and_storage_is_typed_and_granted() {
    let c = Consumer::new("fs.read app:/data\nfs.write app:/data\nsqlite.open app:/data/db");
    // Both names exercise escaped strings; Windows refuses control characters.
    let filename = if cfg!(windows) { r"a\u00e9 b" } else { r"a\nb" };
    c.eval(&format!("globalThis.storageFilename = '{filename}';"))
        .unwrap();
    c.eval(r#"globalThis.result = ''; storage.fs.atomicWriteFile('app:/data/' + storageFilename, new Uint8Array([1,2])).then(function(){ result = 'written'; });"#).unwrap();
    assert!(c.context.wait(Duration::from_secs(5)));
    assert_eq!(c.eval("result").unwrap(), "");
    assert_eq!(c.step(true), 1);
    assert_eq!(
        c.eval("result").unwrap(),
        "",
        "delivery must not drain microtasks"
    );
    c.step(false);
    assert_eq!(c.eval("result").unwrap(), "written");
    c.eval(r#"result = ''; (async function(){
      const names = await storage.fs.readdir('app:/data');
      if (names.length !== 1 || names[0] !== storageFilename) throw Error('filename');
      const stat = await storage.fs.stat('app:/data/' + storageFilename);
      if (!stat.isFile || stat.isDirectory || stat.size !== 2) throw Error('stat');
      const bytes = await storage.fs.readFile('app:/data/' + storageFilename);
      if (!(bytes instanceof ArrayBuffer) || new Uint8Array(bytes)[1] !== 2) throw Error('bytes');
      const db = await storage.sqlite.open('app:/data/db');
      await db.execute('CREATE TABLE notes(body TEXT)');
      await db.transaction([{sql:'INSERT INTO notes VALUES (?)',params:['remember']}]);
      await db.close();
      const again = await storage.sqlite.open('app:/data/db');
      const rows = await again.query('SELECT body, 9223372036854775807 FROM notes');
      await again.close();
      if(rows.rows[0][0] !== 'remember' || rows.rows[0][1] !== BigInt('9223372036854775807')) throw Error('persistence');
      try { await storage.fs.writeFile('app:/cache/no', new Uint8Array([0])); throw Error('leaked'); }
      catch(e) { if(e.message === 'leaked') throw e; }
      result='ok';
    })().catch(e => result=String(e));"#).unwrap();
    assert_eq!(c.finish(), "ok");
    assert!(c.wakes.load(Ordering::SeqCst) > 0);
    assert!(!c.directory.join("cache/no").exists());
}

#[test]
fn detached_capabilities_and_pending_work_do_not_reach_dead_runtime() {
    let c = Consumer::new("fs.write app:/data");
    c.eval("storage.fs.writeFile('app:/data/file', new Uint8Array([1]));")
        .unwrap();
    unsafe { storage_consumer_detach(c.handle) };
    assert!(c
        .eval("storage.fs.writeFile('app:/data/other', new Uint8Array([1]));")
        .is_err());
    assert!(!c.directory.join("data/other").exists());
}

#[test]
fn empty_grants_refuse_files_and_sqlite_before_creation() {
    let c = Consumer::new("");
    c.eval(r#"globalThis.result = ''; (async function(){
      let refused = 0;
      try { await storage.fs.writeFile('app:/data/no', new Uint8Array([1])); } catch(e) { refused++; }
      try { await storage.sqlite.open('app:/data/db'); } catch(e) { refused++; }
      result = String(refused);
    })();"#).unwrap();
    assert_eq!(c.finish(), "2");
    assert_eq!(
        std::fs::read_dir(c.directory.join("data")).unwrap().count(),
        0
    );
}

#[test]
fn sqlite_refuses_a_caller_that_has_not_hardened_its_intrinsics() {
    let c = Consumer::configured("sqlite.open app:/data/db", false);
    c.eval("globalThis.result=''; storage.sqlite.open('app:/data/db').then(() => result='opened', e => result=String(e));").ok();
    // The adapter refuses synchronously before publishing native work.
    let error = c.eval("storage.sqlite.open('app:/data/db')").unwrap_err();
    assert!(error.contains("harden"), "{error}");
    assert!(!c.directory.join("data/db").exists());
}

#[test]
fn freezing_modified_intrinsics_does_not_satisfy_the_installation_contract() {
    let c = Consumer::configured("sqlite.open app:/data/db", false);
    c.eval("WeakMap.prototype.get = function () { return undefined; };")
        .unwrap();
    c.eval(ibex2::bindings::HARDEN_SOURCE).unwrap();
    let error = c.eval("storage.sqlite.open('app:/data/db')").unwrap_err();
    assert!(error.contains("harden"), "{error}");
    assert!(!c.directory.join("data/db").exists());
}

#[test]
fn rejection_tracker_replacements_are_part_of_the_integrity_baseline() {
    let groups = Groups::PURE | Groups::CONSOLE | Groups::TIMERS | Groups::EVENTS | Groups::STORAGE;
    let consumer = BareConsumer::new(groups);
    assert_eq!(
        consumer.eval("[typeof Promise._B, typeof Promise._C].join('|')"),
        "function|function"
    );
    consumer.eval("Promise._B = function () {}; Promise._C = function () {};");
    consumer.eval(ibex2::bindings::HARDEN_SOURCE);

    let error = consumer
        .eval_result("sqlite.open('app:/data/db')")
        .unwrap_err();
    assert!(error.contains("harden"), "{error}");
}
