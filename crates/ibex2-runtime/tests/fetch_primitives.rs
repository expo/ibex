use ibex2::bindings::{Context, Groups};
use ibex2::grant::GrantSet;
use ibex2_runtime::engine::hermes::{DynamicCode, Hermes, InstallOptions};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "loader")]
mod common;

const PRIMITIVES_GLOBAL: &str = "__snapback_ibex2_fetch_primitives";
const ABORT_HOOKS_GLOBAL: &str = "__exact_ibex2_abort_hooks";
const SNAPBACK_FETCH: &str = include_str!("fixtures/snapback_fetch.js");
const SNAPBACK_BOUND: &str = include_str!("fixtures/snapback_bound.js");
const FETCH_GROUPS: Groups = Groups::PURE.union(Groups::ABORT).union(Groups::FETCH);

struct TestServer {
    origin: String,
    hits: Arc<AtomicUsize>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    fn start(expected_requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&hits);
        let thread = std::thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("accept request");
                observed.fetch_add(1, Ordering::SeqCst);
                let request = read_request(&mut stream);
                if request.starts_with("GET /abort ") {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n",
                        )
                        .unwrap();
                    stream.flush().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut byte = [0_u8; 1];
                    while matches!(stream.read(&mut byte), Ok(1)) {}
                    continue;
                }

                let first = vec![b'a'; 20_000];
                let second = vec![b'b'; 20_000];
                let third = vec![b'c'; 20_000];
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Ibex: primitive\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                for chunk in [&first, &second, &third] {
                    write!(stream, "{:x}\r\n", chunk.len()).unwrap();
                    stream.write_all(chunk).unwrap();
                    stream.write_all(b"\r\n").unwrap();
                    stream.flush().unwrap();
                }
                stream.write_all(b"0\r\n\r\n").unwrap();
            }
        });
        Self {
            origin,
            hits,
            thread: Some(thread),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().expect("test server thread");
        }
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let count = stream.read(&mut buffer).expect("read request");
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn install_with_primitives(grants: GrantSet) -> Hermes {
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    let context = Context::new(grants);
    runtime
        .install_with(
            FETCH_GROUPS,
            &context,
            InstallOptions {
                fetch_primitives: Some(PRIMITIVES_GLOBAL),
                ..InstallOptions::default()
            },
        )
        .expect("install fetch primitives");
    runtime
}

#[test]
fn fetch_runtime_hides_abort_hook_authority_after_bootstrap_and_harden() {
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    let context = Context::new(GrantSet::none());
    runtime
        .install_with(
            FETCH_GROUPS,
            &context,
            InstallOptions {
                abort_hooks: Some(ABORT_HOOKS_GLOBAL),
                ..InstallOptions::default()
            },
        )
        .expect("install fetch with abort hooks");
    runtime
        .eval(&format!(
            r#"
            globalThis.embedderAbortSubscribe = (function (hooks) {{
              var subscribe = hooks.subscribe;
              delete globalThis.{ABORT_HOOKS_GLOBAL};
              return (function (subscribeOnly) {{
                return function (signal, callback) {{ return subscribeOnly(signal, callback); }};
              }})(subscribe);
            }})(globalThis.{ABORT_HOOKS_GLOBAL});
            "#
        ))
        .expect("trusted bootstrap wraps subscribe and deletes its global");
    runtime.harden().expect("only a closure retains subscribe");
    assert_eq!(
        runtime
            .eval(&format!(
                r#"
                (function () {{
                  var controller = new AbortController(), callbackArgument = "not-called";
                  var unsubscribe = embedderAbortSubscribe(controller.signal, function () {{
                    callbackArgument = arguments.length === 0 ? "none" : typeof arguments[0];
                  }});
                  controller.abort();
                  return [
                    typeof globalThis.{ABORT_HOOKS_GLOBAL},
                    typeof globalThis.__ibex2_abort,
                    typeof AbortSignal.own,
                    typeof AbortSignal.subscribe,
                    typeof controller.signal.own,
                    typeof controller.signal.subscribe,
                    typeof embedderAbortSubscribe.own,
                    typeof embedderAbortSubscribe.subscribe,
                    typeof unsubscribe,
                    callbackArgument
                  ].join("|");
                }})()
                "#
            ))
            .expect("application probe"),
        "undefined|undefined|undefined|undefined|undefined|undefined|undefined|undefined|function|none"
    );
}

#[test]
fn primitives_fetch_streams_fields_controls_and_reuses_the_context_grant() {
    let server = TestServer::start(2);
    let grants = GrantSet::parse(&format!("net.fetch {}\n", server.origin)).unwrap();
    let mut runtime = install_with_primitives(grants);

    runtime
        .eval(&format!(
            r#"
            globalThis.__runPrimitiveFetch = (function (p) {{
              delete globalThis.{PRIMITIVES_GLOBAL};
              return function (url, deniedUrl, abortUrl) {{
                function raw(target, token) {{
                  var headers = new Headers([["x-request", "primitive"]]);
                  var pending;
                  try {{
                    pending = p.fetch(target, "GET", undefined, "manual", headers._handle, token);
                  }} catch (error) {{
                    p.headersFree(headers._handle);
                    throw error;
                  }}
                  return pending.then(function (handle) {{
                    p.headersFree(headers._handle);
                    return handle;
                  }}, function (error) {{
                    p.headersFree(headers._handle);
                    throw error;
                  }});
                }}

                var token = p.fetchControl(0);
                var granted = raw(url, token).then(function (handle) {{
                  p.fetchControl(2, token);
                  var metadata = {{
                    status: p.responseField(handle, 0),
                    url: p.responseField(handle, 2),
                    header: p.responseField(handle, 3, "x-ibex"),
                    headers: JSON.parse(p.responseField(handle, 7))
                  }};
                  var chunks = [], reads = 0;
                  function read() {{
                    return p.responseRead(handle).then(function (bytes) {{
                      if (bytes === null) return;
                      reads++;
                      chunks.push(p.textDecode(bytes));
                      return read();
                    }});
                  }}
                  return read().then(function () {{
                    metadata.bodyLength = chunks.join("").length;
                    metadata.reads = reads;
                    return metadata;
                  }});
                }});

                var deniedToken = p.fetchControl(0);
                var denied = raw(deniedUrl, deniedToken).then(
                  function () {{ return "unexpected success"; }},
                  function (error) {{ return String(error.message || error); }}
                ).then(function (message) {{
                  p.fetchControl(2, deniedToken);
                  return message;
                }});

                var abortToken = p.fetchControl(0);
                var aborted = raw(abortUrl, abortToken).then(function (handle) {{
                  p.fetchControl(1, abortToken);
                  return p.responseRead(handle).then(
                    function () {{ return "unexpected success"; }},
                    function (error) {{ return String(error.message || error); }}
                  );
                }}, function (error) {{
                  return String(error.message || error);
                }}
                ).then(function (message) {{
                  p.fetchControl(2, abortToken);
                  return message;
                }});

                var destination = new Uint8Array(4);
                var encodeInto = p.textEncodeInto("ok", destination);
                var encoded = p.textDecode(p.textEncode("encoded"));
                return Promise.all([granted, denied, aborted]).then(function (values) {{
                  return {{
                    frozen: Object.isFrozen(p),
                    granted: values[0],
                    denied: values[1],
                    aborted: values[2],
                    encoded: encoded,
                    encodeInto: encodeInto,
                    destination: Array.from(destination)
                  }};
                }});
              }};
            }})(globalThis.{PRIMITIVES_GLOBAL});
            "#
        ))
        .expect("capture and delete primitives");
    runtime.harden().expect("deleted primitive global hardens");

    let granted_url = format!("{}/chunks", server.origin);
    let abort_url = format!("{}/abort", server.origin);
    runtime
        .eval(&format!(
            r#"
            globalThis.__primitiveResult = "pending";
            __runPrimitiveFetch({granted_url:?}, "http://127.0.0.1:1/denied", {abort_url:?})
              .then(function (value) {{ __primitiveResult = JSON.stringify(value); }},
                    function (error) {{ __primitiveResult = JSON.stringify({{ error: String(error && error.stack || error) }}); }});
            "#
        ))
        .unwrap();
    runtime.run_to_quiescence(Duration::from_secs(10));

    let result: Value = serde_json::from_str(&runtime.eval("__primitiveResult").unwrap()).unwrap();
    assert_eq!(result["frozen"], true);
    assert_eq!(result["granted"]["status"], 200);
    assert_eq!(result["granted"]["url"], granted_url);
    assert_eq!(result["granted"]["header"], "primitive");
    assert!(result["granted"]["headers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|pair| pair[0] == "x-ibex" && pair[1] == "primitive"));
    assert_eq!(result["granted"]["bodyLength"], 60_000);
    assert!(result["granted"]["reads"].as_u64().unwrap() >= 3);
    assert_eq!(result["denied"], "denied: net.fetch");
    assert_ne!(result["aborted"], "unexpected success");
    assert_eq!(result["encoded"], "encoded");
    assert_eq!(result["encodeInto"], "2,2");
    assert_eq!(result["destination"], serde_json::json!([111, 107, 0, 0]));
    assert_eq!(server.hits.load(Ordering::SeqCst), 2);
}

#[test]
fn harden_refuses_a_published_primitives_global() {
    let mut runtime = install_with_primitives(GrantSet::none());
    let error = runtime.harden().unwrap_err().to_string();
    assert!(error.contains("refusing to harden while fetch primitives global"));
    assert_eq!(
        runtime
            .eval(&format!(
                "delete globalThis.{PRIMITIVES_GLOBAL}; String(true)"
            ))
            .unwrap(),
        "true"
    );
    runtime
        .harden()
        .expect("deleting the global closes the leak");
}

#[test]
fn fetch_primitives_require_the_fetch_group() {
    let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
    let context = Context::new(GrantSet::none());
    let error = runtime
        .install_with(
            Groups::PURE,
            &context,
            InstallOptions {
                fetch_primitives: Some(PRIMITIVES_GLOBAL),
                ..InstallOptions::default()
            },
        )
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "fetch primitives require the FETCH group"
    );
    assert_eq!(
        runtime
            .eval(&format!("typeof globalThis.{PRIMITIVES_GLOBAL}"))
            .unwrap(),
        "undefined"
    );
}

#[test]
fn snapback_fetch_and_bound_preludes_use_the_opt_in_object() {
    let server = TestServer::start(1);
    let grants = GrantSet::parse(&format!("net.fetch {}\n", server.origin)).unwrap();
    let mut runtime = install_with_primitives(grants);

    let logical_origin = "https://logical.example";
    let bound = SNAPBACK_BOUND
        .replace("__SNAPBACK_GRANTS__", &format!("[{logical_origin:?}]"))
        .replace(
            "__SNAPBACK_BINDINGS__",
            &format!("{{ {logical_origin:?}: {:?} }}", server.origin),
        )
        .replace("__SNAPBACK_EFFECT_NAME__", "\"fixture-effect\"");
    runtime
        .eval(&format!("globalThis.__snapbackBound = {bound}"))
        .expect("evaluate bound transport fixture");
    runtime
        .eval(&format!("globalThis.__snapbackFactory = {SNAPBACK_FETCH}"))
        .expect("evaluate fetch fixture");
    runtime
        .eval(&format!(
            r#"
            globalThis.__snapbackFetch = (function (factory, bound, evidence) {{
              var pending = 0, maxPending = 0;
              var fetch = factory(
                bound,
                function (error) {{ return error; }},
                function (delta) {{ pending += delta; maxPending = Math.max(maxPending, pending); }},
                true
              );
              globalThis.__snapbackFetchState = function () {{
                return {{ pending: pending, maxPending: maxPending, evidence: evidence() }};
              }};
              return fetch;
            }})(__snapbackFactory, __snapbackBound, __sb_provider);
            __sb_provider(true);
            delete globalThis.__snapbackFactory;
            delete globalThis.__snapbackBound;
            delete globalThis.__sb_provider;
            delete globalThis.{PRIMITIVES_GLOBAL};
            "#
        ))
        .expect("capture fixture fetch and delete primitive access");
    runtime
        .harden()
        .expect("Snapback bootstrap closed the leak");

    let logical_url = format!("{logical_origin}/fixture?one=1#fragment");
    runtime
        .eval(&format!(
            r#"
            globalThis.__snapbackResult = "pending";
            __snapbackFetch({logical_url:?}).then(function (response) {{
              return response.text().then(function (body) {{
                var state = __snapbackFetchState();
                __snapbackResult = JSON.stringify({{
                  status: response.status,
                  url: response.url,
                  header: response.headers.get("x-ibex"),
                  bodyLength: body.length,
                  first: body[0],
                  last: body[body.length - 1],
                  pending: state.pending,
                  maxPending: state.maxPending,
                  evidence: state.evidence
                }});
              }});
            }}, function (error) {{
              __snapbackResult = JSON.stringify({{ error: String(error && error.stack || error) }});
            }});
            "#
        ))
        .unwrap();
    runtime.run_to_quiescence(Duration::from_secs(10));

    let result: Value = serde_json::from_str(&runtime.eval("__snapbackResult").unwrap()).unwrap();
    assert_eq!(result["status"], 200);
    assert_eq!(result["url"], format!("{logical_origin}/fixture?one=1"));
    assert_eq!(result["header"], "primitive");
    assert_eq!(result["bodyLength"], 60_000);
    assert_eq!(result["first"], "a");
    assert_eq!(result["last"], "c");
    assert_eq!(result["pending"], 0);
    assert_eq!(result["maxPending"], 1);
    assert_eq!(result["evidence"]["requests"], 1);
    assert_eq!(result["evidence"]["origins"][0], logical_origin);
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);
}

/// Answers each accepted connection, in order, with the next canned response.
/// `build` receives the server's own origin so a response can name it.
fn canned_server(build: impl FnOnce(&str) -> Vec<String>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind canned server");
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let responses = build(&origin);
    let thread = std::thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().expect("accept request");
            read_request(&mut stream);
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
    });
    (origin, thread)
}

fn ok_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Classifies how a synchronous call ended, for JSON assertions.
const KIND: &str = r#"
  function kind(call) {
    try { call(); return "accepted"; }
    catch (error) {
      if (error instanceof RangeError) return "RangeError";
      if (error instanceof TypeError) return "TypeError";
      return String(error);
    }
  }
"#;

/// Trusted bootstrap: capture the object in a closure, delete the global, and
/// publish only a wrapper. `body` is the wrapper function's body and may use
/// `p`, `kind`, and the wrapper's single argument `arg`.
fn bootstrap_probe(runtime: &mut Hermes, body: &str) {
    runtime
        .eval(&format!(
            r#"
            globalThis.__probe = (function (p) {{
              delete globalThis.{PRIMITIVES_GLOBAL};
              {KIND}
              return function (arg) {{ {body} }};
            }})(globalThis.{PRIMITIVES_GLOBAL});
            "#
        ))
        .expect("bootstrap captures the primitives");
}

fn run_probe(runtime: &mut Hermes, argument: &str) -> Value {
    runtime
        .eval(&format!(
            r#"
            globalThis.__probeResult = "pending";
            Promise.resolve(__probe({argument})).then(
              function (value) {{ __probeResult = JSON.stringify(value); }},
              function (error) {{ __probeResult = JSON.stringify({{ error: String(error && error.stack || error) }}); }});
            "#
        ))
        .unwrap();
    runtime.run_to_quiescence(Duration::from_secs(10));
    let text = runtime.eval("__probeResult").unwrap();
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("probe result: {text}"))
}

#[test]
fn an_inherited_value_field_cannot_hide_an_accessor_alias() {
    // Bootstrap hides a member as a getter, then plants a `value` on
    // Object.prototype. Descriptor records are classified by their own fields, so the
    // getter is still found, and an inherited `value` accessor never runs.
    for planted in [
        "Object.defineProperty(Object.prototype, 'value', { value: 0, configurable: true });",
        "Object.defineProperty(Object.prototype, 'value', { get: function () { globalThis.__plantedRan = true; return 0; }, configurable: true });",
    ] {
        let mut runtime = install_with_primitives(GrantSet::none());
        runtime
            .eval(&format!(
                "(function (p) {{ delete globalThis.{PRIMITIVES_GLOBAL}; Object.defineProperty(globalThis, 'leak', {{ get: p.fetch, configurable: true }}); {planted} }})(globalThis.{PRIMITIVES_GLOBAL});"
            ))
            .expect("bootstrap hides an accessor alias");
        let error = runtime.harden().unwrap_err().to_string();
        assert!(
            error.contains("fetch primitives member fetch is still reachable"),
            "{planted}: {error}"
        );
        assert_eq!(
            runtime.eval("String(globalThis.__plantedRan)").unwrap(),
            "undefined",
            "{planted}"
        );
    }
}

#[test]
fn harden_refuses_any_alias_of_the_object_or_a_member() {
    for (alias, reachable) in [
        ("globalThis.alias = p;", "the fetch primitives object"),
        (
            "Object.defineProperty(Object.prototype, 'leak', { value: p });",
            "the fetch primitives object",
        ),
        ("globalThis.f = p.fetch;", "fetch primitives member fetch"),
        (
            "Array.prototype.nested = { deep: [p.responseRead] };",
            "fetch primitives member responseRead",
        ),
        (
            "globalThis[Symbol.for('ibex2.leak')] = p.headersFree;",
            "fetch primitives member headersFree",
        ),
        (
            "Object.defineProperty(globalThis, 'g', { get: p.textDecode, configurable: true });",
            "fetch primitives member textDecode",
        ),
        (
            "Object.setPrototypeOf(Function.prototype.call, { hidden: p.fetchControl });",
            "fetch primitives member fetchControl",
        ),
    ] {
        let mut runtime = install_with_primitives(GrantSet::none());
        runtime
            .eval(&format!(
                "(function (p) {{ delete globalThis.{PRIMITIVES_GLOBAL}; {alias} }})(globalThis.{PRIMITIVES_GLOBAL});"
            ))
            .expect("bootstrap leaves an alias");
        let error = runtime.harden().unwrap_err().to_string();
        assert!(
            error.contains(&format!("{reachable} is still reachable")),
            "{alias}: {error}"
        );
        // A refusal freezes nothing.
        assert_eq!(
            runtime
                .eval("String(Object.isFrozen(Array.prototype))")
                .unwrap(),
            "false",
            "{alias}"
        );
    }

    // Removing the alias closes the leak; a closure capture is outside the
    // walk by design, and the walk never invokes a getter it passes.
    let mut runtime = install_with_primitives(GrantSet::none());
    runtime
        .eval(&format!(
            r#"
            globalThis.__wrapped = (function (p) {{
              delete globalThis.{PRIMITIVES_GLOBAL};
              globalThis.alias = p;
              return function () {{ return typeof p.fetch; }};
            }})(globalThis.{PRIMITIVES_GLOBAL});
            Object.defineProperty(globalThis, "trap", {{
              get: function () {{ globalThis.__getterRan = true; return 1; }},
              configurable: true
            }});
            "#
        ))
        .unwrap();
    assert!(runtime.harden().is_err());
    runtime.eval("delete globalThis.alias").unwrap();
    runtime
        .harden()
        .expect("only a closure holds the primitives");
    assert_eq!(runtime.eval("__wrapped()").unwrap(), "function");
    assert_eq!(
        runtime.eval("String(globalThis.__getterRan)").unwrap(),
        "undefined"
    );
    assert_eq!(
        runtime
            .eval("String(Object.isFrozen(Array.prototype))")
            .unwrap(),
        "true"
    );
}

#[test]
fn install_runtime_with_publishes_the_same_guarded_object() {
    let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
    let context = Context::new(GrantSet::none());
    runtime
        .install_runtime_with(
            Groups::DEFAULT,
            &context,
            InstallOptions {
                fetch_primitives: Some(PRIMITIVES_GLOBAL),
                ..InstallOptions::default()
            },
        )
        .expect("runtime bootstrap with primitives");
    assert_eq!(
        runtime
            .eval(&format!(
                "var p = globalThis.{PRIMITIVES_GLOBAL}; \
                 [Object.isFrozen(p), Object.keys(p).join(), typeof __ibex2_default].join('|')"
            ))
            .unwrap(),
        "true|fetch,responseField,responseRead,fetchControl,textEncode,textDecode,textEncodeInto,headersFree|function"
    );
    let error = runtime.harden().unwrap_err().to_string();
    assert!(
        error.contains("refusing to harden while fetch primitives global"),
        "{error}"
    );
    // `var p` above is itself a global alias.
    runtime
        .eval(&format!("delete globalThis.{PRIMITIVES_GLOBAL}"))
        .unwrap();
    let error = runtime.harden().unwrap_err().to_string();
    assert!(
        error.contains("the fetch primitives object is still reachable"),
        "{error}"
    );
    runtime.eval("p = undefined").unwrap();
    runtime.harden().expect("no path to the primitives remains");
}

#[test]
fn fetch_primitive_names_are_unused_ascii_identifiers() {
    let context = Context::new(GrantSet::none());
    for name in [
        "1abc",
        "has space",
        "a-b",
        "na\u{ef}ve",
        "\u{441}ount",
        "zero\u{200b}width",
        "nul\0byte",
        "x.y",
    ] {
        for runtime_path in [false, true] {
            let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
            let options = InstallOptions {
                fetch_primitives: Some(name),
                ..InstallOptions::default()
            };
            let error = if runtime_path {
                runtime.install_runtime_with(FETCH_GROUPS, &context, options)
            } else {
                runtime.install_with(FETCH_GROUPS, &context, options)
            }
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("must be an ASCII JavaScript identifier"),
                "{name:?}: {error}"
            );
            // Refused before anything was prepared or installed: the same
            // runtime still accepts a valid installation.
            assert_eq!(runtime.eval("typeof __ibex2_default").unwrap(), "undefined");
            runtime
                .install_with(
                    FETCH_GROUPS,
                    &context,
                    InstallOptions {
                        fetch_primitives: Some("$valid_Name1"),
                        ..InstallOptions::default()
                    },
                )
                .expect("a valid name still installs");
        }
    }
    let error = Hermes::new(DynamicCode::Closed)
        .unwrap()
        .install_with(
            FETCH_GROUPS,
            &context,
            InstallOptions {
                fetch_primitives: Some(""),
                ..InstallOptions::default()
            },
        )
        .unwrap_err()
        .to_string();
    assert_eq!(error, "fetch primitives require a non-empty global name");

    for runtime_path in [false, true] {
        let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
        let options = InstallOptions {
            fetch_primitives: Some("__shared_bootstrap_output"),
            abort_hooks: Some("__shared_bootstrap_output"),
            ..InstallOptions::default()
        };
        let error = if runtime_path {
            runtime.install_runtime_with(FETCH_GROUPS, &context, options)
        } else {
            runtime.install_with(FETCH_GROUPS, &context, options)
        }
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "trusted-bootstrap outputs require distinct global names"
        );
        assert_eq!(
            runtime.eval("typeof __ibex2_default").unwrap(),
            "undefined",
            "runtime-only globals must not be prepared before option preflight"
        );
    }

    for (name, expected) in [
        ("Object", "fetch primitives global already exists"),
        ("globalThis", "fetch primitives global already exists"),
        ("toString", "fetch primitives global already exists"),
        ("__proto__", "fetch primitives global already exists"),
        (
            "Headers",
            "fetch primitives global collides with an installed binding",
        ),
    ] {
        let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
        let error = runtime
            .install_with(
                FETCH_GROUPS,
                &context,
                InstallOptions {
                    fetch_primitives: Some(name),
                    ..InstallOptions::default()
                },
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{name}: {error}");
    }
}

#[test]
fn numeric_arguments_are_validated_before_conversion() {
    let (origin, server) = canned_server(|_| vec![ok_response("x")]);
    let grants = GrantSet::parse(&format!("net.fetch {origin}\n")).unwrap();
    let mut runtime = install_with_primitives(grants);
    bootstrap_probe(
        &mut runtime,
        r#"
        var bad = [NaN, Infinity, -Infinity, -1, 0, 0.5, 1.5, 9007199254740992, Math.pow(2, 64)];
        function each(values, call) {
          return values.map(function (value) { return kind(function () { return call(value); }); });
        }
        var handles = {
          responseField: each(bad, function (v) { return p.responseField(v, 0); }),
          responseRead: each(bad, function (v) { return p.responseRead(v); }),
          headersFree: each(bad, function (v) { return p.headersFree(v); }),
          abort: each(bad, function (v) { return p.fetchControl(1, v); }),
          release: each(bad, function (v) { return p.fetchControl(2, v); }),
          fetchHeaders: each(bad, function (v) { return p.fetch(arg, "GET", undefined, "manual", v); }),
          fetchToken: each(bad, function (v) { return p.fetch(arg, "GET", undefined, "manual", undefined, v); })
        };
        var nonNumbers = each(["1", null, true, {}], function (v) { return p.responseRead(v); })
          .concat(each(["1", null], function (v) { return p.headersFree(v); }))
          .concat(each(["0", null], function (v) { return p.fetchControl(v); }));
        var actions = each([NaN, Infinity, -1, 0.5, 3, 9007199254740992], function (v) {
          return p.fetchControl(v, 1);
        });
        var token = p.fetchControl(0);
        return p.fetch(arg, "GET", undefined, "manual", undefined, token).then(function (h) {
          var fields = each([NaN, Infinity, -1, 1.5, 4294967296, 9007199254740992, 4, 6, 9], function (v) {
            return p.responseField(h, v);
          });
          var fieldTypes = [
            kind(function () { return p.responseField(h, "0"); }),
            kind(function () { return p.responseField(h, 3); }),
            kind(function () { return p.responseField(h, 3, 42); })
          ];
          var stillLive = p.responseField(h, 0);
          p.responseField(h, 8);
          p.fetchControl(2, token);
          return {
            handles: handles, nonNumbers: nonNumbers, actions: actions,
            fields: fields, fieldTypes: fieldTypes, stillLive: stillLive,
            stale: kind(function () { return p.responseField(h, 0); })
          };
        });
        "#,
    );
    runtime.harden().unwrap();
    let result = run_probe(&mut runtime, &format!("{:?}", format!("{origin}/x")));
    for (name, kinds) in result["handles"].as_object().expect("handle results") {
        assert_eq!(
            kinds,
            &serde_json::json!(vec!["RangeError"; 9]),
            "{name}: {result}"
        );
    }
    assert_eq!(
        result["nonNumbers"],
        serde_json::json!(vec!["TypeError"; 8]),
        "{result}"
    );
    assert_eq!(
        result["actions"],
        serde_json::json!(vec!["RangeError"; 6]),
        "{result}"
    );
    assert_eq!(
        result["fields"],
        serde_json::json!(vec!["RangeError"; 9]),
        "{result}"
    );
    assert_eq!(
        result["fieldTypes"],
        serde_json::json!(["TypeError", "TypeError", "TypeError"]),
        "{result}"
    );
    assert_eq!(result["stillLive"], 200, "{result}");
    assert_eq!(result["stale"], "TypeError", "{result}");
    server.join().unwrap();
}

#[test]
fn follow_redirects_check_every_hop_against_the_grants() {
    // Every response redirects to an origin the grant does not name.
    let redirect = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/ungranted\r\n\
                    Content-Length: 0\r\nConnection: close\r\n\r\n"
        .to_string();
    let (origin, server) = canned_server(|_| vec![redirect; 4]);
    let grants = GrantSet::parse(&format!("net.fetch {origin}\n")).unwrap();
    let mut runtime = install_with_primitives(grants);
    bootstrap_probe(
        &mut runtime,
        r#"
        function attempt(mode) {
          return p.fetch(arg, "GET", undefined, mode).then(function (h) {
            var status = p.responseField(h, 0);
            p.responseField(h, 8);
            return "status " + status;
          }, function (error) { return String(error.message || error); });
        }
        // Sequential, so each request meets the server in order.
        var out = {};
        return attempt("follow").then(function (v) { out.follow = v; return attempt(undefined); })
          .then(function (v) { out.omitted = v; return attempt("manual"); })
          .then(function (v) { out.manual = v; return attempt("error"); })
          .then(function (v) { out.error = v; return out; });
        "#,
    );
    runtime.harden().unwrap();
    let result = run_probe(&mut runtime, &format!("{:?}", format!("{origin}/redirect")));
    assert_eq!(result["follow"], "denied: net.fetch", "{result}");
    assert_eq!(result["omitted"], "denied: net.fetch", "{result}");
    assert_eq!(result["manual"], "status 302", "{result}");
    assert!(
        result["error"]
            .as_str()
            .unwrap()
            .contains("redirect not allowed"),
        "{result}"
    );
    server.join().unwrap();
}

#[cfg(feature = "loader")]
#[test]
fn released_and_foreign_handles_are_refused_on_the_runtime_path() {
    use ibex2_runtime::loader::{ModuleGrants, Root};

    let (origin, server) =
        canned_server(|_| vec![ok_response("ordinary"), ok_response("primitive")]);
    let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
    let context = Context::new(GrantSet::parse(&format!("net.fetch {origin}\n")).unwrap());
    runtime
        .install_runtime_with(
            Groups::DEFAULT,
            &context,
            InstallOptions {
                fetch_primitives: Some(PRIMITIVES_GLOBAL),
                ..InstallOptions::default()
            },
        )
        .unwrap();
    bootstrap_probe(
        &mut runtime,
        r#"
        // The module's ordinary fetch response is live (its body unread), and
        // every id below the first one this object allocates belongs to that
        // ordinary fetch or to the runtime -- never to these primitives.
        var marker = p.fetchControl(0);
        var foreign = [];
        for (var id = 1; id < marker; id++) {
          foreign.push([
            kind(function () { return p.responseRead(id); }),
            kind(function () { return p.responseField(id, 0); }),
            kind(function () { return p.headersFree(id); }),
            kind(function () { return p.fetchControl(1, id); })
          ].join("/"));
        }
        p.fetchControl(2, marker);
        var appHeaders = new Headers();
        var foreignHeaders = kind(function () { return p.headersFree(appHeaders._handle); });
        var headers = new Headers();
        var token = p.fetchControl(0);
        return p.fetch(arg + "/primitive", "GET", undefined, "manual", headers._handle, token)
          .then(function (h) {
            var firstFree = kind(function () { return p.headersFree(headers._handle); });
            var secondFree = kind(function () { return p.headersFree(headers._handle); });
            p.fetchControl(2, token);
            var tokenAfterRelease = kind(function () { return p.fetchControl(1, token); });
            var chunks = [];
            function drain() {
              return p.responseRead(h).then(function (bytes) {
                if (bytes === null) return;
                chunks.push(p.textDecode(bytes));
                return drain();
              });
            }
            return drain().then(function () {
              return {
                foreign: foreign, foreignHeaders: foreignHeaders,
                firstFree: firstFree, secondFree: secondFree,
                tokenAfterRelease: tokenAfterRelease, body: chunks.join(""),
                readAfterEof: kind(function () { return p.responseRead(h); }),
                fieldAfterEof: kind(function () { return p.responseField(h, 0); })
              };
            });
          });
        "#,
    );
    let project = common::Project::new("fetch-primitives-foreign");
    project.file(
        "index.js",
        &format!(
            r#"
            globalThis.__moduleResult = "pending";
            fetch({origin:?} + "/ordinary").then(function (response) {{
              return __probe({origin:?}).then(function (result) {{
                return response.text().then(function (body) {{
                  result.ordinaryBody = body;
                  __moduleResult = JSON.stringify(result);
                }});
              }});
            }}).catch(function (error) {{
              __moduleResult = JSON.stringify({{ error: String(error && error.stack || error) }});
            }});
            "#
        ),
    );
    runtime
        .set_loader(
            Root::Declared(project.0.clone()),
            ModuleGrants::parse(&format!("[*]\nnet.fetch {origin}\n")).unwrap(),
        )
        .unwrap();
    runtime
        .harden()
        .expect("only the closure holds the primitives");
    runtime.run_entry("./index.js").unwrap();
    runtime.run_to_quiescence(Duration::from_secs(10));
    let text = runtime.eval("__moduleResult").unwrap();
    let result: Value = serde_json::from_str(&text).unwrap_or_else(|_| panic!("{text}"));
    let foreign = result["foreign"]
        .as_array()
        .unwrap_or_else(|| panic!("{result}"));
    assert!(foreign.len() >= 3, "{result}");
    assert!(
        foreign
            .iter()
            .all(|entry| entry == "TypeError/TypeError/TypeError/TypeError"),
        "{result}"
    );
    assert_eq!(result["foreignHeaders"], "TypeError", "{result}");
    assert_eq!(result["firstFree"], "accepted", "{result}");
    assert_eq!(result["secondFree"], "TypeError", "{result}");
    assert_eq!(result["tokenAfterRelease"], "TypeError", "{result}");
    assert_eq!(result["body"], "primitive", "{result}");
    assert_eq!(result["readAfterEof"], "TypeError", "{result}");
    assert_eq!(result["fieldAfterEof"], "TypeError", "{result}");
    // The ordinary response stayed live and readable throughout.
    assert_eq!(result["ordinaryBody"], "ordinary", "{result}");
    server.join().unwrap();
}
