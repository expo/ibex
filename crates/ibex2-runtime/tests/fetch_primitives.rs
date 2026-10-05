use ibex2::bindings::{Context, Groups};
use ibex2::grant::GrantSet;
use ibex2_runtime::engine::hermes::{DynamicCode, Hermes, InstallOptions};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const PRIMITIVES_GLOBAL: &str = "__snapback_ibex2_fetch_primitives";
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
            },
        )
        .expect("install fetch primitives");
    runtime
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
