use ibex2::bindings::{Context, Groups};
use ibex2::boundary::HostError;
use ibex2::grant::GrantSet;
use ibex2::host::Host;
use ibex2::stdlib::abort::AbortSignal;
use ibex2::stdlib::fetch::{Headers, Request, Response, StreamingResponse, Transport};
use ibex2_runtime::engine::hermes::{DynamicCode, Hermes, InstallOptions};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

const PRIMITIVES: &str = "__held_fetch_primitives";
const HOST_WORKERS: usize = 64;
const FETCH_GROUPS: Groups = Groups::PURE.union(Groups::ABORT).union(Groups::FETCH);

struct HeldTransport {
    entered: mpsc::Sender<Option<String>>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl Transport for HeldTransport {
    fn open(
        &self,
        request: &Request,
        signal: &AbortSignal,
    ) -> Result<StreamingResponse, HostError> {
        self.entered
            .send(request.headers.get("x").map(str::to_owned))
            .unwrap();
        let mut released = self.release.0.lock().unwrap();
        while !*released {
            released = self.release.1.wait(released).unwrap();
        }
        signal.check()?;
        Ok(Response {
            status: 200,
            status_text: "OK".into(),
            headers: Headers::new(),
            body: Vec::new(),
            url: request.url.clone(),
            redirected: false,
        }
        .into_stream(request.body_limit(), signal.clone()))
    }
}

struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);

impl ReleaseOnDrop {
    fn release(&self) {
        let (released, wake) = &*self.0;
        *released.lock().unwrap() = true;
        wake.notify_all();
    }
}

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.release();
    }
}

#[test]
fn primitive_fetch_snapshots_headers_before_its_worker_runs() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let bindings = Host::with_transport(Box::new(HeldTransport {
        entered: entered_tx,
        release: Arc::clone(&release),
    }))
    .endow(GrantSet::parse("net.fetch https://headers.example\n").unwrap());
    let context = Context::from_bindings(&bindings);
    let mut runtime = Hermes::new(DynamicCode::Closed).unwrap();
    runtime
        .install_with(
            FETCH_GROUPS,
            &context,
            InstallOptions {
                fetch_primitives: Some(PRIMITIVES),
                ..InstallOptions::default()
            },
        )
        .unwrap();
    let release_on_drop = ReleaseOnDrop(release);

    runtime
        .eval(&format!(
            r#"
            globalThis.headerRace = (function (p) {{
              delete globalThis.{PRIMITIVES};
              var blockerHeaders = [];
              function finish(handle, headersHandle, token) {{
                p.responseField(handle, 8);
                p.headersFree(headersHandle);
                p.fetchControl(2, token);
              }}
              return {{
                startBlockers: function (url, count) {{
                  for (var i = 0; i < count; i++) (function () {{
                    var headers = new Headers({{blocker: String(i)}});
                    var headersHandle = headers._handle;
                    var token = p.fetchControl(0);
                    blockerHeaders.push(headers);
                    p.fetch(url, "GET", undefined, "manual", headersHandle, token).then(
                      function (handle) {{ finish(handle, headersHandle, token); }},
                      function (error) {{
                        p.headersFree(headersHandle);
                        p.fetchControl(2, token);
                        globalThis.blockerError = String(error.message || error);
                      }}
                    );
                  }})();
                  return blockerHeaders.length;
                }},
                startTarget: function (url) {{
                  function temporaryHeadersHandle() {{
                    return new Headers({{x: "y"}})._handle;
                  }}
                  var headersHandle = temporaryHeadersHandle();
                  var token = p.fetchControl(0);
                  globalThis.targetResult = "pending";
                  p.fetch(url, "GET", undefined, "follow", headersHandle, token).then(
                    function (handle) {{
                      finish(handle, headersHandle, token);
                      targetResult = "ok";
                    }},
                    function (error) {{
                      p.headersFree(headersHandle);
                      p.fetchControl(2, token);
                      targetResult = "ERROR: " + String(error.message || error);
                    }}
                  );
                }}
              }};
            }})(globalThis.{PRIMITIVES});
            "#
        ))
        .unwrap();
    assert_eq!(
        runtime
            .eval(&format!(
                "String(headerRace.startBlockers('https://headers.example/block', {HOST_WORKERS}))"
            ))
            .unwrap(),
        HOST_WORKERS.to_string()
    );

    // `pool::MAX` is 64. Once every request has entered this blocking
    // transport, the target job can only remain queued.
    for _ in 0..HOST_WORKERS {
        assert_eq!(
            entered_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            None
        );
    }
    assert_eq!(runtime.live_header_handles_for_test(), HOST_WORKERS);

    runtime
        .eval("headerRace.startTarget('https://headers.example/target'); void 0")
        .unwrap();
    assert_eq!(runtime.live_header_handles_for_test(), HOST_WORKERS + 1);
    for _ in 0..8 {
        assert!(runtime.collect_garbage());
        if runtime.live_header_handles_for_test() == HOST_WORKERS {
            break;
        }
    }
    assert_eq!(
        runtime.live_header_handles_for_test(),
        HOST_WORKERS,
        "the temporary target Headers wrapper must be collected while its job is queued"
    );

    release_on_drop.release();
    assert_eq!(
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
        Some("y".into()),
        "the queued worker must receive the JS-thread header snapshot"
    );
    runtime.run_to_quiescence(Duration::from_secs(10));
    assert_eq!(runtime.eval("targetResult").unwrap(), "ok");
    assert_eq!(
        runtime.eval("String(globalThis.blockerError)").unwrap(),
        "undefined"
    );
}
