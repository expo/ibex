//! Chrome DevTools Protocol (CDP) implementation (MVP).
//!
//! This runs a lightweight WebSocket server in a dedicated thread and forwards
//! key CDP commands to the engine adapter.

// The Network-domain capture layer lives in the Ibex library next to the
// shared HTTP server that feeds it; re-export so both sides share one state.
// @ref LLP 0010#binary-implementation — the binary reuses the local runtime crate.
#[cfg(feature = "host-http-server")]
pub use ibex_runtime::cdp::network;

#[cfg(not(feature = "host-http-server"))]
mod network {
    use serde_json::{json, Value};

    pub fn enable() {}

    pub fn disable() {}

    pub fn get_response_body(_request_id: &str) -> Value {
        json!({
            "body": "",
            "base64Encoded": false,
        })
    }

    pub fn drain_events() -> Vec<String> {
        Vec::new()
    }
}

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::sync::Notify;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

type WsWrite = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    Message,
>;

struct ConnectionState {
    runtime_ready: bool,
    debugger_ready: bool,
    network_enabled: bool,
}

struct RequestContext<'a> {
    backend: Arc<dyn CdpBackend>,
    write: &'a mut WsWrite,
    state: &'a mut ConnectionState,
    debugger_ready: &'a Arc<AtomicBool>,
    debugger_notify: &'a Arc<Notify>,
}

const CDP_MAX_TEXT_MESSAGE_BYTES: usize = 256 * 1024;
const CDP_MAX_MESSAGES_PER_WINDOW: usize = 600;
const CDP_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);
const CDP_HTTP_READ_TIMEOUT: Duration = Duration::from_secs(5);

struct MessageBudget {
    window_started: Instant,
    messages_seen: usize,
}

impl MessageBudget {
    fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            messages_seen: 0,
        }
    }

    fn try_record(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_started) >= CDP_RATE_LIMIT_WINDOW {
            self.window_started = now;
            self.messages_seen = 0;
        }

        if self.messages_seen >= CDP_MAX_MESSAGES_PER_WINDOW {
            return false;
        }

        self.messages_seen += 1;
        true
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DebugCommand {
    Continue,
    StepInto,
    StepOver,
    StepOut,
}

#[derive(Clone, Debug)]
pub struct ScriptInfo {
    pub id: u32,
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct BreakpointInfo {
    pub id: u64,
    pub script_id: u32,
    pub line: u32,
    pub column: u32,
}

pub trait CdpBackend: Send + Sync {
    fn enable(&self) -> bool;
    fn get_scripts(&self) -> Result<Vec<ScriptInfo>>;
    fn get_script_source(&self, script_id: &str) -> Result<Option<String>>;
    fn set_breakpoint(
        &self,
        script_id: u32,
        line: u32,
        column: u32,
        condition: Option<&str>,
    ) -> Result<BreakpointInfo>;
    fn remove_breakpoint(&self, breakpoint_id: u64);
    fn pause(&self);
    fn resume(&self, command: DebugCommand);
    fn next_event(&self) -> Option<String>;
    fn eval(&self, expression: &str, frame_index: u32) -> Result<Value>;
}

fn cdp_log_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("IBEX_CDP_LOG")
            .or_else(|_| std::env::var("EXACT_CDP_LOG"))
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

pub struct CdpServerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
    connected: Arc<AtomicBool>,
    notify: Arc<Notify>,
    debugger_ready: Arc<AtomicBool>,
    debugger_notify: Arc<Notify>,
}

impl CdpServerHandle {
    pub fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }

    pub fn connection_waiter(&self) -> CdpConnectionWaiter {
        CdpConnectionWaiter {
            connected: self.connected.clone(),
            notify: self.notify.clone(),
        }
    }

    pub fn debugger_waiter(&self) -> CdpDebuggerWaiter {
        CdpDebuggerWaiter {
            ready: self.debugger_ready.clone(),
            notify: self.debugger_notify.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CdpConnectionWaiter {
    connected: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CdpConnectionWaiter {
    pub async fn wait(&self) {
        if self.connected.load(Ordering::SeqCst) {
            return;
        }
        self.notify.notified().await;
    }
}

#[derive(Clone)]
pub struct CdpDebuggerWaiter {
    ready: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CdpDebuggerWaiter {
    pub async fn wait(&self) {
        if self.ready.load(Ordering::SeqCst) {
            return;
        }
        self.notify.notified().await;
    }
}

pub fn start_server(
    host: &str,
    port: u16,
    backend: Arc<dyn CdpBackend>,
) -> Result<CdpServerHandle> {
    // Bind the socket synchronously so we can return an error immediately
    // if the port is already in use, rather than silently failing in the background.
    // Resolve via ToSocketAddrs so hostnames (`localhost`) and IPv6 literals
    // work.
    let addr: SocketAddr = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .map_err(|e| anyhow!("Cannot resolve inspector address {}:{}: {}", host, port, e))?
        .next()
        .ok_or_else(|| {
            anyhow!(
                "Inspector address {}:{} resolved to no addresses",
                host,
                port
            )
        })?;
    let std_listener = {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_reuse_address(true)?;
        socket.bind(&addr.into()).map_err(|e| {
            anyhow!("Cannot start debugger on port {port}: {e}. Is another instance running?")
        })?;
        socket.listen(128)?;
        socket.set_nonblocking(true)?;
        std::net::TcpListener::from(socket)
    };
    // Advertise the address we actually bound (also resolves a `:0` port).
    let local_addr = std_listener.local_addr().unwrap_or(addr);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let connected = Arc::new(AtomicBool::new(false));
    let notify = Arc::new(Notify::new());
    let debugger_ready = Arc::new(AtomicBool::new(false));
    let debugger_notify = Arc::new(Notify::new());

    let connected_clone = connected.clone();
    let notify_clone = notify.clone();
    let debugger_ready_clone = debugger_ready.clone();
    let debugger_notify_clone = debugger_notify.clone();
    let join = thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("Failed to build CDP runtime: {err}");
                return;
            }
        };
        runtime.block_on(run_server(
            std_listener,
            local_addr,
            backend,
            shutdown_rx,
            connected_clone,
            notify_clone,
            debugger_ready_clone,
            debugger_notify_clone,
        ));
    });

    Ok(CdpServerHandle {
        shutdown: Some(shutdown_tx),
        join: Some(join),
        connected,
        notify,
        debugger_ready,
        debugger_notify,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_server(
    std_listener: std::net::TcpListener,
    local_addr: SocketAddr,
    backend: Arc<dyn CdpBackend>,
    mut shutdown_rx: oneshot::Receiver<()>,
    connected: Arc<AtomicBool>,
    notify: Arc<Notify>,
    debugger_ready: Arc<AtomicBool>,
    debugger_notify: Arc<Notify>,
) {
    let listener = match TcpListener::from_std(std_listener) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("Failed to create async CDP listener: {err}");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                break;
            }
            accept = listener.accept() => {
                let Ok((stream, _)) = accept else { break; };
                let backend = backend.clone();
                let connected = connected.clone();
                let notify = notify.clone();
                let debugger_ready = debugger_ready.clone();
                let debugger_notify = debugger_notify.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(
                        stream,
                        backend,
                        local_addr,
                        connected,
                        notify,
                        debugger_ready,
                        debugger_notify,
                    )
                    .await
                    {
                        eprintln!("CDP connection error: {err}");
                    }
                });
            }
        }
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    backend: Arc<dyn CdpBackend>,
    local_addr: SocketAddr,
    connected: Arc<AtomicBool>,
    notify: Arc<Notify>,
    debugger_ready: Arc<AtomicBool>,
    debugger_notify: Arc<Notify>,
) -> Result<()> {
    let mut stream = stream;
    let mut peek_buf = [0u8; 2048];
    let peek_len = stream.peek(&mut peek_buf).await?;
    if peek_len == 0 {
        return Ok(());
    }

    let peek_text = String::from_utf8_lossy(&peek_buf[..peek_len]);
    if !is_websocket_upgrade(&peek_text) {
        handle_http_request(&mut stream, local_addr).await?;
        return Ok(());
    }

    if !connected.swap(true, Ordering::SeqCst) {
        notify.notify_waiters();
    }

    let ws = tokio_tungstenite::accept_async(stream).await?;
    let (mut write, mut read) = ws.split();

    if cdp_log_enabled() {
        eprintln!("CDP: WebSocket connected");
    }

    let mut interval = tokio::time::interval(Duration::from_millis(50));
    let mut state = ConnectionState {
        runtime_ready: false,
        debugger_ready: false,
        network_enabled: false,
    };
    let mut message_budget = MessageBudget::new(Instant::now());

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if state.debugger_ready {
                    while let Some(event) = backend.next_event() {
                        if cdp_log_enabled() {
                            eprintln!("CDP <- event={}", event);
                        }
                        let _ = write.send(Message::Text(event)).await;
                    }
                }
                // Drain CDP Network domain events.
                if state.network_enabled {
                    for event_json in network::drain_events() {
                        if cdp_log_enabled() {
                            eprintln!("CDP <- network event={}", event_json);
                        }
                        let _ = write.send(Message::Text(event_json)).await;
                    }
                }
            }
            msg = read.next() => {
                let Some(msg) = msg else { break; };
                let Ok(msg) = msg else { break; };
                let payload = match msg {
                    Message::Text(payload) => payload,
                    Message::Close(_) => break,
                    _ => continue,
                };

                if payload.len() > CDP_MAX_TEXT_MESSAGE_BYTES {
                    close_policy_violation(
                        &mut write,
                        "CDP text message exceeded size limit",
                    )
                    .await;
                    break;
                }
                if !message_budget.try_record(Instant::now()) {
                    close_policy_violation(
                        &mut write,
                        "CDP message rate limit exceeded",
                    )
                    .await;
                    break;
                }

                let value: Value = match serde_json::from_str(&payload) {
                    Ok(value) => value,
                    Err(err) => {
                        if cdp_log_enabled() {
                            eprintln!("CDP ! parse error: {} payload={}", err, payload);
                        }
                        continue;
                    }
                };
                let id = value.get("id").and_then(|v| v.as_i64());
                let method = value.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let params = value.get("params").cloned().unwrap_or(Value::Null);

                if let Some(id) = id {
                    if cdp_log_enabled() {
                        eprintln!("CDP -> id={} method={} params={}", id, method, params);
                    }
                    let mut context = RequestContext {
                        backend: backend.clone(),
                        write: &mut write,
                        state: &mut state,
                        debugger_ready: &debugger_ready,
                        debugger_notify: &debugger_notify,
                    };
                    match handle_request(id, method, params, &mut context).await {
                        Ok(()) => {}
                        Err(err) => {
                            let response = json!({
                                "id": id,
                                "error": {
                                    "code": -32000,
                                    "message": err.to_string()
                                }
                            });
                            if cdp_log_enabled() {
                                eprintln!("CDP <- id={} error={}", id, response);
                            }
                            let _ = write.send(Message::Text(response.to_string())).await;
                        }
                    }
                } else if cdp_log_enabled() {
                    eprintln!("CDP -> method={} params={}", method, params);
                }
            }
        }
    }

    // Connection closed. If this client had enabled the Network domain, disable
    // capture so the HTTP server stops buffering events (and caching response
    // bodies) that nobody will ever drain. Without this the capture state stays
    // `enabled` forever after a DevTools disconnect and leaks unbounded.
    if state.network_enabled {
        network::disable();
    }

    Ok(())
}

async fn close_policy_violation(write: &mut WsWrite, reason: &'static str) {
    if cdp_log_enabled() {
        eprintln!("CDP ! closing websocket: {}", reason);
    }
    let _ = write
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Policy,
            reason: Cow::Borrowed(reason),
        })))
        .await;
}

fn is_websocket_upgrade(headers: &str) -> bool {
    let lower = headers.to_ascii_lowercase();
    lower.contains("upgrade: websocket")
}

async fn handle_http_request(
    stream: &mut tokio::net::TcpStream,
    local_addr: SocketAddr,
) -> Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let read_result = tokio::time::timeout(CDP_HTTP_READ_TIMEOUT, async {
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    match read_result {
        Ok(result) => result?,
        Err(_) => {
            stream
                .write_all(
                    b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            return Ok(());
        }
    }

    let request = String::from_utf8_lossy(&buf);
    let mut lines = request.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    // Advertise the address the server is actually bound to. SocketAddr's
    // Display brackets IPv6 (`[::1]:9229`), which the ws/devtools URL forms
    // expect.
    let websocket_url = format!("ws://{}/", local_addr);
    let devtools_url = format!(
        "devtools://devtools/bundled/inspector.html?ws={}/",
        local_addr
    );
    let devtools_compat_url = format!(
        "chrome-devtools://devtools/bundled/inspector.html?ws={}/",
        local_addr
    );
    let (status, body) = match path {
        "/json" | "/json/list" => (
            "200 OK",
            json!([{
                "id": "1",
                "type": "node",
                "title": "Ibex",
                "description": "Ibex",
                "url": "ibex://cli",
                "webSocketDebuggerUrl": websocket_url,
                "devtoolsFrontendUrl": devtools_url,
                "devtoolsFrontendUrlCompat": devtools_compat_url
            }])
            .to_string(),
        ),
        "/json/version" => (
            "200 OK",
            json!({
                "Browser": "Ibex",
                "Protocol-Version": "1.3",
                "webSocketDebuggerUrl": websocket_url
            })
            .to_string(),
        ),
        _ => ("404 Not Found", "{}".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn handle_request(
    id: i64,
    method: &str,
    params: Value,
    ctx: &mut RequestContext<'_>,
) -> Result<()> {
    match method {
        "Network.enable" => {
            network::enable();
            ctx.state.network_enabled = true;
            let response = json!({ "id": id, "result": {} });
            if cdp_log_enabled() {
                eprintln!("CDP <- id={} result={}", id, response);
            }
            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        "Network.disable" => {
            network::disable();
            ctx.state.network_enabled = false;
            let response = json!({ "id": id, "result": {} });
            if cdp_log_enabled() {
                eprintln!("CDP <- id={} result={}", id, response);
            }
            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        "Network.getResponseBody" => {
            let request_id = params
                .get("requestId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let body_result = network::get_response_body(request_id);
            let response = json!({
                "id": id,
                "result": body_result,
            });
            if cdp_log_enabled() {
                eprintln!("CDP <- id={} result=(response body)", id);
            }
            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        "Runtime.enable" | "Debugger.enable" | "Log.enable" | "Page.enable" => {
            let response = json!({ "id": id, "result": {} });
            ctx.write.send(Message::Text(response.to_string())).await?;

            if method == "Runtime.enable" && !ctx.state.runtime_ready {
                ctx.state.runtime_ready = true;
                let context_event = json!({
                    "method": "Runtime.executionContextCreated",
                    "params": {
                        "context": {
                            "id": 1,
                            "origin": "ibex://cli",
                            "name": "Ibex"
                        }
                    }
                });
                ctx.write
                    .send(Message::Text(context_event.to_string()))
                    .await?;
                if cdp_log_enabled() {
                    eprintln!("CDP <- event={}", context_event);
                }
            }

            if method == "Debugger.enable" {
                let enabled = ctx.backend.enable();
                ctx.state.debugger_ready = enabled;
                if !ctx.debugger_ready.swap(true, Ordering::SeqCst) {
                    ctx.debugger_notify.notify_waiters();
                }
                if enabled {
                    while let Some(event) = ctx.backend.next_event() {
                        if cdp_log_enabled() {
                            eprintln!("CDP <- event={}", event);
                        }
                        let _ = ctx.write.send(Message::Text(event)).await;
                    }
                }
            }
            if cdp_log_enabled() {
                eprintln!("CDP <- id={} result={}", id, response);
            }
            return Ok(());
        }
        // One handler for both evaluate forms: identical wire shape, and
        // Runtime.evaluate accepts an optional callFrameId.
        "Runtime.evaluate" | "Debugger.evaluateOnCallFrame" => {
            let expression = params
                .get("expression")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing expression"))?;
            let frame_index = params
                .get("callFrameId")
                .and_then(|v| v.as_str())
                .and_then(|v| v.strip_prefix("frame-"))
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);

            let eval = ctx.backend.eval(expression, frame_index)?;
            let mut result = json!({
                "id": id,
                "result": {
                    "result": { "type": "undefined" }
                }
            });

            if let Some(obj) = eval.as_object() {
                if let Some(remote) = obj.get("result") {
                    result["result"]["result"] = remote.clone();
                }
                if let Some(exception) = obj.get("exceptionDetails") {
                    result["result"]["exceptionDetails"] = exception.clone();
                }
            }

            if cdp_log_enabled() {
                eprintln!("CDP <- id={} result={}", id, result);
            }
            ctx.write.send(Message::Text(result.to_string())).await?;
            return Ok(());
        }
        "Debugger.setBreakpointByUrl" => {
            let url = params
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing url"))?;
            let line = params
                .get("lineNumber")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let column = params
                .get("columnNumber")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let condition = params.get("condition").and_then(|v| v.as_str());

            let scripts = ctx.backend.get_scripts().unwrap_or_default();
            let script = scripts
                .iter()
                .find(|s| s.url == url || s.url.ends_with(url))
                .cloned();

            let response = if let Some(script) = script {
                let bp = ctx
                    .backend
                    .set_breakpoint(script.id, line, column, condition)?;
                json!({
                    "id": id,
                    "result": {
                        "breakpointId": bp.id.to_string(),
                        "locations": [{
                            "scriptId": bp.script_id.to_string(),
                            "lineNumber": bp.line,
                            "columnNumber": bp.column
                        }]
                    }
                })
            } else {
                json!({
                    "id": id,
                    "result": {
                        "breakpointId": "0",
                        "locations": []
                    }
                })
            };

            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        "Debugger.getScriptSource" => {
            let script_id = params
                .get("scriptId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing scriptId"))?;
            let source = ctx
                .backend
                .get_script_source(script_id)?
                .unwrap_or_default();
            let response = json!({
                "id": id,
                "result": {
                    "scriptSource": source
                }
            });
            if cdp_log_enabled() {
                eprintln!("CDP <- id={} result={}", id, response);
            }
            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        "Debugger.removeBreakpoint" => {
            if let Some(breakpoint_id) = params
                .get("breakpointId")
                .and_then(|v| v.as_str())
                .and_then(|v| v.parse::<u64>().ok())
            {
                ctx.backend.remove_breakpoint(breakpoint_id);
            }
            let response = json!({ "id": id, "result": {} });
            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        "Debugger.resume" => {
            ctx.backend.resume(DebugCommand::Continue);
            let response = json!({ "id": id, "result": {} });
            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        "Debugger.stepInto" => {
            ctx.backend.resume(DebugCommand::StepInto);
            let response = json!({ "id": id, "result": {} });
            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        "Debugger.stepOver" => {
            ctx.backend.resume(DebugCommand::StepOver);
            let response = json!({ "id": id, "result": {} });
            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        "Debugger.stepOut" => {
            ctx.backend.resume(DebugCommand::StepOut);
            let response = json!({ "id": id, "result": {} });
            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        "Debugger.pause" => {
            ctx.backend.pause();
            let response = json!({ "id": id, "result": {} });
            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        "Runtime.runIfWaitingForDebugger" => {
            let response = json!({ "id": id, "result": {} });
            ctx.write.send(Message::Text(response.to_string())).await?;
            return Ok(());
        }
        _ => {}
    }

    // Unknown methods used to return `{"result":{}}`, which made DevTools
    // features silently half-work; answer with the JSON-RPC method-not-found
    // error instead. Methods we deliberately no-op (Log.enable, Page.enable,
    // Runtime.runIfWaitingForDebugger, ...) stay explicitly enumerated above.
    let response = method_not_found_response(id, method);
    if cdp_log_enabled() {
        eprintln!("CDP <- id={} error={}", id, response);
    }
    ctx.write.send(Message::Text(response.to_string())).await?;
    Ok(())
}

/// JSON-RPC method-not-found response, matching Chrome's own wording.
fn method_not_found_response(id: i64, method: &str) -> Value {
    json!({
        "id": id,
        "error": {
            "code": -32601,
            "message": format!("'{}' wasn't found", method)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{
        method_not_found_response, MessageBudget, CDP_MAX_MESSAGES_PER_WINDOW,
        CDP_RATE_LIMIT_WINDOW,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn unknown_method_response_is_json_rpc_method_not_found() {
        let response = method_not_found_response(7, "Profiler.enable");

        assert_eq!(response["id"], 7);
        assert_eq!(response["error"]["code"], -32601);
        assert_eq!(
            response["error"]["message"],
            "'Profiler.enable' wasn't found"
        );
        assert!(
            response.get("result").is_none(),
            "method-not-found must not also claim success: {response}"
        );

        let wire = response.to_string();
        assert!(wire.contains(r#""code":-32601"#), "wire: {wire}");
    }

    #[test]
    fn message_budget_enforces_window_limit() {
        let start = Instant::now();
        let mut budget = MessageBudget::new(start);

        for _ in 0..CDP_MAX_MESSAGES_PER_WINDOW {
            assert!(budget.try_record(start));
        }
        assert!(!budget.try_record(start));
    }

    #[test]
    fn message_budget_resets_after_window() {
        let start = Instant::now();
        let mut budget = MessageBudget::new(start);

        for _ in 0..CDP_MAX_MESSAGES_PER_WINDOW {
            assert!(budget.try_record(start));
        }

        assert!(budget.try_record(start + CDP_RATE_LIMIT_WINDOW + Duration::from_millis(1)));
    }
}
