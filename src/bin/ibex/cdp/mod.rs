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

    pub fn register_client() -> u64 {
        1
    }

    pub fn enable(_client_id: u64) {}

    pub fn disable(_client_id: u64) {}

    pub fn get_response_body(_client_id: u64, _request_id: &str) -> Value {
        json!({
            "body": "",
            "base64Encoded": false,
        })
    }

    pub fn drain_events(_client_id: u64) -> Vec<String> {
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
use tokio::sync::{oneshot, Notify, OwnedSemaphorePermit, Semaphore};
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as WsRequest, Response as WsResponse,
};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
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
    network_client_id: u64,
}

impl RequestContext<'_> {
    async fn send_text(&mut self, text: String) -> Result<()> {
        send_ws(self.write, Message::Text(text)).await
    }
}

struct NetworkClientGuard(u64);

impl Drop for NetworkClientGuard {
    fn drop(&mut self) {
        network::disable(self.0);
    }
}

// @ref LLP 0003#inspector-resource-discipline — handshake/session slots,
// deadlines, frame assembly, writes, idle lifetime, and rate limits are one
// fail-closed resource policy.
const CDP_MAX_TEXT_MESSAGE_BYTES: usize = 256 * 1024;
const CDP_MAX_FRAME_BYTES: usize = CDP_MAX_TEXT_MESSAGE_BYTES;
const CDP_MAX_MESSAGES_PER_WINDOW: usize = 600;
const CDP_MAX_CONNECTIONS: usize = 16;
const CDP_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(1);
const CDP_HTTP_READ_TIMEOUT: Duration = Duration::from_secs(5);
const CDP_PEEK_TIMEOUT: Duration = Duration::from_secs(5);
const CDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const CDP_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CDP_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig {
        write_buffer_size: 64 * 1024,
        max_write_buffer_size: 512 * 1024,
        max_message_size: Some(CDP_MAX_TEXT_MESSAGE_BYTES),
        max_frame_size: Some(CDP_MAX_FRAME_BYTES),
        ..WebSocketConfig::default()
    }
}

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
    #[allow(dead_code)]
    local_addr: SocketAddr,
}

impl CdpServerHandle {
    #[allow(dead_code)]
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

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
        local_addr,
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
    let connection_slots = Arc::new(Semaphore::new(CDP_MAX_CONNECTIONS));

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                break;
            }
            accept = listener.accept() => {
                let (stream, _) = match accept {
                    Ok(value) => value,
                    Err(err) => {
                        eprintln!("CDP accept error: {err}");
                        continue;
                    }
                };
                let permit = match connection_slots.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        // The same bound covers partial handshakes and fully
                        // established sessions, so unauthenticated peers cannot
                        // consume an unbounded number of tasks or descriptors.
                        drop(stream);
                        continue;
                    }
                };
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
                        permit,
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
    _connection_permit: OwnedSemaphorePermit,
) -> Result<()> {
    let mut stream = stream;
    let mut peek_buf = [0u8; 2048];
    let peek_len = tokio::time::timeout(CDP_PEEK_TIMEOUT, stream.peek(&mut peek_buf))
        .await
        .map_err(|_| anyhow!("CDP request peek timed out"))??;
    if peek_len == 0 {
        return Ok(());
    }

    let peek_text = String::from_utf8_lossy(&peek_buf[..peek_len]);
    if !is_websocket_upgrade(&peek_text) {
        handle_http_request(&mut stream, local_addr).await?;
        return Ok(());
    }

    // `peek_text` is only a routing hint; the complete WebSocket handshake is
    // validated by the tungstenite callback below after all headers are parsed.
    let ws = tokio::time::timeout(
        CDP_HANDSHAKE_TIMEOUT,
        tokio_tungstenite::accept_hdr_async_with_config(
            stream,
            |request: &WsRequest, response: WsResponse| {
                if cdp_websocket_request_allowed(request) {
                    Ok(response)
                } else {
                    Err(cdp_websocket_forbidden_response())
                }
            },
            Some(websocket_config()),
        ),
    )
    .await
    .map_err(|_| anyhow!("CDP WebSocket handshake timed out"))??;
    if !connected.swap(true, Ordering::SeqCst) {
        notify.notify_waiters();
    }
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
    let mut last_inbound = Instant::now();
    let network_client_id = network::register_client();
    let _network_client_guard = NetworkClientGuard(network_client_id);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if last_inbound.elapsed() >= CDP_IDLE_TIMEOUT {
                    close_websocket(&mut write, CloseCode::Away, "CDP connection idle timeout").await;
                    break;
                }
                if state.debugger_ready {
                    while let Some(event) = backend.next_event() {
                        if cdp_log_enabled() {
                            eprintln!("CDP <- event={}", event);
                        }
                        send_ws(&mut write, Message::Text(event)).await?;
                    }
                }
                // Drain CDP Network domain events.
                if state.network_enabled {
                    for event_json in network::drain_events(network_client_id) {
                        if cdp_log_enabled() {
                            eprintln!("CDP <- network event={}", event_json);
                        }
                        send_ws(&mut write, Message::Text(event_json)).await?;
                    }
                }
            }
            msg = read.next() => {
                let Some(msg) = msg else { break; };
                let msg = match msg {
                    Ok(msg) => msg,
                    Err(tokio_tungstenite::tungstenite::Error::Capacity(_)) => {
                        close_websocket(
                            &mut write,
                            CloseCode::Size,
                            "CDP frame or message exceeded size limit",
                        )
                        .await;
                        break;
                    }
                    Err(_) => break,
                };
                last_inbound = Instant::now();
                if !message_budget.try_record(last_inbound) {
                    close_policy_violation(
                        &mut write,
                        "CDP message rate limit exceeded",
                    )
                    .await;
                    break;
                }
                let payload = match msg {
                    Message::Text(payload) => payload,
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Binary(_) | Message::Frame(_) => {
                        close_websocket(
                            &mut write,
                            CloseCode::Unsupported,
                            "CDP accepts JSON text frames only",
                        )
                        .await;
                        break;
                    }
                };

                if payload.len() > CDP_MAX_TEXT_MESSAGE_BYTES {
                    close_policy_violation(
                        &mut write,
                        "CDP text message exceeded size limit",
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
                        network_client_id,
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
                            if send_ws(&mut write, Message::Text(response.to_string())).await.is_err() {
                                break;
                            }
                        }
                    }
                } else if cdp_log_enabled() {
                    eprintln!("CDP -> method={} params={}", method, params);
                }
            }
        }
    }

    Ok(())
}

async fn close_policy_violation(write: &mut WsWrite, reason: &'static str) {
    close_websocket(write, CloseCode::Policy, reason).await;
}

async fn close_websocket(write: &mut WsWrite, code: CloseCode, reason: &'static str) {
    if cdp_log_enabled() {
        eprintln!("CDP ! closing websocket: {}", reason);
    }
    let _ = send_ws(
        write,
        Message::Close(Some(CloseFrame {
            code,
            reason: Cow::Borrowed(reason),
        })),
    )
    .await;
}

async fn send_ws(write: &mut WsWrite, message: Message) -> Result<()> {
    tokio::time::timeout(CDP_WRITE_TIMEOUT, write.send(message))
        .await
        .map_err(|_| anyhow!("CDP WebSocket write timed out"))??;
    Ok(())
}

fn is_websocket_upgrade(headers: &str) -> bool {
    header_values(headers, "upgrade")
        .into_iter()
        .any(|value| value.trim().eq_ignore_ascii_case("websocket"))
        && header_values(headers, "connection")
            .into_iter()
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
}

fn header_values<'a>(headers: &'a str, name: &str) -> Vec<&'a str> {
    headers
        .lines()
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_once(':'))
        .filter_map(|(key, value)| {
            key.trim()
                .eq_ignore_ascii_case(name)
                .then_some(value.trim())
        })
        .collect()
}

fn cdp_request_headers_allowed(headers: &str) -> bool {
    let hosts = header_values(headers, "host");
    if hosts.len() != 1 || !loopback_host_header_allowed(hosts[0]) {
        return false;
    }

    let origins = header_values(headers, "origin");
    if origins.len() > 1 {
        return false;
    }
    match origins.first() {
        Some(origin) => inspector_origin_allowed(origin),
        None => true,
    }
}

fn cdp_websocket_request_allowed(request: &WsRequest) -> bool {
    let hosts = request
        .headers()
        .get_all("host")
        .iter()
        .map(|value| value.to_str())
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(hosts) = hosts else {
        return false;
    };
    if hosts.len() != 1 || !loopback_host_header_allowed(hosts[0]) {
        return false;
    }

    let origins = request
        .headers()
        .get_all("origin")
        .iter()
        .map(|value| value.to_str())
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(origins) = origins else {
        return false;
    };
    if origins.len() > 1 {
        return false;
    }
    match origins.first() {
        Some(origin) => inspector_origin_allowed(origin),
        None => true,
    }
}

fn cdp_websocket_forbidden_response() -> ErrorResponse {
    let mut response = ErrorResponse::new(Some("Forbidden".to_string()));
    *response.status_mut() = StatusCode::FORBIDDEN;
    response
}

fn loopback_host_header_allowed(value: &str) -> bool {
    let Some(host) = host_header_name(value) else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn host_header_name(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty()
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || matches!(b, b'/' | b'\\' | b'@'))
    {
        return None;
    }

    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let suffix = &rest[end + 1..];
        if !valid_optional_port_suffix(suffix) {
            return None;
        }
        return (!host.is_empty()).then_some(host);
    }

    let colon_count = value.bytes().filter(|b| *b == b':').count();
    match colon_count {
        0 => Some(value),
        1 => {
            let (host, port) = value.split_once(':')?;
            (valid_port(port) && !host.is_empty()).then_some(host)
        }
        _ => Some(value),
    }
}

fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
}

fn valid_optional_port_suffix(suffix: &str) -> bool {
    if suffix.is_empty() {
        return true;
    }
    let Some(port) = suffix.strip_prefix(':') else {
        return false;
    };
    valid_port(port)
}

fn inspector_origin_allowed(origin: &str) -> bool {
    let origin = origin.trim();
    if origin.is_empty() || origin.eq_ignore_ascii_case("null") {
        return false;
    }

    let lower = origin.to_ascii_lowercase();
    if lower.starts_with("devtools://") || lower.starts_with("chrome-devtools://") {
        return true;
    }

    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return false;
    }
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    loopback_host_header_allowed(authority)
}

async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    write_tcp_with_timeout(stream, response.as_bytes()).await?;
    let _ = tokio::time::timeout(CDP_WRITE_TIMEOUT, stream.shutdown()).await;
    Ok(())
}

async fn write_tcp_with_timeout(stream: &mut tokio::net::TcpStream, bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(CDP_WRITE_TIMEOUT, stream.write_all(bytes))
        .await
        .map_err(|_| anyhow!("CDP HTTP write timed out"))??;
    Ok(())
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
            write_tcp_with_timeout(
                stream,
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
    if !cdp_request_headers_allowed(&request) {
        write_http_response(stream, "403 Forbidden", "{}").await?;
        return Ok(());
    }

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

    write_http_response(stream, status, &body).await
}

async fn handle_request(
    id: i64,
    method: &str,
    params: Value,
    ctx: &mut RequestContext<'_>,
) -> Result<()> {
    match method {
        "Network.enable" => {
            network::enable(ctx.network_client_id);
            ctx.state.network_enabled = true;
            let response = json!({ "id": id, "result": {} });
            if cdp_log_enabled() {
                eprintln!("CDP <- id={} result={}", id, response);
            }
            ctx.send_text(response.to_string()).await?;
            return Ok(());
        }
        "Network.disable" => {
            network::disable(ctx.network_client_id);
            ctx.state.network_enabled = false;
            let response = json!({ "id": id, "result": {} });
            if cdp_log_enabled() {
                eprintln!("CDP <- id={} result={}", id, response);
            }
            ctx.send_text(response.to_string()).await?;
            return Ok(());
        }
        "Network.getResponseBody" => {
            let request_id = params
                .get("requestId")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let body_result = network::get_response_body(ctx.network_client_id, request_id);
            let response = json!({
                "id": id,
                "result": body_result,
            });
            if cdp_log_enabled() {
                eprintln!("CDP <- id={} result=(response body)", id);
            }
            ctx.send_text(response.to_string()).await?;
            return Ok(());
        }
        "Runtime.enable" | "Debugger.enable" | "Log.enable" | "Page.enable" => {
            let response = json!({ "id": id, "result": {} });
            ctx.send_text(response.to_string()).await?;

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
                ctx.send_text(context_event.to_string()).await?;
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
                        ctx.send_text(event).await?;
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
            ctx.send_text(result.to_string()).await?;
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

            ctx.send_text(response.to_string()).await?;
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
            ctx.send_text(response.to_string()).await?;
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
            ctx.send_text(response.to_string()).await?;
            return Ok(());
        }
        "Debugger.resume" => {
            ctx.backend.resume(DebugCommand::Continue);
            let response = json!({ "id": id, "result": {} });
            ctx.send_text(response.to_string()).await?;
            return Ok(());
        }
        "Debugger.stepInto" => {
            ctx.backend.resume(DebugCommand::StepInto);
            let response = json!({ "id": id, "result": {} });
            ctx.send_text(response.to_string()).await?;
            return Ok(());
        }
        "Debugger.stepOver" => {
            ctx.backend.resume(DebugCommand::StepOver);
            let response = json!({ "id": id, "result": {} });
            ctx.send_text(response.to_string()).await?;
            return Ok(());
        }
        "Debugger.stepOut" => {
            ctx.backend.resume(DebugCommand::StepOut);
            let response = json!({ "id": id, "result": {} });
            ctx.send_text(response.to_string()).await?;
            return Ok(());
        }
        "Debugger.pause" => {
            ctx.backend.pause();
            let response = json!({ "id": id, "result": {} });
            ctx.send_text(response.to_string()).await?;
            return Ok(());
        }
        "Runtime.runIfWaitingForDebugger" => {
            let response = json!({ "id": id, "result": {} });
            ctx.send_text(response.to_string()).await?;
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
    ctx.send_text(response.to_string()).await?;
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
        cdp_request_headers_allowed, cdp_websocket_request_allowed, inspector_origin_allowed,
        is_websocket_upgrade, loopback_host_header_allowed, method_not_found_response,
        start_server, websocket_config, BreakpointInfo, CdpBackend, CdpServerHandle, DebugCommand,
        MessageBudget, ScriptInfo, CDP_HANDSHAKE_TIMEOUT, CDP_MAX_CONNECTIONS, CDP_MAX_FRAME_BYTES,
        CDP_MAX_MESSAGES_PER_WINDOW, CDP_MAX_TEXT_MESSAGE_BYTES, CDP_RATE_LIMIT_WINDOW,
    };
    use anyhow::{anyhow, Result};
    use futures_util::{SinkExt, StreamExt};
    use serde_json::Value;
    use std::io::ErrorKind;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::Semaphore;
    use tokio_tungstenite::tungstenite::http::Request;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    use tokio_tungstenite::tungstenite::Error as WebSocketError;
    use tokio_tungstenite::tungstenite::Message;

    struct NoopBackend;

    impl CdpBackend for NoopBackend {
        fn enable(&self) -> bool {
            false
        }

        fn get_scripts(&self) -> Result<Vec<ScriptInfo>> {
            Ok(Vec::new())
        }

        fn get_script_source(&self, _script_id: &str) -> Result<Option<String>> {
            Ok(None)
        }

        fn set_breakpoint(
            &self,
            _script_id: u32,
            _line: u32,
            _column: u32,
            _condition: Option<&str>,
        ) -> Result<BreakpointInfo> {
            Err(anyhow!("no debugger"))
        }

        fn remove_breakpoint(&self, _breakpoint_id: u64) {}
        fn pause(&self) {}
        fn resume(&self, _command: DebugCommand) {}
        fn next_event(&self) -> Option<String> {
            None
        }
        fn eval(&self, _expression: &str, _frame_index: u32) -> Result<Value> {
            Ok(Value::Null)
        }
    }

    async fn connect_websocket(
        server: &CdpServerHandle,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>
    {
        tokio_tungstenite::connect_async(format!("ws://{}/", server.local_addr()))
            .await
            .unwrap()
            .0
    }

    async fn next_close_code(
        socket: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Option<CloseCode> {
        tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(message) = socket.next().await {
                match message {
                    Ok(Message::Close(frame)) => return frame.map(|frame| frame.code),
                    Ok(_) => continue,
                    Err(_) => return None,
                }
            }
            None
        })
        .await
        .ok()
        .flatten()
    }

    async fn send_oversized_and_expect_size_rejection(
        socket: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        message: Message,
    ) {
        match socket.send(message).await {
            Ok(()) => {
                let close = next_close_code(socket).await;
                #[cfg(not(windows))]
                assert_eq!(close, Some(CloseCode::Size));
                #[cfg(windows)]
                assert!(
                    matches!(close, Some(CloseCode::Size) | None),
                    "oversized message received unexpected close code {close:?}"
                );
                // Windows may surface the server's fail-closed reset while the
                // client is reading rather than writing, before Tungstenite can
                // expose the already-enqueued WebSocket close frame.
            }
            Err(WebSocketError::Io(error))
                if matches!(
                    error.kind(),
                    ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                ) =>
            {
                // The server enforces the frame limit before assembly. Some TCP
                // stacks report that fail-closed rejection while the client is
                // still writing, before the WebSocket close frame can be read.
            }
            Err(error) => panic!("unexpected oversized-message send error: {error}"),
        }
    }

    fn masked_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push((if fin { 0x80 } else { 0 }) | opcode);
        match payload.len() {
            len @ 0..=125 => frame.push(0x80 | len as u8),
            len @ 126..=65535 => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            }
            len => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
        }
        let mask = [0x13, 0x37, 0x42, 0x99];
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
        frame
    }

    async fn raw_websocket(server: &CdpServerHandle) -> TcpStream {
        let mut stream = TcpStream::connect(server.local_addr()).await.unwrap();
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            server.local_addr()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let mut byte = [0u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
            response.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 101"));
        stream
    }

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

    #[test]
    fn websocket_limits_apply_before_message_assembly() {
        let config = websocket_config();
        assert_eq!(config.max_frame_size, Some(CDP_MAX_FRAME_BYTES));
        assert_eq!(config.max_message_size, Some(CDP_MAX_TEXT_MESSAGE_BYTES));
        assert!(config.max_write_buffer_size <= 512 * 1024);
    }

    #[tokio::test]
    async fn connection_budget_covers_handshakes_and_established_sessions() {
        let slots = Arc::new(Semaphore::new(CDP_MAX_CONNECTIONS));
        let mut permits = Vec::new();
        for _ in 0..CDP_MAX_CONNECTIONS {
            permits.push(slots.clone().try_acquire_owned().unwrap());
        }
        assert!(slots.clone().try_acquire_owned().is_err());
        permits.pop();
        assert!(slots.try_acquire_owned().is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_drops_connections_beyond_the_shared_handshake_session_cap() {
        let server = start_server("127.0.0.1", 0, Arc::new(NoopBackend)).unwrap();
        let mut held = Vec::new();
        for _ in 0..CDP_MAX_CONNECTIONS {
            held.push(TcpStream::connect(server.local_addr()).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut overflow = TcpStream::connect(server.local_addr()).await.unwrap();
        let _ = overflow.write_all(b"G").await;
        let mut byte = [0u8; 1];
        let result = tokio::time::timeout(Duration::from_secs(1), overflow.read(&mut byte))
            .await
            .expect("overflow connection was not closed");
        assert!(
            matches!(result, Ok(0) | Err(_)),
            "unexpected read: {result:?}"
        );

        drop(held);
        server.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn websocket_rejects_oversized_text_and_all_binary_before_dispatch() {
        let server = start_server("127.0.0.1", 0, Arc::new(NoopBackend)).unwrap();

        let mut text = connect_websocket(&server).await;
        send_oversized_and_expect_size_rejection(
            &mut text,
            Message::Text("x".repeat(CDP_MAX_TEXT_MESSAGE_BYTES + 1)),
        )
        .await;

        let mut binary = connect_websocket(&server).await;
        binary.send(Message::Binary(vec![0; 1024])).await.unwrap();
        assert_eq!(
            next_close_code(&mut binary).await,
            Some(CloseCode::Unsupported)
        );

        let mut oversized_binary = connect_websocket(&server).await;
        send_oversized_and_expect_size_rejection(
            &mut oversized_binary,
            Message::Binary(vec![0; CDP_MAX_TEXT_MESSAGE_BYTES + 1]),
        )
        .await;
        server.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fragmented_text_cannot_exceed_the_reassembled_message_budget() {
        let server = start_server("127.0.0.1", 0, Arc::new(NoopBackend)).unwrap();
        let mut stream = raw_websocket(&server).await;
        let fragment = vec![b'x'; CDP_MAX_TEXT_MESSAGE_BYTES / 2 + 1];
        stream
            .write_all(&masked_frame(false, 0x1, &fragment))
            .await
            .unwrap();
        stream
            .write_all(&masked_frame(true, 0x0, &fragment))
            .await
            .unwrap();

        let mut close = [0u8; 128];
        let count = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut close))
            .await
            .unwrap()
            .unwrap();
        assert!(count >= 4, "close frame too short: {count}");
        assert_eq!(close[0] & 0x0f, 0x8);
        assert_eq!(u16::from_be_bytes([close[2], close[3]]), 1009);
        server.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ping_flood_consumes_the_same_rate_budget_as_text() {
        let server = start_server("127.0.0.1", 0, Arc::new(NoopBackend)).unwrap();
        let mut socket = connect_websocket(&server).await;
        for _ in 0..=CDP_MAX_MESSAGES_PER_WINDOW {
            if socket.send(Message::Ping(Vec::new())).await.is_err() {
                break;
            }
        }
        assert_eq!(next_close_code(&mut socket).await, Some(CloseCode::Policy));
        server.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn incomplete_websocket_handshake_is_closed_at_its_deadline() {
        let server = start_server("127.0.0.1", 0, Arc::new(NoopBackend)).unwrap();
        let mut stream = TcpStream::connect(server.local_addr()).await.unwrap();
        let partial = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            server.local_addr()
        );
        stream.write_all(partial.as_bytes()).await.unwrap();
        let mut byte = [0u8; 1];
        let result = tokio::time::timeout(
            CDP_HANDSHAKE_TIMEOUT + Duration::from_secs(1),
            stream.read(&mut byte),
        )
        .await
        .expect("slow handshake outlived its deadline");
        assert!(
            matches!(result, Ok(0) | Err(_)),
            "unexpected read: {result:?}"
        );
        server.stop();
    }

    #[test]
    fn websocket_upgrade_requires_real_upgrade_headers() {
        assert!(is_websocket_upgrade(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:9229\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n"
        ));
        assert!(!is_websocket_upgrade(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:9229\r\nUpgrade: websocket\r\n\r\n"
        ));
    }

    #[test]
    fn inspector_host_allowlist_is_loopback_only() {
        for host in [
            "localhost",
            "localhost:9229",
            "127.0.0.1",
            "[::1]:9229",
            "::1",
        ] {
            assert!(
                loopback_host_header_allowed(host),
                "host should pass: {host}"
            );
        }
        for host in [
            "attacker.example",
            "attacker.example:9229",
            "localhost.evil",
            "127.0.0.1.evil",
            "0.0.0.0:9229",
        ] {
            assert!(
                !loopback_host_header_allowed(host),
                "host should fail: {host}"
            );
        }
    }

    #[test]
    fn inspector_origin_allowlist_rejects_cross_site_web_pages() {
        for origin in [
            "devtools://devtools",
            "chrome-devtools://devtools",
            "http://localhost:9229",
            "https://127.0.0.1",
            "http://[::1]:9229",
        ] {
            assert!(
                inspector_origin_allowed(origin),
                "origin should pass: {origin}"
            );
        }
        for origin in [
            "https://attacker.example",
            "http://localhost.evil",
            "null",
            "file:///",
        ] {
            assert!(
                !inspector_origin_allowed(origin),
                "origin should fail: {origin}"
            );
        }
    }

    #[test]
    fn cdp_requests_require_loopback_host_and_safe_origin() {
        assert!(cdp_request_headers_allowed(
            "GET /json HTTP/1.1\r\nHost: 127.0.0.1:9229\r\n\r\n"
        ));
        assert!(cdp_request_headers_allowed(
            "GET / HTTP/1.1\r\nHost: localhost:9229\r\nOrigin: devtools://devtools\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        ));
        assert!(!cdp_request_headers_allowed(
            "GET /json HTTP/1.1\r\nHost: attacker.example\r\n\r\n"
        ));
        assert!(!cdp_request_headers_allowed(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:9229\r\nOrigin: https://attacker.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        ));
    }

    #[test]
    fn websocket_handshake_callback_validates_full_headers() {
        let allowed = Request::builder()
            .uri("/")
            .header("Host", "127.0.0.1:9229")
            .header("Origin", "chrome-devtools://devtools")
            .body(())
            .unwrap();
        assert!(cdp_websocket_request_allowed(&allowed));

        let denied = Request::builder()
            .uri("/")
            .header("Host", "127.0.0.1:9229")
            .header("Origin", "https://attacker.example")
            .body(())
            .unwrap();
        assert!(!cdp_websocket_request_allowed(&denied));
    }
}
