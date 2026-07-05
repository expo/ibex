//! HTTP server for `exact:http` module.
//!
//! Provides a hyper-based HTTP/1.1 and HTTP/2 server that bridges incoming
//! requests to a JS `fetch` callback via a waiter + respond channel pattern.
//! Uses hyper-util's auto-detection builder to transparently handle both
//! HTTP/1.1 and HTTP/2 (h2c) connections.
//!
//! Architecture:
//! - Each `serve()` call spawns a dedicated thread with a current_thread tokio
//!   runtime (same pattern as the CDP server).
//! - Incoming requests are queued as `PendingRequest` via an mpsc channel.
//! - The JS event loop waits via `ex_host_http_wait` for queued requests.
//! - After invoking the JS fetch callback, JS calls `ex_host_http_respond`
//!   which sends the response back via a oneshot channel.
//! - The hyper handler awaits the oneshot receiver and writes the HTTP response.

use crate::sync::lock_or_recover;
use anyhow::{anyhow, Result};
use futures_util::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use http_body_util::StreamBody;
use hyper::body::{Bytes, Frame};
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use std::collections::{HashMap, HashSet};
use std::io::Error as IoError;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU32, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::mpsc::error::{TryRecvError, TrySendError};
use tokio::sync::{mpsc, oneshot};

use crate::cdp::network as cdp_network;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Data extracted from an incoming HTTP request for the JS side.
#[derive(Debug)]
pub struct PendingRequest {
    pub id: u32,
    pub method: String,
    pub url: String,
    /// Header pairs as (name, value).
    pub headers: Vec<(String, String)>,
    /// Whether a request body stream exists.
    pub has_body: bool,
    /// Pre-buffered request body (read inline before queueing).
    pub body: Option<Vec<u8>>,
    /// Remote address of the client.
    pub remote_addr: String,
    /// Channel to send the response back to hyper.
    pub responder: oneshot::Sender<PendingResponse>,
}

/// Response data sent from JS back to hyper.
#[derive(Debug)]
pub struct PendingResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug)]
enum RequestBodyChunk {
    Data(Vec<u8>),
    Done,
    Error(String),
}

struct RequestBodyPipe {
    receiver: Mutex<mpsc::Receiver<RequestBodyChunk>>,
}

struct ResponseBodyPipe {
    sender: mpsc::Sender<RequestBodyChunk>,
    total_bytes: AtomicUsize,
}

const HTTP_SERVER_STARTING: u8 = 0;
const HTTP_SERVER_LISTENING: u8 = 1;
const HTTP_SERVER_CLOSING: u8 = 2;
const HTTP_SERVER_CLOSED: u8 = 3;
const HTTP_SHUTDOWN_TIMEOUT_MS: u64 = 5_000;
const HTTP_SHUTDOWN_POLL_MS: u64 = 50;
const HTTP_REQUEST_TIMEOUT_MS: u64 = 30_000;
const HTTP_REQUEST_BODY_TIMEOUT_MS: u64 = 20_000;
const HTTP_REQUEST_BODY_IDLE_TIMEOUT_MS: u64 = 2_500;
/// Longest a single streamed response chunk may wait for room in the bounded
/// body channel before the client is treated as wedged. Backpressure (rather
/// than dropping the chunk) is what prevents silent truncation of a slow but
/// still-draining client; this ceiling only guards against a peer that has
/// stopped reading entirely without closing the connection.
const HTTP_RESPONSE_CHUNK_SEND_TIMEOUT_MS: u64 = 30_000;
/// Poll cadence while a streamed response chunk is blocked on a full channel.
const HTTP_RESPONSE_CHUNK_SEND_POLL_MS: u64 = 2;
const HTTP_REQUEST_URI_MAX_BYTES: usize = 2048;
const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
const MAX_REQUEST_HEADER_COUNT: usize = 128;
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 4 * 1024 * 1024;
const HEADER_TEXT_PLAIN: &str = "text/plain; charset=utf-8";
const HEADER_JSON: &str = "application/json; charset=utf-8";
const HEADER_CONTENT_LENGTH: &str = "content-length";
const HEADER_TRANSFER_ENCODING: &str = "transfer-encoding";

struct ServerState {
    /// Identifier for map removal and lifecycle operations.
    id: u32,
    /// Receiver for pending requests (polled by JS).
    rx: Mutex<mpsc::Receiver<PendingRequest>>,
    /// Pending responders keyed by request id (held while JS processes).
    responders: Mutex<HashMap<u32, oneshot::Sender<PendingResponse>>>,
    /// Shutdown signal.
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    /// Join handle for the server thread.
    join: Mutex<Option<thread::JoinHandle<()>>>,
    /// Bound address.
    address: Mutex<Option<SocketAddr>>,
    /// Number of active keep-alive references.
    ref_count: AtomicU32,
    /// Lifecycle state: starting, listening, closing, or closed.
    lifecycle: AtomicU8,
    /// Active in-flight handlers.
    active_requests: AtomicU32,
    /// Active request body streams keyed by request id.
    request_bodies: Mutex<HashMap<u32, RequestBodyPipe>>,
    /// Active response body streams keyed by request id.
    response_bodies: Mutex<HashMap<u32, ResponseBodyPipe>>,
    /// Versioned request arrival signal.
    request_signal_version: Mutex<u64>,
    /// Request queue wake notifications.
    request_signal: Condvar,
}

// ---------------------------------------------------------------------------
// Global registry
// ---------------------------------------------------------------------------

static NEXT_SERVER_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_REQUEST_ID: AtomicU32 = AtomicU32::new(1);

fn servers() -> &'static Mutex<HashMap<u32, Arc<ServerState>>> {
    static SERVERS: OnceLock<Mutex<HashMap<u32, Arc<ServerState>>>> = OnceLock::new();
    SERVERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn closed_servers() -> &'static Mutex<HashSet<u32>> {
    static CLOSED: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();
    CLOSED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Close all active HTTP servers and return the number of servers addressed.
pub fn close_all_http_servers(force: i32) -> usize {
    let ids = {
        let all = lock_or_recover(servers());
        all.keys().copied().collect::<Vec<u32>>()
    };

    let mut closed = 0usize;
    for server_id in ids {
        if ex_host_http_close(server_id, force) != -1 {
            closed += 1;
        }
    }
    closed
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

/// Start an HTTP server. Returns (server_id, bound_port).
pub fn start_server(port: u16, hostname: &str) -> Result<(u32, u16)> {
    let addr = match format!("{}:{}", hostname, port).parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(_) => (hostname, port)
            .to_socket_addrs()
            .map_err(|e| anyhow!("Invalid address {}:{}: {}", hostname, port, e))?
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "Invalid address {}:{}: no resolved addresses",
                    hostname,
                    port
                )
            })?,
    };

    // Bind synchronously so errors are reported immediately.
    let socket = socket2::Socket::new(
        if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into()).map_err(|e| {
        anyhow!(
            "Cannot bind HTTP server on {}:{}: {}. Is the port in use?",
            hostname,
            port,
            e
        )
    })?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    let std_listener = std::net::TcpListener::from(socket);
    let bound_addr = std_listener.local_addr()?;
    let bound_port = bound_addr.port();

    let server_id = NEXT_SERVER_ID.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = mpsc::channel::<PendingRequest>(4096);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let state = Arc::new(ServerState {
        id: server_id,
        rx: Mutex::new(rx),
        responders: Mutex::new(HashMap::new()),
        request_bodies: Mutex::new(HashMap::new()),
        response_bodies: Mutex::new(HashMap::new()),
        shutdown_tx: Mutex::new(Some(shutdown_tx)),
        join: Mutex::new(None),
        address: Mutex::new(Some(bound_addr)),
        ref_count: AtomicU32::new(1),
        lifecycle: AtomicU8::new(HTTP_SERVER_STARTING),
        active_requests: AtomicU32::new(0),
        request_signal_version: Mutex::new(0),
        request_signal: Condvar::new(),
    });

    let state_clone = state.clone();
    let join = thread::spawn(move || {
        // One dedicated thread per serve() running a current_thread runtime, as
        // documented in this module's header. The workload is bottlenecked on
        // the single JS event loop, so a multi-threaded runtime would only spawn
        // N mostly-idle worker threads per server (N servers => O(N * cores)
        // threads) for no throughput gain. Connection tasks are spawned onto
        // this same runtime and driven cooperatively at the loop's .await points.
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                fail_startup(
                    &state_clone,
                    format!("failed to build HTTP server runtime: {err}"),
                );
                return;
            }
        };
        rt.block_on(run_server(
            std_listener,
            tx,
            shutdown_rx,
            state_clone.clone(),
        ));
    });

    *lock_or_recover(&state.join) = Some(join);

    lock_or_recover(servers()).insert(server_id, state);

    Ok((server_id, bound_port))
}

async fn run_server(
    std_listener: std::net::TcpListener,
    tx: mpsc::Sender<PendingRequest>,
    mut shutdown_rx: oneshot::Receiver<()>,
    state: Arc<ServerState>,
) {
    if state
        .lifecycle
        .compare_exchange(
            HTTP_SERVER_STARTING,
            HTTP_SERVER_LISTENING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_err()
    {
        return;
    }

    let listener = match TcpListener::from_std(std_listener) {
        Ok(listener) => listener,
        Err(err) => {
            fail_startup(&state, format!("failed to create async TcpListener: {err}"));
            return;
        }
    };

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, remote_addr)) => {
                        if state.lifecycle.load(Ordering::SeqCst) != HTTP_SERVER_LISTENING {
                            continue;
                        }
                        let tx = tx.clone();
                        let remote = remote_addr.to_string();
                        let state_clone = state.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                                let tx = tx.clone();
                                let remote = remote.clone();
                                let state = state_clone.clone();
                                async move {
                                    handle_request(req, tx, remote, state).await
                                }
                            });
                            let mut builder = AutoBuilder::new(TokioExecutor::new());
                            builder.http1().title_case_headers(true);
                            builder.http1().auto_date_header(false);
                            if let Err(e) = builder.serve_connection(io, svc).await {
                                // Connection errors are normal (client disconnects, etc.)
                                let err_str = e.to_string();
                                if !err_str.contains("connection closed")
                                    && !err_str.contains("broken pipe")
                                    && !err_str.contains("reset by peer")
                                {
                                    eprintln!("HTTP connection error: {}", e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("HTTP accept error: {}", e);
                    }
                }
            }
        }
    }
}

fn notify_if_draining_complete(state: &Arc<ServerState>) {
    if state.lifecycle.load(Ordering::SeqCst) != HTTP_SERVER_CLOSING {
        return;
    }
    if state.active_requests.load(Ordering::SeqCst) != 0 {
        return;
    }

    let closed = state
        .lifecycle
        .compare_exchange(
            HTTP_SERVER_CLOSING,
            HTTP_SERVER_CLOSED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_ok();
    if !closed {
        return;
    }

    if let Some(tx) = lock_or_recover(&state.shutdown_tx).take() {
        let _ = tx.send(());
    }

    // Drop any pending responders so hyper handlers unblock.
    lock_or_recover(&state.responders).clear();
    // Drop any pending request body streams.
    lock_or_recover(&state.request_bodies).clear();
    // Drop any pending response body streams.
    lock_or_recover(&state.response_bodies).clear();

    lock_or_recover(closed_servers()).insert(state.id);
    // Remove from global registry.
    lock_or_recover(servers()).remove(&state.id);
}

fn finish_active_request(state: &Arc<ServerState>) {
    let mut notify = false;

    let _ = state
        .active_requests
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
            if count == 0 {
                return Some(0);
            }

            let next = count - 1;
            if next == 0 {
                notify = true;
            }
            Some(next)
        });

    if notify {
        notify_if_draining_complete(state);
    }
}

fn fail_startup(state: &Arc<ServerState>, message: String) {
    eprintln!("HTTP server startup error: {message}");
    state.lifecycle.store(HTTP_SERVER_CLOSED, Ordering::SeqCst);
    let _ = lock_or_recover(&state.shutdown_tx).take();
    lock_or_recover(&state.responders).clear();
    lock_or_recover(&state.request_bodies).clear();
    lock_or_recover(&state.response_bodies).clear();
    lock_or_recover(closed_servers()).insert(state.id);
    lock_or_recover(servers()).remove(&state.id);
}

fn schedule_forced_close(state: Arc<ServerState>) {
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(HTTP_SHUTDOWN_TIMEOUT_MS);
        loop {
            if state.lifecycle.load(Ordering::SeqCst) == HTTP_SERVER_CLOSED {
                return;
            }

            if state.active_requests.load(Ordering::SeqCst) == 0 {
                notify_if_draining_complete(&state);
                return;
            }

            if Instant::now() >= deadline {
                let _ = state
                    .lifecycle
                    .compare_exchange(
                        HTTP_SERVER_CLOSING,
                        HTTP_SERVER_CLOSED,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok();
                if let Some(tx) = lock_or_recover(&state.shutdown_tx).take() {
                    let _ = tx.send(());
                }
                lock_or_recover(&state.responders).clear();
                lock_or_recover(&state.request_bodies).clear();
                lock_or_recover(&state.response_bodies).clear();
                lock_or_recover(closed_servers()).insert(state.id);
                lock_or_recover(servers()).remove(&state.id);
                return;
            }

            thread::sleep(Duration::from_millis(HTTP_SHUTDOWN_POLL_MS));
        }
    });
}

fn clear_request_body(state: &Arc<ServerState>, request_id: u32) {
    lock_or_recover(&state.request_bodies).remove(&request_id);
}

fn clear_response_body(state: &Arc<ServerState>, request_id: u32) {
    lock_or_recover(&state.response_bodies).remove(&request_id);
}

fn clear_pending_responder(state: &Arc<ServerState>, request_id: u32) {
    lock_or_recover(&state.responders).remove(&request_id);
}

fn full_body_response(bytes: Bytes) -> BoxBody<Bytes, IoError> {
    let body = http_body_util::Full::from(bytes)
        .map_err(|error| IoError::other(format!("response body error: {error}")));
    BodyExt::boxed(body)
}

fn empty_body_response() -> BoxBody<Bytes, IoError> {
    let body =
        http_body_util::Empty::<Bytes>::new().map_err(|error| IoError::other(error.to_string()));
    BodyExt::boxed(body)
}

fn streamed_body_response(receiver: mpsc::Receiver<RequestBodyChunk>) -> BoxBody<Bytes, IoError> {
    let stream = futures_util::stream::unfold(receiver, |mut rx| async {
        match rx.recv().await {
            Some(chunk) => {
                let frame = match chunk {
                    RequestBodyChunk::Data(bytes) => Ok(Frame::data(Bytes::from(bytes))),
                    RequestBodyChunk::Error(message) => Err(IoError::other(message)),
                    RequestBodyChunk::Done => {
                        return None;
                    }
                };
                Some((frame, rx))
            }
            None => None,
        }
    });
    BodyExt::boxed(StreamBody::new(stream))
}

fn is_no_content_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 100..=199 | 204 | 205 | 304)
}

fn parse_response_headers(
    headers_json: *const std::ffi::c_char,
    status: &mut u16,
) -> Vec<(String, String)> {
    if headers_json.is_null() {
        return Vec::new();
    }

    let json_str = unsafe { std::ffi::CStr::from_ptr(headers_json) }
        .to_string_lossy()
        .to_string();

    let parsed_headers = match serde_json::from_str::<serde_json::Value>(&json_str) {
        Ok(headers) => headers,
        Err(_) => {
            *status = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
            return Vec::new();
        }
    };

    let mut total_header_bytes = 0usize;
    let mut headers = Vec::new();

    let add_header = |name: &str,
                      value: &str,
                      headers: &mut Vec<(String, String)>,
                      total_bytes: &mut usize,
                      status: &mut u16|
     -> bool {
        if name.is_empty() {
            *status = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
            return false;
        }
        *total_bytes += name.len() + value.len();
        if *total_bytes > MAX_REQUEST_HEADER_BYTES || headers.len() >= MAX_REQUEST_HEADER_COUNT {
            *status = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
            return false;
        }
        headers.push((name.to_string(), value.to_string()));
        true
    };

    match parsed_headers {
        serde_json::Value::Object(object_headers) => {
            for (name, value) in object_headers {
                let value = match value.as_str() {
                    Some(value) => value,
                    None => {
                        *status = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
                        return Vec::new();
                    }
                };
                if !add_header(&name, value, &mut headers, &mut total_header_bytes, status) {
                    return Vec::new();
                }
            }
        }
        serde_json::Value::Array(pair_headers) => {
            for pair in pair_headers {
                let pair = match pair.as_array() {
                    Some(pair) => pair,
                    None => {
                        *status = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
                        return Vec::new();
                    }
                };
                if pair.len() != 2 {
                    *status = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
                    return Vec::new();
                }

                let name = match pair.first().and_then(|name| name.as_str()) {
                    Some(name) => name,
                    None => {
                        *status = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
                        return Vec::new();
                    }
                };
                let value = match pair.get(1).and_then(|value| value.as_str()) {
                    Some(value) => value,
                    None => {
                        *status = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
                        return Vec::new();
                    }
                };

                if name.is_empty() {
                    *status = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
                    return Vec::new();
                }

                if !add_header(name, value, &mut headers, &mut total_header_bytes, status) {
                    return Vec::new();
                }
            }
        }
        _ => {
            *status = StatusCode::INTERNAL_SERVER_ERROR.as_u16();
            return Vec::new();
        }
    }

    headers
}

fn sanitize_no_content_headers(status: StatusCode, headers: &mut Vec<(String, String)>) {
    if !is_no_content_status(status) {
        return;
    }

    headers.retain(|(name, _)| !name.eq_ignore_ascii_case(HEADER_TRANSFER_ENCODING));

    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(HEADER_CONTENT_LENGTH))
    {
        headers.push((HEADER_CONTENT_LENGTH.to_string(), "0".to_string()));
    }

    // NOTE: do not force `Connection: close` here. `Content-Length: 0` already
    // delimits these bodyless responses, so keep-alive is safe — and 204/304
    // are the hottest steady-state responses (conditional-GET polling), where
    // closing the connection per request destroys keep-alive. `Connection` is
    // also a hop-by-hop HTTP/1 header that is malformed under h2c on this
    // auto-detecting server. Any explicit `Connection` header the caller set is
    // left untouched.
}

fn send_response(
    state: &Arc<ServerState>,
    request_id: u32,
    status: u16,
    headers: Vec<(String, String)>,
    body: *const u8,
    body_len: u32,
) -> i32 {
    let mut response_status = status;
    if body_len as usize > MAX_RESPONSE_BODY_BYTES {
        response_status = StatusCode::PAYLOAD_TOO_LARGE.as_u16();
    }

    let headers = {
        let mut sanitized_headers = headers;
        sanitize_no_content_headers(
            StatusCode::from_u16(response_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &mut sanitized_headers,
        );
        sanitized_headers
    };

    let responder = {
        let mut responders = lock_or_recover(&state.responders);
        match responders.remove(&request_id) {
            Some(r) => r,
            None => {
                clear_request_body(state, request_id);
                clear_response_body(state, request_id);
                cdp_network::cleanup_request(request_id);
                return -1;
            }
        }
    };
    clear_request_body(state, request_id);

    // Emit CDP Network response event before moving headers.
    let body_slice = if !body.is_null() && body_len > 0 {
        unsafe { std::slice::from_raw_parts(body, body_len as usize) }
    } else {
        &[]
    };
    cdp_network::emit_response(request_id, response_status, &headers, body_slice);

    let response = PendingResponse {
        status: response_status,
        headers,
    };

    if responder.send(response).is_err() {
        clear_response_body(state, request_id);
        return -1;
    }

    if body.is_null() || body_len == 0 {
        end_response_stream(state, request_id);
        return 0;
    }

    if body_len as usize > MAX_RESPONSE_BODY_BYTES {
        let _ = send_response_chunk(
            state,
            request_id,
            RequestBodyChunk::Error("Payload Too Large".to_string()),
        );
        end_response_stream(state, request_id);
        return 0;
    }

    let body_vec = body_slice.to_vec();
    if mark_response_chunk(state, request_id, body_vec.len()) {
        let _ = send_response_chunk(state, request_id, RequestBodyChunk::Data(body_vec));
    }
    end_response_stream(state, request_id);
    0
}

fn request_to_json_value(req: &PendingRequest) -> serde_json::Value {
    let headers: Vec<serde_json::Value> = req
        .headers
        .iter()
        .map(|(k, v)| serde_json::json!([k, v]))
        .collect();

    let mut json = serde_json::json!({
        "id": req.id,
        "method": req.method,
        "url": req.url,
        "headers": headers,
        "hasBody": req.has_body,
        "remoteAddr": req.remote_addr,
    });
    if let Some(ref body) = req.body {
        json["body"] = serde_json::json!(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            body,
        ));
    }
    json
}

fn pop_request_json(state: &Arc<ServerState>) -> Option<String> {
    let mut rx = lock_or_recover(&state.rx);
    let req = match rx.try_recv() {
        Ok(req) => req,
        Err(TryRecvError::Empty) => return None,
        Err(TryRecvError::Disconnected) => return None,
    };

    let id = req.id;
    let json = request_to_json_value(&req);

    lock_or_recover(&state.responders).insert(id, req.responder);

    Some(json.to_string())
}

/// Pop up to `max_count` requests at once, returning a JSON array string.
/// Reduces FFI round-trips under load by batching multiple requests
/// into a single call. Returns None if no requests are available.
/// (Item 8: Batch dequeue)
fn drain_requests_json(state: &Arc<ServerState>, max_count: u32) -> Option<String> {
    let mut rx = lock_or_recover(&state.rx);
    let mut requests = Vec::new();

    for _ in 0..max_count {
        match rx.try_recv() {
            Ok(req) => requests.push(req),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => break,
        }
    }
    drop(rx);

    if requests.is_empty() {
        return None;
    }

    // Build JSON array, storing responders as we consume each request
    let mut values = Vec::with_capacity(requests.len());
    for req in requests.into_iter() {
        let id = req.id;
        let value = request_to_json_value(&req);
        lock_or_recover(&state.responders).insert(id, req.responder);
        values.push(value);
    }
    Some(serde_json::Value::Array(values).to_string())
}

// Import the event loop wake function defined in hermes.rs.
// This ensures zero-latency wake when an HTTP request arrives (Item 7).
extern "C" {
    fn ex_hermes_notify_callback();
}

fn notify_request_available(state: &Arc<ServerState>) {
    let mut version = lock_or_recover(&state.request_signal_version);
    *version = version.wrapping_add(1);
    state.request_signal.notify_all();
    // Also wake the Rust event loop so it drains callbacks immediately
    // instead of sleeping for up to 50ms.
    unsafe {
        ex_hermes_notify_callback();
    }
}

fn response_sender_for_request(
    state: &Arc<ServerState>,
    request_id: u32,
) -> Option<mpsc::Sender<RequestBodyChunk>> {
    let bodies = lock_or_recover(&state.response_bodies);
    bodies.get(&request_id).map(|pipe| pipe.sender.clone())
}

fn send_response_chunk(state: &Arc<ServerState>, request_id: u32, chunk: RequestBodyChunk) -> bool {
    let sender = match response_sender_for_request(state, request_id) {
        Some(sender) => sender,
        None => return false,
    };

    // The body channel is bounded, so a fast producer (JS) can outrun a slow
    // consumer (hyper draining to a slow client). A full channel is NOT fatal:
    // dropping the pipe here would end the unfold stream *cleanly*, so hyper
    // would emit a valid chunked terminator and the client would receive a
    // truncated body that looks complete. Instead we apply backpressure —
    // block the calling (JS) thread until the consumer drains a slot — so the
    // client receives every byte. `Closed` (the receiver/connection is gone) is
    // the only genuinely fatal outcome and is reported distinctly from `Full`.
    //
    // This runs only on the JS thread (via the `ex_host_http_respond*` FFI), not
    // inside the tokio runtime, so blocking here cannot stall connection I/O.
    let deadline = Instant::now() + Duration::from_millis(HTTP_RESPONSE_CHUNK_SEND_TIMEOUT_MS);
    let mut pending = chunk;
    loop {
        match sender.try_send(pending) {
            Ok(_) => return true,
            Err(TrySendError::Closed(_)) => {
                clear_response_body(state, request_id);
                return false;
            }
            Err(TrySendError::Full(returned)) => {
                if Instant::now() >= deadline {
                    // The peer has stopped reading without closing; the
                    // connection is effectively dead. Abort rather than block
                    // the JS event loop indefinitely.
                    clear_response_body(state, request_id);
                    return false;
                }
                pending = returned;
                thread::sleep(Duration::from_millis(HTTP_RESPONSE_CHUNK_SEND_POLL_MS));
            }
        }
    }
}

fn mark_response_chunk(state: &Arc<ServerState>, request_id: u32, chunk_len: usize) -> bool {
    let bodies = lock_or_recover(&state.response_bodies);
    let Some(pipe) = bodies.get(&request_id) else {
        return false;
    };
    let previous = pipe.total_bytes.fetch_add(chunk_len, Ordering::Relaxed);
    if previous.saturating_add(chunk_len) > MAX_RESPONSE_BODY_BYTES {
        drop(bodies);
        let _ = send_response_chunk(
            state,
            request_id,
            RequestBodyChunk::Error("Payload Too Large".to_string()),
        );
        clear_response_body(state, request_id);
        return false;
    }
    true
}

fn end_response_stream(state: &Arc<ServerState>, request_id: u32) -> bool {
    let sent = send_response_chunk(state, request_id, RequestBodyChunk::Done);
    clear_response_body(state, request_id);
    sent
}

fn cleanup_pending_response(state: &Arc<ServerState>, request_id: u32) {
    clear_response_body(state, request_id);
}

fn build_response(
    builder: hyper::http::response::Builder,
    body: BoxBody<Bytes, IoError>,
) -> Response<BoxBody<Bytes, IoError>> {
    match builder.body(body) {
        Ok(response) => response,
        Err(err) => {
            eprintln!("Failed to build HTTP response: {err}");
            let mut fallback = Response::new(full_body_response(Bytes::from_static(
                b"Internal Server Error",
            )));
            *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            fallback
        }
    }
}

fn simple_response(status: StatusCode, body: &'static [u8]) -> Response<BoxBody<Bytes, IoError>> {
    build_response(
        Response::builder().status(status),
        full_body_response(Bytes::from_static(body)),
    )
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    tx: mpsc::Sender<PendingRequest>,
    remote_addr: String,
    state: Arc<ServerState>,
) -> Result<Response<BoxBody<Bytes, IoError>>, hyper::Error> {
    let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

    // Extract request parts.
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    if method.is_empty()
        || uri.is_empty()
        || uri.len() > HTTP_REQUEST_URI_MAX_BYTES
        || req.headers().len() > MAX_REQUEST_HEADER_COUNT
    {
        return Ok(simple_response(StatusCode::BAD_REQUEST, b"Bad Request"));
    }

    let mut headers = Vec::new();
    let mut header_bytes = 0usize;
    for (name, value) in req.headers().iter() {
        let name = name.as_str().to_string();
        let value = match value.to_str() {
            Ok(value) => value.to_string(),
            Err(_) => {
                return Ok(simple_response(StatusCode::BAD_REQUEST, b"Bad Request"));
            }
        };
        header_bytes += name.len() + value.len();
        if header_bytes > MAX_REQUEST_HEADER_BYTES {
            return Ok(simple_response(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                b"Request Header Fields Too Large",
            ));
        }
        headers.push((name, value));
    }

    let has_body = method != "GET" && method != "HEAD";
    let body_bytes = if has_body {
        let mut total = 0usize;
        let mut collected = Vec::new();
        let mut body_stream = req.into_body().into_data_stream();
        let deadline = Instant::now() + Duration::from_millis(HTTP_REQUEST_BODY_TIMEOUT_MS);

        loop {
            if Instant::now() >= deadline {
                return Ok(simple_response(
                    StatusCode::REQUEST_TIMEOUT,
                    b"Request Timeout",
                ));
            }

            let next_chunk = tokio::time::timeout(
                Duration::from_millis(HTTP_REQUEST_BODY_IDLE_TIMEOUT_MS),
                body_stream.next(),
            )
            .await;

            let next_chunk = match next_chunk {
                Ok(next_chunk) => next_chunk,
                Err(_) => {
                    return Ok(simple_response(
                        StatusCode::REQUEST_TIMEOUT,
                        b"Request Timeout",
                    ));
                }
            };

            match next_chunk {
                Some(chunk_result) => match chunk_result {
                    Ok(chunk) => {
                        total = total.saturating_add(chunk.len());
                        if total > MAX_REQUEST_BODY_BYTES {
                            return Ok(simple_response(
                                StatusCode::PAYLOAD_TOO_LARGE,
                                b"Payload Too Large",
                            ));
                        }
                        collected.extend_from_slice(&chunk);
                    }
                    Err(_) => {
                        return Ok(simple_response(StatusCode::BAD_REQUEST, b"Bad Request"));
                    }
                },
                None => {
                    break;
                }
            }
        }

        if collected.is_empty() {
            None
        } else {
            Some(collected)
        }
    } else {
        None
    };

    // Emit CDP Network.requestWillBeSent event (no-op when DevTools is not attached).
    cdp_network::emit_request_will_be_sent(
        request_id,
        &uri,
        &method,
        &headers,
        body_bytes.as_deref(),
    );

    // Reserve the in-flight slot BEFORE checking the lifecycle. Under SeqCst,
    // this closes a graceful-close drain race: if a concurrent close reads
    // active_requests after this increment it sees this request and waits for
    // it; if it read before, then its lifecycle store to CLOSING is ordered
    // before our load below, so we observe the shutdown and reject promptly.
    // Otherwise close could transition CLOSING->CLOSED while this request sat
    // queued, and the client would hang the full request timeout into a 504
    // instead of getting a prompt 503. Every path from here must release the
    // slot via finish_active_request.
    state.active_requests.fetch_add(1, Ordering::SeqCst);

    // If server is closed or draining, reject new requests.
    if state.lifecycle.load(Ordering::SeqCst) != HTTP_SERVER_LISTENING {
        clear_request_body(&state, request_id);
        clear_response_body(&state, request_id);
        cdp_network::cleanup_request(request_id);
        finish_active_request(&state);
        return Ok(simple_response(
            StatusCode::SERVICE_UNAVAILABLE,
            b"Server is shutting down",
        ));
    }

    let (resp_tx, resp_rx) = oneshot::channel();
    let (response_body_tx, response_body_rx) = mpsc::channel::<RequestBodyChunk>(8);
    lock_or_recover(&state.response_bodies).insert(
        request_id,
        ResponseBodyPipe {
            sender: response_body_tx,
            total_bytes: AtomicUsize::new(0),
        },
    );

    let pending = PendingRequest {
        id: request_id,
        method,
        url: uri,
        headers,
        has_body,
        body: body_bytes,
        remote_addr,
        responder: resp_tx,
    };

    // Try to send to the JS side. If the channel is full or closed, return 503.
    if tx.try_send(pending).is_err() {
        clear_request_body(&state, request_id);
        clear_response_body(&state, request_id);
        cdp_network::cleanup_request(request_id);
        finish_active_request(&state);
        return Ok(simple_response(
            StatusCode::SERVICE_UNAVAILABLE,
            b"Service Unavailable",
        ));
    }
    notify_request_available(&state);

    // Wait for JS to respond.
    let response =
        match tokio::time::timeout(Duration::from_millis(HTTP_REQUEST_TIMEOUT_MS), resp_rx).await {
            Ok(Ok(resp)) => {
                clear_request_body(&state, request_id);
                let status =
                    StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                let mut headers = resp.headers;
                sanitize_no_content_headers(status, &mut headers);
                let no_content = is_no_content_status(status);
                let mut builder = Response::builder().status(status);
                for (k, v) in &headers {
                    if k.is_empty() {
                        continue;
                    }
                    if let (Ok(name), Ok(value)) = (
                        k.parse::<HeaderName>(),
                        HeaderValue::from_bytes(v.as_bytes()),
                    ) {
                        builder = builder.header(name, value);
                    }
                }
                if no_content {
                    Ok(build_response(builder, empty_body_response()))
                } else {
                    Ok(build_response(
                        builder,
                        streamed_body_response(response_body_rx),
                    ))
                }
            }
            Ok(Err(_)) => {
                clear_pending_responder(&state, request_id);
                clear_request_body(&state, request_id);
                clear_response_body(&state, request_id);
                cdp_network::cleanup_request(request_id);
                // Responder dropped (server closing or JS error).
                Ok(simple_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    b"Internal Server Error",
                ))
            }
            Err(_) => {
                // Timeout.
                clear_pending_responder(&state, request_id);
                clear_request_body(&state, request_id);
                clear_response_body(&state, request_id);
                cdp_network::cleanup_request(request_id);
                Ok(simple_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    b"Gateway Timeout",
                ))
            }
        };

    finish_active_request(&state);

    response
}

// ---------------------------------------------------------------------------
// C ABI surface (called from hermes_runtime.cc)
// ---------------------------------------------------------------------------

/// Start an HTTP server. Returns a JSON string: {"id": N, "port": N} or {"error": "..."}.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn ex_host_http_serve(
    port: u16,
    hostname: *const std::ffi::c_char,
) -> *mut std::ffi::c_char {
    let hostname = if hostname.is_null() {
        "127.0.0.1".to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(hostname) }
            .to_string_lossy()
            .to_string()
    };

    let result = match start_server(port, &hostname) {
        Ok((id, bound_port)) => serde_json::json!({"id": id, "port": bound_port}).to_string(),
        Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
    };

    match std::ffi::CString::new(result) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Poll for a pending request. Returns a JSON string or null.
/// JSON: {"id": N, "method": "GET", "url": "/path", "headers": [[k,v],...], "hasBody": true, "remoteAddr": "..."}
#[no_mangle]
pub extern "C" fn ex_host_http_poll(server_id: u32) -> *mut std::ffi::c_char {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return std::ptr::null_mut(),
        }
    };

    let json = pop_request_json(&state);
    match json {
        Some(json) => match std::ffi::CString::new(json) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Drain up to `max_count` pending requests at once. Returns a JSON array string
/// or null if no requests are available. Reduces FFI round-trips under load.
/// (Item 8: Batch dequeue)
/// JSON: [{"id":N,...}, {"id":N,...}, ...]
#[no_mangle]
pub extern "C" fn ex_host_http_drain(server_id: u32, max_count: u32) -> *mut std::ffi::c_char {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return std::ptr::null_mut(),
        }
    };

    let max = if max_count == 0 {
        64
    } else {
        max_count.min(256)
    };
    let json = drain_requests_json(&state, max);
    match json {
        Some(json) => match std::ffi::CString::new(json) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// Block until the next request arrives, then return a JSON string.
/// Returns null on timeout/closure.
/// `timeout_ms = 0` means no timeout.
#[no_mangle]
pub extern "C" fn ex_host_http_wait(server_id: u32, timeout_ms: u32) -> *mut std::ffi::c_char {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return std::ptr::null_mut(),
        }
    };

    let timeout = if timeout_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(timeout_ms as u64))
    };

    let deadline = timeout.map(|wait_for| Instant::now() + wait_for);

    let mut version = lock_or_recover(&state.request_signal_version);
    let mut last_version = *version;

    loop {
        if let Some(json) = pop_request_json(&state) {
            return match std::ffi::CString::new(json) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            };
        }

        if state.lifecycle.load(Ordering::SeqCst) != HTTP_SERVER_LISTENING {
            return std::ptr::null_mut();
        }

        if let Some(deadline) = deadline {
            let now = Instant::now();
            if now >= deadline {
                return std::ptr::null_mut();
            }

            let waited =
                state
                    .request_signal
                    .wait_timeout_while(version, deadline - now, |known| *known == last_version);
            match waited {
                Ok((next, timed_out)) => {
                    version = next;
                    if timed_out.timed_out() && *version == last_version {
                        return std::ptr::null_mut();
                    }
                }
                Err(err) => {
                    let (next, _) = err.into_inner();
                    version = next;
                }
            };
            last_version = *version;
            continue;
        }

        version = match state
            .request_signal
            .wait_while(version, |known| *known == last_version)
        {
            Ok(next) => next,
            Err(err) => err.into_inner(),
        };
        last_version = *version;
    }
}

/// Poll the next chunk from a streaming request body.
/// Returns JSON:
/// - {"chunk":"<base64>"} for a chunk
/// - {"done":true} for end of body
/// - {"error":"..."} for malformed request body
/// - {} while no data is currently available
#[no_mangle]
pub extern "C" fn ex_host_http_read_body(server_id: u32, request_id: u32) -> *mut std::ffi::c_char {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return std::ptr::null_mut(),
        }
    };

    let mut bodies = lock_or_recover(&state.request_bodies);
    let pipe = match bodies.get_mut(&request_id) {
        Some(pipe) => pipe,
        None => {
            let json = serde_json::json!({"done": true});
            return match std::ffi::CString::new(json.to_string()) {
                Ok(cstr) => cstr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            };
        }
    };

    let mut rx = lock_or_recover(&pipe.receiver);
    let mut should_clear = false;
    let result = match rx.try_recv() {
        Ok(chunk) => match chunk {
            RequestBodyChunk::Data(bytes) => serde_json::json!({
                "chunk": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &bytes,
                )
            }),
            RequestBodyChunk::Done => {
                should_clear = true;
                serde_json::json!({"done": true})
            }
            RequestBodyChunk::Error(message) => {
                should_clear = true;
                serde_json::json!({"error": message})
            }
        },
        Err(TryRecvError::Empty) => serde_json::json!({}),
        Err(TryRecvError::Disconnected) => {
            should_clear = true;
            serde_json::json!({"done": true})
        }
    };
    drop(rx);
    drop(bodies);

    if should_clear {
        clear_request_body(&state, request_id);
    }

    match std::ffi::CString::new(result.to_string()) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Send a response for a pending request.
#[no_mangle]
pub extern "C" fn ex_host_http_respond(
    server_id: u32,
    request_id: u32,
    status: u16,
    headers_json: *const std::ffi::c_char,
    body: *const u8,
    body_len: u32,
) -> i32 {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return -1,
        }
    };

    let mut response_status = status;
    if body_len as usize > MAX_RESPONSE_BODY_BYTES {
        response_status = StatusCode::PAYLOAD_TOO_LARGE.as_u16();
    }
    let headers = parse_response_headers(headers_json, &mut response_status);
    send_response(&state, request_id, response_status, headers, body, body_len)
}

#[no_mangle]
pub extern "C" fn ex_host_http_respond_text(
    server_id: u32,
    request_id: u32,
    status: u16,
    body: *const u8,
    body_len: u32,
) -> i32 {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return -1,
        }
    };

    let headers = vec![
        (
            String::from("content-type"),
            String::from(HEADER_TEXT_PLAIN),
        ),
        (String::from(HEADER_CONTENT_LENGTH), body_len.to_string()),
    ];
    send_response(&state, request_id, status, headers, body, body_len)
}

#[no_mangle]
pub extern "C" fn ex_host_http_respond_json(
    server_id: u32,
    request_id: u32,
    status: u16,
    body: *const u8,
    body_len: u32,
) -> i32 {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return -1,
        }
    };

    let headers = vec![
        (String::from("content-type"), String::from(HEADER_JSON)),
        (String::from(HEADER_CONTENT_LENGTH), body_len.to_string()),
    ];
    send_response(&state, request_id, status, headers, body, body_len)
}

/// Send a response with a raw string body and explicit headers JSON.
/// The C++ side extracts the JSI string buffer directly and passes it here,
/// avoiding the JS->Uint8Array encoding step entirely.
/// (Item 10: Zero-copy response body for string responses)
#[no_mangle]
pub extern "C" fn ex_host_http_respond_string(
    server_id: u32,
    request_id: u32,
    status: u16,
    headers_json: *const std::ffi::c_char,
    body: *const u8,
    body_len: u32,
) -> i32 {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return -1,
        }
    };

    let mut response_status = status;
    if body_len as usize > MAX_RESPONSE_BODY_BYTES {
        response_status = StatusCode::PAYLOAD_TOO_LARGE.as_u16();
    }
    let headers = parse_response_headers(headers_json, &mut response_status);
    send_response(&state, request_id, response_status, headers, body, body_len)
}

/// Send a streaming response for a pending request and allow chunked writes.
#[no_mangle]
pub extern "C" fn ex_host_http_respond_stream(
    server_id: u32,
    request_id: u32,
    status: u16,
    headers_json: *const std::ffi::c_char,
) -> i32 {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return -1,
        }
    };

    let responder = {
        let mut responders = lock_or_recover(&state.responders);
        match responders.remove(&request_id) {
            Some(r) => r,
            None => {
                clear_request_body(&state, request_id);
                clear_response_body(&state, request_id);
                cdp_network::cleanup_request(request_id);
                return -1;
            }
        }
    };
    clear_request_body(&state, request_id);

    let mut response_status = status;
    let mut headers = parse_response_headers(headers_json, &mut response_status);
    sanitize_no_content_headers(
        StatusCode::from_u16(response_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        &mut headers,
    );

    // Emit CDP Network response event for streaming responses (body not cached).
    cdp_network::emit_response(request_id, response_status, &headers, &[]);

    let response = PendingResponse {
        status: response_status,
        headers,
    };

    if responder.send(response).is_err() {
        cleanup_pending_response(&state, request_id);
        return -1;
    }

    0
}

/// Send a chunk for a streaming response. Returns -1 if the request is not active.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn ex_host_http_respond_chunk(
    server_id: u32,
    request_id: u32,
    chunk: *const u8,
    chunk_len: u32,
) -> i32 {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return -1,
        }
    };

    if chunk.is_null() {
        return -1;
    }
    let len = chunk_len as usize;
    let data = unsafe { std::slice::from_raw_parts(chunk, len) };
    if !mark_response_chunk(&state, request_id, len) {
        return -1;
    }
    match send_response_chunk(&state, request_id, RequestBodyChunk::Data(data.to_vec())) {
        true => 0,
        false => -1,
    }
}

/// Finish a streaming response. Returns -1 if the request is already gone.
#[no_mangle]
pub extern "C" fn ex_host_http_respond_end(server_id: u32, request_id: u32) -> i32 {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return -1,
        }
    };

    match end_response_stream(&state, request_id) {
        true => 0,
        false => -1,
    }
}

/// Get server address as JSON. Returns null if server not found.
#[no_mangle]
pub extern "C" fn ex_host_http_address(server_id: u32) -> *mut std::ffi::c_char {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => return std::ptr::null_mut(),
        }
    };

    let addr = lock_or_recover(&state.address);
    let json = match addr.as_ref() {
        Some(a) => serde_json::json!({
            "address": a.ip().to_string(),
            "port": a.port(),
            "family": if a.is_ipv4() { "ipv4" } else { "ipv6" },
        }),
        None => return std::ptr::null_mut(),
    };

    match std::ffi::CString::new(json.to_string()) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Close a server.
#[no_mangle]
pub extern "C" fn ex_host_http_close(server_id: u32, force: i32) -> i32 {
    let state = {
        let servers = lock_or_recover(servers());
        match servers.get(&server_id) {
            Some(s) => s.clone(),
            None => {
                if lock_or_recover(closed_servers()).contains(&server_id) {
                    return 0;
                }
                return -1;
            }
        }
    };

    let previous = state.lifecycle.swap(HTTP_SERVER_CLOSING, Ordering::SeqCst);
    if previous == HTTP_SERVER_CLOSED {
        notify_request_available(&state);
        return 0;
    }

    if force == 0 && previous == HTTP_SERVER_CLOSING {
        notify_request_available(&state);
        return 0;
    }

    // Remove keep-alive requirement once close is requested.
    state.ref_count.store(0, Ordering::SeqCst);

    if force != 0 {
        state.lifecycle.store(HTTP_SERVER_CLOSED, Ordering::SeqCst);
        if let Some(tx) = lock_or_recover(&state.shutdown_tx).take() {
            let _ = tx.send(());
        }
        lock_or_recover(&state.responders).clear();
        lock_or_recover(&state.request_bodies).clear();
        lock_or_recover(&state.response_bodies).clear();
        lock_or_recover(closed_servers()).insert(server_id);
        lock_or_recover(servers()).remove(&server_id);
        notify_request_available(&state);
        return 0;
    }

    if previous == HTTP_SERVER_LISTENING {
        if let Some(tx) = lock_or_recover(&state.shutdown_tx).take() {
            let _ = tx.send(());
        }
    }

    schedule_forced_close(state.clone());
    notify_request_available(&state);

    0
}

/// Check if a server is referenced (keeps process alive).
#[no_mangle]
pub extern "C" fn ex_host_http_is_referenced(server_id: u32) -> i32 {
    let servers = lock_or_recover(servers());
    match servers.get(&server_id) {
        Some(s) => {
            if s.lifecycle.load(Ordering::SeqCst) == HTTP_SERVER_CLOSED {
                0
            } else if s.ref_count.load(Ordering::SeqCst) > 0 {
                1
            } else {
                0
            }
        }
        None => 0,
    }
}

/// Check if any server is still referenced.
#[no_mangle]
pub extern "C" fn ex_host_http_has_referenced() -> i32 {
    let servers = lock_or_recover(servers());
    for state in servers.values() {
        if state.lifecycle.load(Ordering::SeqCst) != HTTP_SERVER_CLOSED
            && state.ref_count.load(Ordering::SeqCst) > 0
        {
            return 1;
        }
    }
    0
}

/// Check if any server still has in-flight requests.
#[no_mangle]
pub extern "C" fn ex_host_http_has_pending_requests() -> i32 {
    let servers = lock_or_recover(servers());
    for state in servers.values() {
        if state.active_requests.load(Ordering::SeqCst) != 0 {
            return 1;
        }
    }
    0
}

/// Whether a server has reached the LISTENING state. Used by this crate's
/// tests and by binary bridge round-trip tests (cfg(test) would be
/// compiled out of the dependency build, so this stays a plain pub fn).
pub fn is_server_listening(server_id: u32) -> bool {
    let servers = lock_or_recover(servers());
    servers
        .get(&server_id)
        .map(|state| state.lifecycle.load(Ordering::SeqCst) == HTTP_SERVER_LISTENING)
        .unwrap_or(false)
}

/// Set ref/unref on a server.
#[no_mangle]
pub extern "C" fn ex_host_http_set_ref(server_id: u32, referenced: i32) {
    let servers = lock_or_recover(servers());
    if let Some(s) = servers.get(&server_id) {
        if referenced != 0 {
            s.ref_count.fetch_add(1, Ordering::SeqCst);
            return;
        }
        let _ = s
            .ref_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_sub(1)
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn register_test_server(server_id: u32) -> Arc<ServerState> {
        let (_tx, rx) = mpsc::channel::<PendingRequest>(1);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        let address = Some(
            "127.0.0.1:0"
                .parse::<SocketAddr>()
                .expect("valid test address"),
        );
        let state = Arc::new(ServerState {
            id: server_id,
            rx: Mutex::new(rx),
            responders: Mutex::new(HashMap::new()),
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
            join: Mutex::new(None),
            address: Mutex::new(address),
            ref_count: AtomicU32::new(1),
            lifecycle: AtomicU8::new(HTTP_SERVER_LISTENING),
            active_requests: AtomicU32::new(0),
            request_bodies: Mutex::new(HashMap::new()),
            response_bodies: Mutex::new(HashMap::new()),
            request_signal_version: Mutex::new(0),
            request_signal: Condvar::new(),
        });

        lock_or_recover(servers()).insert(server_id, state.clone());
        state
    }

    #[test]
    fn parse_response_headers_rejects_invalid_json() {
        let json = CString::new("{bad json}").unwrap();
        let mut status = StatusCode::OK.as_u16();
        let headers = parse_response_headers(json.as_ptr(), &mut status);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR.as_u16());
        assert!(headers.is_empty());
    }

    #[test]
    fn parse_response_headers_rejects_invalid_pair_shape() {
        let json = serde_json::to_string(&vec![vec!["only-name"]]).unwrap();
        let mut status = StatusCode::OK.as_u16();
        let headers = parse_response_headers(CString::new(json).unwrap().as_ptr(), &mut status);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR.as_u16());
        assert!(headers.is_empty());
    }

    #[test]
    fn start_server_accepts_localhost_hostname() {
        let (server_id, bound_port) = match start_server(0, "localhost") {
            Ok(value) => value,
            Err(err) => {
                assert!(
                    err.to_string().contains("Operation not permitted"),
                    "unexpected bind failure: {err:#}"
                );
                return;
            }
        };
        assert_ne!(bound_port, 0);
        assert_eq!(ex_host_http_close(server_id, 1), 0);
    }

    #[test]
    fn ex_host_http_serve_defaults_to_loopback() {
        let result = ex_host_http_serve(0, std::ptr::null());
        assert!(!result.is_null());
        let result_json = unsafe { std::ffi::CStr::from_ptr(result) }
            .to_string_lossy()
            .into_owned();
        crate::host::abi::ex_host_free_string(result);

        let parsed: serde_json::Value =
            serde_json::from_str(&result_json).expect("serve result should be valid json");
        if let Some(error) = parsed.get("error").and_then(|value| value.as_str()) {
            assert!(
                error.contains("Operation not permitted"),
                "unexpected serve failure: {error}"
            );
            return;
        }
        let server_id = parsed["id"]
            .as_u64()
            .and_then(|id| u32::try_from(id).ok())
            .expect("serve result should contain a server id");

        let address = ex_host_http_address(server_id);
        assert!(!address.is_null());
        let address_json = unsafe { std::ffi::CStr::from_ptr(address) }
            .to_string_lossy()
            .into_owned();
        crate::host::abi::ex_host_free_string(address);

        let parsed_address: serde_json::Value =
            serde_json::from_str(&address_json).expect("address result should be valid json");
        assert_eq!(parsed_address["address"], "127.0.0.1");
        assert_eq!(ex_host_http_close(server_id, 1), 0);
    }

    #[test]
    fn parse_response_headers_rejects_missing_null() {
        let mut status = StatusCode::OK.as_u16();
        let headers = parse_response_headers(std::ptr::null(), &mut status);

        assert_eq!(status, StatusCode::OK.as_u16());
        assert!(headers.is_empty());
    }

    #[test]
    fn parse_response_headers_rejects_too_many_headers() {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for i in 0..(MAX_REQUEST_HEADER_COUNT + 1) {
            pairs.push((format!("x{i}"), "y".to_string()));
        }
        let json = serde_json::to_string(&pairs).unwrap();
        let mut status = StatusCode::OK.as_u16();
        let headers = parse_response_headers(CString::new(json).unwrap().as_ptr(), &mut status);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR.as_u16());
        assert!(headers.is_empty());
    }

    #[test]
    fn parse_response_headers_rejects_too_large_bytes() {
        let mut pairs = Vec::new();
        let long_key = "k".repeat(MAX_REQUEST_HEADER_BYTES);
        pairs.push((long_key, "v".to_string()));
        let json = serde_json::to_string(&pairs).unwrap();
        let mut status = StatusCode::OK.as_u16();
        let headers = parse_response_headers(CString::new(json).unwrap().as_ptr(), &mut status);

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR.as_u16());
        assert!(headers.is_empty());
    }

    #[test]
    fn parse_response_headers_accepts_valid_headers() {
        let pairs = vec![
            ("content-type".to_string(), "text/plain".to_string()),
            ("x-foo".to_string(), "bar".to_string()),
        ];
        let json = serde_json::to_string(&pairs).unwrap();
        let mut status = StatusCode::OK.as_u16();
        let headers = parse_response_headers(CString::new(json).unwrap().as_ptr(), &mut status);

        assert_eq!(status, StatusCode::OK.as_u16());
        assert_eq!(headers, pairs);
    }

    #[test]
    fn parse_response_headers_accepts_empty_header_values() {
        let pairs = vec![("x-empty".to_string(), "".to_string())];
        let json = serde_json::to_string(&pairs).unwrap();
        let mut status = StatusCode::OK.as_u16();
        let headers = parse_response_headers(CString::new(json).unwrap().as_ptr(), &mut status);

        assert_eq!(status, StatusCode::OK.as_u16());
        assert_eq!(headers, pairs);
        let value = HeaderValue::from_bytes(headers[0].1.as_bytes()).unwrap();
        assert_eq!(value.as_bytes(), b"");
    }

    #[test]
    fn ex_host_http_respond_stream_writes_chunked_body_and_ends() {
        let server_id = 90_001u32;
        let request_id = 101u32;
        let state = register_test_server(server_id);

        let (response_tx, mut response_rx) = oneshot::channel();
        let (body_tx, mut body_rx) = mpsc::channel::<RequestBodyChunk>(8);

        state
            .responders
            .lock()
            .expect("test responder lock should succeed")
            .insert(request_id, response_tx);
        lock_or_recover(&state.response_bodies).insert(
            request_id,
            ResponseBodyPipe {
                sender: body_tx,
                total_bytes: AtomicUsize::new(0),
            },
        );

        let start = ex_host_http_respond_stream(
            server_id,
            request_id,
            StatusCode::OK.as_u16(),
            std::ptr::null(),
        );
        assert_eq!(start, 0);

        let response = response_rx.try_recv().unwrap();
        assert_eq!(response.status, StatusCode::OK.as_u16());
        assert!(response.headers.is_empty());

        let first = b"first";
        assert_eq!(
            ex_host_http_respond_chunk(server_id, request_id, first.as_ptr(), first.len() as u32),
            0
        );
        assert!(matches!(
            body_rx.try_recv().unwrap(),
            RequestBodyChunk::Data(ref bytes) if bytes.as_slice() == first
        ));

        let second = b"second";
        assert_eq!(
            ex_host_http_respond_chunk(server_id, request_id, second.as_ptr(), second.len() as u32),
            0
        );
        assert!(matches!(
            body_rx.try_recv().unwrap(),
            RequestBodyChunk::Data(ref bytes) if bytes.as_slice() == second
        ));

        assert_eq!(ex_host_http_respond_end(server_id, request_id), 0);
        assert!(matches!(
            body_rx.try_recv().unwrap(),
            RequestBodyChunk::Done
        ));
        assert_eq!(
            ex_host_http_respond_chunk(server_id, request_id, first.as_ptr(), first.len() as u32),
            -1
        );
        assert!(!state
            .response_bodies
            .lock()
            .expect("test response body lock should succeed")
            .contains_key(&request_id));
        assert!(lock_or_recover(servers()).remove(&server_id).is_some());
    }

    #[test]
    fn ex_host_http_respond_stream_fails_without_responder() {
        let server_id = 90_002u32;
        let request_id = 102u32;
        let state = register_test_server(server_id);
        let (body_tx, _body_rx) = mpsc::channel::<RequestBodyChunk>(8);

        lock_or_recover(&state.response_bodies).insert(
            request_id,
            ResponseBodyPipe {
                sender: body_tx,
                total_bytes: AtomicUsize::new(0),
            },
        );

        let start = ex_host_http_respond_stream(
            server_id,
            request_id,
            StatusCode::OK.as_u16(),
            std::ptr::null(),
        );
        assert_eq!(start, -1);
        assert!(!lock_or_recover(&state.responders).contains_key(&request_id));
        assert!(!state
            .response_bodies
            .lock()
            .expect("test response body lock should succeed")
            .contains_key(&request_id));
        assert!(lock_or_recover(servers()).remove(&server_id).is_some());
    }

    #[test]
    fn ex_host_http_close_is_idempotent_after_graceful_removal() {
        let server_id = 90_003u32;
        register_test_server(server_id);

        ex_host_http_set_ref(server_id, 0);
        assert_eq!(ex_host_http_close(server_id, 0), 0);

        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if !lock_or_recover(servers()).contains_key(&server_id) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(ex_host_http_close(server_id, 0), 0);
    }

    #[test]
    fn finish_active_request_does_not_underflow() {
        let server_id = 90_004u32;
        let state = register_test_server(server_id);
        state.active_requests.store(0, Ordering::SeqCst);

        finish_active_request(&state);

        assert_eq!(state.active_requests.load(Ordering::SeqCst), 0);
        assert!(lock_or_recover(servers()).remove(&server_id).is_some());
    }

    #[test]
    fn send_response_chunk_applies_backpressure_when_channel_is_full() {
        // A full channel must NOT drop the chunk (which would silently truncate
        // the response); it must block until the consumer drains a slot.
        let server_id = 90_005u32;
        let request_id = 105u32;
        let state = register_test_server(server_id);

        let (body_tx, body_rx) = mpsc::channel::<RequestBodyChunk>(1);
        lock_or_recover(&state.response_bodies).insert(
            request_id,
            ResponseBodyPipe {
                sender: body_tx,
                total_bytes: AtomicUsize::new(0),
            },
        );

        // Fill the single slot.
        assert!(send_response_chunk(
            &state,
            request_id,
            RequestBodyChunk::Data(b"first".to_vec())
        ));

        // Drain after a delay so the next send is forced to wait.
        let drainer = std::thread::spawn(move || {
            let mut body_rx = body_rx;
            std::thread::sleep(Duration::from_millis(50));
            assert!(matches!(
                body_rx.blocking_recv(),
                Some(RequestBodyChunk::Data(ref bytes)) if bytes.as_slice() == b"first"
            ));
            assert!(matches!(
                body_rx.blocking_recv(),
                Some(RequestBodyChunk::Data(ref bytes)) if bytes.as_slice() == b"second"
            ));
        });

        let start = Instant::now();
        let ok = send_response_chunk(&state, request_id, RequestBodyChunk::Data(b"second".to_vec()));
        assert!(ok, "a full channel must apply backpressure and then succeed");
        assert!(
            start.elapsed() >= Duration::from_millis(40),
            "send should have blocked until a slot was drained"
        );

        drainer.join().expect("drainer thread should not panic");

        // A successful send leaves the pipe in place for further chunks.
        assert!(lock_or_recover(&state.response_bodies).contains_key(&request_id));
        assert!(lock_or_recover(servers()).remove(&server_id).is_some());
    }

    #[test]
    fn send_response_chunk_reports_closed_channel_distinctly() {
        // A closed receiver (client/connection gone) is the only fatal case and
        // must fail promptly and clear the pipe.
        let server_id = 90_006u32;
        let request_id = 106u32;
        let state = register_test_server(server_id);

        let (body_tx, body_rx) = mpsc::channel::<RequestBodyChunk>(8);
        lock_or_recover(&state.response_bodies).insert(
            request_id,
            ResponseBodyPipe {
                sender: body_tx,
                total_bytes: AtomicUsize::new(0),
            },
        );
        drop(body_rx);

        let start = Instant::now();
        let ok = send_response_chunk(&state, request_id, RequestBodyChunk::Data(b"x".to_vec()));
        assert!(!ok, "a closed channel must fail");
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "closed must be detected immediately, not treated as backpressure"
        );
        assert!(!lock_or_recover(&state.response_bodies).contains_key(&request_id));
        assert!(lock_or_recover(servers()).remove(&server_id).is_some());
    }

    #[test]
    fn sanitize_no_content_headers_preserves_keep_alive() {
        // 304/204 are the hottest keep-alive responses; we must not force
        // Connection: close on them.
        let mut headers = vec![("ETag".to_string(), "\"abc\"".to_string())];
        sanitize_no_content_headers(StatusCode::NOT_MODIFIED, &mut headers);

        assert!(
            headers
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("content-length") && value == "0"),
            "content-length: 0 delimits the bodyless response"
        );
        assert!(
            !headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("connection")),
            "must not inject Connection: close"
        );
        assert!(headers
            .iter()
            .any(|(name, value)| name == "ETag" && value == "\"abc\""));
    }

    #[test]
    fn sanitize_no_content_headers_strips_te_and_keeps_explicit_connection() {
        let mut headers = vec![
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Connection".to_string(), "close".to_string()),
        ];
        sanitize_no_content_headers(StatusCode::NO_CONTENT, &mut headers);

        assert!(
            !headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding")),
            "transfer-encoding is invalid on a no-content response"
        );
        // An explicit Connection header set by the caller is left untouched.
        assert!(headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("connection") && value == "close"));
    }

    #[test]
    fn sanitize_no_content_headers_ignores_normal_status() {
        let mut headers = vec![("content-type".to_string(), "text/plain".to_string())];
        sanitize_no_content_headers(StatusCode::OK, &mut headers);
        assert_eq!(
            headers,
            vec![("content-type".to_string(), "text/plain".to_string())]
        );
    }
}
