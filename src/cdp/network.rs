//! CDP Network domain implementation.
//!
//! Provides a shared capture layer that the HTTP server writes to and the CDP
//! WebSocket connection reads from.  The global singleton pattern (OnceLock)
//! mirrors `http_server::servers()` so neither module needs to know about the
//! other at compile time -- they communicate through this shared state.

use crate::sync::lock_or_recover;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A captured HTTP request/response pair, stored for `Network.getResponseBody`.
struct CapturedExchange {
    response_body: Vec<u8>,
    response_mime_type: String,
}

/// An event to be forwarded over the CDP WebSocket.
#[derive(Clone, Debug)]
struct NetworkCdpEvent {
    json: String,
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static NETWORK_CAPTURE: OnceLock<NetworkCaptureState> = OnceLock::new();

struct NetworkCaptureState {
    /// Whether the Network domain is enabled in DevTools.
    enabled: AtomicBool,
    /// Monotonic request-id counter (stringified for CDP).
    next_id: AtomicU64,
    /// Cached response bodies keyed by CDP request-id.
    exchanges: Mutex<HashMap<String, CapturedExchange>>,
    /// Pending events to be drained by the CDP connection loop.
    events: Mutex<Vec<NetworkCdpEvent>>,
    /// Mapping from HTTP server request_id (u32) to CDP network request_id (String).
    /// This allows the response path (which only knows the HTTP server request_id)
    /// to look up the CDP request_id for emitting response events.
    http_to_cdp: Mutex<HashMap<u32, CdpRequestContext>>,
}

/// Context stored for each in-flight HTTP request so we can emit
/// response events later when `send_response` is called.
struct CdpRequestContext {
    cdp_id: String,
    url: String,
}

fn state() -> &'static NetworkCaptureState {
    NETWORK_CAPTURE.get_or_init(|| NetworkCaptureState {
        enabled: AtomicBool::new(false),
        next_id: AtomicU64::new(1),
        exchanges: Mutex::new(HashMap::new()),
        events: Mutex::new(Vec::new()),
        http_to_cdp: Mutex::new(HashMap::new()),
    })
}

// ---------------------------------------------------------------------------
// CDP command handlers (called from cdp/mod.rs)
// ---------------------------------------------------------------------------

/// Handle `Network.enable`.
pub fn enable() {
    state().enabled.store(true, Ordering::SeqCst);
}

/// Handle `Network.disable`.
pub fn disable() {
    state().enabled.store(false, Ordering::SeqCst);
    // Flush buffered data.
    lock_or_recover(&state().exchanges).clear();
    lock_or_recover(&state().events).clear();
    lock_or_recover(&state().http_to_cdp).clear();
}

/// Handle `Network.getResponseBody` -- returns a CDP result value.
pub fn get_response_body(request_id: &str) -> Value {
    let exchanges = lock_or_recover(&state().exchanges);
    if let Some(exchange) = exchanges.get(request_id) {
        // Try to interpret as UTF-8 text first.
        let is_text = exchange.response_mime_type.starts_with("text/")
            || exchange.response_mime_type.contains("json")
            || exchange.response_mime_type.contains("javascript")
            || exchange.response_mime_type.contains("xml")
            || exchange.response_mime_type.contains("html")
            || exchange.response_mime_type.contains("css");

        if is_text {
            if let Ok(text) = std::str::from_utf8(&exchange.response_body) {
                return json!({
                    "body": text,
                    "base64Encoded": false,
                });
            }
        }

        // Fall back to base64.
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &exchange.response_body,
        );
        json!({
            "body": encoded,
            "base64Encoded": true,
        })
    } else {
        json!({
            "body": "",
            "base64Encoded": false,
        })
    }
}

/// Drain all pending network events (called from the CDP poll loop).
pub fn drain_events() -> Vec<String> {
    let mut events = lock_or_recover(&state().events);
    let drained: Vec<String> = events.iter().map(|e| e.json.clone()).collect();
    events.clear();
    drained
}

// ---------------------------------------------------------------------------
// Event emission (called from the HTTP server)
// ---------------------------------------------------------------------------

fn monotonic_timestamp() -> f64 {
    // CDP timestamps are "monotonically increasing" seconds.
    // We use wall-clock for simplicity -- DevTools is tolerant.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn push_event(event: Value) {
    let json = event.to_string();
    lock_or_recover(&state().events).push(NetworkCdpEvent { json });
}

/// Returns whether network capture is currently enabled.
pub fn is_enabled() -> bool {
    // Fast path: avoid touching the OnceLock if it was never initialised.
    match NETWORK_CAPTURE.get() {
        Some(s) => s.enabled.load(Ordering::Relaxed),
        None => false,
    }
}

/// Emit `Network.requestWillBeSent` and register the HTTP-to-CDP id mapping.
///
/// Called from the HTTP server's `handle_request` after headers and body are
/// parsed.  `http_request_id` is the server's internal request_id (u32).
pub fn emit_request_will_be_sent(
    http_request_id: u32,
    url: &str,
    method: &str,
    headers: &[(String, String)],
    post_data: Option<&[u8]>,
) {
    if !is_enabled() {
        return;
    }

    let cdp_id = state().next_id.fetch_add(1, Ordering::Relaxed).to_string();

    // Store mapping so response events can find the CDP id.
    lock_or_recover(&state().http_to_cdp).insert(
        http_request_id,
        CdpRequestContext {
            cdp_id: cdp_id.clone(),
            url: url.to_string(),
        },
    );

    let ts = monotonic_timestamp();
    let header_map: HashMap<&str, &str> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let mut request = json!({
        "url": url,
        "method": method,
        "headers": header_map,
    });
    if let Some(data) = post_data {
        if let Ok(text) = std::str::from_utf8(data) {
            request["postData"] = json!(text);
        }
    }

    let event = json!({
        "method": "Network.requestWillBeSent",
        "params": {
            "requestId": cdp_id,
            "loaderId": "1",
            "documentURL": url,
            "request": request,
            "timestamp": ts,
            "wallTime": ts,
            "initiator": { "type": "other" },
            "type": "Fetch",
        }
    });
    push_event(event);
}

/// Emit `Network.responseReceived` and `Network.loadingFinished`, and cache
/// the response body for later retrieval via `getResponseBody`.
///
/// Called from the HTTP server's `send_response` (and similar paths) when the
/// response is complete.  `http_request_id` is the server's internal request_id.
pub fn emit_response(
    http_request_id: u32,
    status: u16,
    response_headers: &[(String, String)],
    body: &[u8],
) {
    if !is_enabled() {
        return;
    }

    // Look up and remove the mapping.
    let ctx = lock_or_recover(&state().http_to_cdp).remove(&http_request_id);
    let ctx = match ctx {
        Some(ctx) => ctx,
        None => return, // No mapping -- request was made before Network.enable
    };

    let ts = monotonic_timestamp();
    let header_map: HashMap<&str, &str> = response_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // Determine MIME type from headers.
    let mime_type = response_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| {
            // Strip parameters like "; charset=utf-8".
            v.split(';')
                .next()
                .unwrap_or("application/octet-stream")
                .trim()
                .to_string()
        })
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let status_text = default_status_text(status);

    // responseReceived
    let response_event = json!({
        "method": "Network.responseReceived",
        "params": {
            "requestId": ctx.cdp_id,
            "loaderId": "1",
            "timestamp": ts,
            "type": "Fetch",
            "response": {
                "url": ctx.url,
                "status": status,
                "statusText": status_text,
                "headers": header_map,
                "mimeType": mime_type,
                "connectionReused": false,
                "connectionId": 0,
                "encodedDataLength": body.len(),
                "securityState": "neutral",
            }
        }
    });
    push_event(response_event);

    // loadingFinished
    let finished_event = json!({
        "method": "Network.loadingFinished",
        "params": {
            "requestId": ctx.cdp_id,
            "timestamp": ts,
            "encodedDataLength": body.len(),
        }
    });
    push_event(finished_event);

    // Cache the body for getResponseBody.
    let mut exchanges = lock_or_recover(&state().exchanges);
    exchanges.insert(
        ctx.cdp_id,
        CapturedExchange {
            response_body: body.to_vec(),
            response_mime_type: mime_type,
        },
    );

    // Limit cache size to prevent memory leaks.
    if exchanges.len() > 1000 {
        // Remove oldest entries (by smallest request-id number).
        let mut keys: Vec<String> = exchanges.keys().cloned().collect();
        keys.sort_by(|a, b| {
            let a_num = a.parse::<u64>().unwrap_or(u64::MAX);
            let b_num = b.parse::<u64>().unwrap_or(u64::MAX);
            a_num.cmp(&b_num)
        });
        // Keep the newest 500.
        for key in keys.iter().take(keys.len().saturating_sub(500)) {
            exchanges.remove(key);
        }
    }
}

/// Clean up the HTTP-to-CDP mapping for a request that completed without
/// going through `emit_response` (e.g. timeout, error before JS responded).
pub fn cleanup_request(http_request_id: u32) {
    if !is_enabled() {
        return;
    }
    lock_or_recover(&state().http_to_cdp).remove(&http_request_id);
}

fn default_status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}
