//! CDP Network domain implementation.
//!
//! Provides a shared capture layer that the HTTP server writes to and the CDP
//! WebSocket connection reads from.  The global singleton pattern (OnceLock)
//! mirrors `http_server::servers()` so neither module needs to know about the
//! other at compile time -- they communicate through this shared state.

use crate::sync::lock_or_recover;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A captured HTTP request/response pair, stored for `Network.getResponseBody`.
struct CapturedExchange {
    response_body: Vec<u8>,
    response_mime_type: String,
    original_body_bytes: usize,
    truncated: bool,
    visible_to: Vec<u64>,
}

/// An event to be forwarded over the CDP WebSocket.
#[derive(Clone, Debug)]
struct NetworkCdpEvent {
    json: String,
}

#[derive(Default)]
struct NetworkSubscriber {
    events: VecDeque<NetworkCdpEvent>,
    event_bytes: usize,
    dropped_events: usize,
}

#[derive(Default)]
struct BodyCache {
    exchanges: HashMap<String, CapturedExchange>,
    lru: VecDeque<String>,
    body_bytes: usize,
}

impl BodyCache {
    fn get(&mut self, request_id: &str) -> Option<&CapturedExchange> {
        if self.exchanges.contains_key(request_id) {
            self.lru.retain(|key| key != request_id);
            self.lru.push_back(request_id.to_owned());
        }
        self.exchanges.get(request_id)
    }

    fn insert(&mut self, request_id: String, exchange: CapturedExchange) {
        if let Some(previous) = self.exchanges.remove(&request_id) {
            self.body_bytes = self.body_bytes.saturating_sub(previous.response_body.len());
            self.lru.retain(|key| key != &request_id);
        }
        self.body_bytes += exchange.response_body.len();
        self.lru.push_back(request_id.clone());
        self.exchanges.insert(request_id, exchange);
        while self.body_bytes > MAX_CAPTURED_BODY_BYTES_TOTAL
            || self.exchanges.len() > MAX_CAPTURED_EXCHANGES
        {
            let Some(oldest) = self.lru.pop_front() else {
                break;
            };
            if let Some(removed) = self.exchanges.remove(&oldest) {
                self.body_bytes = self.body_bytes.saturating_sub(removed.response_body.len());
            }
        }
    }

    fn clear(&mut self) {
        self.exchanges.clear();
        self.lru.clear();
        self.body_bytes = 0;
    }

    fn remove_client(&mut self, client_id: u64) {
        let empty = self
            .exchanges
            .iter_mut()
            .filter_map(|(request_id, exchange)| {
                exchange.visible_to.retain(|visible| *visible != client_id);
                exchange.visible_to.is_empty().then(|| request_id.clone())
            })
            .collect::<Vec<_>>();
        for request_id in empty {
            if let Some(exchange) = self.exchanges.remove(&request_id) {
                self.body_bytes = self.body_bytes.saturating_sub(exchange.response_body.len());
            }
            self.lru.retain(|key| key != &request_id);
        }
    }
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
    /// Monotonic CDP client identity; event queues are never shared/drained by
    /// competing inspector connections.
    next_client_id: AtomicU64,
    /// Cached response bodies keyed by CDP request-id.
    exchanges: Mutex<BodyCache>,
    /// One bounded pending-event queue per Network-enabled CDP client.
    subscribers: Mutex<HashMap<u64, NetworkSubscriber>>,
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
    subscribers: Vec<u64>,
}

fn state() -> &'static NetworkCaptureState {
    NETWORK_CAPTURE.get_or_init(|| NetworkCaptureState {
        enabled: AtomicBool::new(false),
        next_id: AtomicU64::new(1),
        next_client_id: AtomicU64::new(1),
        exchanges: Mutex::new(BodyCache::default()),
        subscribers: Mutex::new(HashMap::new()),
        http_to_cdp: Mutex::new(HashMap::new()),
    })
}

// ---------------------------------------------------------------------------
// CDP command handlers (called from cdp/mod.rs)
// ---------------------------------------------------------------------------

/// Allocate an identity for a newly established CDP WebSocket connection.
pub fn register_client() -> u64 {
    state().next_client_id.fetch_add(1, Ordering::Relaxed)
}

/// Handle `Network.enable` for one CDP client.
pub fn enable(client_id: u64) {
    let mut subscribers = lock_or_recover(&state().subscribers);
    subscribers.entry(client_id).or_default();
    state().enabled.store(true, Ordering::SeqCst);
}

/// Handle `Network.disable` (or disconnect) for one CDP client. Shared capture
/// remains live while any other client is subscribed.
pub fn disable(client_id: u64) {
    let mut subscribers = lock_or_recover(&state().subscribers);
    if subscribers.remove(&client_id).is_none() {
        return;
    }
    lock_or_recover(&state().exchanges).remove_client(client_id);
    if subscribers.is_empty() {
        state().enabled.store(false, Ordering::SeqCst);
        lock_or_recover(&state().exchanges).clear();
        lock_or_recover(&state().http_to_cdp).clear();
    } else {
        state().enabled.store(true, Ordering::SeqCst);
    }
}

/// Handle `Network.getResponseBody` -- returns a CDP result value.
pub fn get_response_body(client_id: u64, request_id: &str) -> Value {
    if !lock_or_recover(&state().subscribers).contains_key(&client_id) {
        return json!({ "body": "", "base64Encoded": false });
    }
    let mut exchanges = lock_or_recover(&state().exchanges);
    if let Some(exchange) = exchanges
        .get(request_id)
        .filter(|exchange| exchange.visible_to.contains(&client_id))
    {
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
                    "ibexTruncated": exchange.truncated,
                    "ibexOriginalBodyBytes": exchange.original_body_bytes,
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
            "ibexTruncated": exchange.truncated,
            "ibexOriginalBodyBytes": exchange.original_body_bytes,
        })
    } else {
        json!({
            "body": "",
            "base64Encoded": false,
        })
    }
}

/// Drain this client's pending network events (called from its CDP poll loop).
pub fn drain_events(client_id: u64) -> Vec<String> {
    let mut subscribers = lock_or_recover(&state().subscribers);
    let Some(subscriber) = subscribers.get_mut(&client_id) else {
        return Vec::new();
    };
    let dropped = std::mem::take(&mut subscriber.dropped_events);
    subscriber.event_bytes = 0;
    let mut drained = Vec::with_capacity(subscriber.events.len() + usize::from(dropped > 0));
    if dropped > 0 {
        drained.push(
            json!({
                "method": "Network.ibexBufferLimitExceeded",
                "params": { "droppedEvents": dropped }
            })
            .to_string(),
        );
    }
    drained.extend(subscriber.events.drain(..).map(|event| event.json));
    drained
}

// ---------------------------------------------------------------------------
// Event emission (called from the HTTP server)
// ---------------------------------------------------------------------------

fn monotonic_timestamp() -> f64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    ORIGIN.get_or_init(Instant::now).elapsed().as_secs_f64()
}

fn wall_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Upper bound on undrained events. The CDP poll loop drains every 50ms while
/// a DevTools client is connected, so this is only reached if the client stops
/// draining (e.g. it disconnected before `disable()` ran). Bounding it here --
/// mirroring the `exchanges` cache cap -- prevents the buffer from growing
/// without limit under load and OOM-ing the server.
// @ref LLP 0003#inspector-resource-discipline — every retained diagnostic
// payload is bounded in bytes and each subscriber owns an independent queue.
const MAX_PENDING_EVENTS: usize = 1000;
const MAX_PENDING_EVENT_BYTES_PER_CLIENT: usize = 2 * 1024 * 1024;
const MAX_CAPTURED_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const MAX_CAPTURED_BODY_BYTES_TOTAL: usize = 16 * 1024 * 1024;
const MAX_CAPTURED_EXCHANGES: usize = 1000;
const MAX_CAPTURED_POST_DATA_BYTES: usize = 64 * 1024;
const MAX_IN_FLIGHT_REQUESTS: usize = 4096;

#[cfg(test)]
fn push_event(event: Value) {
    push_event_for(event, None);
}

fn push_event_for(event: Value, recipients: Option<&[u64]>) {
    let json = event.to_string();
    let event_bytes = json.len();
    let mut subscribers = lock_or_recover(&state().subscribers);
    let client_ids = recipients
        .map(|ids| ids.to_vec())
        .unwrap_or_else(|| subscribers.keys().copied().collect());
    for client_id in client_ids {
        let Some(subscriber) = subscribers.get_mut(&client_id) else {
            continue;
        };
        if event_bytes > MAX_PENDING_EVENT_BYTES_PER_CLIENT {
            subscriber.dropped_events = subscriber.dropped_events.saturating_add(1);
            continue;
        }
        while subscriber.events.len() >= MAX_PENDING_EVENTS
            || subscriber.event_bytes + event_bytes > MAX_PENDING_EVENT_BYTES_PER_CLIENT
        {
            let Some(removed) = subscriber.events.pop_front() else {
                break;
            };
            subscriber.event_bytes = subscriber.event_bytes.saturating_sub(removed.json.len());
            subscriber.dropped_events = subscriber.dropped_events.saturating_add(1);
        }
        subscriber.event_bytes += event_bytes;
        subscriber
            .events
            .push_back(NetworkCdpEvent { json: json.clone() });
    }
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
    let subscribers = {
        let subscribers = lock_or_recover(&state().subscribers);
        if subscribers.is_empty() {
            return;
        }
        let mut client_ids = subscribers.keys().copied().collect::<Vec<_>>();
        client_ids.sort_unstable();
        let mut requests = lock_or_recover(&state().http_to_cdp);
        if requests.len() >= MAX_IN_FLIGHT_REQUESTS {
            // Request ids are monotonic at the HTTP-server layer. Dropping one
            // unmatched context loses diagnostics for that request but keeps
            // an abandoned/flooded server from retaining unbounded URLs.
            if let Some(oldest) = requests.keys().min().copied() {
                requests.remove(&oldest);
            }
        }
        requests.insert(
            http_request_id,
            CdpRequestContext {
                cdp_id: cdp_id.clone(),
                url: url.to_string(),
                subscribers: client_ids.clone(),
            },
        );
        client_ids
    };

    let ts = monotonic_timestamp();
    let wall_time = wall_timestamp();
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
        request["hasPostData"] = json!(true);
        let retained = &data[..data.len().min(MAX_CAPTURED_POST_DATA_BYTES)];
        if let Ok(text) = std::str::from_utf8(retained) {
            request["postData"] = json!(text);
        } else {
            request["ibexPostDataOmitted"] = json!("non-utf8");
        }
        if retained.len() != data.len() {
            request["ibexPostDataTruncated"] = json!(true);
            request["ibexOriginalPostDataBytes"] = json!(data.len());
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
            "wallTime": wall_time,
            "initiator": { "type": "other" },
            "type": "Fetch",
        }
    });
    push_event_for(event, Some(&subscribers));
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
    push_event_for(response_event, Some(&ctx.subscribers));

    // loadingFinished
    let finished_event = json!({
        "method": "Network.loadingFinished",
        "params": {
            "requestId": ctx.cdp_id,
            "timestamp": ts,
            "encodedDataLength": body.len(),
        }
    });
    push_event_for(finished_event, Some(&ctx.subscribers));

    // Cache the body for getResponseBody.
    let retained_body = &body[..body.len().min(MAX_CAPTURED_RESPONSE_BODY_BYTES)];
    let subscribers = lock_or_recover(&state().subscribers);
    let visible_to = ctx
        .subscribers
        .iter()
        .copied()
        .filter(|client_id| subscribers.contains_key(client_id))
        .collect::<Vec<_>>();
    if !visible_to.is_empty() {
        lock_or_recover(&state().exchanges).insert(
            ctx.cdp_id,
            CapturedExchange {
                response_body: retained_body.to_vec(),
                response_mime_type: mime_type,
                original_body_bytes: body.len(),
                truncated: retained_body.len() != body.len(),
                visible_to,
            },
        );
    }
}

/// Clean up the HTTP-to-CDP mapping for a request that completed without
/// going through `emit_response` (e.g. timeout, error before JS responded).
pub fn cleanup_request(http_request_id: u32) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn network_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn exchange(bytes: usize) -> CapturedExchange {
        CapturedExchange {
            response_body: vec![b'x'; bytes],
            response_mime_type: "application/octet-stream".to_string(),
            original_body_bytes: bytes,
            truncated: false,
            visible_to: Vec::new(),
        }
    }

    #[test]
    fn body_cache_evicts_by_bytes_and_refreshes_lru_on_access() {
        let mut cache = BodyCache::default();
        for id in 0..20 {
            cache.insert(id.to_string(), exchange(1024 * 1024));
        }
        assert!(cache.body_bytes <= MAX_CAPTURED_BODY_BYTES_TOTAL);
        assert!(cache.exchanges.len() <= 16);
        assert!(cache.get("19").is_some());
        cache.insert("20".to_string(), exchange(1024 * 1024));
        assert!(cache.exchanges.contains_key("19"));
    }

    #[test]
    fn capture_is_byte_bounded_and_events_are_fanned_out_per_client() {
        let _lock = network_test_lock();
        let first = register_client();
        let second = register_client();
        enable(first);
        enable(second);

        let request_id = u32::MAX - first as u32;
        let post_data = vec![b'a'; MAX_CAPTURED_POST_DATA_BYTES + 1024];
        emit_request_will_be_sent(
            request_id,
            "https://example.test/upload",
            "POST",
            &[],
            Some(&post_data),
        );
        let first_events = drain_events(first);
        let second_events = drain_events(second);
        assert_eq!(first_events, second_events);
        let request: Value = serde_json::from_str(&first_events[0]).unwrap();
        assert_eq!(request["params"]["request"]["ibexPostDataTruncated"], true);
        assert_eq!(
            request["params"]["request"]["ibexOriginalPostDataBytes"],
            post_data.len()
        );
        let cdp_id = request["params"]["requestId"].as_str().unwrap().to_owned();

        for sequence in 0..1500 {
            push_event(json!({
                "method": "Network.syntheticFlood",
                "params": { "sequence": sequence, "payload": "x".repeat(2048) }
            }));
        }
        {
            let subscribers = lock_or_recover(&state().subscribers);
            for subscriber in subscribers.values() {
                assert!(subscriber.events.len() <= MAX_PENDING_EVENTS);
                assert!(subscriber.event_bytes <= MAX_PENDING_EVENT_BYTES_PER_CLIENT);
            }
        }
        for client_id in [first, second] {
            let events = drain_events(client_id);
            let diagnostic: Value = serde_json::from_str(&events[0]).unwrap();
            assert_eq!(diagnostic["method"], "Network.ibexBufferLimitExceeded");
            assert!(diagnostic["params"]["droppedEvents"].as_u64().unwrap() > 0);
        }

        // A client enabling after requestWillBeSent must not receive a partial
        // response stream or access another client's retained body.
        let late = register_client();
        enable(late);
        let response = vec![b'b'; MAX_CAPTURED_RESPONSE_BODY_BYTES + 4096];
        emit_response(
            request_id,
            200,
            &[(
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            )],
            &response,
        );
        let body = get_response_body(first, &cdp_id);
        assert_eq!(body["ibexTruncated"], true);
        assert_eq!(body["ibexOriginalBodyBytes"], response.len());
        let encoded = body["body"].as_str().unwrap();
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap();
        assert_eq!(decoded.len(), MAX_CAPTURED_RESPONSE_BODY_BYTES);
        assert_eq!(
            get_response_body(late, &cdp_id),
            json!({ "body": "", "base64Encoded": false })
        );
        assert!(drain_events(late).is_empty());

        disable(first);
        assert!(is_enabled(), "second client must keep capture enabled");
        assert!(drain_events(first).is_empty());
        assert!(!drain_events(second).is_empty());
        disable(second);
        assert!(is_enabled(), "late client remains independently enabled");
        assert_eq!(lock_or_recover(&state().exchanges).body_bytes, 0);
        disable(late);
        assert!(!is_enabled());
    }
}
