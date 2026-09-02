//! `NSURLSession` behind the `Transport` trait.
//!
//! See `src/engine/darwin_http.mm` for the Objective-C++ half, and in
//! particular for why redirects are refused there: Rust re-checks the
//! `net.fetch` grant on every hop, so a platform that followed redirects
//! internally would deliver a response from an origin the caller was never
//! granted.

use std::ffi::{c_char, c_int, c_uchar, CStr, CString};

use crate::boundary::HostError;
use crate::stdlib::fetch::{Headers, Request, Response, Transport};

extern "C" {
    fn ibex2_darwin_session_create() -> *mut std::ffi::c_void;
    fn ibex2_darwin_session_destroy(handle: *mut std::ffi::c_void);
    /// Reports whether the session kept a cookie jar / URL cache, so the
    /// claim can be tested rather than asserted in a comment. Test-only: the
    /// runtime never needs to ask.
    #[cfg(test)]
    fn ibex2_darwin_session_has_state(
        handle: *mut std::ffi::c_void,
        out_cookies: *mut c_int,
        out_cache: *mut c_int,
    );
    fn ibex2_darwin_http_send(
        session: *mut std::ffi::c_void,
        method: *const c_char,
        url: *const c_char,
        header_block: *const c_char,
        body: *const c_uchar,
        body_len: usize,
        // The response ceiling, already resolved by Rust: the platform
        // enforces it, it does not choose it.
        max_body: usize,
        out_status: *mut c_int,
        out_headers: *mut *mut c_char,
        out_body: *mut *mut c_uchar,
        out_body_len: *mut usize,
        out_error: *mut *mut c_char,
        // 1 if the request rode an already-open connection, 0 if it opened
        // one, -1 if the platform did not report. Lets the pool be asserted
        // directly rather than inferred from latency.
        out_reused: *mut c_int,
    ) -> c_int;
    fn ibex2_darwin_free(value: *mut std::ffi::c_void);
}

/// The platform transport on Apple platforms.
///
/// Owns **one** `NSURLSession` for as long as the runtime does. A session owns
/// the connection pool, so a session per request discards every pooled
/// connection and pays a fresh TLS handshake each time — measured at ~80ms per
/// call against ~2ms once connections are reused. `RuntimeState` already holds
/// exactly one transport for exactly one runtime, so this is the lifetime the
/// session wanted all along.
///
/// The session stays *ephemeral*: no cookie jar, no disk cache. Sharing it
/// across a runtime's own requests is connection reuse; sharing it across
/// runtimes would be shared state, which is why it lives here and not in a
/// process-wide static.
///
/// **Created on first use, not at construction.** The first `NSURLSession` in
/// a process costs ~19ms, because it is what drags CFNetwork and the rest of
/// the system network stack in. `RuntimeState::new` runs on the runtime
/// construction path, so building it eagerly would put that on the boot floor
/// of every program — including the ones that never fetch — against a ~4ms
/// budget (LLP 0063). Deferred, it lands on the first request, where a
/// ~100ms round trip is already being paid.
#[derive(Debug, Default)]
pub struct DarwinTransport {
    /// The session pointer, as a `usize` so the struct stays plainly `Send`
    /// and `Sync` without an `unsafe impl` asserting it. `NSURLSession` is
    /// itself thread-safe, and this is written once and only read after.
    session: std::sync::OnceLock<usize>,
    /// Whether the most recent request reused a connection: 1 yes, 0 no, -1
    /// not reported. Test-facing; nothing in the runtime reads it.
    last_reused: std::sync::atomic::AtomicIsize,
}

impl DarwinTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the last request rode an already-open connection.
    /// `Some(true)`/`Some(false)`, or `None` when the platform did not report.
    pub fn last_connection_was_reused(&self) -> Option<bool> {
        match self.last_reused.load(std::sync::atomic::Ordering::Relaxed) {
            1 => Some(true),
            0 => Some(false),
            _ => None,
        }
    }

    /// The runtime's session, built on the first call.
    ///
    /// Two racing first requests may both construct one; `OnceLock` keeps the
    /// winner and the loser's is released here rather than leaked. That costs
    /// one redundant session in a rare race, which is the cheap side of the
    /// trade against holding a lock across a ~19ms initialization.
    fn session(&self) -> *mut std::ffi::c_void {
        if let Some(existing) = self.session.get() {
            return *existing as *mut std::ffi::c_void;
        }
        // SAFETY: returns a retained session or null. Null is handled by the
        // caller, which fails the request rather than dereferencing it.
        let created = unsafe { ibex2_darwin_session_create() };
        match self.session.set(created as usize) {
            Ok(()) => created,
            Err(_) => {
                // Another thread won. Release ours and use theirs.
                // SAFETY: `created` is ours alone and has not been shared.
                unsafe { ibex2_darwin_session_destroy(created) };
                *self.session.get().expect("set by the winner") as *mut std::ffi::c_void
            }
        }
    }
}

impl Drop for DarwinTransport {
    fn drop(&mut self) {
        if let Some(session) = self.session.get() {
            // SAFETY: came from `ibex2_darwin_session_create`, released once.
            unsafe { ibex2_darwin_session_destroy(*session as *mut std::ffi::c_void) };
        }
    }
}

unsafe fn take_string(raw: *mut c_char) -> Option<String> {
    if raw.is_null() {
        return None;
    }
    let text = CStr::from_ptr(raw).to_string_lossy().into_owned();
    ibex2_darwin_free(raw as *mut std::ffi::c_void);
    Some(text)
}

impl Transport for DarwinTransport {
    fn send(&self, request: &Request) -> Result<Response, HostError> {
        let method = CString::new(request.method.as_str())
            .map_err(|_| HostError::Failed("TypeError: invalid method".into()))?;
        let url = CString::new(request.url.as_str())
            .map_err(|_| HostError::Failed("TypeError: invalid URL".into()))?;

        let header_block = request
            .headers
            .entries()
            .iter()
            .map(|(name, value)| format!("{name}: {value}"))
            .collect::<Vec<_>>()
            .join("\n");
        let header_block = CString::new(header_block)
            .map_err(|_| HostError::Failed("TypeError: invalid header value".into()))?;

        let (body_ptr, body_len) = match &request.body {
            Some(body) if !body.is_empty() => (body.as_ptr(), body.len()),
            _ => (std::ptr::null(), 0),
        };

        let mut status: c_int = 0;
        let mut headers_raw: *mut c_char = std::ptr::null_mut();
        let mut body_raw: *mut c_uchar = std::ptr::null_mut();
        let mut body_out_len: usize = 0;
        let mut error_raw: *mut c_char = std::ptr::null_mut();
        let mut reused: c_int = -1;

        // SAFETY: every pointer is valid for the call; all four out-params are
        // released below regardless of outcome.
        let ok = unsafe {
            ibex2_darwin_http_send(
                self.session(),
                method.as_ptr(),
                url.as_ptr(),
                header_block.as_ptr(),
                body_ptr,
                body_len,
                request.body_limit(),
                &mut status,
                &mut headers_raw,
                &mut body_raw,
                &mut body_out_len,
                &mut error_raw,
                &mut reused,
            )
        };
        self.last_reused
            .store(reused as isize, std::sync::atomic::Ordering::Relaxed);

        let header_text = unsafe { take_string(headers_raw) };
        let error_text = unsafe { take_string(error_raw) };
        let body = if body_raw.is_null() || body_out_len == 0 {
            Vec::new()
        } else {
            // SAFETY: the platform side malloc'd exactly body_out_len bytes.
            let slice = unsafe { std::slice::from_raw_parts(body_raw, body_out_len) };
            let owned = slice.to_vec();
            unsafe { ibex2_darwin_free(body_raw as *mut std::ffi::c_void) };
            owned
        };

        if ok != 0 {
            return Err(HostError::Failed(
                error_text.unwrap_or_else(|| "TypeError: Failed to fetch".to_string()),
            ));
        }

        let mut headers = Headers::new();
        for line in header_text.unwrap_or_default().lines() {
            if let Some((name, value)) = line.split_once(": ") {
                headers.set_response(name, value);
            }
        }

        Ok(Response {
            status: status as u16,
            status_text: String::new(),
            headers,
            body,
            url: request.url.clone(),
            redirected: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two runtimes must not share a session, or the ephemeral configuration
    /// stops meaning anything: connection state, and anything the platform
    /// caches with it, would cross a boundary the capability model draws.
    #[test]
    fn each_transport_owns_its_own_session() {
        let a = DarwinTransport::new();
        let b = DarwinTransport::new();
        assert!(!a.session().is_null(), "session was not created");
        assert!(!b.session().is_null(), "session was not created");
        assert_ne!(a.session(), b.session(), "two runtimes shared one session");
    }

    /// Construction must not build the session, or every program pays ~19ms of
    /// CFNetwork initialization on its boot floor whether it fetches or not.
    #[test]
    fn constructing_a_transport_does_not_build_a_session() {
        let t = DarwinTransport::new();
        assert!(
            t.session.get().is_none(),
            "the session was created eagerly; that cost belongs on the first request"
        );
    }

    /// The reuse claim, asserted directly.
    ///
    /// A session owns the connection pool. With one session per request every
    /// call opened a new connection and paid a full TLS handshake.
    ///
    /// **This does not time anything.** An earlier version required a repeat
    /// request under 40ms, which was wrong twice over: it passed because
    /// `NSURLCache` was answering from memory without any connection at all,
    /// and once the cache was disabled it failed whenever the network was
    /// merely slow — 64ms on a working pool. Latency cannot distinguish a
    /// pooled request from a fast handshake. `NSURLSessionTaskMetrics` says
    /// outright whether the connection was reused, so that is what is asserted.
    #[test]
    fn a_second_request_to_one_origin_reuses_the_connection() {
        let transport = DarwinTransport::new();
        if transport
            .send(&Request::get("https://example.com/"))
            .is_err()
        {
            return; // no network; nothing to measure
        }
        // The first request may or may not have opened a connection; only the
        // repeats carry the claim.
        let Some(false) = transport.last_connection_was_reused() else {
            return; // platform did not report metrics; nothing to assert on
        };

        for attempt in 0..3 {
            assert!(
                transport
                    .send(&Request::get("https://example.com/"))
                    .is_ok(),
                "request {attempt} failed after the first one succeeded"
            );
            assert_eq!(
                transport.last_connection_was_reused(),
                Some(true),
                "request {attempt} opened a new connection; the session is not being reused"
            );
        }
    }

    /// Cookies are ambient authority the grant check cannot see, so the
    /// session must not keep any. Asserted on the configuration rather than by
    /// round-tripping a `Set-Cookie`, which would need a server that sets one.
    #[test]
    fn the_session_keeps_no_cookies_and_no_cache() {
        let transport = DarwinTransport::new();
        let session = transport.session();
        assert!(!session.is_null(), "session was not created");
        // SAFETY: `session` is this transport's live session.
        let (mut cookies, mut cache) = (0, 0);
        unsafe { ibex2_darwin_session_has_state(session, &mut cookies, &mut cache) };
        assert_eq!(cookies, 0, "the session has a cookie jar");
        assert_eq!(cache, 0, "the session has a URL cache");
    }
}

#[cfg(test)]
mod session_cost {
    use super::*;

    /// What the first session in a process costs, which is why it is built on
    /// first use rather than at construction: on the runtime construction path
    /// this would land on the boot floor of every program, against LLP 0063's
    /// ~4ms. `constructing_a_transport_does_not_build_a_session` is the guard;
    /// this is the number behind it.
    #[test]
    #[ignore = "measurement, not an assertion"]
    fn report_session_construction_cost() {
        for i in 1..=5 {
            let t = DarwinTransport::new();
            let started = std::time::Instant::now();
            let _ = t.session();
            eprintln!("  session #{i}: {:?}", started.elapsed());
            drop(t);
        }
    }
}
