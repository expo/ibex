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
    fn ibex2_darwin_http_send(
        session: *mut std::ffi::c_void,
        method: *const c_char,
        url: *const c_char,
        header_block: *const c_char,
        body: *const c_uchar,
        body_len: usize,
        out_status: *mut c_int,
        out_headers: *mut *mut c_char,
        out_body: *mut *mut c_uchar,
        out_body_len: *mut usize,
        out_error: *mut *mut c_char,
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
}

impl DarwinTransport {
    pub fn new() -> Self {
        Self::default()
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
                &mut status,
                &mut headers_raw,
                &mut body_raw,
                &mut body_out_len,
                &mut error_raw,
            )
        };

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

    /// The reuse claim, asserted rather than asserted-about.
    ///
    /// A session owns the connection pool. With one session per request every
    /// call paid a full TLS handshake — ~80ms measured. Reusing the runtime's
    /// session drops that to ~2ms. The threshold sits far below the handshake
    /// cost and far above the reuse cost, so it distinguishes the two
    /// implementations without pretending to measure the network precisely.
    ///
    /// Skips rather than fails when the first request does not succeed: with
    /// no network there is nothing to say about connection reuse, and a
    /// failure here would report the wrong thing.
    #[test]
    fn a_second_request_to_one_origin_reuses_the_connection() {
        let transport = DarwinTransport::new();
        let warm = std::time::Instant::now();
        if transport
            .send(&Request::get("https://example.com/"))
            .is_err()
        {
            return; // no network; nothing to measure
        }
        let first = warm.elapsed();

        let mut reused = Vec::new();
        for _ in 0..3 {
            let started = std::time::Instant::now();
            if transport
                .send(&Request::get("https://example.com/"))
                .is_err()
            {
                return;
            }
            reused.push(started.elapsed());
        }
        reused.sort();
        let median = reused[1];

        assert!(
            median < std::time::Duration::from_millis(40),
            "a repeat request took {median:?}, which is handshake territory — \
             the session is not being reused (first request was {first:?})"
        );
    }
}

#[cfg(test)]
mod session_cost {
    use super::*;

    /// The session is created eagerly in `ibex2_queue_create`, so every
    /// runtime pays for it whether or not it ever fetches. LLP 0063 puts the
    /// boot floor at ~4ms, so this needs to stay small enough not to matter.
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
