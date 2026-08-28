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
    fn ibex2_darwin_http_send(
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
#[derive(Debug, Default)]
pub struct DarwinTransport;

impl DarwinTransport {
    pub fn new() -> Self {
        Self
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
