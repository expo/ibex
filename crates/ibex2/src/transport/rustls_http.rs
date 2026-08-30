//! The transport off Apple platforms: HTTP/1.1 over rustls, through `ureq`
//! (LLP 0068 OQ2, resolved 2026-08-30 for Exact 2's Linux host).
//!
//! LLP 0057 §3 keeps everything above the socket in Rust: this transport
//! performs exactly one request and follows no redirect (`fetch` does that
//! above), reports every status as a response (a 4xx or 5xx is an answer,
//! not a transport failure), and turns what never connected into
//! `HostError::Failed` with the browser's own `TypeError: Failed to fetch`
//! spelling. The certificate roots are webpki's, compiled in; a builder
//! with no system TLS and no -dev packages runs it as is.

use crate::boundary::HostError;
use crate::stdlib::fetch::{Headers, Request, Response, Transport};
use std::io::Read;
use std::time::Duration;

/// The transport: one `ureq` agent, rustls underneath.
pub struct RustlsHttpTransport {
    agent: ureq::Agent,
}

impl RustlsHttpTransport {
    /// A thirty-second timeout per request, no redirects.
    pub fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(Duration::from_secs(30))
                .build(),
        }
    }
}

impl Default for RustlsHttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// The largest body kept in memory (the development transport's bound).
const MAX_BODY: usize = 64 * 1024 * 1024;

impl Transport for RustlsHttpTransport {
    fn send(&self, request: &Request) -> Result<Response, HostError> {
        let mut req = self.agent.request(&request.method, &request.url);
        for (name, value) in request.headers.entries() {
            req = req.set(name, value);
        }
        let result = match &request.body {
            Some(body) => req.send_bytes(body),
            None => req.call(),
        };
        let resp = match result {
            Ok(r) => r,
            // A status is an answer; the semantics above decide what it means.
            Err(ureq::Error::Status(_, r)) => r,
            Err(ureq::Error::Transport(t)) => {
                return Err(HostError::Failed(format!(
                    "TypeError: Failed to fetch — {t}"
                )))
            }
        };
        let status = resp.status();
        let status_text = resp.status_text().to_string();
        let mut headers = Headers::new();
        for name in resp.headers_names() {
            for value in resp.all(&name) {
                headers.set_response(&name, value);
            }
        }
        let mut body = Vec::new();
        resp.into_reader()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| HostError::Failed(format!("TypeError: Failed to fetch — {e}")))?;
        if body.len() > MAX_BODY {
            return Err(HostError::Failed(
                "TypeError: Failed to fetch — response exceeded the buffer limit".into(),
            ));
        }
        Ok(Response {
            status,
            status_text,
            headers,
            body,
            url: request.url.clone(),
            redirected: false,
        })
    }
}
