//! The transport off Apple platforms: HTTP/1.1 over rustls, through `ureq`
//! (LLP 0068 OQ2, resolved 2026-08-30 for Exact 2's Linux host).
//!
//! LLP 0057 §3 keeps everything above the socket in Rust: this transport
//! performs exactly one request and follows no redirect (`fetch` does that
//! above), reports every status as a response (a 4xx or 5xx is an answer,
//! not a transport failure), and turns what never connected into
//! `HostError::Failed` with the browser's own `TypeError: Failed to fetch`
//! spelling.
//!
//! **Trust is the platform's.** The roots are the machine's CA bundle —
//! `/etc/ssl/certs`, `SSL_CERT_FILE`/`SSL_CERT_DIR`, what `rustls-native-certs`
//! finds — as `NSURLSession` trusts the Keychain on Apple and a browser
//! trusts the OS-installed roots: an enterprise CA or a development proxy
//! works here the way it works everywhere else. Only a machine with no
//! bundle at all (a stripped container) gets the compiled-in webpki roots
//! — Mozilla's set, the same one a distro installs — and [`Roots`] says which
//! was used so the consumer can say so in its journal.

use crate::boundary::HostError;
use crate::stdlib::fetch::{over_limit, Headers, Request, Response, Transport};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

/// Where the trust roots came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Roots {
    /// The platform's CA bundle: this many certificates loaded.
    System(usize),
    /// No platform bundle was found: the compiled-in webpki roots.
    CompiledIn,
}

impl std::fmt::Display for Roots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Roots::System(n) => write!(f, "the system's trust store ({n} roots)"),
            Roots::CompiledIn => write!(f, "no system trust store; the compiled-in roots"),
        }
    }
}

/// The transport: one `ureq` agent, rustls underneath.
pub struct RustlsHttpTransport {
    agent: ureq::Agent,
    roots: Roots,
}

impl RustlsHttpTransport {
    /// Three deadlines, no redirects, the platform's roots (or the compiled-in
    /// ones where there are none).
    ///
    /// The overall thirty seconds is the one that was always here. The other
    /// two bound the shapes it does not: a peer that accepts the connection
    /// and never answers (`timeout_connect`, `timeout_read` — the read
    /// deadline is what caps time-to-first-byte), and one that answers and
    /// then drips a byte at a time to hold the socket open. Without them a
    /// request that never overflows the byte ceiling can still hold a thread
    /// for as long as the peer likes.
    pub fn new() -> Self {
        let (config, roots) = tls_config();
        Self {
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout_connect(Duration::from_secs(10))
                .timeout_read(Duration::from_secs(15))
                .timeout(Duration::from_secs(30))
                .tls_config(Arc::new(config))
                .build(),
            roots,
        }
    }

    /// Where this transport's trust roots came from.
    pub fn roots(&self) -> Roots {
        self.roots
    }
}

impl Default for RustlsHttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// The rustls client configuration: the platform's roots, else webpki's.
fn tls_config() -> (rustls::ClientConfig, Roots) {
    let mut store = rustls::RootCertStore::empty();
    let mut loaded = 0usize;
    if let Ok(certs) = rustls_native_certs::load_native_certs() {
        for cert in certs {
            if store.add(cert).is_ok() {
                loaded += 1;
            }
        }
    }
    let roots = if loaded > 0 {
        Roots::System(loaded)
    } else {
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Roots::CompiledIn
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth();
    (config, roots)
}

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
        // The ceiling the caller asked for, refused twice: once on the
        // declared length, so a peer that announces five gigabytes is turned
        // away before a byte of it is read, and again on what actually
        // arrives, because Content-Length is the peer's claim and a chunked
        // response makes no claim at all. `take` is what makes the second one
        // a bound rather than an observation — the read stops one byte past
        // the limit, and dropping the reader closes the connection under it.
        let limit = request.body_limit();
        if let Some(declared) = resp
            .header("content-length")
            .and_then(|v| v.trim().parse::<u64>().ok())
        {
            if declared > limit as u64 {
                return Err(over_limit(limit));
            }
        }
        let mut body = Vec::new();
        resp.into_reader()
            .take(limit as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| HostError::Failed(format!("TypeError: Failed to fetch — {e}")))?;
        if body.len() > limit {
            return Err(over_limit(limit));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine with a CA bundle trusts it; one without gets the compiled-in
    /// roots and says so. (`SSL_CERT_FILE`/`SSL_CERT_DIR` are how the bundle
    /// is pointed elsewhere, so pointing them nowhere is "no bundle".)
    #[test]
    fn the_roots_are_the_platforms_else_the_compiled_in_ones() {
        let (_, roots) = tls_config();
        assert!(matches!(roots, Roots::System(n) if n > 0) || roots == Roots::CompiledIn);
        std::env::set_var("SSL_CERT_FILE", "/nonexistent/certs.pem");
        std::env::set_var("SSL_CERT_DIR", "/nonexistent/certs");
        let (config, roots) = tls_config();
        std::env::remove_var("SSL_CERT_FILE");
        std::env::remove_var("SSL_CERT_DIR");
        assert_eq!(roots, Roots::CompiledIn);
        assert!(config.alpn_protocols.is_empty());
    }
}
