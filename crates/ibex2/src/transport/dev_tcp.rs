//! A development transport, and a placeholder for the platform's.
//!
//! LLP 0057 §3 gives the platform sockets, TLS, proxy configuration, HTTP/2
//! and /3, connection pooling, and the system certificate store. This is none
//! of that: it is plaintext HTTP/1.1 over a raw socket, one connection per
//! request, so the semantics above it can be exercised end to end before any
//! platform binding exists.
//!
//! **It does not speak TLS, and that is deliberate rather than unfinished.** A
//! hand-rolled TLS client is exactly the kind of thing LLP 0059.000 §3.4 warns
//! about for URL parsing — a partial implementation of a security-critical
//! protocol is a vulnerability, not a missing feature. `https` is refused here
//! and belongs to `NSURLSession` on Apple platforms and the equivalent
//! elsewhere.
//!
//! @ref LLP 0057#3-the-boundary — the platform owns transport; this stands in for it

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::boundary::HostError;
use crate::stdlib::fetch::{Headers, Request, Response, Transport};

/// Plaintext HTTP/1.1, one connection per request.
#[derive(Debug, Default)]
pub struct DevTcpTransport {
    pub timeout: Option<Duration>,
}

impl DevTcpTransport {
    pub fn new() -> Self {
        Self {
            timeout: Some(Duration::from_secs(10)),
        }
    }
}

/// Cap on a response we will buffer. v1 buffers bodies whole
/// (LLP 0059.000 §5), so there must be a ceiling — an unbounded read from a
/// remote peer is a denial-of-service the runtime hands out for free.
const MAX_BODY: usize = 64 * 1024 * 1024;

impl Transport for DevTcpTransport {
    fn send(&self, request: &Request) -> Result<Response, HostError> {
        let url = url::Url::parse(&request.url)
            .map_err(|e| HostError::Failed(format!("TypeError: invalid URL: {e}")))?;

        if url.scheme() != "http" {
            return Err(HostError::Failed(format!(
                "TypeError: the development transport speaks plaintext http only, not {} — \
                 TLS belongs to the platform transport",
                url.scheme()
            )));
        }

        let host = url
            .host_str()
            .ok_or_else(|| HostError::Failed("TypeError: URL has no host".into()))?;
        let port = url.port_or_known_default().unwrap_or(80);

        let mut stream = TcpStream::connect((host, port))
            .map_err(|e| HostError::Failed(format!("TypeError: Failed to fetch — {e}")))?;
        stream
            .set_read_timeout(self.timeout)
            .and_then(|_| stream.set_write_timeout(self.timeout))
            .map_err(|e| HostError::Failed(format!("TypeError: Failed to fetch — {e}")))?;

        let mut path = url.path().to_string();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }

        // The transport supplies Host, Connection, and Content-Length — which
        // is exactly why fetch::Headers refuses to let a caller set them.
        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            request.method, path, host
        );
        for (name, value) in request.headers.entries() {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if let Some(body) = &request.body {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");

        stream
            .write_all(head.as_bytes())
            .and_then(|_| match &request.body {
                Some(body) => stream.write_all(body),
                None => Ok(()),
            })
            .and_then(|_| stream.flush())
            .map_err(|e| HostError::Failed(format!("TypeError: Failed to fetch — {e}")))?;

        let mut raw = Vec::new();
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&buffer[..n]);
                    if raw.len() > MAX_BODY {
                        return Err(HostError::Failed(
                            "TypeError: Failed to fetch — response exceeded the buffer limit"
                                .into(),
                        ));
                    }
                }
                Err(e) => {
                    return Err(HostError::Failed(format!(
                        "TypeError: Failed to fetch — {e}"
                    )))
                }
            }
        }

        parse_response(&raw, &request.url)
    }
}

pub(crate) fn parse_response(raw: &[u8], url: &str) -> Result<Response, HostError> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            HostError::Failed("TypeError: Failed to fetch — malformed response".into())
        })?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let body = raw[split + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| HostError::Failed("TypeError: Failed to fetch — empty response".into()))?;

    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next();
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| HostError::Failed("TypeError: Failed to fetch — bad status".into()))?;
    let status_text = parts.next().unwrap_or("").to_string();

    let mut headers = Headers::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            // set_response, not set: a response legitimately carries
            // content-length and connection, which a request may not.
            headers.set_response(name, value);
        }
    }

    Ok(Response {
        status,
        status_text,
        headers,
        body,
        url: url.to_string(),
        redirected: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_normal_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        let got = parse_response(raw, "http://x/").unwrap();
        assert_eq!(got.status, 200);
        assert_eq!(got.status_text, "OK");
        assert_eq!(got.headers.get("content-type"), Some("text/plain"));
        assert_eq!(got.text(), "hello");
        assert!(got.ok());
    }

    #[test]
    fn parses_a_response_with_no_body() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let got = parse_response(raw, "http://x/").unwrap();
        assert_eq!(got.status, 204);
        assert!(got.body.is_empty());
    }

    #[test]
    fn a_malformed_response_is_an_error_not_a_panic() {
        assert!(parse_response(b"garbage", "http://x/").is_err());
        assert!(parse_response(b"", "http://x/").is_err());
    }

    #[test]
    fn https_is_refused_rather_than_downgraded() {
        let transport = DevTcpTransport::new();
        let err = transport
            .send(&Request::get("https://example.com/"))
            .unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("plaintext http only"), "unexpected: {text}");
    }
}
