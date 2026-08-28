//! `fetch` — delegating, **capability-bearing** (LLP 0059.000 §3.5).
//!
//! The largest v1 item, and the first one that carries a capability.
//!
//! **Rust owns:** header name case-folding and the forbidden-header list,
//! redirect following and its count limit, the body state machine,
//! and the error taxonomy — so failures are identical on every platform.
//!
//! **The platform owns:** sockets, TLS, proxy configuration, HTTP/2 and /3,
//! connection pooling, and the system certificate store. That split is why the
//! transport is a trait here and not a hard-coded client: inverting it gives
//! four platforms four different `fetch`es, which is the failure mode a
//! cross-platform runtime exists to prevent.
//!
//! @ref LLP 0059.000#35-fetch--delegating-capability-bearing — the surface this implements
//! @ref LLP 0057#3-the-boundary — Rust owns semantics, the platform owns transport

use crate::boundary::HostError;
use crate::grant::{GrantSet, Operation, Origin};

/// How many redirects to follow before giving up. The web platform's limit.
pub const MAX_REDIRECTS: u32 = 20;

/// Header names are case-insensitive; values are not.
///
/// Stored folded so lookup and duplicate detection are exact, and so two
/// platforms cannot disagree about whether `Content-Type` and `content-type`
/// are the same header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

/// Headers a caller may not set, because the transport owns them.
///
/// Per the Fetch spec's forbidden request-header list, trimmed to what this
/// transport actually controls. Silently ignoring an attempt is what the spec
/// requires — not an error, but not honored either.
const FORBIDDEN_REQUEST_HEADERS: &[&str] = &[
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "upgrade",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
];

impl Headers {
    pub fn new() -> Self {
        Self::default()
    }

    fn fold(name: &str) -> String {
        name.trim().to_ascii_lowercase()
    }

    /// Set a header, replacing any existing value. Forbidden names are ignored.
    pub fn set(&mut self, name: &str, value: &str) {
        let folded = Self::fold(name);
        if FORBIDDEN_REQUEST_HEADERS.contains(&folded.as_str()) {
            return;
        }
        let value = value.trim().to_string();
        match self.entries.iter_mut().find(|(k, _)| *k == folded) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((folded, value)),
        }
    }

    /// Append, combining with any existing value as `a, b` per the spec.
    pub fn append(&mut self, name: &str, value: &str) {
        let folded = Self::fold(name);
        if FORBIDDEN_REQUEST_HEADERS.contains(&folded.as_str()) {
            return;
        }
        let value = value.trim().to_string();
        match self.entries.iter_mut().find(|(k, _)| *k == folded) {
            Some(entry) => {
                entry.1.push_str(", ");
                entry.1.push_str(&value);
            }
            None => self.entries.push((folded, value)),
        }
    }

    /// Set without the forbidden-header filter, for headers a *response*
    /// carries. A response's `content-length` is information, not an attempt
    /// to control the transport.
    pub fn set_response(&mut self, name: &str, value: &str) {
        let folded = Self::fold(name);
        let value = value.trim().to_string();
        match self.entries.iter_mut().find(|(k, _)| *k == folded) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((folded, value)),
        }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        let folded = Self::fold(name);
        self.entries
            .iter()
            .find(|(k, _)| *k == folded)
            .map(|(_, v)| v.as_str())
    }

    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn delete(&mut self, name: &str) {
        let folded = Self::fold(name);
        self.entries.retain(|(k, _)| *k != folded);
    }

    pub fn entries(&self) -> &[(String, String)] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// What a redirect response should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectMode {
    /// Follow, up to `MAX_REDIRECTS`. The default.
    Follow,
    /// Return the redirect response itself.
    Manual,
    /// Treat a redirect as a network error.
    Error,
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Headers,
    pub body: Option<Vec<u8>>,
    pub redirect: RedirectMode,
}

impl Request {
    pub fn get(url: &str) -> Self {
        Self {
            method: "GET".into(),
            url: url.into(),
            headers: Headers::new(),
            body: None,
            redirect: RedirectMode::Follow,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub headers: Headers,
    pub body: Vec<u8>,
    /// The URL the response came from, after any redirects.
    pub url: String,
    pub redirected: bool,
}

impl Response {
    /// `Response.ok` — the 200-299 range, and nothing else.
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// What the platform must provide. Everything above this line is Rust's.
pub trait Transport: Send + Sync {
    /// Perform exactly one request. **No redirect following** — that is
    /// semantics and belongs to Rust, above.
    fn send(&self, request: &Request) -> Result<Response, HostError>;
}

/// Extract the origin a URL belongs to, for the capability check.
pub fn origin_of(url: &str) -> Result<Origin, HostError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| HostError::Failed(format!("TypeError: invalid URL: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| HostError::Failed("TypeError: URL has no host".into()))?;
    let port = parsed.port_or_known_default().ok_or_else(|| {
        HostError::Failed(format!(
            "TypeError: no default port for scheme {}",
            parsed.scheme()
        ))
    })?;
    Ok(Origin::new(parsed.scheme(), host, port))
}

/// Perform a fetch: check the grant, then follow redirects up to the limit.
///
/// **The capability check happens per-origin and it happens again on every
/// redirect hop.** A grant for `a.example` must not become a grant for
/// `b.example` because `a.example` answered with a `Location` pointing there —
/// that is the whole redirect-laundering class, and checking only the initial
/// URL is how a runtime falls into it.
pub fn fetch(
    transport: &dyn Transport,
    grants: &GrantSet,
    request: Request,
) -> Result<Response, HostError> {
    let mut current = request;
    let mut redirects = 0;
    let mut redirected = false;

    loop {
        let origin = origin_of(&current.url)?;
        let operation = Operation::Fetch {
            origin: origin.clone(),
        };
        if !grants.permits(&operation) {
            return Err(HostError::Denied {
                capability: "net.fetch",
            });
        }

        let mut response = transport.send(&current)?;
        response.redirected = redirected;

        let is_redirect = matches!(response.status, 301 | 302 | 303 | 307 | 308);
        if !is_redirect {
            return Ok(response);
        }

        match current.redirect {
            RedirectMode::Manual => return Ok(response),
            RedirectMode::Error => {
                return Err(HostError::Failed(
                    "TypeError: Failed to fetch — redirect not allowed".into(),
                ))
            }
            RedirectMode::Follow => {}
        }

        let Some(location) = response.headers.get("location").map(str::to_string) else {
            // A redirect status with no Location is not a redirect; the spec
            // says return it as-is rather than inventing a destination.
            return Ok(response);
        };

        redirects += 1;
        if redirects > MAX_REDIRECTS {
            return Err(HostError::Failed(
                "TypeError: Failed to fetch — too many redirects".into(),
            ));
        }

        // Resolve relative Locations against the URL we just used.
        let base = url::Url::parse(&current.url)
            .map_err(|e| HostError::Failed(format!("TypeError: invalid URL: {e}")))?;
        let next = base
            .join(&location)
            .map_err(|e| HostError::Failed(format!("TypeError: invalid redirect target: {e}")))?;

        // 303, and 301/302 on POST, become GET and drop the body — the web's
        // long-standing behaviour, which surprises people who expect the
        // method to be preserved.
        if response.status == 303
            || (matches!(response.status, 301 | 302)
                && current.method != "GET"
                && current.method != "HEAD")
        {
            current.method = "GET".into();
            current.body = None;
        }
        current.url = next.to_string();
        redirected = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::Grant;
    use std::sync::Mutex;

    /// Records what it was asked for and replays canned responses.
    struct StubTransport {
        responses: Mutex<Vec<Response>>,
        seen: Mutex<Vec<(String, String)>>,
    }

    impl StubTransport {
        fn new(responses: Vec<Response>) -> Self {
            Self {
                responses: Mutex::new(responses),
                seen: Mutex::new(Vec::new()),
            }
        }
        fn seen(&self) -> Vec<(String, String)> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Transport for StubTransport {
        fn send(&self, request: &Request) -> Result<Response, HostError> {
            self.seen
                .lock()
                .unwrap()
                .push((request.method.clone(), request.url.clone()));
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                return Err(HostError::Failed("stub ran out of responses".into()));
            }
            Ok(responses.remove(0))
        }
    }

    fn response(status: u16, location: Option<&str>) -> Response {
        let mut headers = Headers::new();
        if let Some(location) = location {
            headers.set_response("Location", location);
        }
        Response {
            status,
            status_text: "".into(),
            headers,
            body: b"body".to_vec(),
            url: String::new(),
            redirected: false,
        }
    }

    fn granted(host: &str) -> GrantSet {
        GrantSet::none().with(Grant::Fetch(Origin::new("https", host, 443)))
    }

    #[test]
    fn header_names_fold_case_and_values_do_not() {
        let mut headers = Headers::new();
        headers.set("Content-Type", "Application/JSON");
        assert_eq!(headers.get("content-type"), Some("Application/JSON"));
        assert_eq!(headers.get("CONTENT-TYPE"), Some("Application/JSON"));
        headers.set("content-type", "text/plain");
        assert_eq!(headers.len(), 1, "same header, replaced not duplicated");
        assert_eq!(headers.get("Content-Type"), Some("text/plain"));
    }

    #[test]
    fn append_combines_with_a_comma() {
        let mut headers = Headers::new();
        headers.append("Accept", "text/html");
        headers.append("accept", "application/json");
        assert_eq!(headers.get("accept"), Some("text/html, application/json"));
    }

    #[test]
    fn forbidden_request_headers_are_ignored() {
        let mut headers = Headers::new();
        headers.set("Host", "evil.example");
        headers.set("Content-Length", "0");
        headers.set("Connection", "close");
        headers.set("X-Fine", "yes");
        assert!(!headers.has("host"));
        assert!(!headers.has("content-length"));
        assert!(!headers.has("connection"));
        assert_eq!(headers.get("x-fine"), Some("yes"));
    }

    #[test]
    fn a_response_may_carry_content_length() {
        let mut headers = Headers::new();
        headers.set_response("Content-Length", "42");
        assert_eq!(headers.get("content-length"), Some("42"));
    }

    #[test]
    fn ok_is_exactly_the_two_hundreds() {
        for (status, expected) in [
            (199, false),
            (200, true),
            (299, true),
            (300, false),
            (404, false),
        ] {
            let mut r = response(status, None);
            r.status = status;
            assert_eq!(r.ok(), expected, "status {status}");
        }
    }

    #[test]
    fn an_ungranted_origin_is_refused_before_any_request_is_made() {
        let transport = StubTransport::new(vec![response(200, None)]);
        let err = fetch(
            &transport,
            &GrantSet::none(),
            Request::get("https://example.com/"),
        )
        .unwrap_err();
        assert_eq!(
            err,
            HostError::Denied {
                capability: "net.fetch"
            }
        );
        assert!(
            transport.seen().is_empty(),
            "a denied fetch must not reach the transport at all"
        );
    }

    #[test]
    fn a_granted_origin_succeeds() {
        let transport = StubTransport::new(vec![response(200, None)]);
        let got = fetch(
            &transport,
            &granted("example.com"),
            Request::get("https://example.com/x"),
        )
        .unwrap();
        assert!(got.ok());
        assert_eq!(transport.seen().len(), 1);
    }

    /// The redirect-laundering case. A grant for one origin must not become a
    /// grant for another just because the first one redirected there.
    #[test]
    fn a_redirect_to_an_ungranted_origin_is_refused() {
        let transport = StubTransport::new(vec![
            response(302, Some("https://evil.example/steal")),
            response(200, None),
        ]);
        let err = fetch(
            &transport,
            &granted("example.com"),
            Request::get("https://example.com/"),
        )
        .unwrap_err();
        assert_eq!(
            err,
            HostError::Denied {
                capability: "net.fetch"
            }
        );
        assert_eq!(
            transport.seen().len(),
            1,
            "the second hop must never be sent"
        );
    }

    #[test]
    fn a_redirect_within_a_granted_origin_is_followed() {
        let transport =
            StubTransport::new(vec![response(302, Some("/moved")), response(200, None)]);
        let got = fetch(
            &transport,
            &granted("example.com"),
            Request::get("https://example.com/start"),
        )
        .unwrap();
        assert!(got.ok());
        assert!(got.redirected);
        assert_eq!(
            transport.seen(),
            vec![
                ("GET".to_string(), "https://example.com/start".to_string()),
                ("GET".to_string(), "https://example.com/moved".to_string()),
            ]
        );
    }

    #[test]
    fn a_303_turns_a_post_into_a_get_and_drops_the_body() {
        let transport = StubTransport::new(vec![response(303, Some("/done")), response(200, None)]);
        let mut request = Request::get("https://example.com/submit");
        request.method = "POST".into();
        request.body = Some(b"a=1".to_vec());
        fetch(&transport, &granted("example.com"), request).unwrap();
        assert_eq!(transport.seen()[1].0, "GET");
    }

    #[test]
    fn a_307_preserves_the_method() {
        let transport =
            StubTransport::new(vec![response(307, Some("/again")), response(200, None)]);
        let mut request = Request::get("https://example.com/submit");
        request.method = "POST".into();
        fetch(&transport, &granted("example.com"), request).unwrap();
        assert_eq!(transport.seen()[1].0, "POST");
    }

    #[test]
    fn redirect_manual_returns_the_redirect_itself() {
        let transport = StubTransport::new(vec![response(302, Some("/moved"))]);
        let mut request = Request::get("https://example.com/");
        request.redirect = RedirectMode::Manual;
        let got = fetch(&transport, &granted("example.com"), request).unwrap();
        assert_eq!(got.status, 302);
        assert_eq!(transport.seen().len(), 1);
    }

    #[test]
    fn too_many_redirects_is_an_error_not_an_infinite_loop() {
        let responses = (0..MAX_REDIRECTS + 2)
            .map(|_| response(302, Some("/loop")))
            .collect();
        let transport = StubTransport::new(responses);
        let err = fetch(
            &transport,
            &granted("example.com"),
            Request::get("https://example.com/"),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("too many redirects"));
    }

    #[test]
    fn origin_of_uses_the_schemes_default_port() {
        assert_eq!(
            origin_of("https://example.com/x").unwrap(),
            Origin::new("https", "example.com", 443)
        );
        assert_eq!(
            origin_of("http://example.com/x").unwrap(),
            Origin::new("http", "example.com", 80)
        );
        assert_eq!(
            origin_of("https://example.com:8443/x").unwrap(),
            Origin::new("https", "example.com", 8443)
        );
    }
}
