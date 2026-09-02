//! A response may not cost more than the caller agreed to.
//!
//! `Request::max_body` is only a promise until a transport is made to keep it
//! against a peer that does not cooperate, so every case here is a server that
//! answers and then refuses to stop: chunked with no declared length and no
//! terminator, and a declared length larger than any host should accept. The
//! ceilings are small so the test is fast; the mechanism is the same at 64 MB.
//!
//! @ref LLP 0057#3-the-boundary — the platform executes the ceiling, Rust sets it

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use ibex2::stdlib::fetch::{Request, Transport};

/// What the server does once it has read a request head.
#[derive(Clone, Copy)]
enum Answer {
    /// Chunked, no `Content-Length`, and no terminating chunk — the shape a
    /// byte ceiling exists for, because nothing in the response says how much
    /// is coming or when it stops.
    ChunkedForever,
    /// A declared length no client should agree to read.
    DeclaresGigabytes,
    /// An ordinary small body, to prove the ceiling does not break traffic.
    Small,
}

/// A one-shot local HTTP server. Returns its URL; the thread ends with it.
fn serve(answer: Answer) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        read_head(&mut stream);
        match answer {
            Answer::ChunkedForever => {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n",
                );
                let chunk = vec![b'x'; 8 * 1024];
                // Until the client hangs up, which is the outcome under test.
                loop {
                    if stream
                        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                        .and_then(|_| stream.write_all(&chunk))
                        .and_then(|_| stream.write_all(b"\r\n"))
                        .and_then(|_| stream.flush())
                        .is_err()
                    {
                        return;
                    }
                }
            }
            Answer::DeclaresGigabytes => {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4294967296\r\n\r\n",
                );
                let _ = stream.write_all(&vec![b'x'; 4096]);
                let _ = stream.flush();
                // Hold the connection so a client that ignored the declared
                // length would sit here rather than see a tidy EOF.
                thread::sleep(Duration::from_secs(5));
            }
            Answer::Small => {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
                );
                let _ = stream.flush();
            }
        }
    });
    format!("http://127.0.0.1:{port}/")
}

fn read_head(stream: &mut TcpStream) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return;
        }
    }
}

fn bounded(url: &str, limit: usize) -> Request {
    let mut request = Request::get(url);
    request.max_body = Some(limit);
    request
}

/// The transport this platform actually uses, alongside the development one:
/// the ceiling is a property of the boundary, not of one implementation.
fn platform_transport() -> Box<dyn Transport> {
    ibex2::transport::default_transport()
}

fn refused(error: &str, limit: usize) -> bool {
    error.contains(&format!("exceeded the {limit}-byte limit"))
}

#[test]
fn a_chunked_response_with_no_end_is_refused_at_the_ceiling() {
    let limit = 64 * 1024;
    for (name, transport) in named_transports() {
        let url = serve(Answer::ChunkedForever);
        let error = transport
            .send(&bounded(&url, limit))
            .err()
            .unwrap_or_else(|| panic!("{name} accepted an endless response"));
        let text = format!("{error}");
        assert!(refused(&text, limit), "{name}: unexpected error {text}");
    }
}

#[test]
fn a_declared_length_over_the_ceiling_is_refused() {
    let limit = 64 * 1024;
    for (name, transport) in named_transports() {
        let url = serve(Answer::DeclaresGigabytes);
        let error = transport
            .send(&bounded(&url, limit))
            .err()
            .unwrap_or_else(|| panic!("{name} accepted a 4 GB declaration"));
        let text = format!("{error}");
        assert!(refused(&text, limit), "{name}: unexpected error {text}");
    }
}

#[test]
fn a_response_under_the_ceiling_is_untouched() {
    for (name, transport) in named_transports() {
        let url = serve(Answer::Small);
        let response = transport
            .send(&bounded(&url, 64 * 1024))
            .unwrap_or_else(|e| panic!("{name} refused a 5-byte body: {e}"));
        assert_eq!(response.status, 200, "{name}");
        assert_eq!(response.text(), "hello", "{name}");
    }
}

/// The default ceiling applies to a request that names none — the guarantee
/// cannot depend on every caller remembering to ask for it.
#[test]
fn a_request_that_names_no_ceiling_still_has_one() {
    assert_eq!(
        Request::get("http://127.0.0.1/").body_limit(),
        ibex2::stdlib::fetch::DEFAULT_MAX_BODY
    );
}

fn named_transports() -> Vec<(&'static str, Box<dyn Transport>)> {
    vec![
        (
            "dev-tcp",
            Box::new(ibex2::transport::DevTcpTransport::new()) as Box<dyn Transport>,
        ),
        ("platform", platform_transport()),
    ]
}
